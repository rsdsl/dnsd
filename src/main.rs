use std::cell::RefCell;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader};
use std::net::{self, IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use dns_message_parser::question::{QType, Question};
use dns_message_parser::rr::{Class, A, AAAA, PTR, RR};
use dns_message_parser::{Dns, DomainName, Flags, RCode};
use hickory_proto::rr::Name;
use ipnet::IpNet;
use rsdsl_dhcp4d::lease::Lease;
use signal_hook::{
    consts::{SIGUSR1, SIGUSR2},
    iterator::Signals,
};
use thiserror::Error;

const UPSTREAM_PRIMARY: &str = "[2620:fe::fe]:53";
const UPSTREAM_SECONDARY: &str = "9.9.9.9:53";
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(3);

type ForwardHosts = Arc<RwLock<HashMap<String, IpAddr>>>;
type ReverseHosts = Arc<RwLock<HashMap<IpAddr, String>>>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("hosts entry missing address column: {0}")]
    NoAddrColumn(String),
    #[error("failed to send whole packet (expected {0}, got {1})")]
    PartialSend(usize, usize),

    #[error("network address parse error: {0}")]
    AddrParse(#[from] net::AddrParseError),
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error("dns_message_parser decode error: {0}")]
    DnsDecode(#[from] dns_message_parser::DecodeError),
    #[error("dns_message_parser encode error: {0}")]
    DnsEncode(#[from] dns_message_parser::EncodeError),
    #[error("serde_json error: {0}")]
    SerdeJson(#[from] serde_json::Error),
    #[error("hickory_proto error: {0}")]
    HickoryProto(#[from] hickory_proto::error::ProtoError),
}

pub type Result<T> = std::result::Result<T, Error>;

fn refresh_leases(cache: Arc<RwLock<Vec<Lease>>>) -> Result<()> {
    let mut signals = Signals::new([SIGUSR1])?;
    for _ in signals.forever() {
        read_leases(cache.clone())?;
    }

    Ok(()) // unreachable
}

fn refresh_leases_supervised(cache: Arc<RwLock<Vec<Lease>>>) -> ! {
    loop {
        match refresh_leases(cache.clone()) {
            Ok(_) => {}
            Err(e) => println!("[warn] lease refresh: {}", e),
        }
    }
}

fn read_leases(cache: Arc<RwLock<Vec<Lease>>>) -> Result<()> {
    let mut leases = Vec::new();

    let dir = fs::read_dir("/data")?.filter(|entry| {
        entry
            .as_ref()
            .expect("can't access dir entry of /data")
            .file_name()
            .into_string()
            .expect("lease file name is not valid UTF-8")
            .starts_with("dhcp4d.leases_")
    });

    for entry in dir {
        let entry = entry?;

        let file = File::open(entry.path())?;
        let mut net_leases: Vec<Lease> = match serde_json::from_reader(&file) {
            Ok(v) => v,
            Err(e) => {
                println!("[warn] broken lease file {}: {}", entry.path().display(), e);
                continue;
            }
        };

        leases.append(&mut net_leases);
    }

    *cache.write().unwrap() = leases;
    Ok(())
}

fn refresh_hosts(forward: ForwardHosts, reverse: ReverseHosts) -> Result<()> {
    let mut signals = Signals::new([SIGUSR2])?;
    for _ in signals.forever() {
        read_hosts(forward.clone(), reverse.clone())?;
    }

    Ok(()) // unreachable
}

fn refresh_hosts_supervised(forward: ForwardHosts, reverse: ReverseHosts) -> ! {
    loop {
        match refresh_hosts(forward.clone(), reverse.clone()) {
            Ok(_) => {}
            Err(e) => println!("[warn] hosts refresh: {}", e),
        }
    }
}

fn read_hosts(forward: ForwardHosts, reverse: ReverseHosts) -> Result<()> {
    let mut forward_hosts = HashMap::new();
    let mut reverse_hosts = HashMap::new();

    let file = match File::open("/data/hosts.dnsd") {
        Ok(file) => file,
        Err(e) => {
            if e.kind() == io::ErrorKind::NotFound {
                return Ok(());
            } else {
                return Err(e.into());
            }
        }
    };
    let reader = BufReader::new(file);
    for line in reader.lines() {
        let line = line?;
        let split_input = line.clone();

        let mut columns = split_input.split_whitespace();
        let addr = columns.next().ok_or(Error::NoAddrColumn(line))?;
        let parsed_addr = addr.parse()?;
        for host in columns {
            let host = host.to_string() + ".";

            forward_hosts.insert(host.clone(), parsed_addr);
            reverse_hosts.insert(parsed_addr, host);
        }
    }

    *forward.write().unwrap() = forward_hosts;
    *reverse.write().unwrap() = reverse_hosts;

    Ok(())
}

fn main() -> Result<()> {
    println!("[info] init");

    let leases = Arc::new(RwLock::new(Vec::new()));
    read_leases(leases.clone())?;

    let leases2 = leases.clone();
    thread::spawn(move || refresh_leases_supervised(leases2));

    let forward_hosts = Arc::new(RwLock::new(HashMap::new()));
    let reverse_hosts = Arc::new(RwLock::new(HashMap::new()));
    read_hosts(forward_hosts.clone(), reverse_hosts.clone())?;

    let forward2 = forward_hosts.clone();
    let reverse2 = reverse_hosts.clone();
    thread::spawn(move || refresh_hosts_supervised(forward2, reverse2));

    let domain = match fs::read_to_string("/data/dnsd.domain") {
        Ok(v) => match Name::from_utf8(v) {
            Ok(w) => Some(w),
            Err(e) => {
                println!("[warn] parse search domain: {}", e);
                None
            }
        },
        Err(e) => {
            println!("[warn] read search domain: {}", e);
            None
        }
    };

    let sock = UdpSocket::bind("[::]:53")?;

    loop {
        let mut buf = [0; 1024];
        let (n, raddr) = sock.recv_from(&mut buf)?;
        let buf = &buf[..n];

        let domain2 = domain.clone();
        let sock2 = sock.try_clone()?;
        let buf = buf.to_vec();
        let leases3 = leases.clone();
        let forward3 = forward_hosts.clone();
        let reverse3 = reverse_hosts.clone();
        thread::spawn(move || {
            match handle_query(&domain2, &sock2, &buf, raddr, leases3, forward3, reverse3) {
                Ok(_) => {}
                Err(e) => {
                    match respond_with_error(&sock2, &buf, raddr) {
                        Ok(_) => {}
                        Err(e) => println!("[warn] {} send error response: {}", raddr, e),
                    }

                    print_query_error(&buf, raddr, e);
                }
            }
        });
    }
}

fn print_query_error(buf: &[u8], raddr: SocketAddr, e: Error) {
    match extract_questions(buf) {
        Ok(questions) => {
            for q in questions {
                println!("[warn] {} => {}: {}", raddr, q, e);
            }
        }
        Err(eprint) => println!("[warn] {}: {}; printing error: {}", raddr, e, eprint),
    }
}

fn respond_with_error(sock: &UdpSocket, buf: &[u8], raddr: SocketAddr) -> Result<()> {
    let bytes = Bytes::copy_from_slice(buf);
    let msg = Dns::decode(bytes)?;

    let resp = Dns {
        id: msg.id,
        flags: Flags {
            qr: true,
            opcode: msg.flags.opcode,
            aa: false,
            tc: false,
            rd: msg.flags.rd,
            ra: true,
            ad: false,
            cd: false,
            rcode: RCode::ServFail,
        },
        questions: Vec::default(),
        answers: Vec::default(),
        authorities: Vec::default(),
        additionals: Vec::default(),
    };

    let bytes = resp.encode()?;

    let n = sock.send_to(&bytes, raddr)?;
    if n != bytes.len() {
        return Err(Error::PartialSend(bytes.len(), n));
    }

    Ok(())
}

fn extract_questions(buf: &[u8]) -> Result<Vec<Question>> {
    let bytes = Bytes::copy_from_slice(buf);
    let msg = Dns::decode(bytes)?;

    Ok(msg.questions)
}

fn handle_query(
    domain: &Option<Name>,
    sock: &UdpSocket,
    buf: &[u8],
    raddr: SocketAddr,
    leases: Arc<RwLock<Vec<Lease>>>,
    forward_hosts: ForwardHosts,
    reverse_hosts: ReverseHosts,
) -> Result<()> {
    let bytes = Bytes::copy_from_slice(buf);
    let mut msg = Dns::decode(bytes)?;

    let questions = msg.questions.clone();

    // Check for any invalid names. The closures cannot propagate errors to the caller.
    // Failing is okay here because queries usually only contain a single question.
    for q in &questions {
        usable_name(domain, &q.domain_name)?;
    }

    let ptr_nx = RefCell::new(false);

    let (lan, fwd): (_, Vec<Question>) = msg.questions.into_iter().partition(|q| {
        let known = is_file_known(
            &usable_name(domain, &q.domain_name).expect("can't convert domain name"),
            forward_hosts.clone(),
            reverse_hosts.clone(),
        ) || is_dhcp_known(
            &usable_name(domain, &q.domain_name).expect("can't convert domain name"),
            leases.clone(),
        );

        if q.q_type == QType::PTR && !known {
            *ptr_nx.borrow_mut() = true;
        }

        known
    });

    msg.questions = fwd
        .into_iter()
        .filter(|q| q.domain_name.to_string().matches('.').count() >= 2)
        .filter(|q| {
            if q.domain_name.to_string().ends_with(".in-addr.arpa.")
                && q.domain_name.to_string().matches('.').count() <= 6
            {
                !IpNet::from_str("10.128.0.0/16").unwrap().contains(
                    &usable_name(domain, &q.domain_name)
                        .expect("can't convert domain name")
                        .parse_arpa_name()
                        .expect("can't parse arpa name"),
                )
            } else {
                true
            }
        })
        .collect();

    let lan_resp = lan.into_iter().filter_map(|q| {
        let hostname = usable_name(domain, &q.domain_name).expect("can't convert domain name");

        if q.q_type == QType::A {
            if let Some(entry) = file_entry(&hostname, forward_hosts.clone(), reverse_hosts.clone())
            {
                let IpAddr::V4(addr_as_v4) = entry.1 else {
                    return None;
                };
                let answer = RR::A(A {
                    domain_name: q.domain_name,
                    ttl: 300,
                    ipv4_addr: addr_as_v4,
                });

                println!("[file] {} => {}", raddr, answer);
                Some(answer)
            } else {
                let net_id = subnet_id(&raddr.ip());
                let lease = dhcp_lease(&hostname, net_id, leases.clone()).unwrap();

                let lease_ttl = match lease.expires.duration_since(SystemTime::now()) {
                    Ok(v) => v,
                    Err(_) => return None,
                };

                let answer = RR::A(A {
                    domain_name: q.domain_name,
                    ttl: lease_ttl.as_secs() as u32,
                    ipv4_addr: lease.address,
                });

                println!("[dhcp] {} => {}", raddr, answer);
                Some(answer)
            }
        } else if q.q_type == QType::AAAA {
            let entry = file_entry(&hostname, forward_hosts.clone(), reverse_hosts.clone())?;
            let IpAddr::V6(addr_as_v6) = entry.1 else {
                return None;
            };
            let answer = RR::AAAA(AAAA {
                domain_name: q.domain_name,
                ttl: 300,
                ipv6_addr: addr_as_v6,
            });

            println!("[file] {} => {}", raddr, answer);
            Some(answer)
        } else if q.q_type == QType::PTR {
            if let Some(entry) = file_entry(&hostname, forward_hosts.clone(), reverse_hosts.clone())
            {
                let name = entry.0
                    + &domain
                        .as_ref()
                        .map(|domain| domain.to_utf8())
                        .unwrap_or_default();

                let answer = RR::PTR(PTR {
                    domain_name: q.domain_name,
                    ttl: 300,
                    class: Class::IN,
                    ptr_d_name: name.parse().expect("can't parse hostname"),
                });

                println!("[file] {} => {}", raddr, answer);
                Some(answer)
            } else {
                let lease = dhcp_lease(&hostname, u8::MAX, leases.clone()).unwrap();

                let name = match lease.hostname.map(|name| {
                    name + "."
                        + &domain
                            .as_ref()
                            .map(|domain| domain.to_utf8())
                            .unwrap_or_default()
                }) {
                    Some(name) => name,
                    None => {
                        *ptr_nx.borrow_mut() = true;
                        return None;
                    }
                };

                let lease_ttl = match lease.expires.duration_since(SystemTime::now()) {
                    Ok(v) => v,
                    Err(_) => {
                        *ptr_nx.borrow_mut() = true;
                        return None;
                    }
                };

                let answer = RR::PTR(PTR {
                    domain_name: q.domain_name,
                    ttl: lease_ttl.as_secs() as u32,
                    class: Class::IN,
                    ptr_d_name: name.parse().expect("can't parse hostname"),
                });

                println!("[dhcp] {} => {}", raddr, answer);
                Some(answer)
            }
        } else {
            None
        }
    });

    let mut rcode = if *ptr_nx.borrow() {
        RCode::NXDomain
    } else {
        RCode::NoError
    };

    let mut resp_answers = Vec::new();
    let mut resp_authorities = Vec::new();
    let mut resp_additionals = Vec::new();

    if !msg.questions.is_empty() {
        let bytes = msg.encode()?;

        let resp = match upstream_query(UPSTREAM_PRIMARY, &bytes) {
            Ok(v) => v,
            Err(e) => match upstream_query(UPSTREAM_SECONDARY, &bytes) {
                Ok(v) => {
                    println!("[warn] {} primary unavailable: {}", raddr, e);
                    v
                }
                Err(e2) => {
                    println!("[warn] {} secondary unavailable: {}", raddr, e);
                    return Err(e2);
                }
            },
        };

        rcode = resp.flags.rcode;

        resp_answers = resp.answers;
        resp_authorities = resp.authorities;
        resp_additionals = resp.additionals;

        for answer in &resp_answers {
            println!("[fwrd] {} => {}", raddr, answer);
        }
    }

    let answers: Vec<RR> = resp_answers.into_iter().chain(lan_resp).collect();

    let resp = Dns {
        id: msg.id,
        flags: Flags {
            qr: true,
            opcode: msg.flags.opcode,
            aa: true,
            tc: false,
            rd: msg.flags.rd,
            ra: true,
            ad: false,
            cd: false,
            rcode,
        },
        questions,
        answers,
        authorities: resp_authorities,
        additionals: resp_additionals,
    };

    let bytes = resp.encode()?;

    let n = sock.send_to(&bytes, raddr)?;
    if n != bytes.len() {
        return Err(Error::PartialSend(bytes.len(), n));
    }

    Ok(())
}

fn upstream_query<A: ToSocketAddrs>(upstream: A, bytes: &[u8]) -> Result<Dns> {
    let uplink = UdpSocket::bind("[::]:0")?;

    uplink.set_read_timeout(Some(UPSTREAM_TIMEOUT))?;
    uplink.connect(upstream)?;

    let n = uplink.send(bytes)?;
    if n != bytes.len() {
        return Err(Error::PartialSend(bytes.len(), n));
    }

    let mut buf = [0; 1024];
    let n = uplink.recv(&mut buf)?;
    let buf = &buf[..n];

    let bytes = Bytes::copy_from_slice(buf);
    let resp = Dns::decode(bytes)?;

    Ok(resp)
}

fn file_entry(
    hostname: &Name,
    forward_hosts: ForwardHosts,
    reverse_hosts: ReverseHosts,
) -> Option<(String, IpAddr)> {
    let forward_hosts = forward_hosts.read().unwrap();
    let reverse_hosts = reverse_hosts.read().unwrap();

    let mapping = if (Name::from_str("in-addr.arpa.").unwrap().zone_of(hostname)
        && hostname.iter().len() <= 6)
        || (Name::from_str("ip6.arpa.").unwrap().zone_of(hostname) && hostname.iter().len() <= 34)
    {
        let addr = hostname
            .parse_arpa_name()
            .expect("can't parse arpa name")
            .addr();
        let host = reverse_hosts.get(&addr)?;
        (host.to_string(), addr)
    } else {
        let hostname_utf8 = hostname.to_utf8();
        let addr = forward_hosts.get(&hostname_utf8)?;
        (hostname_utf8, *addr)
    };

    Some(mapping)
}

fn is_file_known(
    hostname: &Name,
    forward_hosts: ForwardHosts,
    reverse_hosts: ReverseHosts,
) -> bool {
    file_entry(hostname, forward_hosts, reverse_hosts).is_some()
}

fn find_lease(hostname: &Name, mut leases: impl Iterator<Item = Lease>) -> Option<Lease> {
    leases.find(|lease| {
        if Name::from_str("in-addr.arpa.").unwrap().zone_of(hostname) && hostname.iter().len() <= 6
        {
            IpNet::new(lease.address.into(), 32).unwrap()
                == hostname.parse_arpa_name().expect("can't parse arpa name")
        } else {
            lease.hostname.clone().map(|name| name + ".") == Some(hostname.to_utf8())
        }
    })
}

fn dhcp_lease(hostname: &Name, net_id: u8, leases: Arc<RwLock<Vec<Lease>>>) -> Option<Lease> {
    let leases = leases.read().unwrap();

    let same_subnet = find_lease(
        hostname,
        leases
            .clone()
            .into_iter()
            .filter(|lease| subnet_id(&lease.address.into()) == net_id),
    );

    let any = find_lease(hostname, leases.clone().into_iter());

    same_subnet.or(any)
}

fn is_dhcp_known(hostname: &Name, leases: Arc<RwLock<Vec<Lease>>>) -> bool {
    dhcp_lease(hostname, u8::MAX, leases).is_some()
}

fn subnet_id(addr: &IpAddr) -> u8 {
    match addr {
        IpAddr::V4(v4) => v4.octets()[2],
        IpAddr::V6(v6) => (v6.octets()[7] & 0x07) * 10, // Max. 8 subnets => assume PD /61.
    }
}

fn usable_name(domain: &Option<Name>, name: &DomainName) -> Result<Name> {
    let as_name = Name::from_utf8(name.to_string())?;

    match domain {
        Some(domain) if domain.zone_of(&as_name) => {
            let mut labels = as_name.iter();

            labels.nth_back(domain.iter().len() - 1);
            Ok(Name::from_labels(labels).expect("labels invalid after removing domain"))
        }
        _ => Ok(as_name),
    }
}
