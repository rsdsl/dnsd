use rsdsl_dnsd::error::{Error, Result};

use std::cell::RefCell;
use std::fs::{self, File};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, SystemTime};

use byteorder::{ByteOrder, NetworkEndian as NE};
use bytes::Bytes;
use dns_message_parser::question::{QType, Question};
use dns_message_parser::rr::{Class, A, PTR, RR};
use dns_message_parser::{Dns, DomainName, Flags, Opcode, RCode};
use ipnet::IpNet;
use notify::event::{AccessKind, AccessMode, CreateKind};
use notify::{Event, EventKind, RecursiveMode, Watcher};
use rsdsl_dhcp4d::lease::Lease;
use trust_dns_proto::rr::Name;

const UPSTREAM: &str = "8.8.8.8:53";

fn refresh_leases(cache: Arc<RwLock<Vec<Lease>>>) -> Result<()> {
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<Event>| match res {
        Ok(event) => {
            if event.paths.iter().any(|v| {
                v.to_str()
                    .expect("lease file name is not valid UTF-8")
                    .starts_with("/data/dhcp4d.leases_")
            }) {
                match event.kind {
                    EventKind::Create(kind) if kind == CreateKind::File => {
                        read_leases(cache.clone()).expect("can't read lease files");
                    }
                    EventKind::Access(kind) if kind == AccessKind::Close(AccessMode::Write) => {
                        read_leases(cache.clone()).expect("can't read lease files");
                    }
                    _ => {}
                }
            }
        }
        Err(e) => println!("watch error: {:?}", e),
    })?;

    watcher.watch(Path::new("/data"), RecursiveMode::Recursive)?;

    loop {
        thread::sleep(Duration::MAX)
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
                println!("ignore broken lease file {}: {}", entry.path().display(), e);

                continue;
            }
        };

        leases.append(&mut net_leases);
    }

    *cache.write().unwrap() = leases;
    Ok(())
}

fn main() -> Result<()> {
    println!("init");

    let leases = Arc::new(RwLock::new(Vec::new()));
    read_leases(leases.clone())?;

    let leases2 = leases.clone();
    thread::spawn(move || match refresh_leases(leases2) {
        Ok(_) => unreachable!(),
        Err(e) => println!("{}", e),
    });

    let domain = match fs::read_to_string("/data/dnsd.domain") {
        Ok(v) => match Name::from_utf8(v) {
            Ok(w) => Some(w),
            Err(e) => {
                println!("can't get search domain: {}", e);
                None
            }
        },
        Err(e) => {
            println!("can't get search domain: {}", e);
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
        thread::spawn(
            move || match handle_query(&domain2, sock2, &buf, raddr, leases3) {
                Ok(_) => {}
                Err(e) => println!("can't handle query from {}: {}", raddr, e),
            },
        );
    }
}

fn handle_query(
    domain: &Option<Name>,
    sock: UdpSocket,
    buf: &[u8],
    raddr: SocketAddr,
    leases: Arc<RwLock<Vec<Lease>>>,
) -> Result<()> {
    let bytes = Bytes::copy_from_slice(buf);
    let mut msg = Dns::decode(bytes)?;

    let questions = msg.questions.clone();

    let ptr_nx = RefCell::new(false);

    let (lan, fwd): (_, Vec<Question>) =
        msg.questions.into_iter().partition(|q| {
            match is_dhcp_known(&usable_name(domain, &q.domain_name), leases.clone()) {
                Ok(known) => {
                    if q.q_type == QType::PTR && !known {
                        *ptr_nx.borrow_mut() = true;
                    }

                    known
                }
                Err(e) => {
                    println!("can't read dhcp config, ignoring {}: {}", q.domain_name, e);
                    false
                }
            }
        });

    msg.questions = fwd
        .into_iter()
        .filter(|q| q.domain_name.to_string().matches('.').count() >= 2)
        .filter(|q| {
            if q.domain_name.to_string().ends_with(".arpa.") {
                !IpNet::from_str("10.128.0.0/16").unwrap().contains(
                    &usable_name(domain, &q.domain_name)
                        .parse_arpa_name()
                        .expect("can't parse arpa name"),
                )
            } else {
                true
            }
        })
        .collect();

    let lan_resp = lan.into_iter().filter_map(|q| {
        let hostname = usable_name(domain, &q.domain_name);

        if q.q_type == QType::A {
            let net_id = subnet_id(&raddr.ip());
            let lease = dhcp_lease(&hostname, net_id, leases.clone())
                .unwrap()
                .unwrap();

            let lease_ttl = match lease.expires.duration_since(SystemTime::now()) {
                Ok(v) => v,
                Err(_) => return None,
            };

            let answer = RR::A(A {
                domain_name: q.domain_name,
                ttl: lease_ttl.as_secs() as u32,
                ipv4_addr: lease.address,
            });

            println!("{} dhcp {}", raddr, answer);
            Some(answer)
        } else if q.q_type == QType::PTR {
            let lease = dhcp_lease(&hostname, u8::MAX, leases.clone())
                .unwrap()
                .unwrap();

            let name = match lease.hostname.map(|name| {
                name + "."
                    + &domain
                        .as_ref()
                        .map(|domain| domain.to_utf8())
                        .unwrap_or(String::new())
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

            println!("{} dhcp {}", raddr, answer);
            Some(answer)
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

        let uplink = UdpSocket::bind("0.0.0.0:0")?;

        uplink.set_read_timeout(Some(Duration::from_secs(1)))?;
        uplink.connect(UPSTREAM)?;

        let n = uplink.send(&bytes)?;
        if n != bytes.len() {
            return Err(Error::PartialSend);
        }

        let mut buf = [0; 1024];
        let n = uplink.recv(&mut buf)?;
        let buf = &buf[..n];

        let bytes = Bytes::copy_from_slice(buf);
        let resp = Dns::decode(bytes)?;

        rcode = resp.flags.rcode;

        resp_answers = resp.answers;
        resp_authorities = resp.authorities;
        resp_additionals = resp.additionals;

        for answer in &resp_answers {
            println!("{} fwrd {}", raddr, answer);
        }
    }

    let answers: Vec<RR> = resp_answers.into_iter().chain(lan_resp).collect();

    let resp = Dns {
        id: msg.id,
        flags: Flags {
            qr: true,
            opcode: Opcode::Query,
            aa: true,
            tc: false,
            rd: true,
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
        return Err(Error::PartialSend);
    }

    Ok(())
}

fn find_lease(hostname: &Name, mut leases: impl Iterator<Item = Lease>) -> Option<Lease> {
    leases.find(|lease| {
        if Name::from_str("in-addr.arpa.")
            .unwrap()
            .zone_of(&hostname.base_name())
        {
            IpNet::new(lease.address.into(), 32).unwrap()
                == hostname
                    .parse_arpa_name()
                    .expect("can't parse arpa hostname")
        } else {
            lease.hostname.clone().map(|name| name + ".") == Some(hostname.to_utf8())
        }
    })
}

fn dhcp_lease(
    hostname: &Name,
    net_id: u8,
    leases: Arc<RwLock<Vec<Lease>>>,
) -> Result<Option<Lease>> {
    let leases = leases.read().unwrap();

    let same_subnet = find_lease(
        hostname,
        leases
            .clone()
            .into_iter()
            .filter(|lease| subnet_id(&lease.address.into()) == net_id),
    );

    let any = find_lease(hostname, leases.clone().into_iter());

    Ok(same_subnet.or(any))
}

fn is_dhcp_known(hostname: &Name, leases: Arc<RwLock<Vec<Lease>>>) -> Result<bool> {
    Ok(dhcp_lease(hostname, u8::MAX, leases)?.is_some())
}

fn subnet_id(addr: &IpAddr) -> u8 {
    match addr {
        IpAddr::V4(v4) => v4.octets()[2],
        IpAddr::V6(v6) => NE::read_u16(&v6.octets()[6..8]) as u8,
    }
}

fn usable_name(domain: &Option<Name>, name: &DomainName) -> Name {
    let as_name = Name::from_utf8(name.to_string()).expect("not a valid UTF-8 domain name");

    match domain {
        Some(domain) if domain.zone_of(&as_name) => {
            let mut labels = as_name.iter();

            labels.nth_back(domain.iter().len() - 1);
            Name::from_labels(labels).expect("labels became invalid by removing the domain")
        }
        _ => as_name,
    }
}
