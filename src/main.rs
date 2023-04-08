use rsdsl_dnsd::error::{Error, Result};

use std::fs::{self, File};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::thread;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use dns_message_parser::question::QType;
use dns_message_parser::rr::{A, RR};
use dns_message_parser::{Dns, Flags, Opcode, RCode};
use rsdsl_dhcp4d::lease::Lease;

fn main() -> Result<()> {
    println!("[dnsd] init");

    let sock = UdpSocket::bind("0.0.0.0:53")?;

    loop {
        let mut buf = [0; 1024];
        let (n, raddr) = sock.recv_from(&mut buf)?;
        let buf = &buf[..n];

        let is_local = match raddr.ip() {
            IpAddr::V4(addr) => addr.is_private(),
            IpAddr::V6(_) => unreachable!(), // no IPv6 support for now
        };

        if !is_local {
            println!("[dnsd] drop wan pkt from {}", raddr);
            continue;
        }

        let sock2 = sock.try_clone()?;
        let buf = buf.to_vec();
        thread::spawn(move || match handle_query(sock2, &buf, raddr) {
            Ok(_) => {}
            Err(e) => println!("[dnsd] can't handle query from {}: {}", raddr, e),
        });
    }
}

fn handle_query(sock: UdpSocket, buf: &[u8], raddr: SocketAddr) -> Result<()> {
    let bytes = Bytes::copy_from_slice(buf);
    let mut msg = Dns::decode(bytes)?;

    let questions = msg.questions.clone();

    let (lan, fwd) =
        msg.questions
            .into_iter()
            .partition(|q| match is_dhcp_known(q.domain_name.to_string()) {
                Ok(known) => known,
                Err(e) => {
                    println!(
                        "[dnsd] can't read dhcp config, ignoring {}: {}",
                        q.domain_name, e
                    );
                    false
                }
            });

    msg.questions = fwd;

    let lan_resp = lan.into_iter().filter_map(|q| {
        if q.q_type == QType::A || q.q_type == QType::ALL {
            let net_id = subnet_id(&raddr.ip());
            let lease = dhcp_lease(q.domain_name.to_string(), net_id)
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

            println!("[dnsd] {} dhcp {}", raddr, answer);
            Some(answer)
        } else {
            None
        }
    });

    let mut resp_answers = Vec::new();
    let mut resp_authorities = Vec::new();
    let mut resp_additionals = Vec::new();

    if !msg.questions.is_empty() {
        let bytes = msg.encode()?;

        let uplink = UdpSocket::bind("0.0.0.0:0")?;

        uplink.set_read_timeout(Some(Duration::from_secs(1)))?;
        uplink.connect("8.8.8.8:53")?;

        let n = uplink.send(&bytes)?;
        if n != bytes.len() {
            return Err(Error::PartialSend);
        }

        let mut buf = [0; 1024];
        let n = uplink.recv(&mut buf)?;
        let buf = &buf[..n];

        let bytes = Bytes::copy_from_slice(buf);
        let resp = Dns::decode(bytes)?;

        resp_answers = resp.answers;
        resp_authorities = resp.authorities;
        resp_additionals = resp.additionals;

        for answer in &resp_answers {
            println!("[dnsd] {} fwrd {}", raddr, answer);
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
            rcode: if !answers.is_empty() {
                RCode::NoError
            } else {
                RCode::NXDomain
            },
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

fn find_lease(hostname: String, leases: impl Iterator<Item = Lease>) -> Option<Lease> {
    for lease in leases {
        let lease_name = lease.hostname.clone().map(|name| name + ".");
        if lease_name == Some(hostname.clone()) {
            return Some(lease);
        }
    }

    None
}

fn dhcp_lease(hostname: String, net_id: u8) -> Result<Option<Lease>> {
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
        let file = File::open(entry?.path())?;
        let mut net_leases: Vec<Lease> = serde_json::from_reader(&file)?;

        leases.append(&mut net_leases);
    }

    let same_subnet = find_lease(
        hostname.clone(),
        leases
            .clone()
            .into_iter()
            .filter(|lease| subnet_id(&lease.address.into()) == net_id),
    );

    let any = find_lease(hostname, leases.into_iter());

    Ok(same_subnet.or(any))
}

fn is_dhcp_known(hostname: String) -> Result<bool> {
    Ok(dhcp_lease(hostname, u8::MAX)?.is_some())
}

fn subnet_id(addr: &IpAddr) -> u8 {
    match addr {
        IpAddr::V4(v4) => v4.octets()[2],
        IpAddr::V6(v6) => v6.octets()[7],
    }
}
