use rsdsl_dnsd::error::{Error, Result};

use std::fs::File;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::SystemTime;

use bytes::Bytes;
use dns_message_parser::rr::{A, RR};
use dns_message_parser::Dns;
use rsdsl_dhcp4d::lease::Lease;

fn main() -> Result<()> {
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

        match handle_query(&sock, buf, raddr) {
            Ok(_) => {}
            Err(e) => println!("[dnsd] can't handle query from {}: {}", raddr, e),
        }
    }
}

fn handle_query(sock: &UdpSocket, buf: &[u8], raddr: SocketAddr) -> Result<()> {
    let bytes = Bytes::copy_from_slice(buf);
    let mut msg = Dns::decode(bytes)?;

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

    let bytes = msg.encode()?;

    let uplink = UdpSocket::bind("0.0.0.0:0")?;
    uplink.connect("8.8.8.8:53")?;

    let n = uplink.send(&bytes)?;
    if n != bytes.len() {
        return Err(Error::PartialSend);
    }

    let lan_resp = lan.into_iter().map(|q| {
        let lease = dhcp_lease(q.domain_name.to_string()).unwrap().unwrap();
        RR::A(A {
            domain_name: q.domain_name,
            ttl: lease
                .expires
                .duration_since(SystemTime::now())
                .unwrap()
                .as_secs() as u32,
            ipv4_addr: lease.address,
        })
    });

    let mut buf = [0; 1024];
    let n = uplink.recv(&mut buf)?;
    let buf = &buf[..n];

    let bytes = Bytes::copy_from_slice(buf);
    let mut resp = Dns::decode(bytes)?;

    resp.answers = resp.answers.into_iter().chain(lan_resp).collect();

    let bytes = resp.encode()?;

    let n = sock.send_to(&bytes, raddr)?;
    if n != bytes.len() {
        return Err(Error::PartialSend);
    }

    Ok(())
}

fn dhcp_lease(hostname: String) -> Result<Option<Lease>> {
    let file = File::open("/data/dhcp4d.leases_eth0")?;
    let leases: Vec<Lease> = serde_json::from_reader(&file)?;

    for lease in leases {
        if lease.hostname == Some(hostname.clone()) {
            return Ok(Some(lease));
        }
    }

    Ok(None)
}

fn is_dhcp_known(hostname: String) -> Result<bool> {
    Ok(dhcp_lease(hostname)?.is_some())
}
