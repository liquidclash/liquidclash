//! Observe the two DNS paths used during a real Windows connect transaction.
//!
//! This is deliberately read-only: it only opens short-lived TCP/UDP sockets to the loopback
//! listener and the Tono adapter's conventional fake-IP DNS address. Run it before clicking
//! Connect and correlate its monotonic timestamps with `monitor-windows-connect.ps1`.

use serde::Serialize;
use std::{
    io,
    net::{SocketAddr, TcpStream, UdpSocket},
    thread,
    time::{Duration, Instant},
};

const LOOPBACK_DNS: &str = "127.0.0.1:53";
const TUN_DNS: &str = "198.18.0.2:53";
const ATTEMPT_TIMEOUT: Duration = Duration::from_millis(120);
const PROBE_DURATION: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ProbeState {
    tcp_loopback: String,
    udp_loopback: String,
    tcp_tun: String,
    udp_tun: String,
}

#[derive(Debug, Serialize)]
struct ProbeEvent<'a> {
    elapsed_ms: u128,
    state: &'a ProbeState,
}

fn result_label<T>(result: io::Result<T>) -> String {
    match result {
        Ok(_) => "ok".to_owned(),
        Err(error) => format!(
            "err:{:?}:{}",
            error.kind(),
            error.raw_os_error().unwrap_or(0)
        ),
    }
}

fn tcp_probe(address: &str) -> String {
    let address: SocketAddr = address.parse().expect("static DNS address is valid");
    result_label(TcpStream::connect_timeout(&address, ATTEMPT_TIMEOUT))
}

fn dns_query() -> Vec<u8> {
    let mut query = vec![
        0x54, 0x4f, // transaction ID
        0x01, 0x00, // recursion desired
        0x00, 0x01, // one question
        0x00, 0x00, // answers
        0x00, 0x00, // authority
        0x00, 0x00, // additional
    ];
    for label in ["www", "gstatic", "com"] {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, 1, 0, 1]); // root label, A, IN
    query
}

fn udp_probe(address: &str) -> String {
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(socket) => socket,
        Err(error) => return result_label::<()>(Err(error)),
    };
    if let Err(error) = socket.set_write_timeout(Some(ATTEMPT_TIMEOUT)) {
        return result_label::<()>(Err(error));
    }
    if let Err(error) = socket.set_read_timeout(Some(ATTEMPT_TIMEOUT)) {
        return result_label::<()>(Err(error));
    }
    if let Err(error) = socket.connect(address) {
        return result_label::<()>(Err(error));
    }
    if let Err(error) = socket.send(&dns_query()) {
        return result_label::<()>(Err(error));
    }
    let mut response = [0_u8; 2048];
    result_label(socket.recv(&mut response))
}

fn sample() -> ProbeState {
    ProbeState {
        tcp_loopback: tcp_probe(LOOPBACK_DNS),
        udp_loopback: udp_probe(LOOPBACK_DNS),
        tcp_tun: tcp_probe(TUN_DNS),
        udp_tun: udp_probe(TUN_DNS),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let started = Instant::now();
    let mut previous = None;
    let mut last_heartbeat = Instant::now() - Duration::from_secs(2);

    while started.elapsed() < PROBE_DURATION {
        let state = sample();
        if previous.as_ref() != Some(&state) || last_heartbeat.elapsed() >= Duration::from_secs(1) {
            println!(
                "{}",
                serde_json::to_string(&ProbeEvent {
                    elapsed_ms: started.elapsed().as_millis(),
                    state: &state,
                })?
            );
            previous = Some(state);
            last_heartbeat = Instant::now();
        }
        thread::sleep(Duration::from_millis(40));
    }
    Ok(())
}
