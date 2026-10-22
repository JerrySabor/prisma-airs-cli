//! A loopback TCP port with nothing listening, which no fixture server can be given.
//!
//! Binding port 0, reading the number and dropping the listener leaves a window in which
//! a parallel test's fixture server is given the same ephemeral port, so the "refused"
//! endpoint answers instead (seen on Linux CI, where recently freed ports come back
//! quickly). A bound socket that never listens would hold the port, but macOS drops the
//! SYN, so connections time out instead of being refused. Fixture servers bind port 0
//! and so always get an ephemeral port (Linux 32768–60999, macOS 49152–65535); this
//! picks a currently free port from below both ranges, where they never land.

use std::net::TcpListener;
use std::sync::atomic::{AtomicU16, Ordering};

const FIRST: u16 = 20_000;
const COUNT: u16 = 10_000;

/// Spreads parallel tests over the range; two tests sharing a port is harmless.
static NEXT: AtomicU16 = AtomicU16::new(0);

pub struct ClosedPort {
    port: u16,
}

impl ClosedPort {
    pub fn new() -> Self {
        let start = (std::process::id() as u16).wrapping_mul(7919) % COUNT;
        for _ in 0..COUNT {
            let offset = (start + NEXT.fetch_add(1, Ordering::Relaxed)) % COUNT;
            let port = FIRST + offset;
            // Free right now (nothing listening); dropped at once, and no fixture server
            // can take it afterwards.
            if TcpListener::bind(("127.0.0.1", port)).is_ok() {
                return Self { port };
            }
        }
        panic!("no free loopback port in {FIRST}..{}", FIRST + COUNT);
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Default for ClosedPort {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::io::ErrorKind;
    use std::net::TcpStream;

    use super::{COUNT, ClosedPort, FIRST};

    #[test]
    fn the_port_refuses_connections() {
        let closed = ClosedPort::new();
        let err = TcpStream::connect(("127.0.0.1", closed.port()))
            .expect_err("nothing may accept on a closed port");
        assert_eq!(err.kind(), ErrorKind::ConnectionRefused);
    }

    #[test]
    fn the_port_is_outside_the_ephemeral_ranges_fixture_servers_use() {
        let closed = ClosedPort::new();
        assert!((FIRST..FIRST + COUNT).contains(&closed.port()));
        assert!(
            closed.port() < 32_768,
            "below Linux and macOS ephemeral ports"
        );
        for _ in 0..200 {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
            assert_ne!(listener.local_addr().expect("addr").port(), closed.port());
        }
    }
}
