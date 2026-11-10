//! The client, against a server that actually answers.
//!
//! # Why these tests open a socket
//!
//! Because everything this module decides is a decision about a request that is about to be made, and a test that stubbed
//! the transport would be testing the *stub's* idea of what the guard did. The server below is sixteen lines of
//! `TcpListener` that reads a request line and writes a response — enough to prove the request went where it was sent and
//! that the answer came back, without a dependency that would need the network to fetch.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use synra_core::network::{IpPolicy, NetworkGuard};

use super::{Client, Limits, Request};

/// What the test server answers with.
type Reply = Box<dyn Fn(&str) -> String + Send + Sync>;

/// A server on a loopback port, and its address.
///
/// The handler is given the request's first line — `GET /path HTTP/1.1` — and returns the whole response, so a test can
/// answer differently per path and can issue redirects.
struct Server {
    /// Where it is listening.
    address: SocketAddr,
    /// How many requests it has answered.
    served: Arc<AtomicUsize>,
}

impl Server {
    fn start(reply: impl Fn(&str) -> String + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a port");
        let address = listener.local_addr().expect("an address");
        let served = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&served);
        let reply: Reply = Box::new(reply);

        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                let _ = counted.fetch_add(1, Ordering::Relaxed);
                let first = read_request(&stream);
                let response = reply(&first);
                let mut stream = stream;
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });

        Self { address, served }
    }

    /// A server that answers `body` with `status` for every request.
    fn always(status: u16, body: &str) -> Self {
        let body = body.to_owned();
        Self::start(move |_| response(status, &body, &[]))
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.address)
    }

    fn requests(&self) -> usize {
        self.served.load(Ordering::Relaxed)
    }
}

/// Reads the request line, **and the body**, and returns the line.
///
/// # ★ Why the body has to be read, and why this was a flake rather than a detail
///
/// The first version drained the headers and answered immediately, leaving whatever body the client was still writing
/// unread. The client then wrote into a socket this side had already answered and closed — an intermittent connection
/// reset, which surfaced as `a_method_that_is_not_a_read_sends_its_body` failing about twice in twelve runs under parallel
/// load, and never when the suite ran alone.
///
/// A well-behaved HTTP/1.1 server reads the request it was sent before answering it. The test server now does, which is
/// also what makes the test about the *client* rather than about a race the test itself created.
fn read_request(stream: &TcpStream) -> String {
    let mut reader = BufReader::new(stream);
    let mut first = String::new();
    let _ = reader.read_line(&mut first);

    // The headers, to find out how much body is coming.
    let mut length = 0usize;
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                if line == "\r\n" || line == "\n" {
                    break;
                }
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse().unwrap_or(0);
                }
            }
            Err(_) => break,
        }
    }

    if length > 0 {
        let mut body = vec![0u8; length];
        let _ = reader.read_exact(&mut body);
    }

    first.trim_end().to_owned()
}

/// A whole HTTP response.
fn response(status: u16, body: &str, extra: &[(&str, &str)]) -> String {
    let reason = if (300..400).contains(&status) { "Found" } else { "OK" };
    let mut head = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-length: {}\r\nconnection: close\r\n",
        body.len()
    );
    for (name, value) in extra {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    head.push_str(body);
    head
}

/// A guard that reaches the test's own server: loopback, and plain http.
///
/// # Why the test grants what the product refuses
///
/// Because the product's defaults are the thing being tested elsewhere — `synra-core`'s guard tests assert that loopback
/// and `http` are refused. What these tests are about is the *client*: that a request goes where it was sent, that a
/// redirect is re-validated, that the body limit is applied. So the guard is configured for the test and says so, rather
/// than the test pretending the defaults are different.
fn local_guard() -> NetworkGuard {
    NetworkGuard::for_hosts(&["127.0.0.1".to_owned()])
        .allowing_insecure(true)
        .with_policy(IpPolicy { allow_loopback: true, ..IpPolicy::default() })
}

fn client() -> Client {
    Client::new(local_guard(), Limits::default())
}

fn get(url: &str) -> Request {
    Request {
        url: url.to_owned(),
        method: "GET".to_owned(),
        headers: std::collections::BTreeMap::new(),
        body: None,
    }
}

/// A server that answers one request with raw bytes, for the fetch that must not decode them.
///
/// It answers exactly one connection and exits: the test makes one request, and a second accept would keep the thread
/// alive past the assertion for no reason.
fn raw_server(body: Vec<u8>) -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a port");
    let address = listener.local_addr().expect("an address");
    std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else { return };
        let mut scratch = [0u8; 1024];
        let _ = stream.read(&mut scratch);
        let header = format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(header.as_bytes());
        let _ = stream.write_all(&body);
        let _ = stream.flush();
    });
    address
}

mod authorization;
mod limits;
mod redirects;
mod response_shapes;
