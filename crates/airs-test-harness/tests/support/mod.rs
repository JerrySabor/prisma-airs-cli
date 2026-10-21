//! A tiny blocking HTTP/1.1 client for exercising the fixture server directly.

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use airs_test_harness::FixtureServer;
use serde_json::Value;

pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("response body is JSON")
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// One keep-alive connection.
pub struct Client {
    reader: BufReader<TcpStream>,
}

impl Client {
    pub fn connect(server: &FixtureServer) -> Self {
        let stream = TcpStream::connect(server.addr()).expect("connect to fixture");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("read timeout");
        Self {
            reader: BufReader::new(stream),
        }
    }

    /// Sends a request without waiting for the response.
    pub fn send(&mut self, method: &str, target: &str, headers: &[(&str, &str)], body: &[u8]) {
        let mut head = format!("{method} {target} HTTP/1.1\r\nhost: 127.0.0.1\r\n");
        for (name, value) in headers {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        if !body.is_empty() || method == "POST" {
            head.push_str(&format!("content-length: {}\r\n", body.len()));
        }
        head.push_str("\r\n");
        let stream = self.reader.get_mut();
        stream.write_all(head.as_bytes()).expect("write head");
        stream.write_all(body).expect("write body");
    }

    pub fn read_response(&mut self) -> Response {
        let mut line = String::new();
        self.reader.read_line(&mut line).expect("status line");
        let status = line
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .unwrap_or_else(|| panic!("bad status line {line:?}"));
        let mut headers = Vec::new();
        loop {
            let mut line = String::new();
            self.reader.read_line(&mut line).expect("header line");
            let line = line.trim_end();
            if line.is_empty() {
                break;
            }
            let (name, value) = line.split_once(':').expect("header colon");
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
        }
        let length: usize = headers
            .iter()
            .find(|(name, _)| name == "content-length")
            .and_then(|(_, value)| value.parse().ok())
            .unwrap_or(0);
        let mut body = vec![0; length];
        self.reader.read_exact(&mut body).expect("body");
        Response {
            status,
            headers,
            body,
        }
    }

    pub fn request(
        &mut self,
        method: &str,
        target: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Response {
        self.send(method, target, headers, body);
        self.read_response()
    }
}

/// One request on a fresh connection.
pub fn request(
    server: &FixtureServer,
    method: &str,
    target: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Response {
    Client::connect(server).request(method, target, headers, body)
}

pub fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}
