//! A minimal blocking JSON-RPC client over HTTP/1.1, for `itacoin-cli` and
//! tests.

use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    time::Duration,
};

use base64::Engine;
use serde_json::{Value, json};
use zeroize::Zeroizing;

/// Largest response read.
const MAX_RESPONSE: u64 = 64 * 1024 * 1024;

/// Errors from a call.
#[derive(Debug)]
pub enum ClientError {
    /// The connection failed.
    Io(io::Error),
    /// The server answered with a non-JSON HTTP error.
    Http(u16, String),
    /// The server answered with a JSON-RPC error.
    Rpc {
        /// Error code.
        code: i64,
        /// Message.
        message: String,
        /// Detail, if any.
        data: Option<Value>,
    },
    /// The response could not be understood.
    Malformed,
}

impl core::fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "could not reach the node: {error}"),
            Self::Http(status, body) => write!(formatter, "HTTP {status}: {}", body.trim()),
            Self::Rpc {
                code,
                message,
                data,
            } => match data {
                Some(data) => write!(formatter, "error {code}: {message} ({data})"),
                None => write!(formatter, "error {code}: {message}"),
            },
            Self::Malformed => formatter.write_str("malformed response"),
        }
    }
}

impl std::error::Error for ClientError {}

/// A raw HTTP response.
#[derive(Debug)]
pub struct RawResponse {
    /// Status code.
    pub status: u16,
    /// Header lines, lowercased names.
    pub headers: Vec<(String, String)>,
    /// Body bytes.
    pub body: Vec<u8>,
}

/// A client for one node.
#[derive(Clone)]
pub struct Client {
    addr: SocketAddr,
    authorization: Zeroizing<String>,
    timeout: Duration,
}

impl core::fmt::Debug for Client {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Client")
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

impl Client {
    /// A client for `addr` with HTTP Basic credentials.
    #[must_use]
    pub fn new(addr: SocketAddr, user: &str, password: &str) -> Self {
        let token = Zeroizing::new(format!("{user}:{password}"));
        Self {
            addr,
            authorization: Zeroizing::new(format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(token.as_bytes())
            )),
            timeout: Duration::from_secs(60),
        }
    }

    /// Changes the time a call may take.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Calls `method` and returns its result.
    pub fn call(&self, method: &str, params: Vec<Value>) -> Result<Value, ClientError> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let body = serde_json::to_vec(&body).map_err(|_| ClientError::Malformed)?;
        let response = self
            .post(&body, &[("Content-Type", "application/json")], true)
            .map_err(ClientError::Io)?;
        let parsed: Option<Value> = serde_json::from_slice(&response.body).ok();
        let Some(Value::Object(mut object)) = parsed else {
            return Err(ClientError::Http(
                response.status,
                String::from_utf8_lossy(&response.body).into_owned(),
            ));
        };
        if let Some(error) = object.remove("error").filter(|error| !error.is_null()) {
            return Err(ClientError::Rpc {
                code: error["code"].as_i64().unwrap_or(0),
                message: error["message"].as_str().unwrap_or_default().to_owned(),
                data: error.get("data").cloned(),
            });
        }
        object.remove("result").ok_or(ClientError::Malformed)
    }

    /// Sends a POST with `body` and extra headers, optionally with the
    /// client's credentials. For tests of the HTTP layer.
    pub fn post(
        &self,
        body: &[u8],
        headers: &[(&str, &str)],
        authenticate: bool,
    ) -> io::Result<RawResponse> {
        let mut request = format!(
            "POST / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: {}\r\n",
            self.addr,
            body.len()
        );
        if authenticate {
            request.push_str(&format!(
                "Authorization: {}\r\n",
                self.authorization.as_str()
            ));
        }
        for (name, value) in headers {
            request.push_str(&format!("{name}: {value}\r\n"));
        }
        request.push_str("\r\n");
        let request = Zeroizing::new(request);
        self.exchange(request.as_bytes(), body)
    }

    /// Sends raw request bytes and reads the response.
    pub fn exchange(&self, head: &[u8], body: &[u8]) -> io::Result<RawResponse> {
        let mut stream = TcpStream::connect_timeout(&self.addr, self.timeout)?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;
        stream.write_all(head)?;
        stream.write_all(body)?;
        let mut raw = Vec::new();
        stream.take(MAX_RESPONSE).read_to_end(&mut raw)?;
        parse_response(&raw).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad HTTP"))
    }
}

fn parse_response(raw: &[u8]) -> Option<RawResponse> {
    let split = raw.windows(4).position(|window| window == b"\r\n\r\n")?;
    let head = core::str::from_utf8(&raw[..split]).ok()?;
    let mut lines = head.split("\r\n");
    let status = lines.next()?.split(' ').nth(1)?.parse().ok()?;
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    let mut body = raw[split + 4..].to_vec();
    if headers
        .iter()
        .any(|(name, value)| name == "transfer-encoding" && value.eq_ignore_ascii_case("chunked"))
    {
        body = dechunk(&body)?;
    }
    Some(RawResponse {
        status,
        headers,
        body,
    })
}

fn dechunk(mut data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = data.windows(2).position(|window| window == b"\r\n")?;
        let size_text = core::str::from_utf8(&data[..line_end]).ok()?;
        let size = usize::from_str_radix(size_text.split(';').next()?.trim(), 16).ok()?;
        data = &data[line_end + 2..];
        if size == 0 {
            return Some(out);
        }
        out.extend_from_slice(data.get(..size)?);
        data = data.get(size + 2..)?;
    }
}
