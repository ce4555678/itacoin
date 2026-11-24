//! JSON-RPC 2.0 requests, responses and errors (sections 4.4 and 5.6 of
//! `docs/NODE_PROPOSAL.md`).

use serde_json::{Map, Value, json};

/// Most requests in one batch.
pub const MAX_BATCH: usize = 100;
/// Deepest nesting of arrays and objects accepted.
pub const MAX_DEPTH: usize = 32;

/// Standard and ITACOIN error codes.
pub mod code {
    /// The body is not JSON.
    pub const PARSE_ERROR: i64 = -32_700;
    /// The JSON is not a valid request.
    pub const INVALID_REQUEST: i64 = -32_600;
    /// No such method.
    pub const METHOD_NOT_FOUND: i64 = -32_601;
    /// Wrong parameters.
    pub const INVALID_PARAMS: i64 = -32_602;
    /// The node failed internally.
    pub const INTERNAL_ERROR: i64 = -32_603;
    /// Block or transaction not found.
    pub const NOT_FOUND: i64 = -1_001;
    /// Malformed hex, base64url, address or satoshi string.
    pub const BAD_FORMAT: i64 = -1_002;
    /// Address of another network.
    pub const WRONG_NETWORK: i64 = -1_003;
    /// Transaction refused by the mempool.
    pub const MEMPOOL_REJECTED: i64 = -1_010;
    /// Transaction invalid by consensus.
    pub const INVALID_TRANSACTION: i64 = -1_011;
    /// Block refused.
    pub const BLOCK_REJECTED: i64 = -1_020;
    /// Method unavailable on this network or configuration.
    pub const UNAVAILABLE: i64 = -1_030;
    /// The node is still in initial block download.
    pub const IN_IBD: i64 = -1_031;
    /// The block's witnesses were pruned.
    pub const BLOCK_PRUNED: i64 = -1_032;
}

/// A JSON-RPC error object.
#[derive(Clone, Debug, PartialEq)]
pub struct RpcError {
    /// Error code.
    pub code: i64,
    /// Human-readable message.
    pub message: String,
    /// Optional detail.
    pub data: Option<Value>,
}

impl RpcError {
    /// An error with `code` and `message`.
    pub fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    /// Adds detail to the error.
    #[must_use]
    pub fn with_data(mut self, data: Value) -> Self {
        self.data = Some(data);
        self
    }

    /// Wrong parameters.
    pub fn params(message: impl Into<String>) -> Self {
        Self::new(code::INVALID_PARAMS, message)
    }

    fn to_json(&self) -> Value {
        let mut object = Map::new();
        object.insert("code".into(), json!(self.code));
        object.insert("message".into(), json!(self.message));
        if let Some(data) = &self.data {
            object.insert("data".into(), data.clone());
        }
        Value::Object(object)
    }
}

/// One call.
#[derive(Clone, Debug, PartialEq)]
pub struct Call {
    /// The id to echo, `None` for a notification.
    pub id: Option<Value>,
    /// The method name.
    pub method: String,
    /// Positional parameters.
    pub params: Vec<Value>,
}

/// A parsed body: one call or a batch. Entries that are not valid calls are
/// kept as errors so the batch can answer each one.
#[derive(Debug, PartialEq)]
pub enum Body {
    /// A single request.
    Single(Result<Call, RpcError>),
    /// A batch of requests.
    Batch(Vec<Result<Call, RpcError>>),
}

/// Parses a request body. Depth is checked on the raw bytes before the JSON
/// parser allocates anything.
pub fn parse_body(bytes: &[u8]) -> Result<Body, RpcError> {
    if depth(bytes) > MAX_DEPTH {
        return Err(RpcError::new(
            code::INVALID_REQUEST,
            "JSON nested too deeply",
        ));
    }
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|_| RpcError::new(code::PARSE_ERROR, "parse error"))?;
    match value {
        Value::Array(items) => {
            if items.is_empty() {
                return Err(RpcError::new(code::INVALID_REQUEST, "empty batch"));
            }
            if items.len() > MAX_BATCH {
                return Err(RpcError::new(
                    code::INVALID_REQUEST,
                    format!("batch larger than {MAX_BATCH}"),
                ));
            }
            Ok(Body::Batch(items.into_iter().map(parse_call).collect()))
        }
        other => Ok(Body::Single(parse_call(other))),
    }
}

fn parse_call(value: Value) -> Result<Call, RpcError> {
    let invalid = |message: &str| RpcError::new(code::INVALID_REQUEST, message);
    let Value::Object(mut object) = value else {
        return Err(invalid("request must be an object"));
    };
    match object.get("jsonrpc") {
        None => {}
        Some(Value::String(version)) if version == "2.0" || version == "1.0" => {}
        Some(_) => return Err(invalid("unsupported jsonrpc version")),
    }
    let id = match object.remove("id") {
        None => None,
        Some(id @ (Value::Null | Value::Number(_) | Value::String(_))) => Some(id),
        Some(_) => return Err(invalid("id must be a string, number or null")),
    };
    let Some(Value::String(method)) = object.remove("method") else {
        return Err(invalid("method must be a string"));
    };
    let params = match object.remove("params") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(params)) => params,
        Some(_) => return Err(invalid("params must be an array")),
    };
    Ok(Call { id, method, params })
}

/// Maximum nesting of `[` and `{` outside strings.
#[must_use]
pub fn depth(bytes: &[u8]) -> usize {
    let (mut current, mut deepest) = (0_usize, 0_usize);
    let (mut in_string, mut escaped) = (false, false);
    for &byte in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'[' | b'{' => {
                current += 1;
                deepest = deepest.max(current);
            }
            b']' | b'}' => current = current.saturating_sub(1),
            _ => {}
        }
    }
    deepest
}

/// The response to one call.
#[must_use]
pub fn response(id: Option<Value>, result: Result<Value, RpcError>) -> Value {
    let id = id.unwrap_or(Value::Null);
    match result {
        Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
        Err(error) => json!({"jsonrpc": "2.0", "id": id, "error": error.to_json()}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_and_batch_requests_parse() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"uptime","params":[]}"#;
        assert_eq!(
            parse_body(body).unwrap(),
            Body::Single(Ok(Call {
                id: Some(json!(1)),
                method: "uptime".into(),
                params: vec![],
            }))
        );
        let batch = br#"[{"id":"a","method":"x"},{"id":2},7]"#;
        let Body::Batch(calls) = parse_body(batch).unwrap() else {
            panic!("expected a batch");
        };
        assert_eq!(calls.len(), 3);
        assert!(calls[0].is_ok());
        assert_eq!(calls[1].as_ref().unwrap_err().code, code::INVALID_REQUEST);
        assert_eq!(calls[2].as_ref().unwrap_err().code, code::INVALID_REQUEST);
    }

    #[test]
    fn limits_are_enforced() {
        assert_eq!(parse_body(b"{").unwrap_err().code, code::PARSE_ERROR);
        assert_eq!(parse_body(b"[]").unwrap_err().code, code::INVALID_REQUEST);
        let big = format!("[{}]", vec![r#"{"method":"x"}"#; 101].join(","));
        assert_eq!(
            parse_body(big.as_bytes()).unwrap_err().code,
            code::INVALID_REQUEST
        );
        let ok = format!("[{}]", vec![r#"{"method":"x"}"#; 100].join(","));
        assert!(parse_body(ok.as_bytes()).is_ok());
        let deep = format!("{}{}", "[".repeat(33), "]".repeat(33));
        assert_eq!(
            parse_body(deep.as_bytes()).unwrap_err().code,
            code::INVALID_REQUEST
        );
        // Brackets inside strings do not count.
        let quoted = format!(r#"{{"method":"x","params":["{}\"["]}}"#, "[".repeat(100));
        assert!(matches!(
            parse_body(quoted.as_bytes()),
            Ok(Body::Single(Ok(_)))
        ));
        assert!(matches!(
            parse_body(br#"{"jsonrpc":"3.0","method":"x"}"#),
            Ok(Body::Single(Err(_)))
        ));
        assert!(matches!(
            parse_body(br#"{"method":"x","params":{"a":1}}"#),
            Ok(Body::Single(Err(_)))
        ));
    }
}
