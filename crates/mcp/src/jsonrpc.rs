use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const JSONRPC_VERSION: &str = "2.0";

#[derive(Debug, Serialize)]
pub struct Request<'a> {
    pub jsonrpc: &'static str,
    pub id: u64,
    pub method: &'a str,
    pub params: Value,
}

#[derive(Debug, Serialize)]
pub struct Notification<'a> {
    pub jsonrpc: &'static str,
    pub method: &'a str,
    pub params: Value,
}

#[derive(Debug, Deserialize)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    #[serde(default)]
    pub data: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct Response {
    pub jsonrpc: String,
    pub id: Option<u64>,
    pub result: Option<Value>,
    pub error: Option<RpcError>,
}

pub fn parse_response(line: &str) -> Result<Response> {
    let response: Response = serde_json::from_str(line)?;
    if response.jsonrpc != JSONRPC_VERSION {
        return Err(anyhow!("unexpected jsonrpc version: {}", response.jsonrpc));
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_success_and_error() {
        let ok = parse_response(r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#).unwrap();
        assert_eq!(ok.id, Some(1));
        assert_eq!(ok.result, Some(serde_json::json!({"ok": true})));
        let err = parse_response(
            r#"{"jsonrpc":"2.0","id":2,"error":{"code":-32601,"message":"no method"}}"#,
        )
        .unwrap();
        assert_eq!(err.error.unwrap().code, -32601);
    }
}
