//! HTTP-level tests using a tiny std-only mock server (no dev-dependencies).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use redagent_llm::{Completion, LlmClient, Usage};
use serde_json::{json, Value};

struct Request {
    method: String,
    path: String,
    authorization: Option<String>,
    body: String,
}

fn read_request(stream: &mut TcpStream) -> Request {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut headers = String::new();
    loop {
        let mut line = String::new();
        assert!(
            reader.read_line(&mut line).unwrap() > 0,
            "client closed before finishing headers"
        );
        if line == "\r\n" {
            break;
        }
        headers.push_str(&line);
    }

    let mut lines = headers.lines();
    let request_line = lines.next().expect("missing request line");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap().to_string();
    let path = parts.next().unwrap().to_string();

    let mut content_length = 0usize;
    let mut authorization = None;
    for line in headers.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.trim().parse().unwrap();
        } else if name.eq_ignore_ascii_case("authorization") {
            authorization = Some(value.trim().to_string());
        }
    }
    drop(lines);

    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body).unwrap();
    Request {
        method,
        path,
        authorization,
        body: String::from_utf8(body).unwrap(),
    }
}

fn response(status: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn spawn_server<F>(handler: F) -> (String, JoinHandle<()>)
where
    F: FnOnce(Request) -> String + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_request(&mut stream);
        let reply = handler(request);
        stream.write_all(reply.as_bytes()).unwrap();
        stream.flush().unwrap();
    });
    (base_url, handle)
}

#[test]
fn complete_json_posts_expected_request_and_returns_content() {
    let content =
        "Here is the plan:\n```json\n{\"tool\":\"redhands_health\",\"arguments\":{}}\n```\n";
    let response_body = json!({
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "choices": [{
            "index": 0,
            "message": { "role": "assistant", "content": content },
            "finish_reason": "stop"
        }]
    })
    .to_string();

    let (base_url, handle) = spawn_server(move |request| {
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/chat/completions");
        assert_eq!(request.authorization.as_deref(), Some("Bearer test-key"));

        let body: Value = serde_json::from_str(&request.body).unwrap();
        assert_eq!(body["model"], "test-model");
        assert_eq!(body["messages"][0]["role"], "system");
        assert_eq!(body["messages"][0]["content"], "you are helpful");
        assert_eq!(body["messages"][1]["role"], "user");
        assert_eq!(body["messages"][1]["content"], "do the thing");
        assert_eq!(body["response_format"]["type"], "json_object");

        response("200 OK", &response_body)
    });

    // Trailing/duplicate slashes on the base URL must be normalized.
    let client = LlmClient::new(format!("{base_url}///"), "test-key", "test-model")
        .with_timeout(Duration::from_secs(5));
    assert_eq!(
        client
            .complete_json("you are helpful", "do the thing")
            .unwrap(),
        content
    );
    handle.join().unwrap();
}

#[test]
fn full_endpoint_url_is_not_appended_twice() {
    let (base_url, handle) = spawn_server(|request| {
        assert_eq!(request.path, "/chat/completions");
        response("200 OK", r#"{"choices":[{"message":{"content":"{}"}}]}"#)
    });
    let client = LlmClient::new(
        format!("{base_url}/chat/completions"),
        "test-key",
        "test-model",
    );
    assert_eq!(client.complete_json("s", "u").unwrap(), "{}");
    handle.join().unwrap();
}

#[test]
fn http_errors_do_not_leak_the_api_key() {
    let (base_url, handle) = spawn_server(|_| {
        // A misbehaving gateway echoes the key back: it must still be redacted.
        response(
            "401 Unauthorized",
            r#"{"error":"invalid api key: test-key"}"#,
        )
    });
    let client = LlmClient::new(&base_url, "test-key", "test-model");
    let error = client.complete_json("s", "u").unwrap_err().to_string();
    assert!(error.contains("401"), "{error}");
    assert!(!error.contains("test-key"), "{error}");
    assert!(error.contains("[REDACTED]"), "{error}");
    handle.join().unwrap();

    let long_body = format!("test-key {}", "x".repeat(2000));
    let (base_url, handle) =
        spawn_server(move |_| response("500 Internal Server Error", &long_body));
    let client = LlmClient::new(&base_url, "test-key", "test-model");
    let error = client.complete_json("s", "u").unwrap_err().to_string();
    assert!(error.contains("500"), "{error}");
    assert!(!error.contains("test-key"), "{error}");
    assert!(error.contains("[truncated]"), "{error}");
    assert!(error.len() < 700, "{error}");
    handle.join().unwrap();
}

/// A server that accepts the connection but never replies, to exercise the
/// client-side timeout path.
fn spawn_silent_server() -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let handle = thread::spawn(move || {
        let (_stream, _) = listener.accept().unwrap();
        thread::sleep(Duration::from_secs(2));
    });
    (base_url, handle)
}

#[test]
fn malformed_json_body_echoing_the_key_does_not_leak_it() {
    // A 200 response whose body is malformed JSON and contains the key.
    for body in [
        r#"{"choices":[{"message":{"content":"ok"}}],"echo":test-key}"#,
        "test-key is not json",
        r#"{"choices":[{"message":{"content":test-key}}]}"#,
    ] {
        let (base_url, handle) = spawn_server(move |_| response("200 OK", body));
        let client = LlmClient::new(&base_url, "test-key", "test-model");
        let error = client.complete_json("s", "u").unwrap_err().to_string();
        assert!(!error.contains("test-key"), "{body} -> {error}");
        handle.join().unwrap();
    }
}

#[test]
fn timeout_errors_do_not_leak_the_api_key() {
    let (base_url, _handle) = spawn_silent_server();
    let client = LlmClient::new(&base_url, "test-key", "test-model")
        .with_timeout(Duration::from_millis(100));
    let error = client.complete_json("s", "u").unwrap_err().to_string();
    assert!(!error.contains("test-key"), "{error}");
}

#[test]
fn invalid_base_url_echoing_the_key_does_not_leak_it() {
    let client = LlmClient::new("http://test-key.invalid", "test-key", "test-model");
    // A syntactically invalid URL that also embeds the key must not echo it.
    let client2 = LlmClient::new("::: test-key :::", "test-key", "test-model");
    for client in [client, client2] {
        let error = client.complete_json("s", "u").unwrap_err().to_string();
        assert!(!error.contains("test-key"), "{error}");
    }
}

#[test]
fn content_as_array_of_text_parts_is_accepted() {
    let body = json!({
        "choices": [{
            "message": {
                "content": [
                    {"type": "text", "text": "{\"tool\":\""},
                    {"type": "text", "text": "health\"}"},
                    {"type": "image_url", "image_url": {"url": "http://example/x.png"}}
                ]
            }
        }]
    })
    .to_string();
    let (base_url, handle) = spawn_server(move |_| response("200 OK", &body));
    let client = LlmClient::new(&base_url, "test-key", "test-model");
    assert_eq!(
        client.complete_json("s", "u").unwrap(),
        "{\"tool\":\"health\"}"
    );
    handle.join().unwrap();
}

#[test]
fn content_array_parts_without_type_are_treated_as_text() {
    let body = r#"{"choices":[{"message":{"content":[{"text":"{\"a\":"},{"text":"1}"}]}}]}"#;
    let (base_url, handle) = spawn_server(move |_| response("200 OK", body));
    let client = LlmClient::new(&base_url, "test-key", "test-model");
    assert_eq!(client.complete_json("s", "u").unwrap(), "{\"a\":1}");
    handle.join().unwrap();
}

#[test]
fn large_content_is_returned_intact() {
    let content = "x".repeat(100_000);
    let body = json!({"choices":[{"message":{"content":content}}]}).to_string();
    let (base_url, handle) = spawn_server(move |_| response("200 OK", &body));
    let client = LlmClient::new(&base_url, "test-key", "test-model");
    assert_eq!(client.complete_json("s", "u").unwrap().len(), 100_000);
    handle.join().unwrap();
}

#[test]
fn content_array_without_text_is_an_error() {
    let body =
        r#"{"choices":[{"message":{"content":[{"type":"image_url","image_url":{"url":"x"}}]}}]}"#;
    let (base_url, handle) = spawn_server(move |_| response("200 OK", body));
    let client = LlmClient::new(&base_url, "test-key", "test-model");
    let error = client.complete_json("s", "u").unwrap_err().to_string();
    assert!(
        error.contains("no message content") || error.contains("empty"),
        "{error}"
    );
    handle.join().unwrap();
}

#[test]
fn malformed_responses_are_errors() {
    let cases = [
        (r#"{"choices":[]}"#, "no message content"),
        (
            r#"{"choices":[{"message":{"content":null}}]}"#,
            "no message content",
        ),
        (r#"{"choices":[{"message":{}}]}"#, "no message content"),
        (r#"{"choices":[{"message":{"content":"  "}}]}"#, "was empty"),
        ("not json at all", "not valid JSON"),
        (
            r#"{"choices":[{"message":{"content":42}}]}"#,
            "not valid JSON",
        ),
    ];

    for (body, expected) in cases {
        let (base_url, handle) = spawn_server(move |_| response("200 OK", body));
        let client = LlmClient::new(&base_url, "test-key", "test-model");
        let error = client.complete_json("s", "u").unwrap_err().to_string();
        assert!(error.contains(expected), "{body} -> {error}");
        handle.join().unwrap();
    }
}

/// Build a minimal successful completion payload, optionally with a `usage`
/// object (a `Value::Null` is passed through to test null handling too).
fn completion_body(usage: Option<Value>) -> String {
    let mut body = json!({"choices":[{"message":{"content":"{\"ok\":true}"}}]});
    if let Some(usage) = usage {
        body["usage"] = usage;
    }
    body.to_string()
}

#[test]
fn complete_json_with_usage_parses_full_usage() {
    let body = completion_body(Some(json!({
        "prompt_tokens": 10,
        "completion_tokens": 20,
        "total_tokens": 30,
    })));
    let (base_url, handle) = spawn_server(move |_| response("200 OK", &body));
    let client = LlmClient::new(&base_url, "test-key", "test-model");
    let completion: Completion = client.complete_json_with_usage("s", "u").unwrap();
    assert_eq!(completion.content, "{\"ok\":true}");
    assert_eq!(
        completion.usage,
        Some(Usage {
            prompt_tokens: 10,
            completion_tokens: 20,
            total_tokens: 30,
        })
    );
    handle.join().unwrap();
}

#[test]
fn complete_json_with_usage_defaults_missing_fields_to_zero() {
    let body = completion_body(Some(json!({"prompt_tokens": 7})));
    let (base_url, handle) = spawn_server(move |_| response("200 OK", &body));
    let client = LlmClient::new(&base_url, "test-key", "test-model");
    let completion = client.complete_json_with_usage("s", "u").unwrap();
    assert_eq!(
        completion.usage,
        Some(Usage {
            prompt_tokens: 7,
            completion_tokens: 0,
            total_tokens: 0,
        })
    );
    handle.join().unwrap();
}

#[test]
fn complete_json_with_usage_handles_absent_and_null_usage() {
    for usage in [None, Some(Value::Null)] {
        let body = completion_body(usage.clone());
        let (base_url, handle) = spawn_server(move |_| response("200 OK", &body));
        let client = LlmClient::new(&base_url, "test-key", "test-model");
        let completion = client.complete_json_with_usage("s", "u").unwrap();
        assert_eq!(completion.usage, None, "usage payload: {usage:?}");
        handle.join().unwrap();
    }
}

#[test]
fn complete_json_returns_only_content_even_when_usage_is_present() {
    let body = completion_body(Some(json!({
        "prompt_tokens": 1,
        "completion_tokens": 2,
        "total_tokens": 3,
    })));
    let (base_url, handle) = spawn_server(move |_| response("200 OK", &body));
    let client = LlmClient::new(&base_url, "test-key", "test-model");
    assert_eq!(client.complete_json("s", "u").unwrap(), "{\"ok\":true}");
    handle.join().unwrap();
}
