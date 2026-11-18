//! HTTP-level tests using a tiny std-only mock server (no dev-dependencies).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use redagent_llm::LlmClient;
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
