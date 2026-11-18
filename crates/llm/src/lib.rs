//! Minimal synchronous client for OpenAI-compatible chat endpoints. Only JSON
//! mode is implemented: [`LlmClient::complete_json`]
//! asks the model for a `json_object` response and returns the raw content
//! string, which [`extract_json_object`] can turn into a [`serde_json::Value`].

use std::fmt;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use reqwest::{blocking, Url};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_ERROR_BODY_CHARS: usize = 512;

/// A synchronous, blocking client for `/chat/completions`.
///
/// The API key is never included in error messages or in the [`Debug`] output.
pub struct LlmClient {
    base_url: String,
    api_key: String,
    model: String,
    timeout: Duration,
}

impl fmt::Debug for LlmClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LlmClient")
            .field("base_url", &self.base_url)
            .field("model", &self.model)
            .field("timeout", &self.timeout)
            .field("api_key", &"[REDACTED]")
            .finish()
    }
}

impl LlmClient {
    /// Create a client for `base_url` using `api_key` and `model`.
    ///
    /// `base_url` may be the gateway root (with an optional path prefix such
    /// as `/v1`) or the full `/chat/completions` URL; duplicate and trailing
    /// slashes are normalized.
    pub fn new(
        base_url: impl Into<String>,
        api_key: impl Into<String>,
        model: impl Into<String>,
    ) -> Self {
        Self {
            base_url: base_url.into(),
            api_key: api_key.into(),
            model: model.into(),
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Override the per-request timeout (default: 30 seconds).
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Send a two-message chat completion request in JSON mode.
    ///
    /// Returns the raw `choices[0].message.content` string. Non-2xx responses,
    /// empty choices/content and malformed JSON all produce descriptive errors.
    pub fn complete_json(&self, system: &str, user: &str) -> Result<String> {
        let endpoint = chat_completions_url(&self.base_url)?;
        let payload = ChatRequest {
            model: &self.model,
            messages: vec![
                Message {
                    role: "system",
                    content: system,
                },
                Message {
                    role: "user",
                    content: user,
                },
            ],
            response_format: ResponseFormat {
                format_type: "json_object",
            },
        };

        let client = blocking::Client::builder()
            .timeout(self.timeout)
            .build()
            .context("failed to build HTTP client")?;

        let response = client
            .post(&endpoint)
            .bearer_auth(&self.api_key)
            .json(&payload)
            .send()
            .with_context(|| format!("request to {endpoint} failed"))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            let body = redact_and_truncate(&body, &self.api_key);
            return Err(anyhow!("LLM endpoint returned HTTP {status}: {body}"));
        }

        let parsed: ChatResponse = response
            .json()
            .context("LLM response body was not valid JSON")?;
        let content = parsed
            .choices
            .into_iter()
            .next()
            .and_then(|choice| choice.message.content)
            .ok_or_else(|| anyhow!("LLM response contained no message content"))?;
        if content.trim().is_empty() {
            return Err(anyhow!("LLM response message content was empty"));
        }
        Ok(content)
    }
}

#[derive(Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    messages: Vec<Message<'a>>,
    response_format: ResponseFormat,
}

#[derive(Serialize)]
struct Message<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Serialize)]
struct ResponseFormat {
    #[serde(rename = "type")]
    format_type: &'static str,
}

#[derive(Deserialize)]
struct ChatResponse {
    choices: Vec<Choice>,
}

#[derive(Deserialize)]
struct Choice {
    message: ResponseMessage,
}

#[derive(Deserialize)]
struct ResponseMessage {
    content: Option<String>,
}

/// Resolve the chat completions endpoint, collapsing duplicate/trailing
/// slashes and avoiding a double `/chat/completions` suffix.
fn chat_completions_url(base_url: &str) -> Result<String> {
    let mut url =
        Url::parse(base_url).with_context(|| format!("invalid LLM base URL: {base_url}"))?;
    let mut segments: Vec<&str> = url
        .path()
        .split('/')
        .filter(|part| !part.is_empty())
        .collect();
    let already_suffixed = segments.len() >= 2
        && segments[segments.len() - 2] == "chat"
        && segments[segments.len() - 1] == "completions";
    if !already_suffixed {
        segments.extend(["chat", "completions"]);
    }
    url.set_path(&format!("/{}", segments.join("/")));
    url.set_fragment(None);
    Ok(url.to_string())
}

/// Keep error bodies bounded and never echo the API key back, even if a
/// misbehaving gateway includes it in its error response.
fn redact_and_truncate(body: &str, api_key: &str) -> String {
    let cleaned = if api_key.is_empty() {
        body.to_string()
    } else {
        body.replace(api_key, "[REDACTED]")
    };
    let mut chars = cleaned.chars();
    let mut result: String = chars.by_ref().take(MAX_ERROR_BODY_CHARS).collect();
    if chars.next().is_some() {
        result.push_str("... [truncated]");
    }
    result
}

/// Extract the single JSON object from a model reply.
///
/// Accepts a raw object, a fenced ```` ```json ```` block with surrounding
/// prose, or prose containing one balanced `{...}` object. Nested braces and
/// braces inside strings are handled. Multiple objects are rejected as
/// ambiguous; arrays, other non-object JSON and unbalanced braces are errors.
pub fn extract_json_object(text: &str) -> Result<Value> {
    // A standalone JSON value must be an object (this rejects arrays, etc.).
    if let Ok(value) = serde_json::from_str::<Value>(text.trim()) {
        return match value {
            Value::Object(_) => Ok(value),
            other => Err(anyhow!(
                "expected a JSON object, found {}",
                json_kind(&other)
            )),
        };
    }

    let mut objects = Vec::new();
    for (start, end) in balanced_object_spans(text)? {
        if let Ok(value) = serde_json::from_str::<Value>(&text[start..end]) {
            if matches!(value, Value::Object(_)) {
                objects.push(value);
            }
        }
    }

    match objects.len() {
        0 => Err(anyhow!("no JSON object found in text")),
        1 => Ok(objects.remove(0)),
        count => Err(anyhow!(
            "found {count} JSON objects in text; result is ambiguous, expected exactly one"
        )),
    }
}

fn json_kind(value: &Value) -> &'static str {
    match value {
        Value::Object(_) => "object",
        Value::Array(_) => "array",
        Value::String(_) => "string",
        Value::Number(_) => "number",
        Value::Bool(_) => "boolean",
        Value::Null => "null",
    }
}

/// Byte-based scan for balanced `{...}` spans. The punctuation bytes are
/// ASCII, so they cannot occur inside a UTF-8 multibyte sequence.
fn balanced_object_spans(text: &str) -> Result<Vec<(usize, usize)>> {
    let bytes = text.as_bytes();
    let mut spans = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;
    let mut in_string = false;
    let mut escaped = false;

    for (index, byte) in bytes.iter().copied().enumerate() {
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
            b'{' => {
                if depth == 0 {
                    start = index;
                }
                depth += 1;
            }
            b'}' => {
                if depth == 0 {
                    return Err(anyhow!("unbalanced JSON braces: unexpected '}}'"));
                }
                depth -= 1;
                if depth == 0 {
                    spans.push((start, index + 1));
                }
            }
            _ => {}
        }
    }

    if depth != 0 {
        return Err(anyhow!("unbalanced JSON braces: unclosed '{{'"));
    }
    Ok(spans)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn normalizes_chat_endpoint() {
        let cases = [
            ("http://host.test", "http://host.test/chat/completions"),
            ("http://host.test/", "http://host.test/chat/completions"),
            (
                "http://host.test///v1//",
                "http://host.test/v1/chat/completions",
            ),
            (
                "http://host.test/v1/chat/completions",
                "http://host.test/v1/chat/completions",
            ),
            (
                "http://host.test/v1/chat/completions/",
                "http://host.test/v1/chat/completions",
            ),
        ];
        for (base, expected) in cases {
            assert_eq!(chat_completions_url(base).unwrap(), expected, "{base}");
        }
    }

    #[test]
    fn debug_output_redacts_key() {
        let client = LlmClient::new("http://host.test", "super-secret-key", "model");
        let debug = format!("{client:?}");
        assert!(!debug.contains("super-secret-key"), "{debug}");
        assert!(debug.contains("[REDACTED]"), "{debug}");
    }

    #[test]
    fn extracts_single_json_object_from_various_shapes() {
        let cases: &[(&str, &str, Result<Value, &str>)] = &[
            (
                "raw object",
                r#"{"a":1,"b":{"c":true}}"#,
                Ok(json!({"a":1,"b":{"c":true}})),
            ),
            (
                "fenced block with prose",
                "Here is the plan:\n```json\n{\"tool\":\"redhands_health\",\"n\":2}\n```\nDone.",
                Ok(json!({"tool":"redhands_health","n":2})),
            ),
            (
                "embedded object",
                "The first step is {\"step\":1} in the lab.",
                Ok(json!({"step":1})),
            ),
            (
                "nested braces",
                r#"{"a":{"b":[1,2,{"c":3}]}}"#,
                Ok(json!({"a":{"b":[1,2,{"c":3}]}})),
            ),
            (
                "braces inside strings",
                r#"{"cmd":"echo {hi} and } there","q":"say \" } ok"}"#,
                Ok(json!({"cmd":"echo {hi} and } there","q":"say \" } ok"})),
            ),
            (
                "no object",
                "just prose, no braces here",
                Err("no JSON object"),
            ),
            (
                "array only",
                r#"[{"a":1}]"#,
                Err("expected a JSON object, found array"),
            ),
            ("two objects", "{\"a\":1} and {\"b\":2}", Err("ambiguous")),
        ];

        for (name, input, expected) in cases {
            match expected {
                Ok(value) => assert_eq!(&extract_json_object(input).unwrap(), value, "{name}"),
                Err(fragment) => {
                    let error = extract_json_object(input).unwrap_err().to_string();
                    assert!(error.contains(fragment), "{name}: {error}");
                }
            }
        }
    }

    #[test]
    fn rejects_unbalanced_braces_and_non_object_primitives() {
        for input in [r#"{"a":1"#, r#"{"a":1}} {"#] {
            let error = extract_json_object(input).unwrap_err().to_string();
            assert!(error.contains("unbalanced"), "{input}: {error}");
        }
        for (input, kind) in [
            ("42", "number"),
            ("\"text\"", "string"),
            ("true", "boolean"),
            ("null", "null"),
        ] {
            let error = extract_json_object(input).unwrap_err().to_string();
            assert!(error.contains(kind), "{input}: {error}");
        }
    }
}
