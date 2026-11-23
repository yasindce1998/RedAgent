//! Minimal synchronous client for OpenAI-compatible chat endpoints. Only JSON
//! mode is implemented: [`LlmClient::complete_json`]
//! asks the model for a `json_object` response and returns the raw content
//! string, which [`extract_json_object`] can turn into a [`serde_json::Value`].
//! [`LlmClient::complete_json_with_usage`] returns the same content together
//! with the optional token-usage counters reported by the endpoint.

use std::fmt;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use reqwest::{blocking, Url};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_ERROR_BODY_CHARS: usize = 512;

/// Token usage reported alongside a chat completion.
///
/// Every counter defaults to `0` when the endpoint omits (or does not report)
/// it, so callers can accumulate usage without special-casing partial payloads.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    #[serde(default)]
    pub prompt_tokens: u64,
    #[serde(default)]
    pub completion_tokens: u64,
    #[serde(default)]
    pub total_tokens: u64,
}

/// The content of a completion plus the optional usage counters supplied by
/// the endpoint. `usage` is `None` when the response carries no usage object.
#[derive(Debug, Clone)]
pub struct Completion {
    pub content: String,
    pub usage: Option<Usage>,
}

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
    ///
    /// Every error is funneled through a final redaction pass so the API key
    /// can never be echoed, even when a misconfigured base URL or a gateway
    /// response happens to contain it.
    pub fn complete_json(&self, system: &str, user: &str) -> Result<String> {
        self.complete_json_with_usage(system, user)
            .map(|completion| completion.content)
    }

    /// Send a two-message chat completion request in JSON mode and return the
    /// raw `choices[0].message.content` together with any token usage the
    /// endpoint reports.
    ///
    /// Usage counters are optional and independently default to `0`; a
    /// response without a `usage` object yields `Completion { usage: None }`.
    /// All parsing/error/redaction behaviour is identical to
    /// [`Self::complete_json`].
    pub fn complete_json_with_usage(&self, system: &str, user: &str) -> Result<Completion> {
        self.complete_json_with_usage_inner(system, user)
            .map_err(|err| {
                let rendered = format!("{err:#}");
                if self.api_key.is_empty() || !rendered.contains(&self.api_key) {
                    return err;
                }
                anyhow!("{}", rendered.replace(&self.api_key, "[REDACTED]"))
            })
    }

    fn complete_json_with_usage_inner(&self, system: &str, user: &str) -> Result<Completion> {
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
        let usage = parsed.usage;
        let content = parsed
            .choices
            .into_iter()
            .next()
            .and_then(|choice| choice.message.content)
            .and_then(ResponseContent::into_text)
            .ok_or_else(|| anyhow!("LLM response contained no message content"))?;
        if content.trim().is_empty() {
            return Err(anyhow!("LLM response message content was empty"));
        }
        Ok(Completion { content, usage })
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
    /// Usage is optional; missing (or `null`) means no counters were reported.
    #[serde(default)]
    usage: Option<Usage>,
}

#[derive(Deserialize)]
struct Choice {
    message: ResponseMessage,
}

#[derive(Deserialize)]
struct ResponseMessage {
    content: Option<ResponseContent>,
}

/// `message.content` is normally a string, but some OpenAI-compatible
/// endpoints return an array of content parts. Accept both shapes and stitch
/// the text parts back together in order, ignoring non-text parts.
#[derive(Deserialize)]
#[serde(untagged)]
enum ResponseContent {
    Text(String),
    Parts(Vec<ContentPart>),
}

#[derive(Deserialize)]
struct ContentPart {
    #[serde(rename = "type", default)]
    kind: Option<String>,
    #[serde(default)]
    text: Option<String>,
}

impl ResponseContent {
    fn into_text(self) -> Option<String> {
        match self {
            Self::Text(text) => Some(text),
            Self::Parts(parts) => {
                let text: String = parts
                    .into_iter()
                    // A missing `type` is treated as text; some gateways omit it.
                    .filter(|part| part.kind.as_deref().unwrap_or("text") == "text")
                    .filter_map(|part| part.text)
                    .collect();
                if text.is_empty() {
                    None
                } else {
                    Some(text)
                }
            }
        }
    }
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
            (
                "http://host.test/v1?trace=abc",
                "http://host.test/v1/chat/completions?trace=abc",
            ),
            (
                "http://host.test/v1/chat/completions/?trace=abc#frag",
                "http://host.test/v1/chat/completions?trace=abc",
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

    /// The object scanner is byte-indexed over UTF-8 (punctuation bytes cannot
    /// occur inside a multibyte sequence). A non-ASCII prefix must therefore
    /// neither panic nor shift the slice: the correct object is returned.
    #[test]
    fn extraction_handles_fences_escapes_nesting_arrays_and_unicode_prefixes() {
        let cases: &[(&str, &str, Value)] = &[
            (
                "fenced with language tag and prose",
                "Plan:\n```json\n{\"tool\":\"scan\",\"n\":2}\n```\nDone.",
                json!({"tool":"scan","n":2}),
            ),
            (
                "fenced with prose on both sides",
                "Before\n```JSON\n{\"a\":1}\n```\nAfter",
                json!({"a":1}),
            ),
            (
                "escaped braces and quotes inside strings",
                r#"{"cmd":"echo {hi} and }","q":"say \" } ok"}"#,
                json!({"cmd":"echo {hi} and }","q":"say \" } ok"}),
            ),
            (
                "nested objects and arrays",
                r#"{"a":{"b":[1,2,{"c":3}]}}"#,
                json!({"a":{"b":[1,2,{"c":3}]}}),
            ),
            (
                "single object inside an array in prose",
                "Result: [{\"a\":1}] done",
                json!({"a":1}),
            ),
            (
                "non-ASCII two-byte prefix",
                "Résumé: {\"a\":1}",
                json!({"a":1}),
            ),
            (
                "non-ASCII three-byte prefix",
                "结果：{\"a\":1}",
                json!({"a":1}),
            ),
            ("non-ASCII four-byte prefix", "🎉 {\"a\":1}", json!({"a":1})),
            (
                "non-ASCII inside a string containing braces",
                "{\"cmd\":\"echo {héllo} }\"}",
                json!({"cmd":"echo {héllo} }"}),
            ),
            (
                "non-ASCII escaped via \\uXXXX",
                r#"{"name":"caf\u00e9","b":2}"#,
                json!({"name":"café","b":2}),
            ),
        ];
        for (name, input, expected) in cases {
            assert_eq!(&extract_json_object(input).unwrap(), expected, "{name}");
        }
    }

    #[test]
    fn extraction_rejects_ambiguous_and_non_object_shapes() {
        let cases: &[(&str, &str)] = &[
            ("two objects in prose", "{\"a\":1} and {\"b\":2}"),
            (
                "two objects in fenced blocks",
                "```json\n{\"a\":1}\n```\n```json\n{\"b\":2}\n```",
            ),
            ("pure array of objects", "[{\"a\":1},{\"b\":2}]"),
            ("no object", "just prose"),
        ];
        for (name, input) in cases {
            assert!(extract_json_object(input).is_err(), "{name}");
        }
    }

    #[test]
    fn redaction_handles_repeated_keys_and_unicode_without_panicking() {
        let key = "sk-secret";
        let body = format!("préfix {key} and {key} and 中文 suffix");
        let cleaned = redact_and_truncate(&body, key);
        assert!(!cleaned.contains(key), "{cleaned}");
        assert_eq!(cleaned.matches("[REDACTED]").count(), 2);
        assert!(cleaned.contains("中文"));

        // Truncation happens after redaction and at a char boundary.
        let long = format!("{key} {}", "é".repeat(1000));
        let cleaned = redact_and_truncate(&long, key);
        assert!(!cleaned.contains(key), "{cleaned}");
        assert!(cleaned.ends_with("... [truncated]"));
        assert!(cleaned.chars().count() <= MAX_ERROR_BODY_CHARS + 15);
    }
}
