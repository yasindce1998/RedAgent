#![no_main]

use libfuzzer_sys::fuzz_target;
use redagent_core::{projections, EventBody, StoredEvent};

// Fuzz the public event deserializer and the projections derived from it.
// Any panic, hang or out-of-bounds read here is a ledger-corruption vector.
fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(body) = serde_json::from_str::<EventBody>(text) else {
        return;
    };
    let event = StoredEvent {
        seq: 1,
        ts: "2026-01-01T00:00:00Z".to_string(),
        body: body.clone(),
        prev_hash: "0".repeat(64),
        hash: "1".repeat(64),
    };
    let view = projections::project(std::slice::from_ref(&event));
    let _ = projections::render_markdown(&view);
    let _ = serde_json::to_string(&body);
});
