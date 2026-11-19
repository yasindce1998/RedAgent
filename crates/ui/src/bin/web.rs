//! WASM web shell: selects the `web` Dioxus renderer.

pub use redagent_ui::app;

fn main() {
    dioxus::launch(crate::app);
}
