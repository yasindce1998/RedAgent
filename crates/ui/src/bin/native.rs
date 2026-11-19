//! Native desktop shell: selects the `native` Dioxus renderer.

pub use redagent_ui::app;

fn main() {
    dioxus::launch(crate::app);
}
