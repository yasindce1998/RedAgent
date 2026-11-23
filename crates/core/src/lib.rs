//! Single source of truth for RedAgent: an append-only event ledger and the
//! projections derived from it. Nothing in this crate mutates a projection
//! directly — all state changes are events.

pub mod events;
pub mod ledger;
pub mod projections;

pub use events::{verify_signed_checkpoints, CallProposal, EventBody, StoredEvent};
pub use ledger::Ledger;
pub use projections::{render_markdown, CheckpointView, EngagementView};
