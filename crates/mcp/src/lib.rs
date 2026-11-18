//! Minimal MCP client for RedAgent Phase 0: JSON-RPC 2.0 over stdio.
//! Deliberately small and synchronous — it speaks only `initialize`,
//! `tools/list` and `tools/call`. Approval elicitation and HTTP transport
//! arrive in later phases.

pub mod client;
pub mod jsonrpc;

pub use client::{StdioMcpClient, ToolCallResult, ToolInfo};
