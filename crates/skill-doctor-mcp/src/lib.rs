//! Skill Doctor MCP — Model Context Protocol server.
//!
//! Exposes the `skill_doctor_scan` tool via MCP for host-delegated L2
//! semantic analysis. The scanner performs no inference; it emits static
//! findings plus a neutralized envelope, and the host agent's own model
//! returns a schema-constrained verdict.
//!
//! **Status: Stub.** This crate will be implemented after L1 engines are complete.
