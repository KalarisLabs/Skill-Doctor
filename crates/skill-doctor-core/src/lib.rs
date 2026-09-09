//! Skill Doctor Core — deterministic analysis engine.
//!
//! This crate contains the layered analysis pipeline:
//! - L0: intake, normalization, canonical bundle digest
//! - L1: deterministic static engines (pattern, unicode, entropy, taint, capability differ)
//! - L5: scoring, coverage computation, report generation
//!
//! The core never performs network I/O or LLM inference.

pub mod finding;
pub mod l0;
pub mod l1;
pub mod l5;
pub mod report;
pub mod scoring;
pub mod taxonomy;
