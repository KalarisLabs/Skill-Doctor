//! Skill Doctor Core — scanning engine library.
//!
//! This crate provides the multi-layer analysis pipeline for AI agent skill files.
//! It is used by the CLI binary and can be embedded into other tools.

pub mod intake;
pub mod layer1_static;
pub mod layer2_semantic;
pub mod layer4_threat;
pub mod llm_client;
pub mod models;
pub mod scorer;

pub use models::{Finding, ScanResult, Severity};
