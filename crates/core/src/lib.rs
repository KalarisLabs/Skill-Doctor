//! Skill Doctor Core: scanning engine library.
//!
//! This crate provides the multi-layer analysis pipeline for AI agent skill files.
//! It is used by the CLI binary and can be embedded into other tools.
//!
//! ## Pipeline Architecture
//! The analysis runs through four distinct, gracefully-degrading layers:
//!
//! - **Layer 1: Static Analysis** (`layer1_static`): Blazing-fast pattern matching using YARA-X and Tree-sitter AST parsing.
//! - **Layer 2: Semantic Analysis** (`layer2_semantic`): Intent extraction and context evaluation via an OpenAI-compatible REST LLM client.
//! - **Layer 3: Behavioral Sandbox** (`layer3_sandbox`): Runtime execution tracing in a secure `microsandbox` environment to detect live exfiltration or command injection.
//! - **Layer 4: Threat Intelligence** (`layer4_threat`): Fast cryptographic hash matching against known-malicious community threat datasets.
//!
//! See `ARCHITECTURE.md` in the repository root for detailed dataflow diagrams and layer contracts.

pub mod intake;
pub mod layer1_static;
pub mod layer2_semantic;
pub mod layer3_sandbox;
pub mod layer4_threat;
pub mod llm_client;
pub mod models;
pub mod scorer;

pub use models::{Finding, ScanResult, Severity};
