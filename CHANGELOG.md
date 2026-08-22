# Changelog

All notable changes to Skill Doctor will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- (No unreleased features yet)

### Changed
- (No unreleased changes yet)

### Deprecated
- (No deprecations yet)

### Removed
- (No removals yet)

### Fixed
- (No unreleased fixes yet)

### Security
- (No unreleased security fixes yet)

## [0.2.3] - 2026-08-22

### Added
- Rust-based CLI with OpenTUI rendering engine
- Multi-layer scan pipeline (YARA-X + tree-sitter + microsandbox + LLM)
- Lobe Hub and Skills.sh registry integration with fast scraping
- GitHub shorthand resolution (`owner/repo`)
- Cross-platform binary releases (Windows, macOS, Linux)
- Community threat database with hash-based caching
- SARIF, JSON, and HTML report generation
- Comprehensive malicious corpus for testing (SD-01 through SD-03)

### Changed
- Complete rewrite from Python to Rust for performance
- Static analysis now executes in <30ms (vs ~85ms in Python)
- Cross-file AST taint analysis across entire skill bundles
- Provider-agnostic LLM integration (Groq, OpenAI, Ollama, vLLM)

### Security
- Fixed YARA rule compilation errors for Unicode patterns
- Added comprehensive security-focused testing corpus

## [0.2.2] - 2026-08-15

### Added
- npm package `@kalarislabs/skill-doctor` for cross-platform installation
- Postinstall script for automatic binary download from GitHub Releases
- Windows PowerShell installer script
- Linux/macOS shell installer script

### Changed
- Updated installer scripts to use v0.2.0 binary releases
- Improved error handling in installation process

### Fixed
- Fixed path issues in Windows installer for different user directories

## [0.2.1] - 2026-08-10

### Added
- Initial Rust implementation proof-of-concept
- Basic YARA-X integration
- Core file scanning functionality

### Changed
- Migrated from Python to Rust for performance

### Removed
- Python dependencies and virtual environment requirements

## [0.1.0] - 2026-08-01

### Added
- Initial Python implementation
- Basic YARA pattern matching
- Python AST analysis with tree-sitter
- Entropy and Unicode analysis
- Groq LLM semantic analysis
- CLI with basic commands
- SARIF, JSON, HTML report generation
- Test fixtures for validation

### Security
- Initial security-focused feature set
- AGPL v3 licensing

[0.1.0]: https://github.com/KalarisLabs/Skill-Doctor/releases/tag/v0.1.0
[0.2.1]: https://github.com/KalarisLabs/Skill-Doctor/releases/tag/v0.2.1
[0.2.2]: https://github.com/KalarisLabs/Skill-Doctor/releases/tag/v0.2.2
[0.2.3]: https://github.com/KalarisLabs/Skill-Doctor/releases/tag/v0.2.3
