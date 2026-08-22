# Contributing to Skill Doctor

Thank you for your interest in contributing to Skill Doctor! This document provides guidelines for contributing to the project.

## Development Setup

### Prerequisites

- **Rust toolchain**: Install via [rustup](https://rustup.rs/)
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  rustc --version
  cargo --version
  ```

- **Git**: For cloning and managing the repository

### Building

```bash
# Clone the repository
git clone https://github.com/KalarisLabs/Skill-Doctor.git
cd Skill-Doctor

# Build in debug mode
cargo build

# Build in release mode (optimized)
cargo build --release

# Run the CLI
cargo run -- scan ./test-skill/
```

### Running Tests

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run a specific test
cargo test test_scan_static

# Run tests with release optimizations
cargo test --release
```

### Code Quality

```bash
# Lint (checks for common mistakes)
cargo clippy -- -D warnings

# Format code
cargo fmt

# Check for security vulnerabilities in dependencies
cargo audit
```

## Coding Standards

### Rust Code Style

- Follow [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `cargo fmt` for consistent formatting
- Pass `cargo clippy` with no warnings
- Write tests for new features (unit tests for functions, integration tests for CLI commands)
- Document public APIs with rustdoc comments

### YARA Rules

- Follow the existing YARA rule structure in `crates/core/rules/`
- Each rule should have a clear `meta` section with:
  - `description`: What the rule detects
  - `category`: Which SD-XX attack class it belongs to
  - `severity`: Expected severity level
  - `author`: Attribution if adapting from external sources
- Test rules against the corpus in `tests/corpus/`
- Use hex escapes instead of Unicode character classes in regex patterns (YARA-X limitation)

### tree-sitter Grammars

- New language grammars should be added to `crates/core/src/grammar/`
- Follow the existing integration pattern in `crates/core/src/ast.rs`
- Add tests for the new language to the corpus

## Contribution Areas

We welcome contributions in these areas:

- **Additional YARA rules** for new attack patterns
- **tree-sitter grammars** for more programming languages
- **Registry integrations** (Skills.sh, MCPServers.org, others)
- **Performance optimizations**
- **Documentation improvements**
- **Bug fixes**
- **Test cases** for the malicious corpus

## Pull Request Process

1. **Fork the repository** and create a branch for your feature
2. **Make your changes** following the coding standards above
3. **Run tests** to ensure everything passes
4. **Update documentation** if needed
5. **Submit a pull request** with a clear description of your changes
6. **Address review feedback** promptly

### PR Checklist

- [ ] Code follows the project's coding standards
- [ ] Tests pass locally (`cargo test`)
- [ ] Documentation is updated for user-facing changes
- [ ] Commits are clear and concise
- [ ] PR description explains the change and its rationale

## Adding YARA Rules

To add a new YARA rule:

1. Create a new `.yar` file in `crates/core/rules/`
2. Follow the naming convention: `sdXX_attack_class.yar`
3. Include proper metadata in the `meta` section
4. Add test cases to `tests/corpus/` in the appropriate SD-XX directory
5. Run the corpus tests to verify detection
6. Update the rules count in the CLI output

## Adding tree-sitter Grammars

To add support for a new language:

1. Add the grammar dependency to `Cargo.toml`
2. Place the grammar files in `crates/core/src/grammar/`
3. Implement the AST parsing logic in `crates/core/src/ast.rs`
4. Add language-specific dangerous sinks to the taint analysis
5. Add test cases with the new language to the corpus
6. Update the CLI help text to mention the new language

## Issue Reporting

- Use GitHub Issues for bug reports and feature requests
- Provide clear steps to reproduce bugs
- Include error messages and system information
- Search existing issues before creating new ones

## Security Issues

For security vulnerabilities, please see [SECURITY.md](SECURITY.md) for responsible disclosure guidelines.

## License

By contributing to Skill Doctor, you agree that your contributions will be licensed under the Apache License 2.0 (Apache-2.0).
