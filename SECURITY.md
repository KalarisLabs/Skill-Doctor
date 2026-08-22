# Security Policy

## Supported Versions

| Version | Supported Until |
|---------|----------------|
| v0.2.x | Until v0.3.0 release |
| v0.1.x (Python) | End of life - no longer supported |

Only the current major version and the most recent minor version receive security updates.

## Reporting a Vulnerability

If you discover a security vulnerability in Skill Doctor, please report it responsibly rather than creating a public issue.

### How to Report

**Email**: [sayan@kalarislabs.com](mailto:sayan@kalarislabs.com)

**GitHub Security Advisory**: https://github.com/KalarisLabs/Skill-Doctor/security/advisories

### What to Include

- A description of the vulnerability
- Steps to reproduce the issue
- Affected versions
- Proof of concept (if applicable)
- Your GitHub username (for credit in the fix)

### Response Process

1. **Confirmation**: We will acknowledge receipt within 48 hours
2. **Assessment**: We will assess the severity and determine a fix timeline
3. **Fix Development**: We will develop a patch in private
4. **Release**: We will coordinate a release date with you
5. **Credit**: We will credit you in the release notes unless you prefer anonymity

### Expected Timeline

- **Critical vulnerabilities**: 7 days or less
- **High severity**: 14 days or less
- **Medium severity**: 30 days or less
- **Low severity**: Next release cycle

## Security Best Practices

Skill Doctor is a security tool itself, so we follow strict security practices:

- **Dependencies**: Regularly audited with `cargo audit`
- **Binary distribution**: All releases are signed with GPG signatures
- **Supply chain**: Dependencies are pinned and verified
- **Code review**: All changes undergo peer review
- **Testing**: Comprehensive test coverage including malicious corpus

## Security Features

Skill Doctor includes several security-focused features:

- **YARA-X**: Fast, memory-safe pattern matching engine
- **Sandboxing**: Behavioral analysis in isolated environments
- **AST taint analysis**: Detects command injection patterns
- **Community threat database**: Hash-based malware detection
- **Provenance verification**: Cryptographic signing support (planned)

## Public Disclosure

We will publicly disclose vulnerabilities:

- After a fix has been released
- In coordination with you to avoid impacting users
- In security advisories with severity and mitigation guidance

## Acknowledgments

We acknowledge and thank security researchers who responsibly disclose vulnerabilities to help make Skill Doctor more secure for everyone.
