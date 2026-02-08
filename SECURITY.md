# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability in AgentRegistry, please follow these steps:

### 1. Do NOT open a public issue

Security vulnerabilities should never be reported in public issues, as this could expose users to attacks before a fix is available.

### 2. Email the maintainer directly

Send details to the project maintainer with:

- A clear description of the vulnerability
- Steps to reproduce the issue
- Potential impact assessment
- Any suggested fixes (optional)

### 3. Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Timeline**: Depends on severity
  - Critical: 24-48 hours
  - High: 7 days
  - Medium: 30 days
  - Low: Next release

### 4. Disclosure Policy

- We follow responsible disclosure practices
- Credit will be given to reporters in the changelog (unless anonymity is requested)
- We ask that you do not publicly disclose the issue until we've released a fix

## Security Features

AgentRegistry includes several built-in security features:

- **Localhost Binding**: Server binds to `127.0.0.1` only
- **Host Header Validation**: Rejects non-localhost requests
- **Security Scanner**: Static analysis of all packages (~10ms)
- **Quarantine Flow**: Upstream packages are scanned before caching
- **Input Validation**: Strict regex for package names and versions
- **Path Traversal Protection**: Blocks `../` and null bytes
- **XSS Protection**: Output encoding via `escapeHtml()`

## Known Limitations

AgentRegistry is designed for **local development only**:

- ❌ Not for public internet exposure
- ❌ Not for multi-user production environments
- ✅ Local development and testing
- ✅ Agent-to-agent package sharing

## Security Audit

The codebase has undergone comprehensive security review covering:

- Prototype pollution prevention
- TOCTOU (Time-of-check to time-of-use) protection
- Request smuggling resistance
- Input validation and sanitization

See [CHANGELOG.md](CHANGELOG.md) for security-related updates.
