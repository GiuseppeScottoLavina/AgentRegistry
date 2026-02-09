# 🚀 AgentRegistry — The AI-Native NPM Registry

<p align="center">
  <img src="docs/assets/hero.webp" alt="AgentRegistry - The AI-Native NPM Registry" width="800">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-0.1.3-orange?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/tests-650%2B%20passing-brightgreen?style=flat-square" alt="Tests">
  <img src="https://img.shields.io/badge/coverage-95%25%20lines-brightgreen?style=flat-square" alt="Coverage">
  <img src="https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/bun-%3E%3D1.0-black?style=flat-square&logo=bun" alt="Bun">
  <img src="https://img.shields.io/badge/dependencies-1-brightgreen?style=flat-square" alt="Dependencies">
</p>

<p align="center">
  <a href="https://giuseppescottolavina.github.io/AgentRegistry/">📖 Documentation</a> ·
  <a href="https://giuseppescottolavina.github.io/AgentRegistry/getting-started/">🚀 Getting Started</a> ·
  <a href="https://giuseppescottolavina.github.io/AgentRegistry/api/">📡 API Reference</a>
</p>

<p align="center">
  <strong>A local NPM registry built for the age of AI coding agents.</strong><br>
  Lightweight. Security-first. Blazing fast.
</p>

<p align="center">
  🤖 <strong>MCP Ready</strong> · 🛡️ <strong>Quarantine-First Security</strong> · ⚡ <strong>1ms Response Time</strong> · 🕸️ <strong>Dependency Graph</strong>
</p>

---

## The Vision

AI coding agents are transforming software development. Tools like Cursor, Windsurf, and Claude Code can write, test, and publish entire packages autonomously. But there's a critical gap: **when AI agents install dependencies, they blindly trust everything from npmjs.org** — including packages that contain prompt injection attacks, malicious install scripts, or supply chain exploits designed specifically to compromise AI workflows.

AgentRegistry was born from a simple question: *what if your local registry could protect your AI agents the same way a firewall protects your network?*

**AgentRegistry is a private, local NPM registry that sits between your AI agents and the public npm ecosystem.** Every package — whether published locally or fetched from upstream — is security-scanned in real time. Suspicious packages are quarantined and require human approval before any agent can use them. This creates a **human-in-the-loop security boundary** that prevents supply chain attacks without slowing down your workflow.

### Why It Matters

- 🔍 **SOTA prompt injection detection** — 10-pass scanner based on 2025-2026 academic research, resistant to homoglyphs, leetspeak, FlipAttack, Policy Puppetry, and GCG adversarial suffixes
- 🔒 **Quarantine-first architecture** — Unknown packages are blocked by default, not allowed by default
- 🤖 **Agent-native APIs** — MCP protocol, `llms.txt`, OpenAPI spec, structured error responses with AI directives
- ⚡ **~1ms response time** — Memory-first cache means agents don't wait
- 🏠 **Localhost-only** — Your packages never leave your machine

## Why AgentRegistry Over Verdaccio/Sinopia?

| Pain Point | Traditional Registries | AgentRegistry |
|------------|------------------------|---------| 
| **Dependencies** | 60+ packages to install | **2 dependencies (`tar`, `acorn`)** |
| **Setup Time** | Minutes of configuration | **One command: `bun run start`** |
| **AI Integration** | None | **Native MCP, llms.txt, OpenAPI** |
| **Security** | Afterthought (plugins) | **Quarantine-first architecture** |
| **Response Time** | 50-200ms | **~1ms (memory-first cache)** |
| **Admin UI** | Static page refreshes | **Real-time WebSocket dashboard** |

> ⚠️ **Alpha Software (0.1.0)** — AgentRegistry is under active development. APIs may change. Contributions and feedback welcome!


## Quick Start

```bash
# Start the server
bun run start

# Or with hot-reload for development
bun run dev

# Custom port
bun run server.ts --port 4874
```

## Daemon Mode

AgentRegistry can run as a background daemon with automatic restart on crash.

### CLI Commands

```bash
# Start daemon in background
bun run cli.ts start

# Check status
bun run cli.ts status

# View logs
bun run cli.ts logs

# Stop daemon
bun run cli.ts stop

# Restart
bun run cli.ts restart
```

### macOS Auto-Start (launchd)

```bash
# Install as system service (auto-start on boot)
npm run install-service

# Remove service
npm run uninstall-service
```

### Daemon Files

| File | Location |
|------|----------|
| PID file | `~/.agentregistry/agentregistry.pid` |
| Logs | `~/.agentregistry/logs/agentregistry.log` |
| launchd plist | `~/Library/LaunchAgents/com.agentregistry.daemon.plist` |

## Configuration

Point your npm/bun client to the local registry:

```bash
# NPM
npm config set registry http://localhost:4873

# Bun
echo 'registry = "http://localhost:4873"' >> bunfig.toml

# Per-project (.npmrc)
echo "registry=http://localhost:4873" > .npmrc
```

## Usage

### Publish a Package

```bash
# Standard npm publish
npm publish

# Or with bun
bun publish
```

### Install from Registry

```bash
npm install my-package
bun add my-package
```

### Unpublish

```bash
npm unpublish my-package@1.0.0
```

## Developer Tools

### Scaffold New Packages

Create a ready-to-publish TypeScript package:

```bash
agentregistry create my-pkg
```

### Release Helper

Bump version and publish in one command:

```bash
agentregistry release patch
# or minor, major
```

### Diagnostics
Check for environment issues (permissions, connectivity):
```bash
agentregistry doctor
```

### Dependency Graph

Visualize your local ecosystem at `http://localhost:4873/-/admin` (Graph tab).

### System Backup

Create a full snapshot (database + storage):

```bash
agentregistry backup
agentregistry restore <file.zip>
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | List all packages |
| `GET` | `/-/ping` | Health check |
| `GET` | `/{package}` | Get package metadata |
| `GET` | `/{package}/{version}` | Get specific version |
| `GET` | `/{package}/-/{tarball}.tgz` | Download tarball |
| `PUT` | `/{package}` | Publish package |
| `DELETE` | `/{package}/-/{tarball}/{rev}` | Unpublish version |

### Admin API

> ⚠️ **Authentication Required**: All admin API endpoints require `X-Admin-Token` header. Token is auto-injected in the admin panel UI.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/-/admin` | Admin panel UI (no auth required) |
| `GET` | `/-/admin/stats` | Server stats (memory, cache, etc.) |
| `GET` | `/-/admin/quarantine` | List quarantined packages |
| `DELETE` | `/-/admin/quarantine` | Clear all quarantine |
| `DELETE` | `/-/admin/quarantine/{file}` | Delete specific file |
| `POST` | `/-/admin/quarantine/{file}/approve` | Approve and cache |
| `GET` | `/-/admin/cache` | List cached packages |
| `DELETE` | `/-/admin/cache/{name}` | Delete package |
| `POST` | `/-/admin/cache/{name}/refresh` | Force refresh from NPM |

**Recommended**: Use WebSocket (`/-/admin/ws`) for all admin operations. The admin panel uses WebSocket automatically.

## Admin Panel

Access the admin panel at `http://localhost:4873/-/admin`

Features:
- 📊 **Server stats**: Uptime, memory, cache size, scan metrics
- 🔒 **Quarantine management**: View blocked packages, approve or delete
- 📦 **Cache control**: Delete or force-refresh packages
- 🕸️ **Dependency Graph**: Interactive D3.js force-directed visualization with local-only filter
- 🛡️ **IP Allowlist**: Configure access control with CIDR/wildcard patterns
- 📋 **Sortable Tables**: Click column headers to sort data (asc/desc toggle)
- 📜 **Audit Logs**: Security event tracking with sortable columns
- 📈 **Real-time Metrics**: RPS, latency, cache hit rate dashboard
- 🔄 **Auto-refresh**: WebSocket-powered live updates

## Storage

Packages are stored locally in:
- `storage/packages/` - JSON metadata
- `storage/tarballs/` - Validated package tarballs (.tgz)
- `storage/quarantine/` - Pending security scan (temporary)
- `storage/backups/` - Timestamped backup copies of all published packages

## Testing

```bash
# First, start the server (required for tests)
bun start

# In another terminal, run tests
bun test
```

> ⚠️ Some tests (Admin Panel, Agent-First API, Documentation Site) require a running server to pass.

### Test Coverage

| Category | Tests | Status |
|----------|-------|--------|
| Prompt Injection Scanner | 154 | ✅ |
| Server API | 72 | ✅ |
| Database Module | 54 | ✅ |
| IP Allowlist | 52 | ✅ |
| Admin Panel | 48 | ✅ |
| Security Module | 52 | ✅ |
| CVE Module | 39 | ✅ |
| Helpers & HTTP | 29 | ✅ |
| Validation | 28 | ✅ |
| Documentation Site | 26 | ✅ |
| Agent-First API | 25 | ✅ |
| Metrics Module | 25 | ✅ |
| Services (Cache & Broadcast) | 24 | ✅ |
| Package Allowlist | 21 | ✅ |
| Upstream Module | 18 | ✅ |
| Health Check | 16 | ✅ |
| Daemon | 13 | ✅ |
| Broadcast | 10 | ✅ |
| WebSocket Tests | 10 | ✅ |
| Compression | 9 | ✅ |
| Logger | 9 | ✅ |
| Allowlist | 8 | ✅ |
| CLI | 6 | ✅ |
| Unit Tests | 3 | ✅ |
| AST Scanner | 179 | ✅ |
| **Total** | **650+** | **✅** |

## Automatic Maintenance

AgentRegistry automatically maintains itself:

| Feature | Interval | Details |
|---------|----------|---------|
| **Log Cleanup** | Every 6 hours | Removes request logs >7 days, audit logs >30 days |
| **Quarantine Auto-Approve** | On startup | Re-scans quarantine, approves packages that now pass |
| **Security Alerts** | Kept forever | Blocked packages and security events are never deleted |

## Agent-Friendly Errors

When a package is blocked by security scan, AgentRegistry returns detailed JSON with:
- Clear explanation of what happened
- `action_required: "HUMAN INTERVENTION REQUIRED"`
- Step-by-step `instructions` array for resolution
- Direct link to admin panel
- Location of quarantined package

## Security

> ⚠️ **LOCALHOST ONLY** - This server is hardened for local use only.

### Protection Layers

| Layer | Protection |
|-------|------------|
| **Network** | Binds to `127.0.0.1` only (not `0.0.0.0`) |
| **Host Check** | Rejects requests from non-localhost hosts (403) |
| **Input Validation** | Strict regex for package names and versions |
| **Path Traversal** | Blocks `../`, null bytes, enforces `basename()` checks |
| **XSS Protection** | Output encoding via `escapeHtml()` on all render paths |
| **Length Limits** | Package names max 214 chars |
| **Security Scanner** | Static analysis before caching (~10-50ms) |
| **Quarantine** | All upstream packages scanned before cache |

### Quarantine Flow

All packages fetched from npmjs.org go through security scanning:

```
npm install lodash
       ↓
📥 Download from npmjs.org
       ↓
🔒 Write to storage/quarantine/
       ↓
🔍 Security scan (~10-50ms)
       ↓
✅ SAFE → Move to storage/tarballs/ + memory cache
🚨 BLOCKED → Stays in quarantine, returns 403
```

### What's Scanned (OWASP/CWE Patterns)

| Severity | Patterns Detected |
|----------|-------------------|
| **Critical** | `eval()`, `new Function()`, `curl|sh`, remote code loading |
| **High** | `child_process`, `exec()`, SSH/npmrc access, base64 payloads |
| **Medium** | File system writes, `.env` access, prototype pollution |
| **Low** | `process.env` access |

### SOTA Prompt Injection Scanner (10-Pass Architecture)

The prompt injection scanner uses a **research-backed 10-pass analysis pipeline** to detect LLM manipulation attempts hidden in package metadata, READMEs, and code comments:

| Pass | Technique | Catches |
|------|-----------|--------|
| 1 | Raw content scan | Literal injection patterns in 5 languages |
| 2 | Unicode normalization + homoglyphs | Cyrillic/Greek/fullwidth character substitution |
| 3 | Leetspeak decode | `1gn0r3 4ll pr3v10us 1nstruct10ns` |
| 4 | ROT13 decode | ROT13-encoded payloads |
| 5 | FlipAttack reversal | Character-reversed injection strings |
| 6 | Reconstruction patterns | `String.fromCharCode()`, `reverse().join()` |
| 7 | Policy Puppetry | Config format mimicry (INI/JSON/XML/YAML) |
| 8 | MCP injection | Tool description injection, line jumping |
| 9 | Adversarial suffix | GCG-style high-entropy gibberish detection |
| 10 | Invisible characters | Zero-width, tag characters, BiDi overrides |

**Cross-field payload splitting**: Metadata fields are concatenated and rescanned to catch payloads split across `name`, `description`, and `keywords`.

### Evasion Resistance

| Attack Vector | Paper/Source | Detection Method |
|---------------|--------------|------------------|
| Homoglyph substitution | ACL 2025 (42-59% ASR) | NFKD + 75 character mappings |
| Leetspeak obfuscation | HiddenLayer, April 2025 | Digit→letter substitution |
| Policy Puppetry | HiddenLayer, April 2025 | Config format pattern matching |
| FlipAttack | ACL 2025 (98% GPT-4o bypass) | Reverse content scanning |
| GCG adversarial suffixes | Zou et al., 2023 | Shannon entropy + punctuation analysis |
| Payload splitting | OWASP LLM01:2025 | Cross-field concatenation |
| MCP line jumping | MCP security research, 2025 | Tool description pattern matching |
| Invisible Unicode | Unicode Consortium TR36 | Zero-width/tag character detection |

**154 prompt injection tests** (30 SOTA adversarial) · 100% line coverage · 97% function coverage

### 🧪 AST Deep Scan (Experimental)

> ⚠️ The AST deep scanner is **one approach** to complementing regex-based scanning with lightweight AST analysis. Well-tested (179 tests, 99% coverage) and effective within its scope — but not a replacement for dedicated tools like Semgrep or CodeQL. See [known limitations →](https://giuseppescottolavina.github.io/AgentRegistry/security/#ast-deep)

**Opt-in only** — never runs automatically. Trigger via CLI (`agentregistry scan --deep`) or Admin Panel UI ("🔬 Scan" button).

| Pattern | Severity | Detects |
|---------|----------|---------|
| `eval_family` | Critical | `eval()`, `new Function()` |
| `encoded_payload_exec` | Critical | `eval(atob(...))`, encoded execution |
| `process_spawn` | Critical | `child_process.exec()`, shell commands |
| `network_exfiltration` | Critical | HTTP requests with sensitive data |
| `dynamic_require` | Critical | `require(variable)` |
| `computed_member_exec` | High | `global["ev"+"al"]()` |
| `prototype_pollution` | High | `__proto__` writes |
| `timer_obfuscation` | Medium | `setTimeout("code", 0)` |
| `iife_with_suspicious_args` | Medium | Suspicious IIFE arguments |

Includes lightweight **constant propagation** (tracks `const x = "literal"` values).

**Known limitations**: No data-flow, interprocedural, or control-flow analysis. Cannot track values across function boundaries or detect multi-file payloads.

**179 tests** · 100% function coverage · 99.41% line coverage — [Full docs →](https://giuseppescottolavina.github.io/AgentRegistry/security/#ast-deep)

### Research References

1. Zou et al. — *Universal and Transferable Adversarial Attacks on Aligned Language Models* (GCG, 2023)
2. HiddenLayer — *Policy Puppetry: A Universal Jailbreak for LLMs* (April 2025)
3. ACL 2025 — *FlipAttack: Jailbreak LLMs via Flipping* (78.97% ASR, 98% GPT-4o bypass)
4. ACL 2025 — *Homoglyph Attack Analysis* (42-59% success rate)
5. OWASP — *Top 10 for LLM Applications 2025* (LLM01: Prompt Injection)
6. MCP Security — *Tool Description Injection via Line Jumping* (2025)
7. Unicode Consortium — *TR36: Unicode Security Considerations*
8. npm Supply Chain — *Shai-Hulud worm, Chalk/Debug attack, Contagious Interview campaign* (2024-2025)

### What's Validated

- Package names: `/^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/i`
- Versions: Strict semver pattern
- Paths: Containment check - all file operations stay within `storage/`

### Not For Production

This registry is designed for:
- ✅ Local agent-to-agent package sharing
- ✅ Development and testing
- ❌ NOT for public internet exposure
- ❌ NOT for multi-user production environments

## 🤖 Agent-First Architecture

AgentRegistry is optimized for AI agent workflows with full support for modern agent protocols.

### Machine-Readable Discovery

| Endpoint | Description |
|----------|-------------|
| `GET /llms.txt` | AI discovery file (like robots.txt for LLMs) |
| `GET /openapi.json` | Full OpenAPI 3.0 specification |
| `GET /-/capabilities` | Tool definitions for AI agents |

### MCP Server (Model Context Protocol)

AgentRegistry includes a full MCP server for integration with Claude, GPT, and other AI assistants:

```bash
# Install and run MCP server
cd mcp-server
bun install
bun run start
```

**Claude Desktop Configuration** (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "agentregistry": {
      "command": "bun",
      "args": ["run", "/path/to/AgentRegistry/mcp-server/index.ts"]
    }
  }
}
```

### Available MCP Tools

| Tool | Description |
|------|-------------|
| `publish_package` | Publish with automatic security scanning |
| `get_package` | Get package metadata |
| `search_packages` | Search local + upstream packages |
| `get_server_stats` | Server health and statistics |
| `check_quarantine` | Check for blocked packages |

### Agent-Friendly Features

- **Structured JSON errors** with remediation instructions
- **Idempotent operations** for safe retries
- **Security scan feedback** explains why packages were blocked
- **WebSocket protocol** for real-time admin operations

## Features

- ✅ Full npm publish/install workflow
- ✅ Scoped packages support (@scope/name)
- ✅ SHA1 and SHA512 integrity checksums
- ✅ Dist-tags (latest, next, etc.)
- ✅ Version-specific fetching
- ✅ CORS enabled for browser access
- ✅ **Upstream proxy to npmjs.org** (auto-cache)
- ✅ **Real-time security scanning** (~10-50ms per package)
- ✅ **Quarantine flow** for upstream packages
- ✅ **In-memory cache** (X-Cache: HIT-MEMORY/HIT-DISK)
- ✅ **Localhost-only security hardening**
- ✅ Single runtime dependency (`tar`)
- ✅ ~12,300 lines of code (modular architecture)
- ✅ **Developer Tools**: Scaffolding, Release Helper, Dependency Graph

## How It Works

1. **Local packages first**: If a package exists locally, serve it (memory → disk)
2. **Upstream + Quarantine**: Fetch from npmjs.org → quarantine → scan → cache
3. **Security blocking**: Suspicious packages get 403 Forbidden
4. **Fast caching**: Memory cache for instant response, disk for persistence

## Performance

| Operation | Time |
|-----------|------|
| Memory cache hit | ~1ms |
| Disk cache hit | ~3ms |
| Upstream fetch + scan | ~500ms (network) + ~10-50ms (scan) |

Memory cache stores up to 100 tarballs for instant serving.

