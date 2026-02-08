# Contributing to AgentRegistry

Thank you for your interest in contributing to AgentRegistry! This document provides guidelines and instructions for contributing.

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/GiuseppeScottoLavina/AgentRegistry.git
cd agentregistry

# Install dependencies (only dev deps)
bun install

# Start the server
bun start

# Run tests (server must be running)
bun test
```

## 📋 Prerequisites

- **Bun** >= 1.0.0 ([install](https://bun.sh))
- **macOS** or **Linux** (Windows WSL2 works)
- Basic knowledge of TypeScript and npm registry protocol

## 🏗️ Project Structure

```
agentregistry/
├── src/
│   ├── server.ts          # Main server with all handlers
│   ├── cli.ts             # CLI commands (start, stop, status, etc.)
│   ├── daemon.ts          # Background process management
│   ├── config.ts          # Configuration constants
│   ├── database.ts        # SQLite database operations
│   ├── security.ts        # Security scanner
│   ├── logger.ts          # Logging utilities
│   ├── services/          # Core services
│   │   ├── broadcast.ts   # WebSocket broadcast
│   │   └── cache.ts       # In-memory caching
│   ├── upstream/          # Upstream registry proxy
│   │   └── index.ts       # npmjs.org fetch & quarantine
│   ├── utils/             # Utility modules
│   │   ├── compression.ts # HTTP compression
│   │   ├── helpers.ts     # ID, hash, path helpers
│   │   ├── http.ts        # ETag generation
│   │   └── validation.ts  # Input validation
│   └── web/
│       └── admin.html     # Admin panel (single file)
├── tests/                 # 751 tests across 26 files
├── docs/                  # Documentation website
├── storage/               # Runtime data (gitignored)
└── scripts/               # Installation scripts
```

## 🧪 Testing

Tests require a running server:

```bash
# Terminal 1: Start server
bun start

# Terminal 2: Run tests
bun test

# Run specific test file
bun test tests/allowlist.test.ts
```

### Test Categories

| File | Coverage |
|------|----------|
| `server.test.ts` | HTTP API endpoints |
| `admin-panel.test.ts` | Admin panel structure |
| `security.test.ts` | Security scanner integration |
| `security-unit.test.ts` | Security scanner unit tests |
| `database.test.ts` | SQLite database operations |
| `ip-allowlist.test.ts` | IP allowlist management |
| `allowlist.test.ts` | Allowlist WebSocket API |
| `package-allowlist.test.ts` | Package allowlist |
| `websocket-ops.test.ts` | WebSocket operations |
| `broadcast.test.ts` | WebSocket broadcast events |
| `agent-first.test.ts` | Agent-first API |
| `upstream.test.ts` | Upstream registry proxy |
| `services.test.ts` | Cache & broadcast services |
| `compression.test.ts` | HTTP compression |
| `helpers.test.ts` | Helpers & HTTP utilities |
| `validation.test.ts` | Input validation |
| `prompt-injection.test.ts` | Prompt injection scanner |
| `cve.test.ts` / `cve-mocked.test.ts` | CVE module |
| `metrics.test.ts` | Metrics collection |
| `health-endpoints.test.ts` | Health check endpoints |
| `docs-site.test.ts` | Documentation site |
| `logger.test.ts` | Logging module |
| `daemon.test.ts` | Daemon management |
| `cli.test.ts` | CLI commands |

## 💻 Development Workflow

### 1. Create a Branch

```bash
git checkout -b feature/my-feature
# or
git checkout -b fix/my-bugfix
```

### 2. Make Changes

- Follow the existing code style
- Add tests for new functionality
- Update documentation if needed

### 3. Test Your Changes

```bash
# Run all tests
bun test

# Check for TypeScript errors
bunx tsc --noEmit
```

### 4. Commit

Use conventional commits:

```bash
git commit -m "feat: add new feature"
git commit -m "fix: resolve bug in X"
git commit -m "docs: update README"
git commit -m "test: add tests for Y"
```

### 5. Submit PR

- Provide a clear description
- Reference any related issues
- Ensure all tests pass

## 📝 Code Style

- **TypeScript** with strict mode
- **4 spaces** for indentation
- **Single quotes** for strings
- **No semicolons** (Bun default)
- **Async/await** over callbacks

### Example

```typescript
async function handleRequest(req: Request): Promise<Response> {
    const url = new URL(req.url)
    
    if (url.pathname === '/-/ping') {
        return Response.json({ ok: true })
    }
    
    return new Response('Not Found', { status: 404 })
}
```

## 🔒 Security

If you discover a security vulnerability:

1. **DO NOT** open a public issue
2. Email the maintainer directly
3. Provide detailed reproduction steps
4. Allow time for a fix before disclosure

## 📚 Documentation

- Update `README.md` for user-facing changes
- Update `docs/` for detailed documentation
- Add JSDoc comments for public functions
- Update `CHANGELOG.md` for notable changes

## 🎯 Areas for Contribution

### Good First Issues
- Documentation improvements
- Test coverage expansion
- Error message clarity
- UI/UX in admin panel

### Advanced
- Performance optimizations
- New security patterns
- Protocol extensions
- Plugin architecture

## 📄 License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.

---

**Questions?** Open an issue or check existing discussions.

Thank you for contributing! 🙏
