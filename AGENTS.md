# AgentRegistry - AI Agent Documentation

<p align="center">
  <img src="docs/assets/docs.webp" alt="AgentRegistry Documentation" width="600">
</p>

> **Minimal local NPM registry server for agent-to-agent package sharing.**
> Built with Bun for maximum performance. Single dependency (tar).
> Licensed under **Apache 2.0** (see [NOTICE](NOTICE) for attribution).

## Quick Reference

### Start Server
```bash
bun run server.ts
# or with custom port
bun run server.ts --port 4873
```

### Configure npm/bun to use AgentRegistry
```bash
npm config set registry http://localhost:4873
# or per-project in .npmrc:
echo "registry=http://localhost:4873" > .npmrc
```

### Publish Package
```bash
npm publish --registry http://localhost:4873
```

---

## ⚠️ NO AUTHENTICATION REQUIRED

> **AgentRegistry is NOT Verdaccio!** Do NOT follow Verdaccio instructions.

| Action | Authentication |
|--------|----------------|
| `npm publish` | ❌ **None** |
| `npm install` | ❌ **None** |
| `npm unpublish` | ❌ **None** |
| Admin Panel UI | ❌ **None** (auto-injected) |
| Admin HTTP API | ✅ Token (WebSocket recommended) |

### ❌ You do NOT need:
- `.npmrc` with `_authToken`
- `htpasswd` files
- `~/.config/verdaccio/` anything
- Any login/authentication

### ✅ Just use:
```bash
# Configure registry
npm config set registry http://localhost:4873

# Publish directly (no token!)
npm publish

# Or per-command
npm publish --registry http://localhost:4873
```

### ⚠️ Bun Users - Important Workaround

Bun's client performs a client-side auth check **before** contacting the server.
AgentRegistry doesn't require auth, but Bun needs to see *something* in `.npmrc`:

```bash
# Add a dummy token to satisfy Bun's client-side check
echo "//localhost:4873/:_authToken=agentregistry-no-auth-needed" >> ~/.npmrc

# Now Bun will work
bun publish --registry http://localhost:4873
```

**Note**: AgentRegistry ignores this token completely - it's only to bypass Bun's local validation.

**Alternative**: Use `npm publish` instead of `bun publish` (npm doesn't have this restriction).

---

## Architecture

```
AgentRegistry/
├── src/
│   ├── server.ts          # Main HTTP/WebSocket server (monolithic router)
│   ├── database.ts        # SQLite operations
│   ├── security.ts        # Tarball security scanning
│   ├── prompt-injection.ts # Prompt injection detection in packages
│   ├── config.ts          # Constants, env vars
│   ├── cli.ts             # Daemon management CLI
│   ├── daemon.ts          # Daemon lifecycle management
│   ├── ip-allowlist.ts    # IP access control
│   ├── package-allowlist.ts # Dynamic package allowlist
│   ├── cve.ts             # CVE scanning
│   ├── metrics.ts         # Performance metrics
│   ├── logger.ts          # Structured logging
│   ├── handlers/          # Route handlers
│   ├── lifecycle/         # Server lifecycle
│   ├── services/          # Business logic
│   │   ├── cache.ts       # Memory caching
│   │   └── broadcast.ts   # WebSocket broadcasting
│   ├── types/             # TypeScript type definitions
│   ├── templates/         # HTML templates
│   ├── upstream/          # Upstream registry proxy
│   ├── utils/             # Shared utilities
│   └── web/
│       ├── admin.html     # Admin dashboard UI
│       └── assets/        # Images, D3.js
├── docs/                   # GitHub Pages documentation
└── storage/                # Data directory (~/.agentregistry)
    ├── agentregistry.db         # SQLite database
    ├── tarballs/          # Approved .tgz files
    ├── quarantine/        # Blocked packages
    └── backups/           # Version backups
```

---

## Key APIs

### Package Handlers (`src/handlers/package.ts`)

| Function | Description |
|----------|-------------|
| `handleGetPackage(name)` | Returns package metadata (cache → DB → upstream) |
| `handleGetTarball(name, tarball)` | Downloads tarball (local → upstream with scan) |
| `handlePublish(req, name)` | Publishes package with security scan |
| `handleUnpublish(name, tarball?)` | Removes package/version |

### Admin Handlers (`src/handlers/admin.ts`)

| WebSocket Action | Description |
|------------------|-------------|
| `getStats` | Server statistics |
| `getQuarantine` | List quarantined packages with issues |
| `rescanQuarantine` | Rescan all quarantined packages |
| `approveQuarantine` | Manually approve a package |

### Security Scanner (`src/security.ts`)

| Function | Description |
|----------|-------------|
| `scanTarball(path)` | Scans tarball for security issues |

Returns:
```typescript
interface ScanResult {
    safe: boolean;
    issues: Array<{
        severity: "critical" | "high" | "medium" | "low";
        description: string;
        file?: string;
    }>;
    filesScanned: number;
    scanTimeMs: number;
}
```

### Database (`database.ts`)

| Function | Description |
|----------|-------------|
| `loadPackageFromDB(name)` | Load package metadata |
| `savePackageToDB(pkg)` | Save package metadata |
| `saveScanResult(result)` | Store scan result |
| `logAudit(action, target, data?)` | Log audit event |

---

## Security Features

1. **Localhost-only binding** - Rejects remote connections
2. **Package name validation** - Prevents path traversal
3. **Security scanning** - Static analysis for malware patterns
4. **Quarantine system** - Blocks packages with issues
5. **Audit logging** - All operations logged to SQLite
6. **Rate limiting** - Per-IP request limits

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `STORAGE_DIR` | `./storage` | Data directory path |

---

## Testing

```bash
bun test
# 557 tests covering all endpoints, security, admin panel, and agent APIs
```

---

## Common Patterns

### Adding a new WebSocket action

```typescript
// In src/handlers/admin.ts handleAdminWSMessage()
case "myAction":
    const result = await doSomething(msg.payload);
    respond("myActionResult", { data: result });
    break;
```

### Broadcasting real-time events

```typescript
import { broadcastToAdmin } from "./src/services/broadcast";
broadcastToAdmin("event_name", { key: "value" });
```

### Adding to whitelist

```typescript
// In security_scanner.ts TRUSTED_PACKAGES array
const TRUSTED_PACKAGES = [
    "new-trusted-package",
    // ...
];
```
