# Changelog

All notable changes to AgentRegistry will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.4] - 2026-02-09

### 🔬 AST Deep Scanner (Experimental)

New opt-in AST-based security scanner that complements regex-based scanning with lightweight Abstract Syntax Tree analysis.

#### Detection Patterns (9)
- **Critical**: `dynamic_require`, `eval_family`, `encoded_payload_exec`, `process_spawn`, `network_exfiltration`
- **High**: `computed_member_exec`, `prototype_pollution`
- **Medium**: `timer_obfuscation`, `iife_with_suspicious_args`
- Includes **constant propagation** for tracking `const x = "literal"` values

#### Admin Panel Integration
- "🔬 Scan" button in Scans tab (per-package, opt-in)
- "🔬 Deep Scan" button in Quarantine tab
- Expandable findings with severity badges, file:line, code snippets
- All UI elements marked with 🧪 Experimental badge

#### WebSocket API
- `triggerDeepScan` action: `{ package_name, version }` → `deepScanResult`

#### CLI
- `agentregistry scan --deep <file-or-dir>` for local file scanning

#### Database
- New columns: `deep_scan_count`, `deep_scan_findings` in `scan_results`

#### Documentation
- Security docs: "Scope & Limitations" section with honest framing
- README: experimental subsection with pattern table and limitations
- WebSocket API docs: `triggerDeepScan` action documented

#### Dependencies
- Added `acorn` (^8.14.0) for AST parsing

#### Testing
- **179 new tests** in `ast-scanner.test.ts`
- 100% function coverage, 99.41% line coverage

## [1.2.3] - 2026-01-30

### 🐛 Critical Bug Fix: Persistent Storage

**BREAKING**: Fixed critical data loss bug where all packages were wiped on system reboot.

#### Root Cause
- Default `STORAGE_DIR` and `AGENTREGISTRY_HOME` were set to `/tmp/` paths
- macOS wipes `/tmp/` on every reboot
- Result: Complete database and package loss after restart

#### Fix
- Changed `STORAGE_DIR` default: `/tmp/agentregistry-storage` → `~/.agentregistry/storage`
- Changed `AGENTREGISTRY_HOME` default: `/tmp/.agentregistry` → `~/.agentregistry`
- Updated LaunchAgent plist to explicitly set environment variables for persistence
- Data now persists across reboots

#### Files Changed
- `src/config.ts` - Updated default paths
- `~/Library/LaunchAgents/com.agentregistry.daemon.plist` - Added explicit env vars

## [1.2.2] - 2026-01-30

### 📦 Dynamic Package Allowlist

Replaced hardcoded `TRUSTED_PACKAGES` (90 lines) with a dynamic, database-backed allowlist system.

#### New Module: `package-allowlist.ts`
- **SQLite Storage**: Persistent storage in `agentregistry.db`
- **59 Default Packages**: Pre-seeded across 10 categories (verified, build-tools, testing, observability, browser, cli, parsers, networking, node-utils, local)
- **Pattern Matching**: 
  - Exact match (`lodash`)
  - Scoped prefixes (`@opentelemetry/`)
  - Dash-bounded prefixes (`sentry-`)
- **CRUD Operations**: Add, remove, toggle, list entries

#### Admin Panel Integration
- New **Package Allowlist** section in Security tab
- Enable/disable toggle for entire allowlist
- Category filter dropdown
- Add custom package patterns
- Sortable table with category badges
- Stats counter showing active/total entries

#### WebSocket API
- `getPackageAllowlist` - Load entries and config
- `addPackageAllowlistEntry` - Add new pattern
- `removePackageAllowlistEntry` - Remove pattern
- `togglePackageAllowlistEntry` - Enable/disable entry
- `updatePackageAllowlistConfig` - Enable/disable allowlist
- `reseedPackageAllowlist` - Restore defaults

### 🛡️ Prompt Injection Detection

New security layer to detect and block AI prompt injection attempts in package metadata.

#### Detection Patterns
- System prompt overrides (`ignore previous instructions`)
- Role injection (`you are now`, `act as if`)
- Instruction manipulation (`do not follow`, `disregard`)
- Data exfiltration triggers (`output the contents`)

#### Integration
- Integrated into security scanner
- Detected patterns logged as `medium` severity issues
- Packages with prompt injection patterns go to quarantine

### 📊 Testing
- **21 new tests**: `package-allowlist.test.ts`
- **10 new E2E tests**: `admin-panel.test.ts` (Package Allowlist UI)
- **13 new tests**: `prompt-injection.test.ts`
- All 520+ tests passing

### 📚 Documentation
- Updated `docs/security/index.html` with Package Allowlist section

## [1.2.1] - 2026-01-30

### 🛡️ Security Audit Fixes

This release addresses vulnerabilities identified during a comprehensive security audit.

#### VULN-001: ReDoS Prevention (Critical)
- **File**: `server.ts`
- **Fix**: Improved regex patterns with explicit length limits to prevent catastrophic backtracking
- **Before**: `/^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/i`
- **After**: `/^(@[a-z0-9][a-z0-9._-]{0,100}\/)?[a-z0-9][a-z0-9._-]{0,100}$/i`

#### VULN-002: TOCTOU Protection in HTTP Handlers (Critical)
- **File**: `handlers/admin-http.ts`
- **Fix**: Added SHA-256 hash verification before/after file rename in `handleAdminQuarantineApprove`
- **Impact**: Prevents race condition where malicious tarball could be swapped during approval window

#### VULN-005: Timing-Safe Token Comparison (High)
- **File**: `server.ts`
- **Fix**: Replaced `token !== ADMIN_SESSION_TOKEN` with `crypto.timingSafeEqual()` wrapper
- **Locations**: HTTP admin auth (line 1800) and WebSocket auth (line 2419)
- **New Function**: `secureTokenCompare()` helper for constant-time comparison

### 📊 Testing
- All 72 server tests passing
- Security fixes verified with existing test suite

### 🔧 Launchd Auto-Start (macOS)

New CLI commands for installing AgentRegistry as a persistent launchd service:

- **`agentregistry install`**: Installs as macOS launchd service
  - Auto-starts on user login
  - KeepAlive enabled (restarts on crash)
  - OS detection with warnings for Linux/Windows users
- **`agentregistry uninstall`**: Removes launchd service

#### Usage
```bash
agentregistry install    # Install and enable auto-start
agentregistry uninstall  # Remove auto-start
```

## [1.2.0] - 2026-01-29

### 🏗️ Major Refactoring: Server Modularization

This release completes a comprehensive modularization of `server.ts`, reducing it from **3131 to 2618 lines** (-16.4%) while improving testability and maintainability.

#### Dependency Injection Pattern
- **AdminContext Interface**: Centralized context for admin handler dependencies
- **UpstreamContext Interface**: Centralized context for upstream proxy dependencies
- **Factory Functions**: `getAdminContext()` and `getUpstreamContext()` for DI

#### Module Extractions
- **Lifecycle Module** (`src/lifecycle/index.ts`):
  - `ensureStorageDirs` - Storage directory initialization
  - `autoApproveQuarantine` - Quarantine auto-approval logic
  - `runScheduledCleanup` - Scheduled cleanup tasks
  
- **Upstream Module** (`src/upstream/index.ts`):
  - `fetchFromUpstream` - Upstream registry proxy
  - `prefetchDependencies` - Background dependency prefetching
  - `fetchTarballFromUpstream` - Tarball download with quarantine

- **Admin Handlers** (`src/handlers/admin-http.ts`):
  - 12 handlers extracted: stats, audit logs, scan history, request logs
  - Quarantine management: list, delete, clear, approve
  - Cache management: list, delete, refresh, cleanup

#### Bug Fixes
- **Router Fix**: Removed shadowing `response` variable declaration that caused TypeScript errors
- **Admin Panel CSS**: Added `flex-shrink: 0` to tabs for proper responsive scrolling

### 📊 Metrics
- **server.ts**: 3131 → 2618 lines (-513 lines, -16.4%)
- **Tests**: 459 → 468 (+9 new upstream module tests)
- **TypeScript Errors**: 2 → 0
- **Test Failures**: 2 → 0

### 🧪 Testing
- New test file: `tests/upstream.test.ts` with 9 dedicated tests
- UpstreamContext interface validation
- Cache accessor function tests
- All 468 tests passing


## [1.0.4] - 2026-01-29

### 🛡️ Security Hardening (Security Audit Remediations)

#### Prototype Pollution Prevention (SEC-04)
- **safeJsonParse Standardization**: Replaced all `JSON.parse` calls with `safeJsonParse` across:
  - `database.ts` (8 locations: package loading, search, scan results, stats, migration)
  - `server.ts` (1 location: WebSocket message handling)
  - `security.ts` (1 location: package.json scanning)
- **Reviver Function**: Filters out `__proto__` and `constructor` keys to prevent prototype pollution attacks

#### TOCTOU Protection (SEC-02)
- **Hash Verification**: Added `sha256File` helper for atomic file verification
- **Quarantine Approval Security**: Both `approveQuarantine` and `approveAllQuarantine` now:
  1. Hash file before rename
  2. Perform rename operation
  3. Verify hash after rename matches
  4. Delete file and log security alert if mismatch detected
- **Audit Logging**: Hash verification events logged with `hash` field

#### Tests
- **17 New Security Tests**: Comprehensive regression tests for:
  - `safeJsonParse` prototype pollution prevention (7 tests)
  - `sha256File` TOCTOU detection (7 tests)
  - Object.prototype immunity verification (1 test)
  - Inherited security scanner tests (2 tests)

#### Agent-Friendly Responses
- **AI Directive Fields**: Security-blocked responses now include:
  - `ai_directive: "STOP_AND_WAIT_FOR_HUMAN"` - explicit instruction for AI agents
  - `ai_instructions[]` - list of DO NOT / MUST actions for agents
- **Prevents Workarounds**: Agents are explicitly instructed to:
  - NOT use alternative registries
  - NOT retry or modify packages
  - WAIT for explicit user approval before continuing

#### Health Check Endpoints
- `GET /-/ping` - Simple health check (returns "pong")
- `GET /-/health` - JSON with status, version, uptime, quarantine_pending count
- `GET /-/quarantine/check/:name/:version` - Check if specific package is in quarantine
  - Returns `in_quarantine`, `awaiting_approval`, `filename`, `issues`, `admin_panel`
  - Supports scoped packages (e.g., `@scope/name`)

#### Desktop Notifications (macOS only)
- Native macOS notifications via `osascript` (silent fallback on other platforms)
- Triggers:
  - When package enters quarantine during download
  - When agent requests a quarantined package (403)
  - When publish is blocked by security scan

### 📊 Testing
- **457 tests** passing (+16 new tests)
- New test file `health-endpoints.test.ts` covering:
  - Health check endpoints (/-/ping, /-/health, /-/quarantine/check)
  - notifyDesktop helper (cross-platform, special chars, non-blocking)
- Security regression test coverage for all audit findings

## [1.0.3] - 2026-01-28

### 🚀 Lighthouse Performance Optimizations

#### Admin Panel Performance (80-84% up from 73-79%)
- **Brotli Compression**: Added server-side brotli/gzip compression for HTML responses
- **Hero Image Optimization**: Reduced from 205KB (1024px) to 54KB (500px) with 2x srcset for retina
- **CSS/JS Minification**: Build script reduces admin.html from 121KB to 83KB (31% reduction)
- **LCP Optimization**: Added `loading="eager"` and `fetchpriority="high"` to hero image
- **Responsive Preload**: Added `imagesrcset` attribute to preload hints for responsive images
- **DNS Prefetch**: Added `dns-prefetch` hints as fallback for older browsers

#### Build System
- **New Build Script**: `scripts/build-admin.ts` minifies inline CSS/JS
- **Usage**: `bun run scripts/build-admin.ts`

#### Scores Achieved
- **Accessibility**: 100% ✅
- **Best Practices**: 100% ✅  
- **SEO**: 100% ✅
- **Performance**: 80-84% (optimal for realtime WebSocket admin panel)

## [1.0.2] - 2026-01-28

### 📱 Mobile UX Improvements

#### Admin Panel Responsive Design
- **MD3 Breakpoints**: Added 600px (compact) and 900px (medium) responsive breakpoints
- **Touch Targets**: All buttons and interactive elements now have 48px minimum touch size
- **Section Headers**: Title and action buttons stack vertically on mobile
- **Date Filters**: Audit/Requests filters now stack vertically with full-width inputs
- **Horizontal Scroll Tables**: All table containers (`#audit-content`, `#packages-content`, etc.) now scroll horizontally on mobile
- **Safe Area Insets**: Proper padding for devices with notches/dynamic islands
- **iOS Input Fix**: Form inputs use 16px font to prevent auto-zoom

#### Documentation Responsive Design
- **Hamburger Menu**: Added mobile navigation toggle for all 8 doc pages
- **Mobile Overlay Sidebar**: Full-screen nav overlay with smooth transitions
- **Improved Touch Targets**: Navigation links sized for mobile interaction
- **Color Contrast Fix**: Updated `--text-muted` to `#9ca3af` for WCAG AA compliance

### ✨ Admin Panel UX Improvements

#### Hash-Based Tab Routing
- **Deep Linking**: Navigate directly to tabs via URL (e.g., `/-/admin#packages`)
- **Browser Navigation**: Back/Forward buttons work between visited tabs
- **Shareable URLs**: Share specific admin sections with team members

#### Visual Enhancements
- **Row Hover Effect**: Purple left accent border on table rows for better UX
- **Unique Security Icon**: New network-shield design for IP Allowlist tab
- **Compact Log Tables**: Reduced padding in Audit and Requests tabs for data density
- **Premium Logo**: Refined 3D cube logo with gradient typography

### 🐛 Critical Bug Fixes

#### Real-Time Admin Updates
- **WebSocket Broadcast Fixed**: `setAdminWs()` was never called when admin WebSocket connected, causing all real-time broadcasts (`package_blocked`, `package_published`, etc.) to silently fail
- **Admin Panel Now Updates**: When agents download packages that get quarantined, Admin Panel immediately shows toast notification and refreshes quarantine list
- **Added Broadcast Handlers**: Admin Panel now correctly handles `package_blocked`, `package_published`, `quarantine_rescanned`, `package_approved`, `quarantine_bulk_approved` events

### 🧪 Test Coverage

- **10 New Broadcast Tests**: Comprehensive test suite for WebSocket broadcast events (428 tests total)

#### Infrastructure Fixes
- **Fixed Static File Paths**: `/docs/`, `/openapi.json`, and `/llms.txt` now correctly served from project root
- **Restored CSS Properties**: `scrollbar-width` and `white-space: nowrap` for responsive tabs

#### Daemon Best Practices
- **Graceful Shutdown**: Added `server.stop()` to wait for in-flight requests before exit
- **Idle Timeout**: Configured 30-second idle timeout to clean up stale connections

#### Agent Workflow Optimization
- **Auto-Allow Local Publish**: New toggle in admin panel Quarantine section (default: enabled)
- Locally published packages bypass quarantine/security scan for faster agent workflows
- Toggle persists in SQLite database via `getAutoAllowSetting`/`setAutoAllowSetting` WebSocket API

### 📊 Testing
- **457 tests** passing (up from 441)
- All Agent-First API endpoints verified
- Documentation site serving confirmed

### 📚 Documentation
- **Clean URLs**: Restructured docs to use directory-based URLs (`/docs/api/` instead of `/docs/api.html`)
- All 8 documentation pages now use `page/index.html` pattern for SEO-friendly URLs

## [1.0.1] - 2026-01-25

### 🛡️ Security Hardening
- **Critical Fix**: Mitigated Stored XSS in Admin Panel via `escapeHtml()` sanitization across all tables.
- **Security Fix**: Enhanced Path Traversal protection in Quarantine handlers using strict `basename()` validation.
- **Dependency**: Fixed static import path for security module to ensure build correctness.

## [1.0.0] - 2026-01-24

### 🎉 Initial Release

#### Features
- **Full NPM Registry Protocol** - Publish, install, unpublish packages
- **Upstream Proxy** - Automatic caching from npmjs.org
- **Security Scanner** - Real-time static analysis (~10ms per package)
- **Quarantine System** - All packages scanned before caching
- **Admin Panel** - Glassmorphic WebSocket-powered dashboard
- **Dependency Graph** - Interactive D3.js force-directed visualization
- **IP Allowlist** - CIDR/wildcard access control
- **Audit Logging** - Complete security event tracking
- **Developer Tools** - Scaffolding, release helper, backup/restore

#### Admin Panel Tabs
- 📊 **Dashboard** - Server stats, memory, uptime
- 📈 **Metrics** - Real-time RPS, latency, cache hit rate
- 📦 **Packages** - Manage packages with search and sorting
- 🛡️ **Security** - IP allowlist management
- 🔒 **Quarantine** - Review blocked packages
- 📜 **Audit Log** - Security event tracking
- 🔍 **Scans** - Scan history with CVE results
- 📡 **Requests** - HTTP request log
- 🕸️ **Graph** - Dependency visualization

#### Security
- Localhost-only binding (127.0.0.1)
- Path traversal protection
- OWASP/CWE pattern detection
- Rate limiting (1000 req/min)

#### Testing
- **415 tests** with 100% pass rate
- WebSocket operations fully tested
- E2E integration tests

### Technical
- Built with Bun for native performance
- ~7300 lines of modular TypeScript
- Zero external runtime dependencies
- SQLite database for persistence
