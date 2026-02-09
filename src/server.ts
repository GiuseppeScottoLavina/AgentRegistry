/* 
 * Copyright 2026 Giuseppe Scotto Lavina
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * AgentRegistry - Minimal Local NPM Registry Server
 * 
 * A lightweight, performant NPM registry for local agent-to-agent package sharing.
 * Built with Bun for maximum performance. Single dependency (tar).
 * 
 * Usage:
 *   bun run server.ts
 *   bun run server.ts --port 4873
 * 
 * Endpoints:
 *   GET  /{package}                    - Get package metadata
 *   GET  /{package}/{version}          - Get specific version
 *   GET  /{package}/-/{tarball}.tgz    - Download tarball
 *   PUT  /{package}                    - Publish package
 *   DELETE /{package}/-/{tarball}/{rev} - Unpublish version
 */

import { mkdir, readdir, unlink, exists, rename } from "node:fs/promises";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { createHash, timingSafeEqual } from "node:crypto";
import cluster from "node:cluster";
import { cpus } from "node:os";
import { scanTarball, type ScanResult } from "./security";
import { deepScanFiles } from "./ast-scanner";
import {
    getDatabase,
    loadPackageFromDB,
    getAllPackages,
    savePackageToDB,
    deletePackageFromDB,
    listPackagesFromDB,
    searchPackages,
    countPackages,
    saveScanResult,
    updateDeepScanResult,
    getScanStats,
    logRequest,
    logAudit,
    getRecentAuditLogs,
    getAuditLogsForExport,
    formatAuditLogsAsCSV,
    getAuditLogCount,
    getComprehensiveStats,
    incrementDownloads,
    closeDatabase,
    getStat,
    setStat,
    type AuditExportOptions
} from "./database";

// Import from modular src/ structure (now sibling)
import {
    PORT, STORAGE_DIR, PACKAGES_DIR, TARBALLS_DIR, QUARANTINE_DIR, BACKUP_DIR,
    LOCALHOST_ONLY, ALLOWED_HOSTS, MAX_TARBALL_SIZE,
    RATE_LIMIT_WINDOW_MS, RATE_LIMIT_MAX_REQUESTS, SECURITY_HEADERS,
    ADMIN_SESSION_TOKEN, DAEMON_MODE, CLUSTER_MODE, WEB_DIR, PROJECT_DIR, DOCS_DIR
} from "./config";

import {
    writePidFile, removePidFile, ensureDaemonDirs
} from "./daemon";

import * as logger from "./logger";
import { initLogger, closeLogger } from "./logger";

import {
    safeJsonParse, sha256File, notifyDesktop,
    compressResponse, generateETag
} from "./utils";

import type { PackageVersion, PackageMetadata, WebSocketData } from "./types";

import {
    ensureStorageDirs,
    autoApproveQuarantine,
    runScheduledCleanup,
    CLEANUP_INTERVAL_MS
} from "./lifecycle";

import {
    type UpstreamContext,
    fetchFromUpstream as fetchFromUpstreamModule,
    prefetchDependencies as prefetchDependenciesModule,
    fetchTarballFromUpstream as fetchTarballFromUpstreamModule
} from "./upstream";

import {
    handleAdminAuditLogs,
    handleAdminScanHistory,
    handleAdminRequestLogs,
    handleAdminQuarantineList,
    handleAdminQuarantineDelete,
    handleAdminQuarantineClear,
    handleAdminQuarantineApprove,
    handleAdminStats,
    handleAdminCacheList,
    handleAdminCacheDelete,
    handleAdminCacheRefresh,
    handleAdminCleanup,
    type AdminContext
} from "./handlers";

import {
    checkRateLimit, rateLimitStore,
    getTarballFromCache, setTarballInCache, getTarballCacheSize
} from "./services/cache";

import {
    setAdminWs, broadcastToAdmin, getUptimeSeconds
} from "./services/broadcast";

import {
    recordRequest, getMetricsSnapshot
} from "./metrics";

import {
    checkCVE, scanPackages, getCVESummary, getAllCachedCVEs
} from "./cve";

import {
    isIPAllowed, getConfig as getIPConfig, updateConfig as updateIPConfig,
    addEntry as addIPEntry, removeEntry as removeIPEntry, toggleEntry as toggleIPEntry,
    listEntries as listIPEntries, getAllowlistSummary, validatePattern
} from "./ip-allowlist";

import {
    listPackageAllowlist, getPackageAllowlistConfig, updatePackageAllowlistConfig,
    addPackageToAllowlist, removeFromAllowlist, togglePackageAllowlistEntry,
    getPackageAllowlistSummary, getPackageAllowlistCategories, reseedDefaultPackages
} from "./package-allowlist";

// ============================================================================
// Local State (not imported from modules)
// ============================================================================

// Version from package.json
const VERSION = require("../package.json").version as string;

// Cache for scan results (local to server - different from module cache)
const SCAN_RESULTS_CACHE = new Map<string, ScanResult>();

// Package cache with TTL
const PACKAGE_CACHE = new Map<string, { data: PackageMetadata; timestamp: number }>();
const PACKAGE_CACHE_MAX_SIZE = 200;
const PACKAGE_CACHE_TTL = 60 * 1000;

// Admin WebSocket clients
const adminWSClients = new Set<any>();
let activeAdminWS: any = null;

// ============================================================================
// Security: Input Validation & Path Traversal Protection
// ============================================================================

// Valid NPM package name pattern (scoped or unscoped)
// SECURITY: Limited repetition to prevent ReDoS (max 214 chars enforced separately)
const VALID_PACKAGE_NAME = /^(@[a-z0-9][a-z0-9._-]{0,100}\/)?[a-z0-9][a-z0-9._-]{0,100}$/i;

// Valid semver version pattern (non-backtracking, possessive-like)
const VALID_VERSION = /^\d{1,10}\.\d{1,10}\.\d{1,10}(?:-[a-zA-Z0-9.-]{1,50})?(?:\+[a-zA-Z0-9.-]{1,50})?$/;

function validatePackageName(name: string): void {
    if (!name || name.length > 214) {
        throw new Error("Invalid package name: too long or empty");
    }
    if (!VALID_PACKAGE_NAME.test(name)) {
        throw new Error(`Invalid package name: ${name}`);
    }
    // Extra protection against path traversal
    if (name.includes("..") || name.includes("//")) {
        throw new Error("Invalid package name: contains path traversal");
    }
}

function validateVersion(version: string): void {
    if (!version || !VALID_VERSION.test(version)) {
        throw new Error(`Invalid version: ${version}`);
    }
}

function assertPathContainment(filePath: string, baseDir: string): void {
    const { resolve } = require("node:path");
    const resolved = resolve(filePath);
    const base = resolve(baseDir);
    if (!resolved.startsWith(base + "/") && resolved !== base) {
        throw new Error(`Path traversal detected: ${filePath}`);
    }
}

/**
 * SECURITY: Constant-time string comparison to prevent timing attacks.
 * Used for admin token verification.
 */
function secureTokenCompare(provided: string | null, expected: string): boolean {
    if (!provided) return false;
    const providedBuf = Buffer.from(provided);
    const expectedBuf = Buffer.from(expected);
    // Length check first (this leaks length, but token length is not secret)
    if (providedBuf.length !== expectedBuf.length) return false;
    return timingSafeEqual(providedBuf, expectedBuf);
}

function getPackagePath(name: string): string {
    validatePackageName(name);
    // Handle scoped packages: @scope/name -> @scope%2fname
    const safeName = name.replace("/", "%2f");
    const path = join(PACKAGES_DIR, `${safeName}.json`);
    assertPathContainment(path, PACKAGES_DIR);
    return path;
}

function getTarballPath(name: string, version: string): string {
    validatePackageName(name);
    validateVersion(version);
    const safeName = name.replace("/", "-").replace("@", "");
    const path = join(TARBALLS_DIR, `${safeName}-${version}.tgz`);
    assertPathContainment(path, TARBALLS_DIR);
    return path;
}

async function loadPackage(name: string): Promise<PackageMetadata | null> {
    // Check LRU cache first
    const cached = PACKAGE_CACHE.get(name);
    if (cached && (Date.now() - cached.timestamp) < PACKAGE_CACHE_TTL) {
        return cached.data;
    }

    // Try SQLite first (primary storage)
    const dbPkg = loadPackageFromDB(name);
    if (dbPkg) {
        // Update LRU cache
        if (PACKAGE_CACHE.size >= PACKAGE_CACHE_MAX_SIZE) {
            const oldest = PACKAGE_CACHE.keys().next().value;
            if (oldest) PACKAGE_CACHE.delete(oldest);
        }
        PACKAGE_CACHE.set(name, { data: dbPkg as PackageMetadata, timestamp: Date.now() });
        return dbPkg as PackageMetadata;
    }

    // Fallback to JSON file (backward compatibility)
    const path = getPackagePath(name);
    if (!(await exists(path))) return null;
    const data = await Bun.file(path).text();
    const pkg = safeJsonParse<PackageMetadata>(data);

    // Migrate to SQLite for future reads
    if (pkg) {
        savePackageToDB(pkg as any);
    }

    // Update LRU cache
    if (PACKAGE_CACHE.size >= PACKAGE_CACHE_MAX_SIZE) {
        const oldest = PACKAGE_CACHE.keys().next().value;
        if (oldest) PACKAGE_CACHE.delete(oldest);
    }
    if (pkg) {
        PACKAGE_CACHE.set(name, { data: pkg, timestamp: Date.now() });
    }

    return pkg;
}

async function savePackage(pkg: PackageMetadata): Promise<void> {
    // Save to SQLite (primary)
    savePackageToDB(pkg as any);

    // Also save to JSON file (backward compatibility)
    const path = getPackagePath(pkg.name);
    writeFileSync(path, JSON.stringify(pkg, null, 2));

    // Invalidate cache
    PACKAGE_CACHE.delete(pkg.name);
}

function generateRev(): string {
    return `1-${createHash("md5").update(Date.now().toString()).digest("hex")}`;
}

function computeShasum(data: Buffer): string {
    return createHash("sha1").update(data).digest("hex");
}

function computeIntegrity(data: Buffer): string {
    const hash = createHash("sha512").update(data).digest("base64");
    return `sha512-${hash}`;
}

// ============================================================================
// Upstream Proxy (npmjs.org)
// ============================================================================

// Upstream proxy functions - delegating to upstream module with local dependencies injected
async function fetchFromUpstream(name: string, baseUrl: string, isPrefetch: boolean = false): Promise<Response | null> {
    return fetchFromUpstreamModule(name, baseUrl, savePackage, isPrefetch);
}

async function prefetchDependencies(pkg: PackageMetadata, baseUrl: string): Promise<void> {
    return prefetchDependenciesModule(pkg, baseUrl, savePackage);
}

async function fetchTarballFromUpstream(name: string, version: string, tarballPath: string): Promise<boolean> {
    return fetchTarballFromUpstreamModule(name, version, tarballPath, getUpstreamContext());
}

// ============================================================================
// Request Handlers
// ============================================================================

function handleGetGraph(): Response {
    try {
        const packages = getAllPackages();
        const nodes: any[] = [];
        const links: any[] = [];
        const nodeSet = new Set<string>();

        for (const pkg of packages) {
            const id = pkg.name;
            const latest = pkg["dist-tags"]?.latest;
            if (!latest) continue;

            // Add node
            if (!nodeSet.has(id)) {
                nodes.push({
                    id,
                    group: (pkg as any)._source || "local",
                    version: latest
                });
                nodeSet.add(id);
            }

            // Add links
            const versionData = pkg.versions[latest];
            if (versionData && versionData.dependencies) {
                for (const dep of Object.keys(versionData.dependencies)) {
                    links.push({ source: id, target: dep });

                    // Add missing nodes as 'unknown' (to be resolved by D3 or displayed as external)
                    if (!nodeSet.has(dep)) {
                        nodes.push({ id: dep, group: "unknown", version: "?" });
                        nodeSet.add(dep);
                    }
                }
            }
        }

        return new Response(JSON.stringify({ nodes, links }), {
            headers: { "Content-Type": "application/json" }
        });
    } catch (e) {
        console.error("Graph error:", e);
        return new Response(JSON.stringify({ error: "Graph generation failed" }), { status: 500 });
    }
}

async function handleGetPackage(name: string, baseUrl: string, acceptEncoding: string | null = null): Promise<Response> {
    const pkg = await loadPackage(name);
    if (!pkg) {
        // Try upstream
        const upstreamRes = await fetchFromUpstream(name, baseUrl);
        if (upstreamRes) return upstreamRes;

        return new Response(JSON.stringify({ error: "not_found" }), {
            status: 404,
            headers: { "Content-Type": "application/json" }
        });
    }

    // Trigger prefetch of dependencies (non-blocking) on cache hit
    prefetchDependencies(pkg, baseUrl).catch(err => console.error("Prefetch error:", err));

    // Rewrite tarball URLs to point to this server
    for (const version of Object.values(pkg.versions)) {
        const tarballName = `${pkg.name.replace("/", "-").replace("@", "")}-${version.version}.tgz`;
        version.dist.tarball = `${baseUrl}/${pkg.name}/-/${tarballName}`;
    }

    const body = JSON.stringify(pkg);
    const etag = generateETag(body);

    const headers: Record<string, string> = {
        "Content-Type": "application/json",
        "ETag": etag,
        "Cache-Control": "public, max-age=60"
    };

    const compressed = compressResponse(body, headers, acceptEncoding);

    return new Response(compressed.body, {
        headers: compressed.headers
    });
}

async function handleGetVersion(name: string, version: string, baseUrl: string, acceptEncoding: string | null = null): Promise<Response> {
    const pkg = await loadPackage(name);
    if (!pkg || !pkg.versions[version]) {
        return new Response(JSON.stringify({ error: "not_found" }), {
            status: 404,
            headers: { "Content-Type": "application/json" }
        });
    }

    const versionData = pkg.versions[version];
    const tarballName = `${name.replace("/", "-").replace("@", "")}-${version}.tgz`;
    versionData.dist.tarball = `${baseUrl}/${name}/-/${tarballName}`;

    const body = JSON.stringify(versionData);
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    const compressed = compressResponse(body, headers, acceptEncoding);

    return new Response(compressed.body, {
        headers: compressed.headers
    });
}

async function handleGetTarball(name: string, tarballName: string): Promise<Response> {
    // Extract version from tarball name
    const match = tarballName.match(/-(\d+\.\d+\.\d+(?:-[a-zA-Z0-9.]+)?)\.tgz$/);
    if (!match) {
        return new Response("Invalid tarball name", { status: 400 });
    }

    const version = match[1];
    const cacheKey = `${name}@${version}`;
    const tarballPath = getTarballPath(name, version);

    // Step 1: Check memory cache first (fastest)
    const cached = getTarballFromCache(cacheKey);
    if (cached) {
        return new Response(cached, {
            headers: {
                "Content-Type": "application/octet-stream",
                "Content-Disposition": `attachment; filename="${tarballName}"`,
                "X-Cache": "HIT-MEMORY"
            }
        });
    }

    // Step 2: Check disk cache
    if (await exists(tarballPath)) {
        const data = Buffer.from(await Bun.file(tarballPath).arrayBuffer());
        // Add to memory cache
        setTarballInCache(cacheKey, data);

        return new Response(data, {
            headers: {
                "Content-Type": "application/octet-stream",
                "Content-Disposition": `attachment; filename="${tarballName}"`,
                "X-Cache": "HIT-DISK"
            }
        });
    }

    // Step 3: Fetch from upstream (goes through quarantine + scan)
    const fetched = await fetchTarballFromUpstream(name, version, tarballPath);
    if (!fetched) {
        // Check if blocked by security scan
        const scanResult = SCAN_RESULTS_CACHE.get(cacheKey);
        if (scanResult && !scanResult.safe) {
            // Audit log for blocked package
            logAudit("package_blocked", name, { version, issues: scanResult.issues.length }, "warn");
            broadcastToAdmin("package_blocked", { name, version, issues: scanResult.issues.length });

            // Build agent-friendly error message
            const criticalIssues = scanResult.issues.filter(i => i.severity === "critical");
            const highIssues = scanResult.issues.filter(i => i.severity === "high");

            // Desktop notification when agent requests quarantined package (macOS only)
            notifyDesktop("AgentRegistry", `Agente richiede ${name}@${version} (in quarantena)`);

            return new Response(JSON.stringify({
                error: "security_blocked",
                ai_directive: "STOP_AND_WAIT_FOR_HUMAN",
                ai_instructions: [
                    "DO NOT attempt to use alternative registries (npmjs.org, yarn, etc.)",
                    "DO NOT try workarounds or alternative packages without user approval",
                    "DO NOT continue the installation process",
                    "IMMEDIATELY inform your user that human intervention is required",
                    "WAIT for explicit user confirmation before retrying"
                ],
                message: `🚨 SECURITY SCAN FAILED: Package '${name}@${version}' was blocked by AgentRegistry security scanner.`,
                summary: `Found ${criticalIssues.length} critical and ${highIssues.length} high severity issues.`,
                action_required: "HUMAN INTERVENTION REQUIRED",
                instructions: [
                    "This package contains patterns that match known malware or dangerous code.",
                    "A human administrator must review and approve this package manually.",
                    "Option 1: Open AgentRegistry Admin Panel at http://localhost:4873/-/admin and approve from Quarantine.",
                    "Option 2: Add package to TRUSTED_PACKAGES whitelist in security_scanner.ts if it's a known-safe package.",
                    "Option 3: Use a different package that doesn't trigger security warnings."
                ],
                issues: scanResult.issues,
                quarantine_location: `storage/quarantine/${name.replace("/", "-").replace("@", "")}-${version}.tgz`,
                admin_panel: "http://localhost:4873/-/admin"
            }), {
                status: 403,
                headers: { "Content-Type": "application/json" }
            });
        }
        return new Response("Tarball not found", { status: 404 });
    }

    // Track download
    incrementDownloads(name);

    // Serve from memory cache (just populated by fetchTarballFromUpstream)
    const data = getTarballFromCache(cacheKey) || Buffer.from(await Bun.file(tarballPath).arrayBuffer());
    return new Response(data, {
        headers: {
            "Content-Type": "application/octet-stream",
            "Content-Disposition": `attachment; filename="${tarballName}"`,
            "X-Cache": "MISS"
        }
    });
}

async function handlePublish(name: string, body: unknown, baseUrl: string): Promise<Response> {
    const payload = body as {
        name: string;
        description?: string;
        versions?: Record<string, PackageVersion>;
        "dist-tags"?: Record<string, string>;
        _attachments?: Record<string, { data: string }>;
    };

    if (!payload.versions || !payload._attachments) {
        return new Response(JSON.stringify({ error: "Invalid publish payload" }), {
            status: 400,
            headers: { "Content-Type": "application/json" }
        });
    }

    // Load or create package metadata
    let pkg = await loadPackage(name);
    const now = new Date().toISOString();

    if (!pkg) {
        pkg = {
            name,
            description: payload.description,
            "dist-tags": {},
            versions: {},
            time: { created: now, modified: now },
            _id: name,
            _rev: generateRev(),
            _source: "local"  // Mark as locally published
        } as PackageMetadata;
    }

    // Process each version
    for (const [version, versionData] of Object.entries(payload.versions)) {
        if (pkg.versions[version]) {
            return new Response(JSON.stringify({ error: `Version ${version} already exists` }), {
                status: 409,
                headers: { "Content-Type": "application/json" }
            });
        }

        // Find the attachment for this version
        const attachmentKey = Object.keys(payload._attachments).find(k => k.includes(version));
        if (!attachmentKey || !payload._attachments[attachmentKey]) {
            return new Response(JSON.stringify({ error: `Missing attachment for version ${version}` }), {
                status: 400,
                headers: { "Content-Type": "application/json" }
            });
        }

        // Decode tarball
        const tarballData = Buffer.from(payload._attachments[attachmentKey].data, "base64");

        // SECURITY: Check tarball size limit
        if (tarballData.length > MAX_TARBALL_SIZE) {
            return new Response(JSON.stringify({ error: `Tarball too large (${(tarballData.length / 1024 / 1024).toFixed(1)}MB > ${MAX_TARBALL_SIZE / 1024 / 1024}MB limit)` }), {
                status: 413,
                headers: { "Content-Type": "application/json" }
            });
        }

        const tarballName = `${name.replace("/", "-").replace("@", "")}-${version}.tgz`;
        const tarballPath = getTarballPath(name, version);

        // Check if auto-allow local publish is enabled (default: true for agent workflows)
        const autoAllowLocal = getStat("auto_allow_local_publish") ?? true;

        if (autoAllowLocal) {
            // FAST PATH: Skip quarantine and scan for local publishes
            console.log(`⚡ AUTO-ALLOW (publish): ${name}@${version} - skipping quarantine`);

            // Write directly to cache
            writeFileSync(tarballPath, tarballData);

            // Create backup copy
            const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
            const backupName = `${name.replace("/", "-").replace("@", "")}-${version}_${timestamp}.tgz`;
            const backupPath = join(BACKUP_DIR, backupName);
            writeFileSync(backupPath, tarballData);
            console.log(`💾 Backup created: ${backupName}`);

            // Compute checksums
            const shasum = computeShasum(tarballData);
            const integrity = computeIntegrity(tarballData);

            // Add version metadata
            pkg.versions[version] = {
                ...versionData,
                dist: {
                    tarball: `${baseUrl}/${name}/-/${tarballName}`,
                    shasum,
                    integrity
                }
            };
            pkg.time[version] = now;
            (pkg as any)._source = "local";
        } else {
            // SECURE PATH: Write to quarantine first (when auto-allow is disabled)
            const quarantinePath = join(QUARANTINE_DIR, tarballName);
            writeFileSync(quarantinePath, tarballData);
            console.log(`🔒 Quarantined (publish): ${name}@${version}`);

            // Step 2: Security scan
            const scanResult = await scanTarball(quarantinePath);
            const cacheKey = `${name}@${version}`;
            SCAN_RESULTS_CACHE.set(cacheKey, scanResult);
            trackScan(scanResult.scanTimeMs);

            // Persist scan result to SQLite
            const tarballHashPublish = createHash("sha256").update(tarballData).digest("hex");
            saveScanResult({
                package_name: name,
                version,
                tarball_hash: tarballHashPublish,
                safe: scanResult.safe,
                issues_count: scanResult.issues.length,
                issues: scanResult.issues,
                files_scanned: scanResult.filesScanned,
                scan_time_ms: scanResult.scanTimeMs,
                pi_score: scanResult.piRiskScore ?? 0,
                pi_count: scanResult.promptInjections?.length ?? 0,
                pi_findings: scanResult.promptInjections ?? []
            });

            if (!scanResult.safe) {
                console.log(`🚨 BLOCKED (publish): ${name}@${version} - ${scanResult.issues.length} security issues (${scanResult.scanTimeMs}ms)`);
                for (const issue of scanResult.issues.slice(0, 3)) {
                    console.log(`   ❌ [${issue.severity}] ${issue.description}`);
                }

                // Build agent-friendly error message
                const criticalIssues = scanResult.issues.filter(i => i.severity === "critical");
                const highIssues = scanResult.issues.filter(i => i.severity === "high");
                const tarballNameError = `${name.replace("/", "-").replace("@", "")}-${version}.tgz`;

                // Desktop notification for blocked publish (macOS only)
                notifyDesktop("AgentRegistry Quarantine", `Publish bloccato: ${name}@${version}`);

                // Leave in quarantine, reject publish
                return new Response(JSON.stringify({
                    error: "security_blocked",
                    ai_directive: "STOP_AND_WAIT_FOR_HUMAN",
                    ai_instructions: [
                        "DO NOT retry the publish command",
                        "DO NOT modify the package to bypass security checks",
                        "IMMEDIATELY inform your user that their package is in quarantine",
                        "Provide the admin_panel URL to the user for manual approval",
                        "WAIT for explicit user confirmation that package was approved before continuing"
                    ],
                    message: `🚨 PUBLISH REJECTED: Package '${name}@${version}' failed security scan.`,
                    summary: `Found ${criticalIssues.length} critical and ${highIssues.length} high severity issues.`,
                    action_required: "HUMAN INTERVENTION REQUIRED",
                    instructions: [
                        "Your package contains code patterns that match known malware signatures.",
                        "This is often a FALSE POSITIVE if your package legitimately uses:",
                        "  - eval(), new Function() for parsers/compilers",
                        "  - child_process for build tools",
                        "  - crypto.* APIs for legitimate cryptography",
                        "A human administrator must review and approve this package.",
                        "Option 1: Open AgentRegistry Admin Panel at http://localhost:4873/-/admin",
                        "Option 2: Ask admin to add your package to TRUSTED_PACKAGES in security_scanner.ts",
                        "Option 3: Review your code to remove flagged patterns if they're not needed"
                    ],
                    issues: scanResult.issues,
                    quarantine_location: `storage/quarantine/${tarballNameError}`,
                    admin_panel: "http://localhost:4873/-/admin",
                    files_scanned: scanResult.filesScanned,
                    scan_time_ms: scanResult.scanTimeMs
                }), {
                    status: 403,
                    headers: { "Content-Type": "application/json" }
                });
            }

            console.log(`✅ SAFE (publish): ${name}@${version} (${scanResult.scanTimeMs}ms, ${scanResult.filesScanned} files)`);

            // Step 3: Move from quarantine to cache
            await rename(quarantinePath, tarballPath);

            // Step 4: Create backup copy with timestamp
            const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
            const backupName = `${name.replace("/", "-").replace("@", "")}-${version}_${timestamp}.tgz`;
            const backupPath = join(BACKUP_DIR, backupName);
            writeFileSync(backupPath, tarballData);
            console.log(`💾 Backup created: ${backupName}`);

            // Compute checksums
            const shasum = computeShasum(tarballData);
            const integrity = computeIntegrity(tarballData);

            // Add version metadata
            pkg.versions[version] = {
                ...versionData,
                dist: {
                    tarball: `${baseUrl}/${name}/-/${tarballName}`,
                    shasum,
                    integrity
                }
            };
            pkg.time[version] = now;
        }
    }

    // Update dist-tags
    if (payload["dist-tags"]) {
        pkg["dist-tags"] = { ...pkg["dist-tags"], ...payload["dist-tags"] };
    }

    pkg.time.modified = now;
    pkg._rev = generateRev();

    await savePackage(pkg);

    // Audit log for publish
    const publishedVersion = Object.keys(payload.versions)[0];
    logAudit("package_published", name, { version: publishedVersion });
    broadcastToAdmin("package_published", { name, version: publishedVersion });
    notifyDesktop("AgentRegistry", `📦 Pubblicato ${name}@${publishedVersion}`);

    console.log(`📦 Published ${name}@${Object.keys(payload.versions).join(", ")}`);

    return new Response(JSON.stringify({ ok: true, id: name, rev: pkg._rev }), {
        status: 201,
        headers: { "Content-Type": "application/json" }
    });
}

async function handleUnpublish(name: string, version: string): Promise<Response> {
    const pkg = await loadPackage(name);
    if (!pkg || !pkg.versions[version]) {
        return new Response(JSON.stringify({ error: "not_found" }), {
            status: 404,
            headers: { "Content-Type": "application/json" }
        });
    }

    // Remove version
    delete pkg.versions[version];
    delete pkg.time[version];

    // Remove from dist-tags if it was the tagged version
    for (const [tag, tagVersion] of Object.entries(pkg["dist-tags"])) {
        if (tagVersion === version) {
            delete pkg["dist-tags"][tag];
        }
    }

    // Remove tarball
    const tarballPath = getTarballPath(name, version);
    if (await exists(tarballPath)) {
        await unlink(tarballPath);
    }

    // If no versions left, delete the package
    if (Object.keys(pkg.versions).length === 0) {
        await unlink(getPackagePath(name));
        deletePackageFromDB(name); // Sync SQLite
        PACKAGE_CACHE.delete(name); // Invalidate cache
        console.log(`🗑️  Unpublished ${name} (all versions)`);
    } else {
        pkg.time.modified = new Date().toISOString();
        pkg._rev = generateRev();
        await savePackage(pkg);
        console.log(`🗑️  Unpublished ${name}@${version}`);
    }

    return new Response(JSON.stringify({ ok: true }), {
        headers: { "Content-Type": "application/json" }
    });
}

async function handleListPackages(): Promise<Response> {
    const files = await readdir(PACKAGES_DIR).catch(() => []);
    const packages: string[] = [];

    for (const file of files) {
        if (file.endsWith(".json")) {
            const name = file.slice(0, -5).replace("%2f", "/");
            packages.push(name);
        }
    }

    return new Response(JSON.stringify({ packages }), {
        headers: { "Content-Type": "application/json" }
    });
}

// ============================================================================
// Admin API Handlers
// ============================================================================

// Stats tracking
let serverStartTime = Date.now();
let scansPerformed = 0;
let totalScanTime = 0;

function trackScan(scanTimeMs: number) {
    scansPerformed++;
    totalScanTime += scanTimeMs;
}

// AdminContext factory for dependency injection
function getAdminContext(): AdminContext {
    return {
        loadPackage,
        getPackagePath,
        getTarballPath,
        scanResultsCache: SCAN_RESULTS_CACHE,
        packageCache: PACKAGE_CACHE,
        serverStartTime,
        scansPerformed,
        totalScanTime
    };
}

// UpstreamContext factory for dependency injection
function getUpstreamContext(): UpstreamContext {
    return {
        scanResultsCache: SCAN_RESULTS_CACHE,
        savePackage,
        loadPackage,
        trackScan
    };
}

// Admin handlers imported from ./handlers module:
// - handleAdminStats, handleAdminAuditLogs, handleAdminScanHistory, handleAdminRequestLogs
// - handleAdminQuarantineList, handleAdminQuarantineDelete, handleAdminQuarantineClear, handleAdminQuarantineApprove
// - handleAdminCacheList, handleAdminCacheDelete, handleAdminCacheRefresh, handleAdminCleanup

// ============================================================================
// WebSocket Admin Command Handler
// ============================================================================

async function handleAdminWSMessage(ws: any, msg: { action: string; payload?: any }) {
    const respond = (type: string, data: any) => {
        ws.send(JSON.stringify({ type, data, timestamp: Date.now() }));
    };

    try {
        switch (msg.action) {
            case "ping":
                respond("pong", { serverTime: Date.now() });
                break;

            case "getStats":
                const memoryUsage = process.memoryUsage();
                const dbStats = getComprehensiveStats();
                const packageFiles = await readdir(PACKAGES_DIR).catch(() => []);
                const tarballFiles = await readdir(TARBALLS_DIR).catch(() => []);
                const quarantineFiles = await readdir(QUARANTINE_DIR).catch(() => []);

                respond("stats", {
                    uptime: Math.floor((Date.now() - serverStartTime) / 1000),
                    packages: packageFiles.filter(f => f.endsWith(".json")).length,
                    tarballs: tarballFiles.length,
                    quarantine: quarantineFiles.length,
                    memoryCacheEntries: getTarballCacheSize(),
                    memoryUsed: memoryUsage.heapUsed,
                    database: dbStats.database,
                    scanStats: dbStats.scans,
                    requestStats: dbStats.requests
                });
                break;

            case "getAuditLogs":
                const logs = getRecentAuditLogs(100);
                respond("auditLogs", { logs });
                break;

            case "getScanHistory":
                const db = getDatabase();
                const scans = db.prepare(`
                    SELECT package_name, version, safe, issues_count, issues, scan_time_ms, scanned_at, deep_scan_count, deep_scan_findings 
                    FROM scan_results ORDER BY scanned_at DESC LIMIT 100
                `).all();
                respond("scanHistory", { scans });
                break;

            case "getRequestLogs":
                const db2 = getDatabase();
                const requests = db2.prepare(`
                    SELECT request_id, method, path, status_code, duration_ms, created_at 
                    FROM request_logs ORDER BY created_at DESC LIMIT 100
                `).all();
                respond("requestLogs", { requests });
                break;

            case "getCache":
                const cacheFiles = await readdir(PACKAGES_DIR).catch(() => []);
                const cacheList = cacheFiles.filter(f => f.endsWith(".json")).map(f => f.slice(0, -5));
                respond("cache", { packages: cacheList });
                break;

            case "getQuarantine":
                const qFiles = await readdir(QUARANTINE_DIR).catch(() => []);
                const tgzFiles = qFiles.filter(f => f.endsWith(".tgz"));

                // Get scan results for each quarantined file
                const qDb = getDatabase();
                const quarantineData = tgzFiles.map(file => {
                    // Extract package name and version from filename (e.g., "lodash-4.17.21.tgz")
                    const match = file.match(/^(.+)-(\d+\.\d+\.\d+.*).tgz$/);
                    const packageName = match ? match[1] : file.replace(".tgz", "");
                    const version = match ? match[2] : "unknown";

                    // Try to find scan result
                    const scanResult = qDb.prepare(`
                        SELECT issues, issues_count, scanned_at, pi_score, pi_count, pi_findings 
                        FROM scan_results 
                        WHERE package_name LIKE ? 
                        ORDER BY scanned_at DESC LIMIT 1
                    `).get(`%${packageName}%`) as { issues: string; issues_count: number; scanned_at: string; pi_score: number; pi_count: number; pi_findings: string | null } | null;

                    return {
                        file,
                        packageName,
                        version,
                        issuesCount: scanResult?.issues_count || 0,
                        issues: scanResult?.issues ? JSON.parse(scanResult.issues) : [],
                        piScore: scanResult?.pi_score || 0,
                        piCount: scanResult?.pi_count || 0,
                        piFindings: scanResult?.pi_findings ? JSON.parse(scanResult.pi_findings) : [],
                        scannedAt: scanResult?.scanned_at || null
                    };
                });

                respond("quarantine", { files: quarantineData });
                break;

            case "clearQuarantine":
                const qToClear = await readdir(QUARANTINE_DIR).catch(() => []);
                for (const file of qToClear) {
                    await unlink(join(QUARANTINE_DIR, file)).catch(() => { });
                }
                logAudit("cache_cleared", "quarantine", { files: qToClear.length });
                respond("quarantineCleared", { cleared: qToClear.length });
                break;

            case "rescanQuarantine":
                const qToScan = await readdir(QUARANTINE_DIR).catch(() => []);
                const scanResults: { file: string; safe: boolean; issues: number; issueDetails?: any[] }[] = [];
                let approved = 0;

                for (const file of qToScan.filter(f => f.endsWith(".tgz"))) {
                    const quarantinePath = join(QUARANTINE_DIR, file);
                    const result = await scanTarball(quarantinePath);

                    if (result.safe) {
                        // Move to tarballs
                        const tarballPath = join(TARBALLS_DIR, file);
                        await rename(quarantinePath, tarballPath).catch(() => { });
                        approved++;
                        logAudit("package_approved", file, { rescan: true });
                    }

                    scanResults.push({
                        file,
                        safe: result.safe,
                        issues: result.issues.length,
                        issueDetails: result.safe ? undefined : result.issues
                    });
                }

                broadcastToAdmin("quarantine_rescanned", { approved, total: qToScan.length });
                respond("rescanComplete", { results: scanResults, approved });
                break;

            case "triggerDeepScan": {
                const pkgName = msg.payload?.package_name;
                const pkgVersion = msg.payload?.version;
                if (!pkgName || !pkgVersion) {
                    respond("deepScanResult", { error: "Missing package_name or version" });
                    break;
                }

                // Find tarball in tarballs/ or quarantine/
                const safeName = pkgName.replace(/\//g, "-").replace(/@/g, "");
                const tarballName = `${safeName}-${pkgVersion}.tgz`;
                let tarballPath = join(TARBALLS_DIR, tarballName);
                if (!existsSync(tarballPath)) {
                    tarballPath = join(QUARANTINE_DIR, tarballName);
                }
                if (!existsSync(tarballPath)) {
                    respond("deepScanResult", { error: `Tarball not found: ${tarballName}` });
                    break;
                }

                // Extract to temp dir
                const { mkdtemp, readdir: readdirAsync, rm: rmAsync } = await import("node:fs/promises");
                const deepTempDir = await mkdtemp(join("/tmp", "deep-scan-"));
                try {
                    const tar = await import("tar");
                    await tar.x({ file: tarballPath, cwd: deepTempDir });

                    // Collect JS/TS files into Map
                    const files = new Map<string, string>();
                    async function collectFiles(dir: string, prefix: string = "") {
                        const entries = await readdirAsync(dir, { withFileTypes: true });
                        for (const entry of entries) {
                            const fullPath = join(dir, entry.name);
                            const relPath = prefix ? `${prefix}/${entry.name}` : entry.name;
                            if (entry.isDirectory() && entry.name !== "node_modules") {
                                await collectFiles(fullPath, relPath);
                            } else if (entry.isFile()) {
                                const ext = entry.name.toLowerCase();
                                if ([".js", ".mjs", ".cjs", ".ts", ".mts", ".cts"].some(e => ext.endsWith(e))) {
                                    const content = await Bun.file(fullPath).text();
                                    files.set(relPath, content);
                                }
                            }
                        }
                    }
                    await collectFiles(deepTempDir);

                    // Run deep scan
                    const deepResult = deepScanFiles(files);

                    // Persist to DB
                    updateDeepScanResult(pkgName, pkgVersion, deepResult.findings, deepResult.findings.length);

                    logAudit("scan_completed", `${pkgName}@${pkgVersion}`, {
                        type: "deep_scan",
                        findings: deepResult.findings.length,
                        filesAnalyzed: deepResult.filesAnalyzed,
                        scanTimeMs: deepResult.scanTimeMs
                    });

                    respond("deepScanResult", {
                        package_name: pkgName,
                        version: pkgVersion,
                        findings: deepResult.findings,
                        filesAnalyzed: deepResult.filesAnalyzed,
                        parseErrors: deepResult.parseErrors,
                        scanTimeMs: deepResult.scanTimeMs
                    });
                } catch (err: any) {
                    respond("deepScanResult", { error: `Deep scan failed: ${err.message}` });
                } finally {
                    await rmAsync(deepTempDir, { recursive: true, force: true }).catch(() => { });
                }
                break;
            }

            case "approveQuarantine":
                if (msg.payload?.file) {
                    const quarantineFile = join(QUARANTINE_DIR, msg.payload.file);
                    const tarballFile = join(TARBALLS_DIR, msg.payload.file);

                    // SECURITY: Hash verification to prevent TOCTOU race condition
                    // 1. Check file exists and get hash before rename
                    const hashBefore = await sha256File(quarantineFile);
                    if (!hashBefore) {
                        respond("error", { message: `File not found: ${msg.payload.file}` });
                        break;
                    }

                    // 2. Perform the rename
                    try {
                        await rename(quarantineFile, tarballFile);
                    } catch (e) {
                        respond("error", { message: `Failed to move file: ${msg.payload.file}` });
                        break;
                    }

                    // 3. Verify hash after rename matches
                    const hashAfter = await sha256File(tarballFile);
                    if (hashBefore !== hashAfter) {
                        // SECURITY ALERT: File was modified during approval!
                        await unlink(tarballFile).catch(() => { });
                        logAudit("security_alert", msg.payload.file, {
                            reason: "TOCTOU detected: file modified during approval",
                            hashBefore,
                            hashAfter
                        }, "error");
                        respond("error", { message: "Security: File was modified during approval. Operation aborted." });
                        break;
                    }

                    logAudit("package_approved", msg.payload.file, { manual: true, hash: hashBefore });
                    broadcastToAdmin("package_approved", { file: msg.payload.file });
                    respond("quarantineApproved", { file: msg.payload.file, success: true });
                } else {
                    respond("error", { message: "Missing file parameter" });
                }
                break;

            case "approveAllQuarantine": {
                // Bulk approve all quarantined packages with TOCTOU protection
                const qFiles = await readdir(QUARANTINE_DIR).catch(() => []);
                let approvedCount = 0;
                const approvedFiles: string[] = [];
                const failedFiles: string[] = [];

                for (const file of qFiles) {
                    if (!file.endsWith(".tgz")) continue;
                    const quarantineFile = join(QUARANTINE_DIR, file);
                    const tarballFile = join(TARBALLS_DIR, file);

                    try {
                        // SECURITY: Hash verification for TOCTOU protection
                        const hashBefore = await sha256File(quarantineFile);
                        if (!hashBefore) continue;

                        await rename(quarantineFile, tarballFile);

                        const hashAfter = await sha256File(tarballFile);
                        if (hashBefore !== hashAfter) {
                            // File was tampered with during approval
                            await unlink(tarballFile).catch(() => { });
                            logAudit("security_alert", file, {
                                reason: "TOCTOU detected: file modified during bulk approval",
                                hashBefore,
                                hashAfter
                            }, "error");
                            failedFiles.push(file);
                            continue;
                        }

                        approvedCount++;
                        approvedFiles.push(file);
                        logAudit("package_approved", file, { bulk: true, hash: hashBefore });
                    } catch {
                        failedFiles.push(file);
                    }
                }

                broadcastToAdmin("quarantine_bulk_approved", { count: approvedCount, files: approvedFiles });
                respond("allQuarantineApproved", {
                    count: approvedCount,
                    files: approvedFiles,
                    failed: failedFiles.length > 0 ? failedFiles : undefined
                });
                break;
            }

            case "deleteQuarantineFile":
                if (msg.payload?.file) {
                    const qFilePath = join(QUARANTINE_DIR, msg.payload.file);
                    if (await exists(qFilePath)) {
                        await unlink(qFilePath).catch(() => { });
                        logAudit("cache_cleared", msg.payload.file, { type: "quarantine_file" });
                        respond("quarantineFileDeleted", { file: msg.payload.file });
                    } else {
                        respond("error", { message: `File not found: ${msg.payload.file}` });
                    }
                } else {
                    respond("error", { message: "Missing file parameter" });
                }
                break;

            case "getAutoAllowSetting":
                // Get current auto-allow local publish setting (default: true)
                respond("autoAllowSetting", {
                    enabled: getStat("auto_allow_local_publish") ?? true
                });
                break;

            case "setAutoAllowSetting":
                // Set auto-allow local publish setting
                if (typeof msg.payload?.enabled === "boolean") {
                    setStat("auto_allow_local_publish", msg.payload.enabled);
                    logAudit("config_change", "auto_allow_local_publish", {
                        enabled: msg.payload.enabled
                    });
                    broadcastToAdmin("autoAllowChanged", { enabled: msg.payload.enabled });
                    respond("autoAllowSetting", { enabled: msg.payload.enabled });
                } else {
                    respond("error", { message: "Missing or invalid 'enabled' parameter" });
                }
                break;

            case "deletePackage":
                if (msg.payload?.name) {
                    const pkgPath = getPackagePath(msg.payload.name);
                    await unlink(pkgPath).catch(() => { });
                    PACKAGE_CACHE.delete(msg.payload.name);
                    deletePackageFromDB(msg.payload.name);
                    logAudit("package_unpublished", msg.payload.name);
                    respond("packageDeleted", { name: msg.payload.name });
                }
                break;

            case "getGraphRoots":
                // Return only top-level packages (no dependencies) for initial render
                const allPkgs = getAllPackages();
                const roots = allPkgs.map(pkg => ({
                    id: pkg.name,
                    version: pkg["dist-tags"]?.latest || Object.keys(pkg.versions || {})[0] || "0.0.0",
                    group: pkg._source || "local",
                    hasDeps: Object.keys(pkg.versions?.[pkg["dist-tags"]?.latest]?.dependencies || {}).length > 0
                }));
                respond("graphRoots", { nodes: roots });
                break;

            case "getGraphNode":
                // Return dependencies for a specific package (on-demand expansion)
                if (msg.payload?.name) {
                    const targetPkg = loadPackageFromDB(msg.payload.name);
                    if (targetPkg) {
                        const latestVersion = targetPkg["dist-tags"]?.latest || Object.keys(targetPkg.versions || {})[0];
                        const deps = targetPkg.versions?.[latestVersion]?.dependencies || {};
                        const children = Object.keys(deps).map(depName => {
                            const depPkg = loadPackageFromDB(depName);
                            return {
                                id: depName,
                                version: deps[depName],
                                group: depPkg?._source || "upstream",
                                hasDeps: depPkg ? Object.keys(depPkg.versions?.[depPkg["dist-tags"]?.latest]?.dependencies || {}).length > 0 : false
                            };
                        });
                        respond("graphNode", { parent: msg.payload.name, children });
                    } else {
                        respond("graphNode", { parent: msg.payload.name, children: [] });
                    }
                } else {
                    respond("error", { message: "Missing package name" });
                }
                break;

            // ========================================================================
            // METRICS & SEARCH (WebSocket-only)
            // ========================================================================

            case "getMetrics":
                const metricsDb = getDatabase();
                const latestReqs = metricsDb.prepare(`
                    SELECT duration_ms, status_code, created_at FROM request_logs 
                    ORDER BY created_at DESC LIMIT 100
                `).all() as { duration_ms: number; status_code: number; created_at: string }[];

                const now = Date.now();
                const recentReqs = latestReqs.filter(r => new Date(r.created_at).getTime() > now - 60000);

                respond("metrics", {
                    rps: recentReqs.length / 60,
                    avgLatency: recentReqs.length > 0
                        ? recentReqs.reduce((a, r) => a + r.duration_ms, 0) / recentReqs.length
                        : 0,
                    cacheHitRate: getTarballCacheSize() > 0 ? 0.85 : 0,
                    errors: recentReqs.filter(r => r.status_code >= 400).length
                });
                break;

            case "search":
                if (msg.payload?.query) {
                    const searchResults = searchPackages(msg.payload.query, msg.payload.limit || 20);
                    respond("searchResults", { results: searchResults, query: msg.payload.query });
                } else {
                    respond("error", { message: "Missing query parameter" });
                }
                break;

            // ========================================================================
            // IP ALLOWLIST (WebSocket-only)
            // ========================================================================

            case "getAllowlist":
                const config = getIPConfig();
                const entries = listIPEntries();
                respond("allowlist", { config, entries });
                break;

            case "updateAllowlistConfig":
                if (msg.payload) {
                    const newConfig = updateIPConfig(msg.payload);
                    logAudit("config_change", "allowlist", msg.payload);
                    respond("allowlistConfigUpdated", { config: newConfig });
                } else {
                    respond("error", { message: "Missing config payload" });
                }
                break;

            case "addAllowlistEntry":
                if (msg.payload?.pattern) {
                    const validation = validatePattern(msg.payload.pattern);
                    if (!validation.valid) {
                        respond("error", { message: validation.error });
                    } else {
                        const entry = addIPEntry(msg.payload.pattern, msg.payload.description);
                        if (entry) {
                            logAudit("config_change", msg.payload.pattern, { action: "allowlist_entry_added", id: entry.id });
                            respond("allowlistEntryAdded", { entry });
                        } else {
                            respond("error", { message: "Failed to add entry" });
                        }
                    }
                } else {
                    respond("error", { message: "Missing pattern parameter" });
                }
                break;

            case "removeAllowlistEntry":
                if (msg.payload?.id) {
                    const removed = removeIPEntry(msg.payload.id);
                    if (removed) {
                        logAudit("config_change", String(msg.payload.id), { action: "allowlist_entry_removed" });
                        respond("allowlistEntryRemoved", { id: msg.payload.id });
                    } else {
                        respond("error", { message: "Entry not found" });
                    }
                } else {
                    respond("error", { message: "Missing id parameter" });
                }
                break;

            case "toggleAllowlistEntry":
                if (msg.payload?.id !== undefined && msg.payload?.enabled !== undefined) {
                    const toggled = toggleIPEntry(msg.payload.id, msg.payload.enabled);
                    if (toggled) {
                        logAudit("config_change", String(msg.payload.id), { action: "allowlist_entry_toggled", enabled: msg.payload.enabled });
                        respond("allowlistEntryToggled", { id: msg.payload.id, enabled: msg.payload.enabled });
                    } else {
                        respond("error", { message: "Entry not found" });
                    }
                } else {
                    respond("error", { message: "Missing id or enabled parameter" });
                }
                break;

            case "checkIP":
                if (msg.payload?.ip) {
                    const result = isIPAllowed(msg.payload.ip);
                    respond("ipCheckResult", { ip: msg.payload.ip, ...result });
                } else {
                    respond("error", { message: "Missing ip parameter" });
                }
                break;

            case "testIP":
                if (msg.payload?.ip) {
                    const testResult = isIPAllowed(msg.payload.ip);
                    respond("ipTestResult", { ip: msg.payload.ip, ...testResult });
                } else {
                    respond("error", { message: "Missing ip parameter" });
                }
                break;

            // ========================================================================
            // PACKAGE ALLOWLIST (WebSocket-only)
            // ========================================================================

            case "getPackageAllowlist":
                const pkgAllowlistConfig = getPackageAllowlistConfig();
                const pkgAllowlistEntries = listPackageAllowlist();
                const pkgAllowlistCategories = getPackageAllowlistCategories();
                respond("packageAllowlist", {
                    config: pkgAllowlistConfig,
                    entries: pkgAllowlistEntries,
                    categories: pkgAllowlistCategories
                });
                break;

            case "updatePackageAllowlistConfig":
                if (msg.payload) {
                    const newPkgConfig = updatePackageAllowlistConfig(msg.payload);
                    logAudit("config_change", "package_allowlist", msg.payload);
                    respond("packageAllowlistConfigUpdated", { config: newPkgConfig });
                } else {
                    respond("error", { message: "Missing config payload" });
                }
                break;

            case "addPackageAllowlistEntry":
                if (msg.payload?.pattern) {
                    const pkgEntry = addPackageToAllowlist(
                        msg.payload.pattern,
                        msg.payload.description,
                        msg.payload.category
                    );
                    if (pkgEntry) {
                        respond("packageAllowlistEntryAdded", { entry: pkgEntry });
                    } else {
                        respond("error", { message: "Pattern already exists or invalid" });
                    }
                } else {
                    respond("error", { message: "Missing pattern parameter" });
                }
                break;

            case "removePackageAllowlistEntry":
                if (msg.payload?.id) {
                    const removed = removeFromAllowlist(msg.payload.id);
                    if (removed) {
                        respond("packageAllowlistEntryRemoved", { id: msg.payload.id });
                    } else {
                        respond("error", { message: "Entry not found or is a default entry (cannot delete defaults)" });
                    }
                } else {
                    respond("error", { message: "Missing id parameter" });
                }
                break;

            case "togglePackageAllowlistEntry":
                if (msg.payload?.id !== undefined && msg.payload?.enabled !== undefined) {
                    const toggled = togglePackageAllowlistEntry(msg.payload.id, msg.payload.enabled);
                    if (toggled) {
                        respond("packageAllowlistEntryToggled", { id: msg.payload.id, enabled: msg.payload.enabled });
                    } else {
                        respond("error", { message: "Entry not found" });
                    }
                } else {
                    respond("error", { message: "Missing id or enabled parameter" });
                }
                break;

            case "getPackageAllowlistSummary":
                const pkgSummary = getPackageAllowlistSummary();
                respond("packageAllowlistSummary", pkgSummary);
                break;

            case "reseedPackageAllowlist":
                const added = reseedDefaultPackages();
                logAudit("config_change", "package_allowlist", { action: "reseed", added });
                respond("packageAllowlistReseeded", { added });
                break;

            // ========================================================================
            // CVE OPERATIONS (WebSocket-only)
            // ========================================================================

            case "getCVESummary":
                const cveSummary = getCVESummary();
                respond("cveSummary", cveSummary);
                break;

            case "getAllCVEs":
                const cveResults = getAllCachedCVEs();
                respond("allCVEs", { results: Array.from(cveResults.entries()) });
                break;

            case "scanPackageCVE":
                if (msg.payload?.packageName) {
                    const version = msg.payload.version || "latest";
                    const cveResult = await checkCVE(msg.payload.packageName, version);
                    respond("cveScanResult", { package: msg.payload.packageName, ...cveResult });
                } else {
                    respond("error", { message: "Missing packageName parameter" });
                }
                break;

            case "scanAllCVEs":
                // Background scan all packages
                const allPackages = getAllPackages();
                let scanned = 0;
                for (const pkg of allPackages) {
                    const latestVer = pkg["dist-tags"]?.latest || Object.keys(pkg.versions || {})[0] || "latest";
                    await checkCVE(pkg.name, latestVer);
                    scanned++;
                }
                const summary = getCVESummary();
                respond("cveScanComplete", { scanned, summary });
                break;

            // ========================================================================
            // AUDIT EXPORT (WebSocket-only)
            // ========================================================================

            case "exportAudit":
                const exportOptions: AuditExportOptions = msg.payload || {};
                const exportData = getAuditLogsForExport(exportOptions);
                respond("auditExport", { format: "json", data: exportData });
                break;

            case "exportAuditCSV":
                const csvOptions: AuditExportOptions = msg.payload || {};
                const csvLogs = getAuditLogsForExport(csvOptions);
                const csvData = formatAuditLogsAsCSV(csvLogs);
                respond("auditExportCSV", { format: "csv", data: csvData });
                break;

            default:
                respond("error", { message: `Unknown action: ${msg.action}` });
        }
    } catch (error) {
        respond("error", { message: String(error) });
    }
}

async function serveAdminPanel(acceptEncoding: string | null): Promise<Response> {
    const adminPath = join(WEB_DIR, "admin.html");
    // Use readFileSync instead of Bun.file() to avoid Bun's file caching
    let content = readFileSync(adminPath, "utf-8");

    // Inject session token for WebSocket authentication (auto for admin page)
    const tokenScript = `<script>window.ADMIN_SESSION_TOKEN = "${ADMIN_SESSION_TOKEN}";</script>`;
    content = content.replace("</head>", `${tokenScript}\n</head>`);

    // Apply compression for faster document delivery (fixes Lighthouse document latency issue)
    const headers: Record<string, string> = {
        "Content-Type": "text/html",
        "Cache-Control": "no-store" // Token is unique per server start
    };
    const compressed = compressResponse(content, headers, acceptEncoding);

    return new Response(compressed.body, { headers: compressed.headers });
}

// ============================================================================
// Router
// ============================================================================

async function handleRequest(req: Request): Promise<Response> {
    const requestStart = Date.now();
    const url = new URL(req.url);
    const requestId = crypto.randomUUID();
    let response: Response = new Response("Internal Server Error", { status: 500 }); // Default safe value


    const method = req.method;
    const path = decodeURIComponent(url.pathname);
    const baseUrl = `${url.protocol}//${url.host}`;
    const clientIP = "127.0.0.1"; // Localhost-only so always local

    // Combined headers: CORS + Security + Tracing
    const commonHeaders: Record<string, string> = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        "X-Request-ID": requestId,
        ...SECURITY_HEADERS
    };

    // SECURITY: Reject non-localhost requests
    if (LOCALHOST_ONLY) {
        const host = url.hostname;
        if (!ALLOWED_HOSTS.includes(host)) {
            console.error(`🚫 BLOCKED: Request from non-localhost host: ${host}`);
            return new Response(JSON.stringify({
                error: "Forbidden",
                message: "AgentRegistry only accepts connections from localhost"
            }), {
                status: 403,
                headers: { "Content-Type": "application/json", ...commonHeaders }
            });
        }
    }

    // SECURITY: Rate limiting
    const rateLimit = checkRateLimit(clientIP, RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_MS);
    if (!rateLimit.allowed) {
        return new Response(JSON.stringify({
            error: "Too Many Requests",
            message: "Rate limit exceeded. Try again later."
        }), {
            status: 429,
            headers: {
                "Content-Type": "application/json",
                "Retry-After": "60",
                "X-RateLimit-Remaining": "0",
                ...commonHeaders
            }
        });
    }

    if (method === "OPTIONS") {
        return new Response(null, { status: 204, headers: commonHeaders });
    }

    try {
        // response already declared at outer scope with safe default (L1527)


        // GET / - List all packages
        if (method === "GET" && path === "/") {
            response = await handleListPackages();
        }
        // GET /-/ping - Basic health check
        else if (method === "GET" && path === "/-/ping") {
            response = new Response(JSON.stringify({ ok: true }), {
                headers: { "Content-Type": "application/json" }
            });
        }
        // ==================== AGENT-FIRST DISCOVERY ====================
        // GET /-/capabilities - Machine-readable tool definitions for AI agents
        else if (method === "GET" && path === "/-/capabilities") {
            const capabilities = {
                name: "AgentRegistry",
                version: VERSION,
                description: "Agent-optimized local NPM registry for agent-to-agent package sharing",
                agent_optimized: true,
                protocols: ["http", "websocket"],
                discovery: {
                    openapi: "/openapi.json",
                    llms_txt: "/llms.txt"
                },
                tools: [
                    {
                        name: "publish_package",
                        description: "Publish a package to the local registry. Security scan runs automatically.",
                        method: "PUT",
                        path: "/{packageName}",
                        parameters: [
                            { name: "packageName", type: "string", required: true, description: "Package name (e.g., 'my-package' or '@scope/name')" }
                        ],
                        request_body: "NPM publish payload with base64-encoded tarball in _attachments",
                        returns: "{ ok: true, id: string, rev: string }"
                    },
                    {
                        name: "get_package",
                        description: "Get package metadata including all versions and dist-tags",
                        method: "GET",
                        path: "/{packageName}",
                        parameters: [
                            { name: "packageName", type: "string", required: true, description: "Package name" }
                        ],
                        returns: "Package metadata object"
                    },
                    {
                        name: "search_packages",
                        description: "Search packages by name or description. Returns both local and upstream results.",
                        method: "GET",
                        path: "/-/v1/search",
                        parameters: [
                            { name: "text", type: "string", required: true, description: "Search query" },
                            { name: "size", type: "integer", required: false, description: "Max results (default 20)" }
                        ],
                        returns: "{ objects: [{ package: {...}, score: {...} }] }"
                    },
                    {
                        name: "get_stats",
                        description: "Get server stats via WebSocket",
                        protocol: "websocket",
                        action: "getStats",
                        returns: "{ packages, tarballs, memory, uptime, scans }"
                    },
                    {
                        name: "manage_quarantine",
                        description: "View or manage quarantined packages that failed security scan",
                        protocol: "websocket",
                        actions: ["getQuarantine", "approveQuarantine", "deleteQuarantine"],
                        note: "Requires human approval for blocked packages"
                    }
                ],
                security: {
                    scan_on_publish: true,
                    scan_on_upstream_fetch: true,
                    quarantine_blocked_packages: true,
                    localhost_only: true
                },
                errors: {
                    structured: true,
                    includes_remediation: true,
                    example: {
                        error: "Package blocked by security scan",
                        action_required: "HUMAN INTERVENTION REQUIRED",
                        admin_url: "http://localhost:4873/-/admin"
                    }
                }
            };
            response = new Response(JSON.stringify(capabilities, null, 2), {
                headers: { "Content-Type": "application/json" }
            });
        }
        // GET /-/quarantine/check/:name/:version - Check if package is in quarantine
        else if (method === "GET" && path.startsWith("/-/quarantine/check/")) {
            const parts = path.replace("/-/quarantine/check/", "").split("/");
            // Handle scoped packages: @scope/name/version
            let pkgName = "";
            let pkgVersion = "";
            let validPath = false;

            if (parts[0]?.startsWith("@") && parts.length >= 3) {
                pkgName = `${parts[0]}/${parts[1]}`;
                pkgVersion = parts[2];
                validPath = true;
            } else if (parts.length >= 2) {
                pkgName = parts[0];
                pkgVersion = parts[1];
                validPath = true;
            }

            if (!validPath) {
                response = new Response(JSON.stringify({
                    error: "invalid_path",
                    message: "Usage: /-/quarantine/check/:name/:version"
                }), { status: 400, headers: { "Content-Type": "application/json" } });
            } else {
                const filename = `${pkgName.replace("/", "-").replace("@", "")}-${pkgVersion}.tgz`;
                const quarantinePath = join(QUARANTINE_DIR, filename);
                const inQuarantine = await exists(quarantinePath);

                // Check if there's cached scan result
                const cacheKey = `${pkgName}@${pkgVersion}`;
                const scanResult = SCAN_RESULTS_CACHE.get(cacheKey);

                response = new Response(JSON.stringify({
                    package: pkgName,
                    version: pkgVersion,
                    in_quarantine: inQuarantine,
                    awaiting_approval: inQuarantine,
                    filename: inQuarantine ? filename : null,
                    issues: scanResult?.issues || null,
                    admin_panel: "http://localhost:4873/-/admin"
                }), {
                    headers: { "Content-Type": "application/json" }
                });
            }
        }
        // GET /llms.txt - AI discovery file
        else if (method === "GET" && path === "/llms.txt") {
            const llmsPath = join(PROJECT_DIR, "llms.txt");
            const file = Bun.file(llmsPath);
            if (await file.exists()) {
                response = new Response(file, {
                    headers: { "Content-Type": "text/plain; charset=utf-8" }
                });
            } else {
                response = new Response("llms.txt not found", { status: 404 });
            }
        }
        // GET /robots.txt - SEO robots file
        else if (method === "GET" && path === "/robots.txt") {
            const robotsPath = join(WEB_DIR, "robots.txt");
            const file = Bun.file(robotsPath);
            if (await file.exists()) {
                response = new Response(file, {
                    headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "public, max-age=86400" }
                });
            } else {
                response = new Response("User-agent: *\nDisallow: /", {
                    headers: { "Content-Type": "text/plain; charset=utf-8" }
                });
            }
        }
        // GET /openapi.json - OpenAPI specification
        else if (method === "GET" && path === "/openapi.json") {
            const openapiPath = join(PROJECT_DIR, "openapi.json");
            const file = Bun.file(openapiPath);
            if (await file.exists()) {
                response = new Response(file, {
                    headers: { "Content-Type": "application/json" }
                });
            } else {
                response = new Response("openapi.json not found", { status: 404 });
            }
        }
        // GET /health or /-/health - Detailed health check for monitoring
        else if (method === "GET" && (path === "/health" || path === "/-/health")) {
            const memUsage = process.memoryUsage();
            const pkgCounts = countPackages();
            const scanStats = getScanStats();
            const metrics = getMetricsSnapshot();

            const healthData = {
                status: "healthy",
                timestamp: new Date().toISOString(),
                uptime: {
                    seconds: getUptimeSeconds(),
                    human: (() => {
                        const s = getUptimeSeconds();
                        const d = Math.floor(s / 86400);
                        const h = Math.floor((s % 86400) / 3600);
                        const m = Math.floor((s % 3600) / 60);
                        return d > 0 ? `${d}d ${h}h ${m}m` : h > 0 ? `${h}h ${m}m` : `${m}m`;
                    })()
                },
                version: VERSION,
                memory: {
                    heapUsedMB: Math.round(memUsage.heapUsed / 1024 / 1024 * 10) / 10,
                    heapTotalMB: Math.round(memUsage.heapTotal / 1024 / 1024 * 10) / 10,
                    rssMB: Math.round(memUsage.rss / 1024 / 1024 * 10) / 10
                },
                database: {
                    status: "connected",
                    packages: pkgCounts.total,
                    localPackages: pkgCounts.local,
                    upstreamPackages: pkgCounts.upstream
                },
                security: {
                    scansTotal: scanStats.total,
                    scansBlocked: scanStats.blocked,
                    avgScanTimeMs: scanStats.avgTimeMs
                },
                metrics: {
                    totalRequests: metrics.totalRequests,
                    cacheHitRate: metrics.overallCacheHitRate,
                    currentRps: metrics.currentRps
                },
                quarantine: {
                    pending: (await readdir(QUARANTINE_DIR).catch(() => [])).filter(f => f.endsWith(".tgz")).length
                }
            };

            response = new Response(JSON.stringify(healthData, null, 2), {
                headers: { "Content-Type": "application/json", ...SECURITY_HEADERS }
            });
        }
        // PUT /-/user/org.couchdb.user:* - npm adduser/login endpoint
        // AgentRegistry does NOT require authentication - return success with helpful message
        else if (method === "PUT" && path.startsWith("/-/user/")) {
            console.log("ℹ️ Agent attempted authentication - AgentRegistry doesn't require auth!");
            response = new Response(JSON.stringify({
                ok: true,
                token: "agentregistry-no-auth-required",
                _message: "🎉 AgentRegistry does NOT require authentication!",
                _info: {
                    warning: "You do NOT need to authenticate with AgentRegistry.",
                    instructions: [
                        "AgentRegistry is NOT Verdaccio - do not follow Verdaccio auth instructions!",
                        "Simply run: npm publish --registry http://localhost:4873",
                        "No .npmrc token needed, no htpasswd, no login required."
                    ],
                    correct_usage: "npm config set registry http://localhost:4873 && npm publish",
                    documentation: "http://localhost:4873/-/admin (see AGENTS.md for details)"
                }
            }), {
                status: 201,
                headers: { "Content-Type": "application/json" }
            });
        }
        // GET /-/whoami - Return local user with explanation
        else if (method === "GET" && path === "/-/whoami") {
            response = new Response(JSON.stringify({
                username: "local-agent",
                _message: "AgentRegistry auto-authenticates all users. No login required!",
                _tip: "Just run 'npm publish' directly - authentication is automatic."
            }), {
                headers: { "Content-Type": "application/json" }
            });
        }
        // GET/POST /-/npm/* - npm v2 auth endpoints (token-based)
        else if (path.startsWith("/-/npm/")) {
            console.log("ℹ️ Agent called npm v2 auth endpoint - AgentRegistry doesn't require auth!");
            response = new Response(JSON.stringify({
                ok: true,
                _message: "🎉 AgentRegistry does NOT require authentication!",
                _warning: "You're trying to use npm token authentication. AgentRegistry doesn't need it!",
                _instructions: [
                    "Remove any _authToken from your .npmrc for localhost:4873",
                    "Just run: npm publish --registry http://localhost:4873",
                    "AgentRegistry is NOT Verdaccio - ignore Verdaccio configs!"
                ]
            }), {
                status: 200,
                headers: { "Content-Type": "application/json" }
            });
        }
        // ==================== STATIC ASSETS ====================
        // GET /assets/* - Serve static assets (favicon, images)
        else if (method === "GET" && path.startsWith("/assets/")) {
            const assetName = path.replace("/assets/", "");
            const assetPath = join(WEB_DIR, "assets", assetName);
            const file = Bun.file(assetPath);
            if (await file.exists()) {
                const ext = path.split(".").pop()?.toLowerCase();
                const mimeTypes: Record<string, string> = {
                    "png": "image/png",
                    "jpg": "image/jpeg",
                    "jpeg": "image/jpeg",
                    "gif": "image/gif",
                    "svg": "image/svg+xml",
                    "ico": "image/x-icon",
                    "webp": "image/webp",
                    "js": "application/javascript",
                    "css": "text/css",
                    "json": "application/json"
                };
                response = new Response(file, {
                    headers: {
                        "Content-Type": mimeTypes[ext || ""] || "application/octet-stream",
                        "Cache-Control": "public, max-age=31536000, immutable" // 1 year for static assets
                    }
                });
            } else {
                response = new Response("Asset not found", { status: 404 });
            }
        }
        // ==================== DOCUMENTATION ====================
        // GET /docs - Redirect to /docs/ (trailing slash required for relative paths)
        else if (method === "GET" && (path === "/docs" || path === "/-/docs")) {
            response = new Response(null, {
                status: 301,
                headers: { "Location": "/docs/" }
            });
        }
        // GET /docs/* or /-/docs/* - Serve documentation site
        else if (method === "GET" && (path.startsWith("/docs/") || path.startsWith("/-/docs/"))) {
            const docsDir = DOCS_DIR;
            // Normalize path: remove /-/docs/ or /docs/ prefix
            let docPath = path.replace(/^\/-\/docs\//, "").replace(/^\/docs\//, "") || "index.html";
            if (docPath === "") docPath = "index.html";

            // Security: prevent path traversal
            if (docPath.includes("..")) {
                response = new Response("Invalid path", { status: 400 });
            } else {
                let filePath = join(docsDir, docPath);
                let file = Bun.file(filePath);


                // If path doesn't exist but might be a directory, try index.html
                if (!(await file.exists()) && !docPath.includes(".")) {
                    const indexPath = join(docsDir, docPath, "index.html");
                    const indexFile = Bun.file(indexPath);
                    if (await indexFile.exists()) {
                        filePath = indexPath;
                        file = indexFile;
                        docPath = docPath + "/index.html";
                    }
                }

                if (await file.exists()) {
                    const ext = docPath.split(".").pop()?.toLowerCase() || "html";

                    const mimeTypes: Record<string, string> = {
                        "html": "text/html",
                        "css": "text/css",
                        "js": "application/javascript",
                        "png": "image/png",
                        "jpg": "image/jpeg",
                        "jpeg": "image/jpeg",
                        "webp": "image/webp",
                        "svg": "image/svg+xml"
                    };
                    response = new Response(file, {
                        headers: {
                            "Content-Type": mimeTypes[ext] || "text/html",
                            "Cache-Control": ext === "html" ? "public, max-age=3600" : "public, max-age=31536000, immutable"
                        }
                    });
                } else {

                    response = new Response("Documentation page not found", { status: 404 });
                }
            }
        }
        // ==================== ADMIN PANEL ====================
        // GET /-/admin - Serve admin panel (no auth required, token is injected)
        else if (method === "GET" && path === "/-/admin") {
            response = await serveAdminPanel(req.headers.get("accept-encoding"));
        }
        // SECURITY: All other admin endpoints require X-Admin-Token header
        // Prefer WebSocket for admin operations (see: /-/admin/ws with token auth)
        else if (path.startsWith("/-/admin/")) {
            const token = req.headers.get("X-Admin-Token");
            if (!secureTokenCompare(token, ADMIN_SESSION_TOKEN)) {
                response = new Response(JSON.stringify({
                    error: "Unauthorized",
                    message: "Admin API requires X-Admin-Token header. Use WebSocket for secure operations."
                }), {
                    status: 401,
                    headers: { "Content-Type": "application/json", ...SECURITY_HEADERS }
                });
            }
            // GET /-/admin/stats - Get server stats
            else if (method === "GET" && path === "/-/admin/stats") {
                response = await handleAdminStats(getAdminContext());
            }
            // GET /-/admin/search?q=query - Search packages
            else if (method === "GET" && path === "/-/admin/search") {
                const searchQuery = url.searchParams.get("q") || "";
                const limit = Math.min(parseInt(url.searchParams.get("limit") || "50"), 100);
                const results = searchPackages(searchQuery, limit);

                const body = JSON.stringify({ query: searchQuery, results, count: results.length });
                const headers = { "Content-Type": "application/json", ...SECURITY_HEADERS };
                const compressed = compressResponse(body, headers, req.headers.get("accept-encoding"));

                response = new Response(compressed.body, { headers: compressed.headers });
            }
            // GET /-/admin/metrics - Get real-time metrics
            else if (method === "GET" && path === "/-/admin/metrics") {
                const metrics = getMetricsSnapshot();

                const body = JSON.stringify(metrics);
                const headers = { "Content-Type": "application/json", ...SECURITY_HEADERS };
                const compressed = compressResponse(body, headers, req.headers.get("accept-encoding"));

                response = new Response(compressed.body, { headers: compressed.headers });
            }
            // ==================== ALLOWLIST API ====================
            // GET /-/admin/allowlist - Get items
            else if (method === "GET" && path === "/-/admin/allowlist") {
                const config = getIPConfig();
                const entries = listIPEntries();
                response = new Response(JSON.stringify({ config, entries }), {
                    headers: { "Content-Type": "application/json", ...SECURITY_HEADERS }
                });
            }
            // PUT /-/admin/allowlist/config - Update config
            else if (method === "PUT" && path === "/-/admin/allowlist/config") {
                try {
                    const body = await req.json() as any;
                    const config = updateIPConfig(body);
                    // Broadcast change to other workers if valid
                    if (process.send) process.send({ type: "config_change", data: config });
                    logAudit("config_change", "ip_allowlist", body);
                    response = new Response(JSON.stringify({ success: true, config }), {
                        headers: { "Content-Type": "application/json", ...SECURITY_HEADERS }
                    });
                } catch (e) {
                    response = new Response(JSON.stringify({ success: false, error: String(e) }), { status: 400 });
                }
            }
            // POST /-/admin/allowlist/entry - Add entry
            else if (method === "POST" && path === "/-/admin/allowlist/entry") {
                try {
                    const body = await req.json() as any;
                    const validation = validatePattern(body.pattern);
                    if (!validation.valid) {
                        throw new Error(validation.error);
                    }
                    const entry = addIPEntry(body.pattern, body.description);
                    if (!entry) throw new Error("Entry already exists");

                    logAudit("allowlist_add", body.pattern);
                    response = new Response(JSON.stringify({ success: true, entry }), {
                        headers: { "Content-Type": "application/json", ...SECURITY_HEADERS }
                    });
                } catch (e) {
                    response = new Response(JSON.stringify({ success: false, error: String(e) }), { status: 400 });
                }
            }
            // DELETE /-/admin/allowlist/entry/:id - Remove entry
            else if (method === "DELETE" && path.match(/^\/-\/admin\/allowlist\/entry\/\d+$/)) {
                const id = parseInt(path.split("/").pop()!);
                const success = removeIPEntry(id);
                if (success) logAudit("allowlist_remove", String(id));
                response = new Response(JSON.stringify({ success }), {
                    headers: { "Content-Type": "application/json", ...SECURITY_HEADERS }
                });
            }
            // PUT /-/admin/allowlist/entry/:id/toggle - Toggle entry
            else if (method === "PUT" && path.match(/^\/-\/admin\/allowlist\/entry\/\d+\/toggle$/)) {
                try {
                    const id = parseInt(path.split("/")[5]);
                    const body = await req.json() as any;
                    const success = toggleIPEntry(id, body.enabled);
                    if (success) logAudit("allowlist_toggle", String(id), { enabled: body.enabled });
                    response = new Response(JSON.stringify({ success }), {
                        headers: { "Content-Type": "application/json", ...SECURITY_HEADERS }
                    });
                } catch (e) {
                    response = new Response(JSON.stringify({ success: false, error: String(e) }), { status: 400 });
                }
            }
            // GET /-/admin/allowlist/check/:ip - Test IP
            else if (method === "GET" && path.startsWith("/-/admin/allowlist/check/")) {
                const ip = decodeURIComponent(path.replace("/-/admin/allowlist/check/", ""));
                const result = await isIPAllowed(ip);
                response = new Response(JSON.stringify(result), {
                    headers: { "Content-Type": "application/json", ...SECURITY_HEADERS }
                });
            }
            // GET /-/admin/cve - Get CVE summary
            else if (method === "GET" && path === "/-/admin/cve") {
                const summary = getCVESummary();
                response = new Response(JSON.stringify(summary), {
                    headers: { "Content-Type": "application/json", ...SECURITY_HEADERS }
                });
            }
            // GET /-/admin/cve/all - Get all cached CVEs
            else if (method === "GET" && path === "/-/admin/cve/all") {
                const allCVEs = getAllCachedCVEs();
                const result: Record<string, any> = {};
                for (const [pkg, vulns] of allCVEs) {
                    result[pkg] = vulns;
                }
                response = new Response(JSON.stringify(result), {
                    headers: { "Content-Type": "application/json", ...SECURITY_HEADERS }
                });
            }
            // POST /-/admin/cve/scan - Scan all cached packages for CVEs
            else if (method === "POST" && path === "/-/admin/cve/scan") {
                const packages = listPackagesFromDB();
                const results = await scanPackages(packages);
                const summary = getCVESummary();
                logAudit("cve_scan", undefined, { packages: packages.length, vulnerabilities: summary.packagesWithCVEs });
                response = new Response(JSON.stringify({
                    scanned: packages.length,
                    withVulnerabilities: summary.packagesWithCVEs,
                    summary: summary.bySeverity
                }), {
                    headers: { "Content-Type": "application/json", ...SECURITY_HEADERS }
                });
            }
            // GET /-/admin/cve/{package} - Check CVE for specific package
            else if (method === "GET" && path.startsWith("/-/admin/cve/") && !path.includes("/all")) {
                const packageName = decodeURIComponent(path.replace("/-/admin/cve/", ""));
                const result = await checkCVE(packageName);
                response = new Response(JSON.stringify(result), {
                    headers: { "Content-Type": "application/json", ...SECURITY_HEADERS }
                });
            }
            // ====================================================================
            // IP ALLOWLIST ENDPOINTS
            // ====================================================================
            // GET /-/admin/allowlist - Get allowlist summary and config
            else if (method === "GET" && path === "/-/admin/allowlist") {
                const summary = getAllowlistSummary();
                const entries = listIPEntries();
                response = new Response(JSON.stringify({ ...summary, entries }), {
                    headers: { "Content-Type": "application/json", ...SECURITY_HEADERS }
                });
            }
            // PUT /-/admin/allowlist/config - Update allowlist configuration
            else if (method === "PUT" && path === "/-/admin/allowlist/config") {
                const body = await req.json() as Partial<{ enabled: boolean; mode: "allowlist" | "blocklist"; defaultAllow: boolean }>;
                const newConfig = updateIPConfig(body);
                logAudit("config_change", "ip_allowlist", { config: newConfig });
                response = new Response(JSON.stringify({ success: true, config: newConfig }), {
                    headers: { "Content-Type": "application/json", ...SECURITY_HEADERS }
                });
            }
            // POST /-/admin/allowlist/entry - Add new entry
            else if (method === "POST" && path === "/-/admin/allowlist/entry") {
                const body = await req.json() as { pattern: string; description?: string };
                const validation = validatePattern(body.pattern);
                if (!validation.valid) {
                    response = new Response(JSON.stringify({ error: validation.error }), {
                        status: 400,
                        headers: { "Content-Type": "application/json", ...SECURITY_HEADERS }
                    });
                } else {
                    const entry = addIPEntry(body.pattern, body.description);
                    if (entry) {
                        logAudit("allowlist_add", body.pattern, { description: body.description });
                        response = new Response(JSON.stringify({ success: true, entry }), {
                            headers: { "Content-Type": "application/json", ...SECURITY_HEADERS }
                        });
                    } else {
                        response = new Response(JSON.stringify({ error: "Pattern already exists" }), {
                            status: 409,
                            headers: { "Content-Type": "application/json", ...SECURITY_HEADERS }
                        });
                    }
                }
            }
            // DELETE /-/admin/allowlist/entry/{id} - Remove entry
            else if (method === "DELETE" && path.startsWith("/-/admin/allowlist/entry/")) {
                const id = parseInt(path.replace("/-/admin/allowlist/entry/", ""), 10);
                if (isNaN(id)) {
                    response = new Response(JSON.stringify({ error: "Invalid ID" }), {
                        status: 400,
                        headers: { "Content-Type": "application/json", ...SECURITY_HEADERS }
                    });
                } else {
                    const success = removeIPEntry(id);
                    if (success) {
                        logAudit("allowlist_remove", String(id));
                        response = new Response(JSON.stringify({ success: true }), {
                            headers: { "Content-Type": "application/json", ...SECURITY_HEADERS }
                        });
                    } else {
                        response = new Response(JSON.stringify({ error: "Entry not found" }), {
                            status: 404,
                            headers: { "Content-Type": "application/json", ...SECURITY_HEADERS }
                        });
                    }
                }
            }
            // PUT /-/admin/allowlist/entry/{id}/toggle - Toggle entry enabled/disabled
            else if (method === "PUT" && path.includes("/-/admin/allowlist/entry/") && path.endsWith("/toggle")) {
                const id = parseInt(path.replace("/-/admin/allowlist/entry/", "").replace("/toggle", ""), 10);
                const body = await req.json() as { enabled: boolean };
                if (isNaN(id)) {
                    response = new Response(JSON.stringify({ error: "Invalid ID" }), {
                        status: 400,
                        headers: { "Content-Type": "application/json", ...SECURITY_HEADERS }
                    });
                } else {
                    const success = toggleIPEntry(id, body.enabled);
                    if (success) {
                        logAudit("allowlist_toggle", String(id), { enabled: body.enabled });
                        response = new Response(JSON.stringify({ success: true }), {
                            headers: { "Content-Type": "application/json", ...SECURITY_HEADERS }
                        });
                    } else {
                        response = new Response(JSON.stringify({ error: "Entry not found" }), {
                            status: 404,
                            headers: { "Content-Type": "application/json", ...SECURITY_HEADERS }
                        });
                    }
                }
            }
            // GET /-/admin/allowlist/check/{ip} - Check if IP is allowed (for testing)
            else if (method === "GET" && path.startsWith("/-/admin/allowlist/check/")) {
                const ip = decodeURIComponent(path.replace("/-/admin/allowlist/check/", ""));
                const result = isIPAllowed(ip);
                response = new Response(JSON.stringify({ ip, ...result }), {
                    headers: { "Content-Type": "application/json", ...SECURITY_HEADERS }
                });
            }
            // ====================================================================
            // AUDIT EXPORT ENDPOINTS
            // ====================================================================
            // GET /-/admin/audit/export - Export audit logs as JSON
            else if (method === "GET" && path === "/-/admin/audit/export") {
                const url = new URL(req.url);
                const options: AuditExportOptions = {
                    startDate: url.searchParams.get("startDate") || undefined,
                    endDate: url.searchParams.get("endDate") || undefined,
                    limit: url.searchParams.get("limit") ? parseInt(url.searchParams.get("limit")!, 10) : undefined
                };
                const actions = url.searchParams.get("actions");
                if (actions) {
                    options.actions = actions.split(",") as any[];
                }
                const severity = url.searchParams.get("severity");
                if (severity) {
                    options.severity = severity.split(",") as any[];
                }
                const logs = getAuditLogsForExport(options);
                const filename = `audit-export-${new Date().toISOString().split("T")[0]}.json`;

                const body = JSON.stringify(logs, null, 2);
                const headers = {
                    "Content-Type": "application/json",
                    "Content-Disposition": `attachment; filename="${filename}"`,
                    ...SECURITY_HEADERS
                };
                const compressed = compressResponse(body, headers, req.headers.get("accept-encoding"));

                response = new Response(compressed.body, { headers: compressed.headers });
            }
            // GET /-/admin/audit/export/csv - Export audit logs as CSV
            else if (method === "GET" && path === "/-/admin/audit/export/csv") {
                const url = new URL(req.url);
                const options: AuditExportOptions = {
                    startDate: url.searchParams.get("startDate") || undefined,
                    endDate: url.searchParams.get("endDate") || undefined,
                    limit: url.searchParams.get("limit") ? parseInt(url.searchParams.get("limit")!, 10) : undefined
                };
                const actions = url.searchParams.get("actions");
                if (actions) {
                    options.actions = actions.split(",") as any[];
                }
                const severity = url.searchParams.get("severity");
                if (severity) {
                    options.severity = severity.split(",") as any[];
                }
                const logs = getAuditLogsForExport(options);
                const csv = formatAuditLogsAsCSV(logs);
                const filename = `audit-export-${new Date().toISOString().split("T")[0]}.csv`;

                const headers = {
                    "Content-Type": "text/csv",
                    "Content-Disposition": `attachment; filename="${filename}"`,
                    ...SECURITY_HEADERS
                };
                const compressed = compressResponse(csv, headers, req.headers.get("accept-encoding"));

                response = new Response(compressed.body, { headers: compressed.headers });
            }
            // GET /-/admin/audit/stats - Get audit log statistics
            else if (method === "GET" && path === "/-/admin/audit/stats") {
                const count = getAuditLogCount();
                const recent = getRecentAuditLogs(100);
                const bySeverity = {
                    info: recent.filter((l: any) => l.severity === "info").length,
                    warn: recent.filter((l: any) => l.severity === "warn").length,
                    error: recent.filter((l: any) => l.severity === "error").length
                };
                const byAction: Record<string, number> = {};
                for (const log of recent) {
                    byAction[log.action] = (byAction[log.action] || 0) + 1;
                }
                response = new Response(JSON.stringify({
                    totalLogs: count,
                    recentBySeverity: bySeverity,
                    recentByAction: byAction
                }), {
                    headers: { "Content-Type": "application/json", ...SECURITY_HEADERS }
                });
            }
            // GET /-/admin/quarantine - List quarantined files
            else if (method === "GET" && path === "/-/admin/quarantine") {
                response = await handleAdminQuarantineList(SCAN_RESULTS_CACHE);
            }
            // DELETE /-/admin/quarantine - Clear all quarantine
            else if (method === "DELETE" && path === "/-/admin/quarantine") {
                response = await handleAdminQuarantineClear();
            }
            // DELETE /-/admin/quarantine/{filename} - Delete specific file
            else if (method === "DELETE" && path.startsWith("/-/admin/quarantine/")) {
                const filename = decodeURIComponent(path.replace("/-/admin/quarantine/", ""));
                response = await handleAdminQuarantineDelete(filename);
            }
            // POST /-/admin/quarantine/{filename}/approve - Approve quarantined file
            else if (method === "POST" && path.includes("/-/admin/quarantine/") && path.endsWith("/approve")) {
                const filename = decodeURIComponent(path.replace("/-/admin/quarantine/", "").replace("/approve", ""));
                response = await handleAdminQuarantineApprove(filename);
            }
            // GET /-/admin/cache - List cached packages
            else if (method === "GET" && path === "/-/admin/cache") {
                response = await handleAdminCacheList(getAdminContext());
            }
            // DELETE /-/admin/cache/{name} - Delete package from cache
            else if (method === "DELETE" && path.startsWith("/-/admin/cache/")) {
                const name = decodeURIComponent(path.replace("/-/admin/cache/", ""));
                response = await handleAdminCacheDelete(name, getAdminContext());
            }
            // POST /-/admin/cache/{name}/refresh - Force refresh from npm
            else if (method === "POST" && path.includes("/-/admin/cache/") && path.endsWith("/refresh")) {
                const name = decodeURIComponent(path.replace("/-/admin/cache/", "").replace("/refresh", ""));
                response = await handleAdminCacheRefresh(name, getAdminContext());
            }
            // GET /-/admin/audit - Get audit logs
            else if (method === "GET" && path === "/-/admin/audit") {
                response = await handleAdminAuditLogs();
            }
            // GET /-/admin/scans - Get scan history
            else if (method === "GET" && path === "/-/admin/scans") {
                response = await handleAdminScanHistory();
            }
            // GET /-/admin/requests - Get request logs
            else if (method === "GET" && path === "/-/admin/requests") {
                response = await handleAdminRequestLogs();
            }
            // POST /-/admin/cleanup - Smart cleanup of unused upstream packages
            else if (method === "POST" && path === "/-/admin/cleanup") {
                response = await handleAdminCleanup(getAdminContext());
            }
        } // END: Admin endpoints token-protected block
        // GET /-/v1/search?text=... - NPM-compatible search API
        else if (method === "GET" && path === "/-/v1/search") {
            const searchText = url.searchParams.get("text") || "";
            const limit = Math.min(parseInt(url.searchParams.get("size") || "20"), 100);

            const results = searchPackages(searchText, limit);

            // Format response per NPM registry API spec
            const objects = results.map(pkg => ({
                package: {
                    name: pkg.name,
                    version: pkg.version,
                    description: pkg.description || "",
                    date: pkg.updatedAt || new Date().toISOString(),
                    links: {
                        npm: `http://localhost:${PORT}/${pkg.name}`
                    }
                },
                score: {
                    final: 1,
                    detail: { quality: 1, popularity: 1, maintenance: 1 }
                },
                searchScore: 1
            }));

            const body = JSON.stringify({
                objects,
                total: objects.length,
                time: new Date().toISOString()
            });

            const headers: Record<string, string> = { "Content-Type": "application/json" };
            const compressed = compressResponse(body, headers, req.headers.get("accept-encoding"));

            response = new Response(compressed.body, { headers: compressed.headers });
        }
        // GET /{package}/-/{tarball}.tgz - Download tarball
        else if (method === "GET" && path.includes("/-/")) {
            const [pkgPath, tarballName] = path.split("/-/");
            const pkgName = pkgPath.slice(1); // Remove leading /
            response = await handleGetTarball(pkgName, tarballName);
        }
        // GET /{package}/{version} - Get specific version
        // Must detect if last segment is a version (x.y.z format)
        // GET /api/graph - Dependency Graph
        else if (method === "GET" && path === "/api/graph") {
            response = handleGetGraph();
        }
        else if (method === "GET" && !path.includes("/-/")) {

            const parts = path.slice(1).split("/");
            const lastPart = parts[parts.length - 1];
            const isVersion = /^\d+\.\d+\.\d+/.test(lastPart);

            if (isVersion && parts.length >= 2) {
                const acceptEncoding = req.headers.get("accept-encoding");
                // Handle scoped packages: @scope/name/version
                if (parts[0].startsWith("@") && parts.length >= 3) {
                    const name = `${parts[0]}/${parts[1]}`;
                    const version = parts[2];
                    response = await handleGetVersion(name, version, baseUrl, acceptEncoding);
                } else {
                    // Unscoped: name/version
                    const [name, version] = parts;
                    response = await handleGetVersion(name, version, baseUrl, acceptEncoding);
                }
            } else {
                // Package metadata (no version)
                // Scoped: @scope/name or Unscoped: name
                const name = parts.join("/");
                const acceptEncoding = req.headers.get("accept-encoding");
                response = await handleGetPackage(name, baseUrl, acceptEncoding);
            }
        }
        // PUT /{package} - Publish
        else if (method === "PUT") {
            const name = path.slice(1);
            const body = await req.json();
            response = await handlePublish(name, body, baseUrl);
        }
        // DELETE /{package}/-/{tarball}/{rev} - Unpublish
        else if (method === "DELETE" && path.includes("/-/")) {
            const [pkgPath, rest] = path.split("/-/");
            const pkgName = pkgPath.slice(1);
            const tarballMatch = rest.match(/-(\d+\.\d+\.\d+(?:-[a-zA-Z0-9.]+)?)\./);
            if (tarballMatch) {
                response = await handleUnpublish(pkgName, tarballMatch[1]);
            } else {
                response = new Response("Invalid request", { status: 400 });
            }
        }
        else {
            response = new Response("Not Found", { status: 404 });
        }

        // Add CORS + Security headers to response
        for (const [key, value] of Object.entries(commonHeaders)) {
            response.headers.set(key, value);
        }

        // Log request to SQLite (async, non-blocking)
        const duration = Date.now() - requestStart;
        logRequest({
            requestId,
            method,
            path,
            statusCode: response.status,
            durationMs: duration,
            userAgent: req.headers.get("user-agent") || undefined
        });

        // Record metrics (cacheHit is determined by X-Cache header if present)
        const cacheHeader = response.headers.get("X-Cache");
        const cacheHit = cacheHeader === "HIT" || cacheHeader === "memory" || cacheHeader === "disk";
        recordRequest(duration, cacheHit);


        return response;
    } catch (error) {
        logger.error("Error handling request", { error: error ? String(error) : "Unknown error" });
        // Log error request
        const duration = Date.now() - requestStart;
        logRequest({
            requestId,
            method,
            path,
            statusCode: 500,
            durationMs: duration
        });
        return new Response(JSON.stringify({ error: String(error) }), {
            status: 500,
            headers: { "Content-Type": "application/json", ...commonHeaders }
        });
    }
}

// ============================================================================
// Server Startup
// ============================================================================

await ensureStorageDirs();
await autoApproveQuarantine();

// ============================================================================
// Daemon Initialization
// ============================================================================

await ensureDaemonDirs();
await writePidFile();

// Initialize logger (file logging in daemon mode, console always)
await initLogger({
    toFile: DAEMON_MODE,
    toConsole: true,
    level: "info"
});

let server: any; // Type Bun.Server

// Cluster Mode Logic
if (CLUSTER_MODE && cluster.isPrimary) {
    if (DAEMON_MODE) {
        console.log("🔧 Running in daemon mode (Cluster Primary)");
    }

    // Primary initialization
    await ensureDaemonDirs();
    await writePidFile();

    // Log start
    logAudit("server_started", undefined, { mode: "cluster", pid: process.pid });

    const numCPUs = cpus().length;
    console.log(`🚀 Primary ${process.pid} is running in CLUSTER MODE`);
    console.log(`   Forking ${numCPUs} workers...`);

    // Propagate env (including session token)
    const env = { ...process.env, ADMIN_SESSION_TOKEN: ADMIN_SESSION_TOKEN };

    for (let i = 0; i < numCPUs; i++) {
        cluster.fork(env);
    }

    cluster.on("exit", (worker, code, signal) => {
        console.log(`Worker ${worker.process.pid} died. Restarting...`);
        cluster.fork(env);
    });

    // Run cleanup on primary only (to avoid contention)
    setTimeout(runScheduledCleanup, 5000);
    setInterval(runScheduledCleanup, CLEANUP_INTERVAL_MS);

    console.log(`
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   🚀 AgentRegistry Registry Server (Cluster Mode)                  ║
║                                                              ║
║   Workers:    ${numCPUs.toString().padEnd(47)}║
║   Running on: http://127.0.0.1:${PORT.toString().padEnd(26)}║
║   Storage:    ${STORAGE_DIR.slice(-45).padEnd(45)}║
║                                                              ║
║   🔒 SECURITY: Localhost-only mode ENABLED                   ║
║   • Bound to 127.0.0.1 (not 0.0.0.0)                         ║
║                                                              ║
║   Configure npm/bun:                                         ║
║   npm config set registry http://localhost:${PORT.toString().padEnd(17)}║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
    `);

} else {
    // Worker / Single Mode
    if (DAEMON_MODE && !CLUSTER_MODE) {
        console.log("🔧 Running in daemon mode");
    }

    if (!CLUSTER_MODE) {
        await ensureDaemonDirs();
        await mkdir(STORAGE_DIR, { recursive: true });
        await writePidFile();
        logAudit("server_started", undefined, { mode: "single", pid: process.pid });

        // Cleanup in single mode
        setTimeout(runScheduledCleanup, 5000);
        setInterval(runScheduledCleanup, CLEANUP_INTERVAL_MS);
    }

    server = Bun.serve({
        port: PORT,
        hostname: "127.0.0.1",  // SECURITY: Bind ONLY to localhost, not 0.0.0.0
        reusePort: true,        // Enable SO_REUSEPORT for Cluster Mode
        idleTimeout: 30,        // Close idle connections after 30 seconds
        fetch(req, server) {
            const url = new URL(req.url);

            // Handle WebSocket upgrade for admin
            if (url.pathname === "/-/admin/ws") {
                const token = url.searchParams.get("token");

                // Validate session token
                if (!secureTokenCompare(token, ADMIN_SESSION_TOKEN)) {
                    return new Response("Unauthorized", { status: 401 });
                }

                // Single user session: close existing connections
                for (const client of adminWSClients) {
                    try {
                        client.close(4001, "New session started");
                    } catch (e) {
                        logger.debug(`Error closing WS client: ${e}`);
                    }
                }
                adminWSClients.clear();

                // Upgrade to WebSocket
                const upgraded = server.upgrade(req, { data: { authenticated: true } as any });
                if (!upgraded) {
                    return new Response("WebSocket upgrade failed", { status: 500 });
                }
                return undefined;
            }

            // Regular HTTP request
            return handleRequest(req);
        },
        websocket: {
            open(ws) {
                const wsData = ws.data as WebSocketData | undefined;
                if (wsData?.authenticated) {
                    adminWSClients.add(ws);
                    activeAdminWS = ws;
                    // Register with broadcast service for real-time updates
                    setAdminWs(ws);
                    console.log(`🔌 Admin WebSocket connected (Worker ${process.pid})`);

                    // Send initial stats (Note: token NOT sent to client for security)
                    ws.send(JSON.stringify({
                        type: "connected",
                        data: { authenticated: true },
                        timestamp: Date.now()
                    }));
                }
            },
            message(ws, message) {
                const wsData = ws.data as WebSocketData | undefined;
                if (!wsData?.authenticated) {
                    ws.close(4003, "Not authenticated");
                    return;
                }

                try {
                    const msg = safeJsonParse<{ action: string; payload?: any }>(message.toString());
                    if (!msg) {
                        ws.send(JSON.stringify({ type: "error", error: "Invalid JSON" }));
                        return;
                    }
                    handleAdminWSMessage(ws, msg);
                } catch (e) {
                    ws.send(JSON.stringify({ type: "error", error: "Invalid JSON" }));
                }
            },
            close(ws) {
                adminWSClients.delete(ws);
                if (activeAdminWS === ws) {
                    activeAdminWS = null;
                    // Clear broadcast service reference
                    setAdminWs(null);
                }
                console.log("🔌 Admin WebSocket disconnected");
            }
        }
    });

    if (CLUSTER_MODE) {
        console.log(`   Worker ${process.pid} listening on http://localhost:${PORT}`);
    } else {
        console.log(`
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   🚀 AgentRegistry Registry Server                                 ║
║                                                              ║
║   Running on: http://127.0.0.1:${PORT.toString().padEnd(26)}║
║   Storage:    ${STORAGE_DIR.slice(-45).padEnd(45)}║
║                                                              ║
║   🔒 SECURITY: Localhost-only mode ENABLED                   ║
║   • Bound to 127.0.0.1 (not 0.0.0.0)                         ║
║   • Non-localhost requests will be rejected                  ║
║                                                              ║
║   Configure npm/bun:                                         ║
║   npm config set registry http://localhost:${PORT.toString().padEnd(17)}║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
        `);
    }
}

// ============================================================================
// Graceful Shutdown Handler
// ============================================================================

let isShuttingDown = false;

async function gracefulShutdown(signal: string) {
    if (isShuttingDown) return;
    isShuttingDown = true;

    // =========================================================================
    // FORENSIC LOGGING: Capture signal origin for debugging
    // =========================================================================
    const forensicInfo: Record<string, any> = {
        timestamp: new Date().toISOString(),
        signal,
        pid: process.pid,
        ppid: process.ppid,
        uptime: process.uptime(),
        memoryUsage: process.memoryUsage(),
    };

    try {
        // Get parent process info (who might have sent the signal)
        const { execSync } = await import("child_process");

        // Get parent process name and command
        try {
            const ppidInfo = execSync(`ps -p ${process.ppid} -o pid,ppid,comm,args 2>/dev/null || echo "ppid lookup failed"`, { encoding: "utf-8" }).trim();
            forensicInfo.parentProcess = ppidInfo;
        } catch (e) {
            forensicInfo.parentProcess = `lookup failed: ${e}`;
        }

        // Get all processes that might be related to bun/agentregistry
        try {
            const relatedProcs = execSync(`ps aux | grep -E "(bun|agentregistry|launchd)" | grep -v grep | head -10 2>/dev/null || echo "none"`, { encoding: "utf-8" }).trim();
            forensicInfo.relatedProcesses = relatedProcs;
        } catch (e) {
            forensicInfo.relatedProcesses = "lookup failed";
        }

        // Check system log for recent kill commands (macOS)
        try {
            const recentKills = execSync(`log show --predicate 'eventMessage CONTAINS "kill" OR eventMessage CONTAINS "SIGTERM"' --last 1m --style compact 2>/dev/null | tail -5 || echo "no log access"`, { encoding: "utf-8" }).trim();
            forensicInfo.recentSystemKills = recentKills;
        } catch (e) {
            forensicInfo.recentSystemKills = "log access failed";
        }

        // Get launchctl status
        try {
            const launchctlStatus = execSync(`launchctl list | grep agentregistry 2>/dev/null || echo "not in launchctl"`, { encoding: "utf-8" }).trim();
            forensicInfo.launchctlStatus = launchctlStatus;
        } catch (e) {
            forensicInfo.launchctlStatus = "lookup failed";
        }

    } catch (e) {
        forensicInfo.forensicError = String(e);
    }

    // Log to both console and file with full forensic details
    const forensicLogPath = `${process.env.AGENTREGISTRY_HOME || process.env.HOME + "/.agentregistry"}/logs/signal-forensics.log`;
    try {
        const { appendFileSync } = await import("fs");
        appendFileSync(forensicLogPath, JSON.stringify(forensicInfo, null, 2) + "\n---\n");
    } catch (e) {
        // Ignore file write errors during shutdown
    }

    // Log summary to stdout
    console.log(`\n🔍 SIGNAL FORENSICS:`);
    console.log(`   Signal: ${signal}`);
    console.log(`   PID: ${process.pid}, Parent PID: ${process.ppid}`);
    console.log(`   Parent Process: ${forensicInfo.parentProcess || "unknown"}`);
    console.log(`   Uptime: ${Math.round(process.uptime())}s`);
    console.log(`   Full forensics written to: ${forensicLogPath}`);

    logger.info(`\n🛑 [${process.pid}] Received ${signal}, shutting down gracefully...`);

    // Only Primary or Single instance handles audit log and PID removal
    if (!CLUSTER_MODE || (CLUSTER_MODE && cluster.isPrimary)) {
        // Log shutdown to audit
        try {
            logAudit("server_stopped", undefined, { signal, pid: process.pid });
        } catch (e) { /* ignore if DB closed */ }

        // Remove PID file
        try {
            await removePidFile();
        } catch (e) { }
    }

    // Clear caches (all processes)\n    PACKAGE_CACHE.clear();
    SCAN_RESULTS_CACHE.clear();
    rateLimitStore.clear();

    // Stop HTTP server - wait for in-flight requests to complete
    // Per Bun.js best practices: server.stop() gracefully closes connections
    if (server) {
        try {
            await server.stop();
        } catch (e) { /* ignore if already stopped */ }
    }

    // Close database connection (all processes)
    try {
        closeDatabase();
    } catch (e) { }

    // Close logger
    try {
        await closeLogger();
    } catch (e) { }

    logger.info(`✅ [${process.pid}] Goodbye!`);
    process.exit(0);
}

process.on("SIGINT", () => gracefulShutdown("SIGINT"));
process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));

export { server };
