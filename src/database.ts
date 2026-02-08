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
 * AgentRegistry SQLite Database Module - SOTA Edition
 * 
 * Comprehensive data storage using Bun's native SQLite:
 * - Package metadata
 * - Scan results & history
 * - Request logs
 * - Audit trail
 * - Statistics
 */

import { Database } from "bun:sqlite";
import { join } from "node:path";
import * as logger from "./logger";
import { safeJsonParse } from "./utils";

// ============================================================================
// Database Initialization
// ============================================================================

import { STORAGE_DIR } from "./config";
let DB_PATH: string; // Deferred initialization

let db: Database | null = null;

/**
 * FOR TESTING ONLY: Set a custom database path for isolated tests.
 * Call closeDatabase() first if switching databases.
 */
export function setDatabaseForTesting(customPath: string): void {
    if (db) {
        db.close();
        db = null;
    }
    DB_PATH = customPath;
}

/**
 * FOR TESTING ONLY: Reset to default database path.
 */
export function resetDatabasePath(): void {
    if (db) {
        db.close();
        db = null;
    }
    DB_PATH = join(STORAGE_DIR, "agentregistry.db");
}

export function getDatabase(): Database {
    if (!db) {
        if (!DB_PATH) {
            // Use STORAGE_DIR from config (which handles env var internally)
            DB_PATH = join(STORAGE_DIR, "agentregistry.db");
        }
        db = new Database(DB_PATH, { create: true });
        // Performance optimizations
        db.exec("PRAGMA journal_mode = WAL");
        db.exec("PRAGMA synchronous = NORMAL");
        db.exec("PRAGMA cache_size = 10000");
        db.exec("PRAGMA temp_store = MEMORY");
        db.exec("PRAGMA mmap_size = 268435456"); // 256MB memory-mapped I/O
        initAllSchemas();
    }
    return db;
}

function initAllSchemas(): void {
    const db = getDatabase();

    // ========================================================================
    // PACKAGES TABLE - Core package metadata
    // ========================================================================
    db.exec(`
        CREATE TABLE IF NOT EXISTS packages (
            name TEXT PRIMARY KEY,
            metadata TEXT NOT NULL,
            _source TEXT DEFAULT 'local',
            version_count INTEGER DEFAULT 0,
            total_downloads INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_packages_source ON packages(_source);
        CREATE INDEX IF NOT EXISTS idx_packages_updated ON packages(updated_at);
    `);

    // ========================================================================
    // SCAN_RESULTS TABLE - Security scan history
    // ========================================================================
    db.exec(`
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            package_name TEXT NOT NULL,
            version TEXT NOT NULL,
            tarball_hash TEXT NOT NULL,
            safe INTEGER NOT NULL,
            issues_count INTEGER DEFAULT 0,
            issues TEXT,
            files_scanned INTEGER DEFAULT 0,
            scan_time_ms INTEGER DEFAULT 0,
            pi_score INTEGER DEFAULT 0,
            pi_count INTEGER DEFAULT 0,
            pi_findings TEXT,
            scanned_at TEXT DEFAULT (datetime('now')),
            UNIQUE(package_name, version)
        );
        CREATE INDEX IF NOT EXISTS idx_scan_package ON scan_results(package_name);
        CREATE INDEX IF NOT EXISTS idx_scan_hash ON scan_results(tarball_hash);
        CREATE INDEX IF NOT EXISTS idx_scan_safe ON scan_results(safe);
    `);

    // Migration: add PI columns if missing (for existing databases)
    try {
        db.exec(`ALTER TABLE scan_results ADD COLUMN pi_score INTEGER DEFAULT 0`);
    } catch { /* column already exists */ }
    try {
        db.exec(`ALTER TABLE scan_results ADD COLUMN pi_count INTEGER DEFAULT 0`);
    } catch { /* column already exists */ }
    try {
        db.exec(`ALTER TABLE scan_results ADD COLUMN pi_findings TEXT`);
    } catch { /* column already exists */ }

    // ========================================================================
    // REQUEST_LOGS TABLE - HTTP request history
    // ========================================================================
    db.exec(`
        CREATE TABLE IF NOT EXISTS request_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id TEXT NOT NULL,
            method TEXT NOT NULL,
            path TEXT NOT NULL,
            status_code INTEGER,
            duration_ms INTEGER,
            client_ip TEXT DEFAULT '127.0.0.1',
            user_agent TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_request_created ON request_logs(created_at);
        CREATE INDEX IF NOT EXISTS idx_request_path ON request_logs(path);
        CREATE INDEX IF NOT EXISTS idx_request_status ON request_logs(status_code);
    `);

    // ========================================================================
    // AUDIT_LOG TABLE - Security & admin actions
    // ========================================================================
    db.exec(`
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            target TEXT,
            details TEXT,
            severity TEXT DEFAULT 'info',
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
        CREATE INDEX IF NOT EXISTS idx_audit_severity ON audit_log(severity);
        CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
    `);

    // ========================================================================
    // STATS TABLE - Aggregated statistics
    // ========================================================================
    db.exec(`
        CREATE TABLE IF NOT EXISTS stats (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT DEFAULT (datetime('now'))
        );
    `);

    // ========================================================================
    // RATE_LIMIT TABLE - Persistent rate limiting
    // ========================================================================
    db.exec(`
        CREATE TABLE IF NOT EXISTS rate_limits (
            ip TEXT PRIMARY KEY,
            request_count INTEGER DEFAULT 0,
            window_start TEXT DEFAULT (datetime('now'))
        );
    `);
}

// ============================================================================
// Package Operations
// ============================================================================

export interface PackageMetadata {
    name: string;
    description?: string;
    "dist-tags": Record<string, string>;
    versions: Record<string, any>;
    time: Record<string, string>;
    _id: string;
    _rev: string;
    _source?: string;
}

export function loadPackageFromDB(name: string): PackageMetadata | null {
    const db = getDatabase();
    const stmt = db.prepare("SELECT metadata FROM packages WHERE name = ?");
    const row = stmt.get(name) as { metadata: string } | null;
    if (!row) return null;
    return safeJsonParse<PackageMetadata>(row.metadata);
}

export function getAllPackages(): PackageMetadata[] {
    const db = getDatabase();
    const rows = db.query("SELECT metadata FROM packages").all() as { metadata: string }[];
    return rows.map(row => safeJsonParse<PackageMetadata>(row.metadata)).filter((p): p is PackageMetadata => p !== null);
}

export function savePackageToDB(pkg: PackageMetadata): void {
    const db = getDatabase();
    const versionCount = Object.keys(pkg.versions || {}).length;
    const stmt = db.prepare(`
        INSERT INTO packages (name, metadata, _source, version_count, updated_at) 
        VALUES (?, ?, ?, ?, datetime('now'))
        ON CONFLICT(name) DO UPDATE SET 
            metadata = excluded.metadata,
            _source = excluded._source,
            version_count = excluded.version_count,
            updated_at = datetime('now')
    `);
    stmt.run(pkg.name, JSON.stringify(pkg), pkg._source || "local", versionCount);
}

export function deletePackageFromDB(name: string): boolean {
    const db = getDatabase();
    const stmt = db.prepare("DELETE FROM packages WHERE name = ?");
    const result = stmt.run(name);
    return result.changes > 0;
}

export function listPackagesFromDB(): string[] {
    const db = getDatabase();
    const stmt = db.prepare("SELECT name FROM packages ORDER BY name");
    const rows = stmt.all() as { name: string }[];
    return rows.map(r => r.name);
}

export interface PackageSearchResult {
    name: string;
    description?: string;
    version: string;
    source: string;
    downloads: number;
    updatedAt: string;
}

export function searchPackages(query: string, limit: number = 50): PackageSearchResult[] {
    const db = getDatabase();
    const terms = query.toLowerCase().split(/\s+/).filter(t => t.length > 0);
    if (terms.length === 0) return [];

    // Fetch all packages for in-memory scoring (efficient for local registry size)
    const stmt = db.prepare(`
        SELECT 
            name, 
            metadata, 
            _source as source,
            total_downloads as downloads,
            updated_at as updatedAt
        FROM packages
    `);

    const rows = stmt.all() as any[];

    const scored = rows.map(row => {
        let description = "";
        let version = "0.0.0";
        let keywords: string[] = [];

        const meta = safeJsonParse<any>(row.metadata);
        if (meta) {
            description = (meta.description || "").toLowerCase();
            const latestTag = meta["dist-tags"]?.latest;
            version = latestTag || Object.keys(meta.versions || {})[0] || "0.0.0";
            keywords = (meta.keywords || []).map((k: any) => String(k).toLowerCase());
        }

        const name = row.name.toLowerCase();
        let score = 0;

        // Scoring Logic
        for (const term of terms) {
            // Name matches
            if (name === term) score += 100;
            else if (name.startsWith(term)) score += 50;
            else if (name.includes(term)) score += 20;

            // Description matches
            if (description.includes(term)) score += 5;

            // Keyword matches
            if (keywords.some(k => k === term)) score += 15;
            else if (keywords.some(k => k.includes(term))) score += 5;
        }

        if (name.includes("smart")) {

        }

        // Boost by downloads (log scale)
        const downloadBoost = Math.log10((row.downloads || 0) + 1) * 2;
        score += downloadBoost;

        return {
            name: row.name,
            description: description, // Return original case? user expects display text.
            // Ideally we need original description.
            originalDescription: safeJsonParse<any>(row.metadata)?.description || "",
            version,
            source: row.source || "local",
            downloads: row.downloads || 0,
            updatedAt: row.updatedAt,
            score
        };
    });

    return scored
        .filter(r => r.score > 0)
        .sort((a, b) => b.score - a.score)
        .slice(0, limit)
        .map(r => ({
            name: r.name,
            description: r.originalDescription,
            version: r.version,
            source: r.source,
            downloads: r.downloads,
            updatedAt: r.updatedAt
        }));
}

export function getPackagesBySource(source: "local" | "upstream"): string[] {
    const db = getDatabase();
    const stmt = db.prepare("SELECT name FROM packages WHERE _source = ?");
    const rows = stmt.all(source) as { name: string }[];
    return rows.map(r => r.name);
}

export function countPackages(): { total: number; local: number; upstream: number } {
    const db = getDatabase();
    const total = (db.prepare("SELECT COUNT(*) as count FROM packages").get() as { count: number }).count;
    const local = (db.prepare("SELECT COUNT(*) as count FROM packages WHERE _source = 'local'").get() as { count: number }).count;
    const upstream = (db.prepare("SELECT COUNT(*) as count FROM packages WHERE _source = 'upstream'").get() as { count: number }).count;
    return { total, local, upstream };
}

export function incrementDownloads(name: string): void {
    const db = getDatabase();
    db.prepare("UPDATE packages SET total_downloads = total_downloads + 1 WHERE name = ?").run(name);
}

// ============================================================================
// Scan Results Operations
// ============================================================================

export interface ScanResultRecord {
    package_name: string;
    version: string;
    tarball_hash: string;
    safe: boolean;
    issues_count: number;
    issues: any[];
    files_scanned: number;
    scan_time_ms: number;
    pi_score?: number;
    pi_count?: number;
    pi_findings?: any[];
}

export function saveScanResult(result: ScanResultRecord): void {
    const db = getDatabase();
    const stmt = db.prepare(`
        INSERT INTO scan_results (package_name, version, tarball_hash, safe, issues_count, issues, files_scanned, scan_time_ms, pi_score, pi_count, pi_findings)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(package_name, version) DO UPDATE SET
            tarball_hash = excluded.tarball_hash,
            safe = excluded.safe,
            issues_count = excluded.issues_count,
            issues = excluded.issues,
            files_scanned = excluded.files_scanned,
            scan_time_ms = excluded.scan_time_ms,
            pi_score = excluded.pi_score,
            pi_count = excluded.pi_count,
            pi_findings = excluded.pi_findings,
            scanned_at = datetime('now')
    `);
    stmt.run(
        result.package_name,
        result.version,
        result.tarball_hash,
        result.safe ? 1 : 0,
        result.issues_count,
        JSON.stringify(result.issues),
        result.files_scanned,
        result.scan_time_ms,
        result.pi_score ?? 0,
        result.pi_count ?? 0,
        result.pi_findings ? JSON.stringify(result.pi_findings) : null
    );
}

export function getScanResultByHash(hash: string): ScanResultRecord | null {
    const db = getDatabase();
    const stmt = db.prepare("SELECT * FROM scan_results WHERE tarball_hash = ?");
    const row = stmt.get(hash) as any | null;
    if (!row) return null;
    return {
        ...row,
        safe: row.safe === 1,
        issues: safeJsonParse<any[]>(row.issues || "[]") || []
    };
}

export function getScanStats(): { total: number; safe: number; blocked: number; avgTimeMs: number } {
    const db = getDatabase();
    const total = (db.prepare("SELECT COUNT(*) as count FROM scan_results").get() as { count: number }).count;
    const safe = (db.prepare("SELECT COUNT(*) as count FROM scan_results WHERE safe = 1").get() as { count: number }).count;
    const avgTime = (db.prepare("SELECT AVG(scan_time_ms) as avg FROM scan_results").get() as { avg: number }).avg || 0;
    return { total, safe, blocked: total - safe, avgTimeMs: Math.round(avgTime) };
}

export function getRecentBlockedPackages(limit: number = 10): { package_name: string; version: string; issues_count: number; scanned_at: string }[] {
    const db = getDatabase();
    const stmt = db.prepare(`
        SELECT package_name, version, issues_count, scanned_at 
        FROM scan_results 
        WHERE safe = 0 
        ORDER BY scanned_at DESC 
        LIMIT ?
    `);
    return stmt.all(limit) as { package_name: string; version: string; issues_count: number; scanned_at: string }[];
}

// ============================================================================
// Request Logging
// ============================================================================

export function logRequest(log: {
    requestId: string;
    method: string;
    path: string;
    statusCode: number;
    durationMs: number;
    userAgent?: string;
}): void {
    const db = getDatabase();
    const stmt = db.prepare(`
        INSERT INTO request_logs (request_id, method, path, status_code, duration_ms, user_agent)
        VALUES (?, ?, ?, ?, ?, ?)
    `);
    stmt.run(log.requestId, log.method, log.path, log.statusCode, log.durationMs, log.userAgent || null);
}

export function getRequestStats(): {
    total: number;
    avgDurationMs: number;
    errorRate: number;
    requestsPerMinute: number;
} {
    const db = getDatabase();
    const total = (db.prepare("SELECT COUNT(*) as count FROM request_logs").get() as { count: number }).count;
    const avgDuration = (db.prepare("SELECT AVG(duration_ms) as avg FROM request_logs").get() as { avg: number }).avg || 0;
    const errors = (db.prepare("SELECT COUNT(*) as count FROM request_logs WHERE status_code >= 400").get() as { count: number }).count;
    const lastMinute = (db.prepare(`
        SELECT COUNT(*) as count FROM request_logs 
        WHERE created_at > datetime('now', '-1 minute')
    `).get() as { count: number }).count;

    return {
        total,
        avgDurationMs: Math.round(avgDuration),
        errorRate: total > 0 ? (errors / total) * 100 : 0,
        requestsPerMinute: lastMinute
    };
}

// ============================================================================
// Audit Logging
// ============================================================================

export type AuditAction =
    | "package_published"
    | "package_unpublished"
    | "package_blocked"
    | "package_approved"
    | "scan_completed"
    | "cache_cleared"
    | "rate_limit_exceeded"
    | "security_alert"
    | "server_started"
    | "server_stopped"
    | "cve_scan"
    | "config_change"
    | "allowlist_add"
    | "allowlist_remove"
    | "allowlist_toggle";
export interface AuditLogEntry {
    id: number;
    action: AuditAction;
    target?: string | null;
    details?: string | null; // JSON string in DB
    severity: "info" | "warn" | "error";
    created_at: string;
}

export function logAudit(action: AuditAction, target?: string | null, details?: unknown, severity: "info" | "warn" | "error" = "info"): void {
    const db = getDatabase();
    const stmt = db.prepare(`
        INSERT INTO audit_log (action, target, details, severity)
        VALUES (?, ?, ?, ?)
    `);
    stmt.run(action, target || null, details ? JSON.stringify(details) : null, severity);
}

export function getRecentAuditLogs(limit: number = 50): AuditLogEntry[] {
    const db = getDatabase();
    const stmt = db.prepare(`
        SELECT * FROM audit_log 
        ORDER BY created_at DESC 
        LIMIT ?
    `);
    return stmt.all(limit) as AuditLogEntry[];
}

export interface AuditExportOptions {
    startDate?: string;
    endDate?: string;
    actions?: AuditAction[];
    severity?: ("info" | "warn" | "error")[];
    limit?: number;
}

export function getAuditLogsForExport(options: AuditExportOptions = {}): AuditLogEntry[] {
    const db = getDatabase();

    let query = "SELECT * FROM audit_log WHERE 1=1";
    const params: any[] = [];

    if (options.startDate) {
        query += " AND created_at >= ?";
        params.push(options.startDate);
    }
    if (options.endDate) {
        query += " AND created_at <= ?";
        params.push(options.endDate);
    }
    if (options.actions && options.actions.length > 0) {
        query += ` AND action IN (${options.actions.map(() => "?").join(", ")})`;
        params.push(...options.actions);
    }
    if (options.severity && options.severity.length > 0) {
        query += ` AND severity IN (${options.severity.map(() => "?").join(", ")})`;
        params.push(...options.severity);
    }

    query += " ORDER BY created_at DESC";

    if (options.limit) {
        query += " LIMIT ?";
        params.push(options.limit);
    }

    const stmt = db.prepare(query);
    return stmt.all(...params) as AuditLogEntry[];
}

export function formatAuditLogsAsCSV(logs: AuditLogEntry[]): string {
    if (logs.length === 0) return "id,action,target,details,severity,created_at\n";

    const header = "id,action,target,details,severity,created_at";
    const rows = logs.map(log => {
        const details = log.details ? `"${String(log.details).replace(/"/g, '""')}"` : "";
        const target = log.target ? `"${String(log.target).replace(/"/g, '""')}"` : "";
        return `${log.id},${log.action},${target},${details},${log.severity},${log.created_at}`;
    });

    return [header, ...rows].join("\n");
}

export function getAuditLogCount(): number {
    const db = getDatabase();
    const stmt = db.prepare("SELECT COUNT(*) as count FROM audit_log");
    const row = stmt.get() as { count: number };
    return row.count;
}

export function getAuditLogsByAction(action: AuditAction, limit: number = 20): AuditLogEntry[] {
    const db = getDatabase();
    const stmt = db.prepare(`
        SELECT * FROM audit_log 
        WHERE action = ? 
        ORDER BY created_at DESC 
        LIMIT ?
    `);
    return stmt.all(action, limit) as AuditLogEntry[];
}

// ============================================================================
// Statistics
// ============================================================================

export function setStat(key: string, value: unknown): void {
    const db = getDatabase();
    const stmt = db.prepare(`
        INSERT INTO stats (key, value, updated_at)
        VALUES (?, ?, datetime('now'))
        ON CONFLICT(key) DO UPDATE SET
            value = excluded.value,
            updated_at = datetime('now')
    `);
    stmt.run(key, JSON.stringify(value));
}

export function getStat(key: string): unknown {
    const db = getDatabase();
    const stmt = db.prepare("SELECT value FROM stats WHERE key = ?");
    const row = stmt.get(key) as { value: string } | null;
    return row ? safeJsonParse(row.value) : null;
}

export function getAllStats(): Record<string, unknown> {
    const db = getDatabase();
    const rows = db.prepare("SELECT key, value FROM stats").all() as { key: string; value: string }[];
    const stats: Record<string, unknown> = {};
    for (const row of rows) {
        stats[row.key] = safeJsonParse(row.value);
    }
    return stats;
}

// ============================================================================
// Persistent Rate Limiting
// ============================================================================

export function checkRateLimitDB(ip: string, maxRequests: number, windowMs: number): { allowed: boolean; remaining: number } {
    const db = getDatabase();
    const now = new Date().toISOString();
    const windowStart = new Date(Date.now() - windowMs).toISOString();

    // Clean up old entries
    db.prepare("DELETE FROM rate_limits WHERE window_start < ?").run(windowStart);

    // Get current count
    const row = db.prepare("SELECT request_count, window_start FROM rate_limits WHERE ip = ?").get(ip) as { request_count: number; window_start: string } | null;

    if (!row || row.window_start < windowStart) {
        // New window
        db.prepare(`
            INSERT INTO rate_limits (ip, request_count, window_start)
            VALUES (?, 1, ?)
            ON CONFLICT(ip) DO UPDATE SET
                request_count = 1,
                window_start = excluded.window_start
        `).run(ip, now);
        return { allowed: true, remaining: maxRequests - 1 };
    }

    if (row.request_count >= maxRequests) {
        return { allowed: false, remaining: 0 };
    }

    // Increment
    db.prepare("UPDATE rate_limits SET request_count = request_count + 1 WHERE ip = ?").run(ip);
    return { allowed: true, remaining: maxRequests - row.request_count - 1 };
}

// ============================================================================
// Comprehensive Stats for Admin Dashboard
// ============================================================================

export function getComprehensiveStats(): {
    packages: { total: number; local: number; upstream: number };
    scans: { total: number; safe: number; blocked: number; avgTimeMs: number };
    requests: { total: number; avgDurationMs: number; errorRate: number; requestsPerMinute: number };
    database: { sizeBytes: number; tableCount: number };
} {
    const db = getDatabase();

    // Get DB file size
    let dbSize = 0;
    try {
        const file = Bun.file(DB_PATH);
        dbSize = file.size;
    } catch { }

    return {
        packages: countPackages(),
        scans: getScanStats(),
        requests: getRequestStats(),
        database: {
            sizeBytes: dbSize,
            tableCount: 6
        }
    };
}

// ============================================================================
// Migration & Cleanup
// ============================================================================

export async function migrateJsonToSqlite(packagesDir: string): Promise<number> {
    const { readdir } = await import("node:fs/promises");

    let migrated = 0;
    const files = await readdir(packagesDir).catch(() => []);

    for (const file of files) {
        if (!file.endsWith(".json")) continue;

        const filePath = join(packagesDir, file);

        try {
            const content = await Bun.file(filePath).text();
            const pkg = safeJsonParse<PackageMetadata>(content);
            if (pkg) savePackageToDB(pkg);
            migrated++;
        } catch (e) {
            logger.error(`Failed to migrate ${file}: ${e}`);
        }
    }

    logAudit("server_started", undefined, { migratedPackages: migrated });
    return migrated;
}

export function vacuumDatabase(): void {
    const db = getDatabase();
    db.exec("VACUUM");
}

// ============================================================================
// Automatic Log Cleanup (prevents infinite growth)
// ============================================================================

export interface CleanupResult {
    requestLogs: number;
    auditLogs: number;
    scanResults: number;
    freedBytes: number;
}

/**
 * Clean up old logs older than specified days.
 * Default: 7 days for request_logs, 30 days for audit_logs, 30 days for scan_results
 */
export function cleanupOldLogs(options?: {
    requestLogsDays?: number;
    auditLogsDays?: number;
    scanResultsDays?: number;
}): CleanupResult {
    const db = getDatabase();
    const requestDays = options?.requestLogsDays ?? 7;
    const auditDays = options?.auditLogsDays ?? 30;
    const scanDays = options?.scanResultsDays ?? 30;

    // Get initial DB size
    let initialSize = 0;
    try {
        initialSize = Bun.file(DB_PATH).size;
    } catch { }

    // Cleanup request_logs (keep last N days)
    const reqResult = db.prepare(`
        DELETE FROM request_logs 
        WHERE created_at < datetime('now', '-' || ? || ' days')
    `).run(requestDays);

    // Cleanup audit_logs (keep last N days, but never delete security_alert or package_blocked)
    const auditResult = db.prepare(`
        DELETE FROM audit_log 
        WHERE created_at < datetime('now', '-' || ? || ' days')
        AND action NOT IN ('security_alert', 'package_blocked')
    `).run(auditDays);

    // Cleanup scan_results (keep last N days, but keep blocked packages forever)
    const scanResult = db.prepare(`
        DELETE FROM scan_results 
        WHERE scanned_at < datetime('now', '-' || ? || ' days')
        AND safe = 1
    `).run(scanDays);

    // Vacuum to reclaim space
    db.exec("VACUUM");

    // Get final DB size
    let finalSize = 0;
    try {
        finalSize = Bun.file(DB_PATH).size;
    } catch { }

    const result: CleanupResult = {
        requestLogs: reqResult.changes,
        auditLogs: auditResult.changes,
        scanResults: scanResult.changes,
        freedBytes: Math.max(0, initialSize - finalSize)
    };

    // Log cleanup action
    if (result.requestLogs > 0 || result.auditLogs > 0 || result.scanResults > 0) {
        logAudit("cache_cleared", "logs_cleanup", {
            ...result,
            config: { requestDays, auditDays, scanDays }
        });
    }

    return result;
}

/**
 * Get log counts for monitoring
 */
export function getLogCounts(): { requestLogs: number; auditLogs: number; scanResults: number } {
    const db = getDatabase();
    return {
        requestLogs: (db.prepare("SELECT COUNT(*) as count FROM request_logs").get() as { count: number }).count,
        auditLogs: (db.prepare("SELECT COUNT(*) as count FROM audit_log").get() as { count: number }).count,
        scanResults: (db.prepare("SELECT COUNT(*) as count FROM scan_results").get() as { count: number }).count
    };
}

export function closeDatabase(): void {
    if (db) {
        db.close();
        db = null;
    }
}
