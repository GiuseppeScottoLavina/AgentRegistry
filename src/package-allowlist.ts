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
 * AgentRegistry Package Allowlist Module
 * 
 * Provides dynamic package whitelisting with:
 * - SQLite-backed persistent storage
 * - Prefix/glob pattern support (e.g., "@opentelemetry/", "lodash*")
 * - Category organization (build-tools, testing, observability, etc.)
 * - Default entries (pre-seeded, can disable but not delete)
 * - Admin management via WebSocket
 */

import { Database } from "bun:sqlite";
import { join } from "node:path";
import { STORAGE_DIR } from "./config";

// Safe audit logging that doesn't fail if database context is different (test isolation)
function safeLogAudit(action: string, target: string, details?: Record<string, unknown>): void {
    try {
        // Dynamic import to avoid circular dependency and handle test isolation
        const { logAudit } = require("./database");
        logAudit(action, target, details);
    } catch {
        // Silently ignore if we're in test mode with isolated database
    }
}

// ============================================================================
// Types & Interfaces
// ============================================================================

export interface PackageAllowlistEntry {
    id: number;
    pattern: string;           // e.g., "@opentelemetry/", "lodash", "esbuild"
    description: string | null;
    category: string;          // e.g., "build-tools", "testing", "observability"
    is_default: boolean;       // Pre-seeded defaults (user can disable but not delete)
    enabled: boolean;
    created_at: string;
}

export interface PackageAllowlistConfig {
    enabled: boolean;          // Is allowlist enforcement active? (default: true)
}

// ============================================================================
// Default Packages (migrated from hardcoded TRUSTED_PACKAGES)
// ============================================================================

const DEFAULT_PACKAGES: Array<{ pattern: string; description: string; category: string }> = [
    // Observability
    { pattern: "@opentelemetry/", description: "OpenTelemetry CNCF project", category: "observability" },
    { pattern: "opentelemetry-", description: "OpenTelemetry tarball names", category: "observability" },
    { pattern: "@sentry/", description: "Sentry error monitoring", category: "observability" },
    { pattern: "sentry-", description: "Sentry tarball names", category: "observability" },
    { pattern: "lighthouse", description: "Google Lighthouse", category: "observability" },

    // Build tools
    { pattern: "esbuild", description: "Fast JS bundler", category: "build-tools" },
    { pattern: "vite", description: "Next-gen frontend tooling", category: "build-tools" },
    { pattern: "webpack", description: "Module bundler", category: "build-tools" },
    { pattern: "rollup", description: "ES module bundler", category: "build-tools" },
    { pattern: "parcel", description: "Zero-config bundler", category: "build-tools" },
    { pattern: "turbo", description: "Turborepo build system", category: "build-tools" },

    // Testing
    { pattern: "jest", description: "JavaScript testing framework", category: "testing" },
    { pattern: "mocha", description: "Test framework", category: "testing" },
    { pattern: "vitest", description: "Vite-native testing", category: "testing" },
    { pattern: "cypress", description: "E2E testing framework", category: "testing" },
    { pattern: "axe-core", description: "Accessibility testing", category: "testing" },

    // Parsers/Compilers
    { pattern: "acorn", description: "JavaScript parser", category: "parsers" },
    { pattern: "babel", description: "JavaScript compiler", category: "parsers" },
    { pattern: "typescript", description: "TypeScript compiler", category: "parsers" },
    { pattern: "esprima", description: "ECMAScript parser", category: "parsers" },
    { pattern: "terser", description: "JavaScript minifier", category: "parsers" },
    { pattern: "uglify", description: "JavaScript minifier", category: "parsers" },

    // CLI tools
    { pattern: "enquirer", description: "CLI prompts", category: "cli" },
    { pattern: "commander", description: "CLI framework", category: "cli" },
    { pattern: "yargs", description: "CLI parser", category: "cli" },
    { pattern: "chalk", description: "Terminal colors", category: "cli" },
    { pattern: "ora", description: "Terminal spinners", category: "cli" },

    // Node.js utilities
    { pattern: "fs-extra", description: "Extended fs module", category: "node-utils" },
    { pattern: "graceful-fs", description: "Graceful filesystem", category: "node-utils" },
    { pattern: "rimraf", description: "rm -rf for Node", category: "node-utils" },
    { pattern: "mkdirp", description: "mkdir -p for Node", category: "node-utils" },

    // Networking
    { pattern: "axios", description: "HTTP client", category: "networking" },
    { pattern: "got", description: "HTTP client", category: "networking" },
    { pattern: "node-fetch", description: "Fetch for Node", category: "networking" },
    { pattern: "undici", description: "HTTP/1.1 client", category: "networking" },

    // Browser automation
    { pattern: "puppeteer", description: "Chrome automation", category: "browser" },
    { pattern: "playwright", description: "Browser automation", category: "browser" },
    { pattern: "chrome-launcher", description: "Launch Chrome", category: "browser" },

    // Verified utilities
    { pattern: "lodash", description: "Utility library", category: "verified" },
    { pattern: "lodash-es", description: "Lodash ES modules", category: "verified" },
    { pattern: "debug", description: "Debug logging", category: "verified" },
    { pattern: "dotenv", description: "Environment variables", category: "verified" },
    { pattern: "semver", description: "Semantic versioning", category: "verified" },
    { pattern: "uuid", description: "UUID generation", category: "verified" },
    { pattern: "moment", description: "Date library", category: "verified" },
    { pattern: "dayjs", description: "Date library", category: "verified" },
    { pattern: "date-fns", description: "Date utilities", category: "verified" },

    // FormatJS
    { pattern: "@formatjs/", description: "FormatJS i18n", category: "verified" },
    { pattern: "formatjs-", description: "FormatJS tarball names", category: "verified" },
    { pattern: "intl-messageformat", description: "FormatJS message format", category: "verified" },

    // Additional verified packages
    { pattern: "atomically", description: "Atomic file operations", category: "verified" },
    { pattern: "csp_evaluator", description: "Google CSP checker", category: "verified" },
    { pattern: "http-link-header", description: "HTTP Link header", category: "verified" },
    { pattern: "import-in-the-middle", description: "Import interception", category: "verified" },
    { pattern: "js-library-detector", description: "Library detection", category: "verified" },
    { pattern: "paulirish-", description: "Paul Irish DevTools", category: "verified" },
    { pattern: "trace_engine", description: "Chrome trace engine", category: "verified" },
    { pattern: "xdg-basedir", description: "XDG directories", category: "verified" },
    { pattern: "signalbus", description: "Local postMessage wrapper", category: "local" },
];

// ============================================================================
// Database Setup
// ============================================================================

let ALLOWLIST_DB_PATH = join(STORAGE_DIR, "agentregistry.db");
let db: Database | null = null;

/**
 * FOR TESTING ONLY: Set a custom database path for isolated tests.
 */
export function setPackageAllowlistDatabaseForTesting(customPath: string): void {
    if (db) {
        db.close();
        db = null;
    }
    ALLOWLIST_DB_PATH = customPath;
}

/**
 * FOR TESTING ONLY: Reset to default database path.
 */
export function resetPackageAllowlistDatabasePath(): void {
    if (db) {
        db.close();
        db = null;
    }
    ALLOWLIST_DB_PATH = join(STORAGE_DIR, "agentregistry.db");
}

/**
 * FOR TESTING ONLY: Close the database connection.
 */
export function closePackageAllowlistDatabase(): void {
    if (db) {
        db.close();
        db = null;
    }
}

function getDatabase(): Database {
    if (!db) {
        db = new Database(ALLOWLIST_DB_PATH, { create: true });
        initSchema();
    }
    return db;
}

function initSchema(): void {
    const database = getDatabase();

    // Package Allowlist table
    database.exec(`
        CREATE TABLE IF NOT EXISTS package_allowlist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern TEXT NOT NULL UNIQUE,
            description TEXT,
            category TEXT DEFAULT 'custom',
            is_default INTEGER DEFAULT 0,
            enabled INTEGER DEFAULT 1,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_pkg_allowlist_pattern ON package_allowlist(pattern);
        CREATE INDEX IF NOT EXISTS idx_pkg_allowlist_category ON package_allowlist(category);
        CREATE INDEX IF NOT EXISTS idx_pkg_allowlist_enabled ON package_allowlist(enabled);
    `);

    // Allowlist configuration table
    database.exec(`
        CREATE TABLE IF NOT EXISTS package_allowlist_config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
    `);

    // Insert default config if not exists
    const configCheck = database.prepare("SELECT COUNT(*) as count FROM package_allowlist_config").get() as { count: number };
    if (configCheck.count === 0) {
        database.exec(`
            INSERT INTO package_allowlist_config (key, value) VALUES
            ('enabled', 'true')
        `);
    }

    // Seed default packages if empty
    const entriesCheck = database.prepare("SELECT COUNT(*) as count FROM package_allowlist").get() as { count: number };
    if (entriesCheck.count === 0) {
        seedDefaultPackages();
    }
}

function seedDefaultPackages(): void {
    const database = getDatabase();
    const stmt = database.prepare(`
        INSERT OR IGNORE INTO package_allowlist (pattern, description, category, is_default, enabled)
        VALUES (?, ?, ?, 1, 1)
    `);

    for (const pkg of DEFAULT_PACKAGES) {
        stmt.run(pkg.pattern, pkg.description, pkg.category);
    }
}

// ============================================================================
// Configuration Management
// ============================================================================

export function getPackageAllowlistConfig(): PackageAllowlistConfig {
    const database = getDatabase();
    const rows = database.prepare("SELECT key, value FROM package_allowlist_config").all() as { key: string; value: string }[];

    const config: PackageAllowlistConfig = {
        enabled: true
    };

    for (const row of rows) {
        if (row.key === "enabled") config.enabled = row.value === "true";
    }

    return config;
}

export function updatePackageAllowlistConfig(updates: Partial<PackageAllowlistConfig>): PackageAllowlistConfig {
    const database = getDatabase();
    const stmt = database.prepare("INSERT OR REPLACE INTO package_allowlist_config (key, value) VALUES (?, ?)");

    if (updates.enabled !== undefined) {
        stmt.run("enabled", String(updates.enabled));
    }

    return getPackageAllowlistConfig();
}

// ============================================================================
// Allowlist Entry Management
// ============================================================================

export function addPackageToAllowlist(
    pattern: string,
    description?: string,
    category?: string
): PackageAllowlistEntry | null {
    const database = getDatabase();

    try {
        const stmt = database.prepare(`
            INSERT INTO package_allowlist (pattern, description, category, is_default, enabled)
            VALUES (?, ?, ?, 0, 1)
        `);
        stmt.run(pattern.trim(), description || null, category || "custom");

        const entry = database.prepare("SELECT * FROM package_allowlist WHERE pattern = ?").get(pattern.trim()) as PackageAllowlistEntry;

        safeLogAudit("allowlist_add", pattern, { description, category });

        return {
            ...entry,
            is_default: Boolean(entry.is_default),
            enabled: Boolean(entry.enabled)
        };
    } catch {
        // Unique constraint violation - pattern already exists
        return null;
    }
}

export function removeFromAllowlist(id: number): boolean {
    const database = getDatabase();

    // Check if it's a default entry (can't delete)
    const entry = database.prepare("SELECT * FROM package_allowlist WHERE id = ?").get(id) as PackageAllowlistEntry | null;
    if (!entry) return false;
    if (entry.is_default) {
        // Default entries can't be deleted, only disabled
        return false;
    }

    const stmt = database.prepare("DELETE FROM package_allowlist WHERE id = ? AND is_default = 0");
    const result = stmt.run(id);

    if (result.changes > 0) {
        safeLogAudit("allowlist_remove", entry.pattern, { id });
    }

    return result.changes > 0;
}

export function togglePackageAllowlistEntry(id: number, enabled: boolean): boolean {
    const database = getDatabase();
    const stmt = database.prepare("UPDATE package_allowlist SET enabled = ? WHERE id = ?");
    const result = stmt.run(enabled ? 1 : 0, id);

    if (result.changes > 0) {
        const entry = database.prepare("SELECT pattern FROM package_allowlist WHERE id = ?").get(id) as { pattern: string } | null;
        safeLogAudit("allowlist_toggle", entry?.pattern || String(id), { enabled });
    }

    return result.changes > 0;
}

export function listPackageAllowlist(): PackageAllowlistEntry[] {
    const database = getDatabase();
    const rows = database.prepare(`
        SELECT * FROM package_allowlist 
        ORDER BY category, pattern
    `).all() as PackageAllowlistEntry[];

    return rows.map(row => ({
        ...row,
        is_default: Boolean(row.is_default),
        enabled: Boolean(row.enabled)
    }));
}

export function getPackageAllowlistEntry(id: number): PackageAllowlistEntry | null {
    const database = getDatabase();
    const row = database.prepare("SELECT * FROM package_allowlist WHERE id = ?").get(id) as PackageAllowlistEntry | null;
    if (!row) return null;
    return {
        ...row,
        is_default: Boolean(row.is_default),
        enabled: Boolean(row.enabled)
    };
}

export function getPackageAllowlistCategories(): string[] {
    const database = getDatabase();
    const rows = database.prepare("SELECT DISTINCT category FROM package_allowlist ORDER BY category").all() as { category: string }[];
    return rows.map(r => r.category);
}

// ============================================================================
// Package Matching Logic
// ============================================================================

/**
 * Check if a package name matches any allowlist pattern.
 * Supports:
 * - Exact match: "lodash"
 * - Prefix match: "@opentelemetry/" matches "@opentelemetry/api"
 * - Ends with dash: "sentry-" matches "sentry-node"
 */
export function isPackageAllowlisted(packageName: string): boolean {
    try {
        const config = getPackageAllowlistConfig();

        // If allowlist is disabled, nothing is whitelisted (all packages get scanned)
        if (!config.enabled) {
            return false;
        }

        const entries = listPackageAllowlist().filter(e => e.enabled);

        for (const entry of entries) {
            if (matchesPackagePattern(packageName, entry.pattern)) {
                return true;
            }
        }

        return false;
    } catch {
        // Database unavailable (likely during test isolation) - fail safe by scanning
        return false;
    }
}

/**
 * Match a package name against a pattern.
 */
export function matchesPackagePattern(packageName: string, pattern: string): boolean {
    const name = packageName.toLowerCase();
    const pat = pattern.toLowerCase();

    // Exact match
    if (name === pat) {
        return true;
    }

    // Scoped package prefix (e.g., "@opentelemetry/" matches "@opentelemetry/api")
    if (pat.endsWith("/") && name.startsWith(pat)) {
        return true;
    }

    // Dash suffix (e.g., "sentry-" matches "sentry-node")
    if (pat.endsWith("-") && name.startsWith(pat)) {
        return true;
    }

    // Package name starts with pattern (e.g., "lodash" matches "lodash-es")
    if (name.startsWith(pat) && (name.length === pat.length || name[pat.length] === "-")) {
        return true;
    }

    return false;
}

// ============================================================================
// Summary & Stats
// ============================================================================

export function getPackageAllowlistSummary(): {
    config: PackageAllowlistConfig;
    totalEntries: number;
    enabledEntries: number;
    disabledEntries: number;
    defaultEntries: number;
    customEntries: number;
    categories: string[];
} {
    const config = getPackageAllowlistConfig();
    const entries = listPackageAllowlist();

    return {
        config,
        totalEntries: entries.length,
        enabledEntries: entries.filter(e => e.enabled).length,
        disabledEntries: entries.filter(e => !e.enabled).length,
        defaultEntries: entries.filter(e => e.is_default).length,
        customEntries: entries.filter(e => !e.is_default).length,
        categories: getPackageAllowlistCategories()
    };
}

// ============================================================================
// Re-seed function (for admin use)
// ============================================================================

/**
 * Re-seed default packages (useful after updates).
 * Only adds new defaults, doesn't overwrite existing entries.
 */
export function reseedDefaultPackages(): number {
    const database = getDatabase();
    const stmt = database.prepare(`
        INSERT OR IGNORE INTO package_allowlist (pattern, description, category, is_default, enabled)
        VALUES (?, ?, ?, 1, 1)
    `);

    let added = 0;
    for (const pkg of DEFAULT_PACKAGES) {
        const result = stmt.run(pkg.pattern, pkg.description, pkg.category);
        if (result.changes > 0) added++;
    }

    return added;
}
