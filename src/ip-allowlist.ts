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
 * AgentRegistry IP Allowlist Module
 * 
 * Provides IP-based access control with:
 * - SQLite-backed persistent storage
 * - CIDR notation support (e.g., 192.168.1.0/24)
 * - Wildcard patterns (e.g., 192.168.*)
 * - Admin management API
 * - Default: allow all (empty list = no restrictions)
 */

import { Database } from "bun:sqlite";
import { join } from "node:path";

// ============================================================================
// Types & Interfaces
// ============================================================================

export interface AllowlistEntry {
    id: number;
    pattern: string;
    description: string | null;
    created_at: string;
    enabled: boolean;
}

export interface AllowlistConfig {
    enabled: boolean;           // Is allowlist enforcement active?
    mode: "allowlist" | "blocklist";  // Allow or block matching IPs
    defaultAllow: boolean;      // If no rules match, allow or deny?
}

// ============================================================================
// Database Setup
// ============================================================================

import { STORAGE_DIR } from "./config";
let ALLOWLIST_DB_PATH = join(STORAGE_DIR, "agentregistry.db");

let db: Database | null = null;

/**
 * FOR TESTING ONLY: Set a custom database path for isolated tests.
 */
export function setAllowlistDatabaseForTesting(customPath: string): void {
    if (db) {
        db.close();
        db = null;
    }
    ALLOWLIST_DB_PATH = customPath;
}

/**
 * FOR TESTING ONLY: Reset to default database path.
 */
export function resetAllowlistDatabasePath(): void {
    if (db) {
        db.close();
        db = null;
    }
    ALLOWLIST_DB_PATH = join(STORAGE_DIR, "agentregistry.db");
}

/**
 * FOR TESTING ONLY: Close the database connection.
 */
export function closeAllowlistDatabase(): void {
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

    // IP Allowlist table
    database.exec(`
        CREATE TABLE IF NOT EXISTS ip_allowlist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern TEXT NOT NULL UNIQUE,
            description TEXT,
            enabled INTEGER DEFAULT 1,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_allowlist_pattern ON ip_allowlist(pattern);
        CREATE INDEX IF NOT EXISTS idx_allowlist_enabled ON ip_allowlist(enabled);
    `);

    // Allowlist configuration table
    database.exec(`
        CREATE TABLE IF NOT EXISTS ip_allowlist_config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
    `);

    // Insert default config if not exists
    const configCheck = database.prepare("SELECT COUNT(*) as count FROM ip_allowlist_config").get() as { count: number };
    if (configCheck.count === 0) {
        database.exec(`
            INSERT INTO ip_allowlist_config (key, value) VALUES
            ('enabled', 'false'),
            ('mode', 'allowlist'),
            ('defaultAllow', 'true')
        `);
    }
}

// ============================================================================
// Configuration Management
// ============================================================================

export function getConfig(): AllowlistConfig {
    const database = getDatabase();
    const rows = database.prepare("SELECT key, value FROM ip_allowlist_config").all() as { key: string; value: string }[];

    const config: AllowlistConfig = {
        enabled: false,
        mode: "allowlist",
        defaultAllow: true
    };

    for (const row of rows) {
        if (row.key === "enabled") config.enabled = row.value === "true";
        if (row.key === "mode") config.mode = row.value as "allowlist" | "blocklist";
        if (row.key === "defaultAllow") config.defaultAllow = row.value === "true";
    }

    return config;
}

export function updateConfig(updates: Partial<AllowlistConfig>): AllowlistConfig {
    const database = getDatabase();
    const stmt = database.prepare("INSERT OR REPLACE INTO ip_allowlist_config (key, value) VALUES (?, ?)");

    if (updates.enabled !== undefined) {
        stmt.run("enabled", String(updates.enabled));
    }
    if (updates.mode !== undefined) {
        stmt.run("mode", updates.mode);
    }
    if (updates.defaultAllow !== undefined) {
        stmt.run("defaultAllow", String(updates.defaultAllow));
    }

    return getConfig();
}

// ============================================================================
// Allowlist Entry Management
// ============================================================================

export function addEntry(pattern: string, description?: string): AllowlistEntry | null {
    const database = getDatabase();

    try {
        const stmt = database.prepare(`
            INSERT INTO ip_allowlist (pattern, description)
            VALUES (?, ?)
        `);
        stmt.run(pattern, description || null);

        const entry = database.prepare("SELECT * FROM ip_allowlist WHERE pattern = ?").get(pattern) as AllowlistEntry;
        return {
            ...entry,
            enabled: Boolean(entry.enabled)
        };
    } catch (e) {
        // Unique constraint violation - pattern already exists
        return null;
    }
}

export function removeEntry(id: number): boolean {
    const database = getDatabase();
    const stmt = database.prepare("DELETE FROM ip_allowlist WHERE id = ?");
    const result = stmt.run(id);
    return result.changes > 0;
}

export function toggleEntry(id: number, enabled: boolean): boolean {
    const database = getDatabase();
    const stmt = database.prepare("UPDATE ip_allowlist SET enabled = ? WHERE id = ?");
    const result = stmt.run(enabled ? 1 : 0, id);
    return result.changes > 0;
}

export function listEntries(): AllowlistEntry[] {
    const database = getDatabase();
    const rows = database.prepare("SELECT * FROM ip_allowlist ORDER BY created_at DESC").all() as AllowlistEntry[];
    return rows.map(row => ({
        ...row,
        enabled: Boolean(row.enabled)
    }));
}

export function getEntry(id: number): AllowlistEntry | null {
    const database = getDatabase();
    const row = database.prepare("SELECT * FROM ip_allowlist WHERE id = ?").get(id) as AllowlistEntry | null;
    if (!row) return null;
    return {
        ...row,
        enabled: Boolean(row.enabled)
    };
}

// ============================================================================
// IP Matching Logic
// ============================================================================

/**
 * Check if an IP matches a pattern
 * Supports:
 * - Exact match: 192.168.1.1
 * - Wildcard: 192.168.* or 192.168.1.*
 * - CIDR: 192.168.1.0/24
 * - IPv6: ::1, ::ffff:127.0.0.1
 */
export function matchesPattern(clientIP: string, pattern: string): boolean {
    // Normalize IPv6-mapped IPv4 addresses
    const normalizedIP = normalizeIP(clientIP);
    const normalizedPattern = normalizeIP(pattern);

    // Exact match
    if (normalizedIP === normalizedPattern) {
        return true;
    }

    // CIDR notation (e.g., 192.168.1.0/24)
    if (pattern.includes("/")) {
        return matchesCIDR(normalizedIP, normalizedPattern);
    }

    // Wildcard pattern (e.g., 192.168.*)
    if (pattern.includes("*")) {
        return matchesWildcard(normalizedIP, normalizedPattern);
    }

    return false;
}

function normalizeIP(ip: string): string {
    // Handle IPv6-mapped IPv4 (::ffff:127.0.0.1)
    if (ip.startsWith("::ffff:")) {
        return ip.substring(7);
    }
    // Handle IPv6 localhost
    if (ip === "::1") {
        return "127.0.0.1";
    }
    return ip;
}

function matchesWildcard(ip: string, pattern: string): boolean {
    const ipParts = ip.split(".");
    const patternParts = pattern.split(".");

    if (ipParts.length !== 4) return false;

    for (let i = 0; i < patternParts.length; i++) {
        if (patternParts[i] === "*") continue;
        if (patternParts[i] !== ipParts[i]) return false;
    }

    return true;
}

function matchesCIDR(ip: string, cidr: string): boolean {
    const [network, prefixStr] = cidr.split("/");
    const prefix = parseInt(prefixStr, 10);

    if (isNaN(prefix) || prefix < 0 || prefix > 32) return false;

    const ipNum = ipToNumber(ip);
    const networkNum = ipToNumber(network);

    if (ipNum === null || networkNum === null) return false;

    // Create subnet mask
    const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;

    return (ipNum & mask) === (networkNum & mask);
}

function ipToNumber(ip: string): number | null {
    const parts = ip.split(".").map(Number);
    if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) {
        return null;
    }
    return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

// ============================================================================
// Main Access Control Function
// ============================================================================

/**
 * Check if an IP is allowed to access the server
 * Returns { allowed: boolean, reason: string }
 */
export function isIPAllowed(clientIP: string): { allowed: boolean; reason: string } {
    const config = getConfig();

    // If allowlist is disabled, allow all
    if (!config.enabled) {
        return { allowed: true, reason: "IP allowlist disabled" };
    }

    const entries = listEntries().filter(e => e.enabled);

    // No rules defined - use default action
    if (entries.length === 0) {
        return {
            allowed: config.defaultAllow,
            reason: config.defaultAllow ? "No rules defined, default allow" : "No rules defined, default deny"
        };
    }

    // Check if IP matches any pattern
    const matchedEntry = entries.find(entry => matchesPattern(clientIP, entry.pattern));

    if (config.mode === "allowlist") {
        // Allowlist mode: matched = allow, no match = use default
        if (matchedEntry) {
            return {
                allowed: true,
                reason: `Matched allowlist: ${matchedEntry.pattern}`
            };
        }
        return {
            allowed: config.defaultAllow,
            reason: config.defaultAllow ? "No match, default allow" : "No match, default deny"
        };
    } else {
        // Blocklist mode: matched = block, no match = use default
        if (matchedEntry) {
            return {
                allowed: false,
                reason: `Matched blocklist: ${matchedEntry.pattern}`
            };
        }
        return {
            allowed: config.defaultAllow,
            reason: config.defaultAllow ? "No match, default allow" : "No match, default deny"
        };
    }
}

// ============================================================================
// Validation Helpers
// ============================================================================

/**
 * Validate an IP pattern before adding to the allowlist
 */
export function validatePattern(pattern: string): { valid: boolean; error?: string } {
    // Empty pattern
    if (!pattern || pattern.trim() === "") {
        return { valid: false, error: "Pattern cannot be empty" };
    }

    const trimmed = pattern.trim();

    // CIDR notation
    if (trimmed.includes("/")) {
        const [network, prefix] = trimmed.split("/");
        const prefixNum = parseInt(prefix, 10);

        if (isNaN(prefixNum) || prefixNum < 0 || prefixNum > 32) {
            return { valid: false, error: "Invalid CIDR prefix (must be 0-32)" };
        }

        const ipValid = validateIPv4(network.replace("*", "0"));
        if (!ipValid.valid) {
            return { valid: false, error: "Invalid network address in CIDR" };
        }

        return { valid: true };
    }

    // Wildcard pattern
    if (trimmed.includes("*")) {
        // Replace wildcards with 0 for validation
        const testIP = trimmed.replace(/\*/g, "0");
        return validateIPv4(testIP);
    }

    // Regular IPv4
    return validateIPv4(trimmed);
}

function validateIPv4(ip: string): { valid: boolean; error?: string } {
    const parts = ip.split(".");

    if (parts.length !== 4) {
        return { valid: false, error: "Invalid IPv4 format (expected 4 octets)" };
    }

    for (const part of parts) {
        const num = parseInt(part, 10);
        if (isNaN(num) || num < 0 || num > 255) {
            return { valid: false, error: `Invalid octet value: ${part}` };
        }
    }

    return { valid: true };
}

// ============================================================================
// Summary & Stats
// ============================================================================

export function getAllowlistSummary(): {
    config: AllowlistConfig;
    totalRules: number;
    enabledRules: number;
    disabledRules: number;
} {
    const config = getConfig();
    const entries = listEntries();

    return {
        config,
        totalRules: entries.length,
        enabledRules: entries.filter(e => e.enabled).length,
        disabledRules: entries.filter(e => !e.enabled).length
    };
}
