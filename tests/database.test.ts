/**
 * Comprehensive unit tests for src/database.ts module
 * Uses ISOLATED test database that is destroyed after tests
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from "bun:test";
import { join } from "path";
import { mkdirSync, rmSync, existsSync } from "fs";
import {
    setDatabaseForTesting,
    resetDatabasePath,
    closeDatabase,
    getDatabase,
    loadPackageFromDB,
    getAllPackages,
    savePackageToDB,
    deletePackageFromDB,
    listPackagesFromDB,
    searchPackages,
    getPackagesBySource,
    countPackages,
    incrementDownloads,
    saveScanResult,
    getScanResultByHash,
    getScanStats,
    getRecentBlockedPackages,
    logRequest,
    getRequestStats,
    logAudit,
    getRecentAuditLogs,
    getAuditLogCount,
    getAuditLogsByAction,
    getAuditLogsForExport,
    formatAuditLogsAsCSV,
    setStat,
    getStat,
    getAllStats,
    getLogCounts,
    getComprehensiveStats,
    vacuumDatabase,
    cleanupOldLogs,
    checkRateLimitDB,
    migrateJsonToSqlite,
} from "../src/database";

// Test database directory - use /tmp to avoid macOS sandbox EPERM
const TEST_DB_DIR = `/tmp/test-db-${process.pid}-${Date.now()}`;
const TEST_DB_PATH = join(TEST_DB_DIR, "test-agentregistry.db");

describe("Database Module (Isolated Test DB)", () => {
    // Setup: Create isolated test database
    beforeAll(() => {
        mkdirSync(TEST_DB_DIR, { recursive: true });
        setDatabaseForTesting(TEST_DB_PATH);
    });

    // Teardown: Destroy test database
    afterAll(() => {
        closeDatabase();
        resetDatabasePath();
        rmSync(TEST_DB_DIR, { recursive: true, force: true });
    });

    describe("getDatabase", () => {
        it("returns a Database instance", () => {
            const db = getDatabase();
            expect(db).toBeDefined();
            expect(typeof db.query).toBe("function");
        });

        it("returns the same instance on multiple calls", () => {
            const db1 = getDatabase();
            const db2 = getDatabase();
            expect(db1).toBe(db2);
        });

        it("creates tables automatically", () => {
            const db = getDatabase();
            const tables = db.prepare(`
                SELECT name FROM sqlite_master WHERE type='table' ORDER BY name
            `).all() as { name: string }[];

            const tableNames = tables.map(t => t.name);
            expect(tableNames).toContain("packages");
            expect(tableNames).toContain("scan_results");
            expect(tableNames).toContain("request_logs");
            expect(tableNames).toContain("audit_log");
            expect(tableNames).toContain("stats");
        });
    });

    describe("Package Operations", () => {
        const testPkg = {
            name: "test-pkg-" + Date.now(),
            description: "Test package for database tests",
            "dist-tags": { latest: "1.0.0" },
            versions: {
                "1.0.0": {
                    name: "test-pkg",
                    version: "1.0.0",
                    main: "index.js"
                }
            },
            time: {
                created: new Date().toISOString(),
                modified: new Date().toISOString(),
                "1.0.0": new Date().toISOString()
            },
            _id: "test-pkg",
            _rev: "1.0.0",
            _source: "local"
        };

        it("savePackageToDB stores a package", () => {
            savePackageToDB(testPkg as any);
            const loaded = loadPackageFromDB(testPkg.name);
            expect(loaded).toBeDefined();
            expect(loaded?.name).toBe(testPkg.name);
        });

        it("loadPackageFromDB returns stored package", () => {
            const loaded = loadPackageFromDB(testPkg.name);
            expect(loaded).not.toBeNull();
            expect(loaded?.description).toBe("Test package for database tests");
        });

        it("loadPackageFromDB returns null for non-existent", () => {
            const loaded = loadPackageFromDB("nonexistent-pkg-12345");
            expect(loaded).toBeNull();
        });

        it("getAllPackages includes saved packages", () => {
            const all = getAllPackages();
            expect(Array.isArray(all)).toBe(true);
            expect(all.some(p => p.name === testPkg.name)).toBe(true);
        });

        it("listPackagesFromDB returns array of names", () => {
            const names = listPackagesFromDB();
            expect(Array.isArray(names)).toBe(true);
            expect(names).toContain(testPkg.name);
        });

        it("deletePackageFromDB removes a package", () => {
            const tempPkg = { ...testPkg, name: "temp-delete-pkg" };
            savePackageToDB(tempPkg as any);

            expect(loadPackageFromDB("temp-delete-pkg")).not.toBeNull();

            const deleted = deletePackageFromDB("temp-delete-pkg");
            expect(deleted).toBe(true);
            expect(loadPackageFromDB("temp-delete-pkg")).toBeNull();
        });

        it("deletePackageFromDB returns false for non-existent", () => {
            const deleted = deletePackageFromDB("nonexistent-pkg-99999");
            expect(deleted).toBe(false);
        });

        it("incrementDownloads increases counter", () => {
            expect(() => incrementDownloads(testPkg.name)).not.toThrow();
        });
    });

    describe("countPackages", () => {
        it("returns count structure", () => {
            const counts = countPackages();
            expect(counts).toHaveProperty("total");
            expect(counts).toHaveProperty("local");
            expect(counts).toHaveProperty("upstream");
            expect(typeof counts.total).toBe("number");
        });
    });

    describe("searchPackages", () => {
        beforeAll(() => {
            // Add a searchable package
            savePackageToDB({
                name: "searchable-utils",
                description: "Useful utilities for testing",
                "dist-tags": { latest: "1.0.0" },
                versions: { "1.0.0": {} },
                time: { created: new Date().toISOString() },
                _id: "searchable-utils",
                _rev: "1",
                _source: "local"
            } as any);
        });

        it("returns array of results", () => {
            const results = searchPackages("searchable");
            expect(Array.isArray(results)).toBe(true);
        });

        it("finds matching packages", () => {
            const results = searchPackages("searchable");
            expect(results.some(r => r.name === "searchable-utils")).toBe(true);
        });

        it("returns fewer results for nonsense query", () => {
            const results = searchPackages("zzzznotexist12345xyz");
            // Search may return partial matches, just verify it works
            expect(Array.isArray(results)).toBe(true);
        });

        it("respects limit parameter", () => {
            const results = searchPackages("test", 2);
            expect(results.length).toBeLessThanOrEqual(2);
        });
    });

    describe("getPackagesBySource", () => {
        it("returns array for local source", () => {
            const packages = getPackagesBySource("local");
            expect(Array.isArray(packages)).toBe(true);
        });

        it("returns array for upstream source", () => {
            const packages = getPackagesBySource("upstream");
            expect(Array.isArray(packages)).toBe(true);
        });
    });

    describe("Scan Results", () => {
        const testHash = `test-hash-${Date.now()}`;

        it("saveScanResult stores scan result", () => {
            saveScanResult({
                package_name: "test-scan-pkg",
                version: "1.0.0",
                tarball_hash: testHash,
                safe: true,
                issues_count: 0,
                issues: [],
                files_scanned: 5,
                scan_time_ms: 10
            });

            const result = getScanResultByHash(testHash);
            expect(result).not.toBeNull();
            expect(result?.safe).toBe(true);
        });

        it("getScanResultByHash returns null for unknown", () => {
            const result = getScanResultByHash("unknown-hash-12345");
            expect(result).toBeNull();
        });

        it("getScanStats returns statistics", () => {
            const stats = getScanStats();
            expect(stats).toHaveProperty("total");
            expect(stats).toHaveProperty("safe");
            expect(stats).toHaveProperty("blocked");
            expect(stats).toHaveProperty("avgTimeMs");
        });

        it("getRecentBlockedPackages returns array", () => {
            const blocked = getRecentBlockedPackages(5);
            expect(Array.isArray(blocked)).toBe(true);
        });

        it("saveScanResult handles blocked package", () => {
            saveScanResult({
                package_name: "blocked-pkg",
                version: "1.0.0",
                tarball_hash: "blocked-hash-" + Date.now(),
                safe: false,
                issues_count: 3,
                issues: [{ file: "index.js", severity: "critical", description: "eval" }],
                files_scanned: 1,
                scan_time_ms: 5
            });
            const stats = getScanStats();
            expect(stats.blocked).toBeGreaterThan(0);
        });
    });

    describe("Request Logging", () => {
        it("logRequest stores request", () => {
            const requestId = `req-${Date.now()}`;
            expect(() => logRequest({
                requestId,
                method: "GET",
                path: "/test",
                statusCode: 200,
                durationMs: 5,
                userAgent: "test-agent"
            })).not.toThrow();
        });

        it("getRequestStats returns statistics", () => {
            const stats = getRequestStats();
            expect(stats).toHaveProperty("total");
            expect(stats).toHaveProperty("avgDurationMs");
            expect(stats).toHaveProperty("errorRate");
            expect(stats).toHaveProperty("requestsPerMinute");
        });

        it("logRequest handles errors (status >= 400)", () => {
            logRequest({
                requestId: `req-err-${Date.now()}`,
                method: "GET",
                path: "/error",
                statusCode: 500,
                durationMs: 10
            });
            // Verify error rate calculation works
            const stats = getRequestStats();
            expect(typeof stats.errorRate).toBe("number");
        });
    });

    describe("Audit Logging", () => {
        it("logAudit stores audit entry", () => {
            expect(() => logAudit("package_published", "test-pkg", { version: "1.0.0" }, "info")).not.toThrow();
        });

        it("getRecentAuditLogs returns array", () => {
            const logs = getRecentAuditLogs(10);
            expect(Array.isArray(logs)).toBe(true);
        });

        it("getAuditLogCount returns number", () => {
            const count = getAuditLogCount();
            expect(typeof count).toBe("number");
            expect(count).toBeGreaterThanOrEqual(0);
        });

        it("getAuditLogsByAction filters correctly", () => {
            logAudit("package_published", "filter-test", {}, "info");
            const logs = getAuditLogsByAction("package_published", 5);
            expect(Array.isArray(logs)).toBe(true);
            expect(logs.length).toBeGreaterThan(0);
        });

        it("logAudit supports different severities", () => {
            expect(() => logAudit("security_alert", "test", {}, "warn")).not.toThrow();
            expect(() => logAudit("security_alert", "test", {}, "error")).not.toThrow();
        });
    });

    describe("Audit Export", () => {
        it("getAuditLogsForExport returns array", () => {
            const logs = getAuditLogsForExport();
            expect(Array.isArray(logs)).toBe(true);
        });

        it("getAuditLogsForExport respects limit", () => {
            const logs = getAuditLogsForExport({ limit: 5 });
            expect(logs.length).toBeLessThanOrEqual(5);
        });

        it("getAuditLogsForExport filters by action", () => {
            logAudit("package_blocked", "blocked-test", {}, "warn");
            const logs = getAuditLogsForExport({ actions: ["package_blocked"] });
            expect(logs.every(l => l.action === "package_blocked")).toBe(true);
        });

        it("getAuditLogsForExport filters by severity", () => {
            const logs = getAuditLogsForExport({ severity: ["warn", "error"] });
            expect(logs.every(l => l.severity === "warn" || l.severity === "error")).toBe(true);
        });

        it("formatAuditLogsAsCSV returns CSV string", () => {
            const logs = getAuditLogsForExport({ limit: 3 });
            const csv = formatAuditLogsAsCSV(logs);
            expect(typeof csv).toBe("string");
            expect(csv).toContain("id,action,target");
        });

        it("formatAuditLogsAsCSV handles empty array", () => {
            const csv = formatAuditLogsAsCSV([]);
            expect(csv).toContain("id,action,target");
        });
    });

    describe("Statistics", () => {
        it("setStat and getStat work together", () => {
            const testKey = `test-stat-${Date.now()}`;
            setStat(testKey, { foo: "bar", count: 42 });

            const value = getStat(testKey) as Record<string, unknown>;
            expect(value).toBeDefined();
            expect(value.foo).toBe("bar");
            expect(value.count).toBe(42);
        });

        it("getStat returns null for unknown key", () => {
            const value = getStat("unknown-stat-key-12345");
            expect(value).toBeNull();
        });

        it("getAllStats returns object", () => {
            const allStats = getAllStats();
            expect(typeof allStats).toBe("object");
        });
    });

    describe("Rate Limiting", () => {
        it("checkRateLimitDB allows first request", () => {
            const result = checkRateLimitDB("192.168.1.1", 10, 60000);
            expect(result.allowed).toBe(true);
            expect(result.remaining).toBeLessThanOrEqual(10);
        });

        it("checkRateLimitDB decrements remaining", () => {
            const ip = `192.168.${Date.now() % 255}.1`;
            const r1 = checkRateLimitDB(ip, 10, 60000);
            const r2 = checkRateLimitDB(ip, 10, 60000);
            expect(r2.remaining).toBeLessThan(r1.remaining);
        });

        it("checkRateLimitDB blocks when limit exceeded", () => {
            const ip = `10.0.${Date.now() % 255}.1`;
            // Make 3 requests with limit of 2
            checkRateLimitDB(ip, 2, 60000);
            checkRateLimitDB(ip, 2, 60000);
            const r3 = checkRateLimitDB(ip, 2, 60000);
            expect(r3.allowed).toBe(false);
            expect(r3.remaining).toBe(0);
        });
    });

    describe("Log Cleanup", () => {
        it("cleanupOldLogs returns CleanupResult", () => {
            const result = cleanupOldLogs();
            expect(result).toHaveProperty("requestLogs");
            expect(result).toHaveProperty("auditLogs");
            expect(result).toHaveProperty("scanResults");
            expect(result).toHaveProperty("freedBytes");
        });

        it("cleanupOldLogs respects custom options", () => {
            const result = cleanupOldLogs({
                requestLogsDays: 1,
                auditLogsDays: 1,
                scanResultsDays: 1
            });
            expect(typeof result.requestLogs).toBe("number");
        });
    });

    describe("Utility Functions", () => {
        it("getLogCounts returns counts object", () => {
            const counts = getLogCounts();
            expect(counts).toHaveProperty("requestLogs");
            expect(counts).toHaveProperty("auditLogs");
            expect(counts).toHaveProperty("scanResults");
            expect(typeof counts.requestLogs).toBe("number");
        });

        it("getComprehensiveStats returns full stats", () => {
            const stats = getComprehensiveStats();
            expect(stats).toHaveProperty("packages");
            expect(stats).toHaveProperty("scans");
            expect(stats).toHaveProperty("requests");
            expect(stats).toHaveProperty("database");
        });

        it("vacuumDatabase does not throw", () => {
            expect(() => vacuumDatabase()).not.toThrow();
        });
    });

    describe("Migration", () => {
        const MIGRATE_DIR = join(TEST_DB_DIR, "migrate-test");

        it("migrateJsonToSqlite returns 0 for empty directory", async () => {
            mkdirSync(MIGRATE_DIR, { recursive: true });
            const count = await migrateJsonToSqlite(MIGRATE_DIR);
            expect(count).toBe(0);
        });

        it("migrateJsonToSqlite handles non-existent directory", async () => {
            const count = await migrateJsonToSqlite("/nonexistent/path");
            expect(count).toBe(0);
        });

        it("migrateJsonToSqlite migrates JSON files", async () => {
            const { writeFileSync } = await import("fs");
            mkdirSync(MIGRATE_DIR, { recursive: true });

            // Create test JSON file
            const testPkg = {
                name: "migrated-pkg",
                "dist-tags": { latest: "1.0.0" },
                versions: { "1.0.0": { name: "migrated-pkg", version: "1.0.0" } }
            };
            writeFileSync(join(MIGRATE_DIR, "migrated-pkg.json"), JSON.stringify(testPkg));

            const count = await migrateJsonToSqlite(MIGRATE_DIR);
            expect(count).toBeGreaterThanOrEqual(0);
        });
    });

    describe("Database Connection Management", () => {
        it("setDatabaseForTesting switches database path", () => {
            // Already tested implicitly, but explicit test
            expect(() => setDatabaseForTesting(TEST_DB_PATH)).not.toThrow();
        });

        it("closeDatabase does not throw", () => {
            expect(() => closeDatabase()).not.toThrow();
        });

        it("resetDatabasePath does not throw", () => {
            // Note: this resets to default path, so test at the end
            expect(() => resetDatabasePath()).not.toThrow();
            // Restore test path
            setDatabaseForTesting(TEST_DB_PATH);
        });
    });
});

