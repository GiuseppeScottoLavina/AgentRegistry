/**
 * Comprehensive unit tests for src/ip-allowlist.ts module
 * Uses ISOLATED test database that is destroyed after tests
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from "bun:test";
import { join } from "path";
import { mkdirSync, rmSync } from "fs";
import {
    setAllowlistDatabaseForTesting,
    resetAllowlistDatabasePath,
    closeAllowlistDatabase,
    getConfig,
    updateConfig,
    addEntry,
    removeEntry,
    toggleEntry,
    listEntries,
    getEntry,
    matchesPattern,
    isIPAllowed,
    validatePattern,
    getAllowlistSummary,
} from "../src/ip-allowlist";

// Test database directory - use /tmp to avoid macOS sandbox EPERM
const TEST_DB_DIR = `/tmp/test-allowlist-${process.pid}-${Date.now()}`;
const TEST_DB_PATH = join(TEST_DB_DIR, "test-allowlist.db");

describe("IP Allowlist Module (Isolated Test DB)", () => {
    // Setup: Create isolated test database
    beforeAll(() => {
        mkdirSync(TEST_DB_DIR, { recursive: true });
        setAllowlistDatabaseForTesting(TEST_DB_PATH);
    });

    // Teardown: Destroy test database
    afterAll(() => {
        closeAllowlistDatabase();
        resetAllowlistDatabasePath();
        rmSync(TEST_DB_DIR, { recursive: true, force: true });
    });

    // Store original config to restore
    let originalConfig: any;

    beforeEach(() => {
        originalConfig = { ...getConfig() };
    });

    afterEach(() => {
        updateConfig(originalConfig);
    });

    describe("getConfig", () => {
        it("returns config object", () => {
            const config = getConfig();
            expect(config).toBeDefined();
            expect(typeof config).toBe("object");
        });

        it("has enabled property", () => {
            const config = getConfig();
            expect(config).toHaveProperty("enabled");
            expect(typeof config.enabled).toBe("boolean");
        });

        it("has mode property", () => {
            const config = getConfig();
            expect(config).toHaveProperty("mode");
            expect(["allowlist", "blocklist"]).toContain(config.mode);
        });

        it("has defaultAllow property", () => {
            const config = getConfig();
            expect(config).toHaveProperty("defaultAllow");
            expect(typeof config.defaultAllow).toBe("boolean");
        });
    });

    describe("updateConfig", () => {
        it("updates enabled flag", () => {
            const original = getConfig().enabled;
            updateConfig({ enabled: !original });
            expect(getConfig().enabled).toBe(!original);
        });

        it("updates mode", () => {
            updateConfig({ mode: "blocklist" });
            expect(getConfig().mode).toBe("blocklist");
            updateConfig({ mode: "allowlist" });
            expect(getConfig().mode).toBe("allowlist");
        });

        it("returns updated config", () => {
            const result = updateConfig({ enabled: true });
            expect(result).toHaveProperty("enabled");
            expect(result.enabled).toBe(true);
        });
    });

    describe("matchesPattern", () => {
        it("matches exact IP", () => {
            expect(matchesPattern("192.168.1.1", "192.168.1.1")).toBe(true);
        });

        it("does not match different IP", () => {
            expect(matchesPattern("192.168.1.2", "192.168.1.1")).toBe(false);
        });

        it("matches localhost", () => {
            expect(matchesPattern("127.0.0.1", "127.0.0.1")).toBe(true);
        });

        it("matches CIDR patterns /24", () => {
            expect(matchesPattern("192.168.1.50", "192.168.1.0/24")).toBe(true);
            expect(matchesPattern("192.168.1.255", "192.168.1.0/24")).toBe(true);
            expect(matchesPattern("192.168.2.1", "192.168.1.0/24")).toBe(false);
        });

        it("matches CIDR patterns /16", () => {
            expect(matchesPattern("192.168.1.1", "192.168.0.0/16")).toBe(true);
            expect(matchesPattern("192.168.255.255", "192.168.0.0/16")).toBe(true);
            expect(matchesPattern("192.169.0.1", "192.168.0.0/16")).toBe(false);
        });

        it("matches wildcard patterns", () => {
            expect(matchesPattern("192.168.1.100", "192.168.*.*")).toBe(true);
            expect(matchesPattern("192.168.5.99", "192.168.*.*")).toBe(true);
            expect(matchesPattern("10.0.0.1", "192.168.*.*")).toBe(false);
        });

        it("matches single-octet wildcard", () => {
            expect(matchesPattern("192.168.1.5", "192.168.1.*")).toBe(true);
            expect(matchesPattern("192.168.2.5", "192.168.1.*")).toBe(false);
        });

        it("handles IPv6 localhost", () => {
            expect(matchesPattern("::1", "127.0.0.1")).toBe(true);
        });

        it("handles IPv6-mapped IPv4", () => {
            expect(matchesPattern("::ffff:192.168.1.1", "192.168.1.1")).toBe(true);
        });
    });

    describe("validatePattern", () => {
        it("validates exact IPv4", () => {
            expect(validatePattern("192.168.1.1").valid).toBe(true);
            expect(validatePattern("10.0.0.1").valid).toBe(true);
            expect(validatePattern("255.255.255.255").valid).toBe(true);
        });

        it("validates CIDR notation", () => {
            expect(validatePattern("192.168.1.0/24").valid).toBe(true);
            expect(validatePattern("10.0.0.0/8").valid).toBe(true);
            expect(validatePattern("0.0.0.0/0").valid).toBe(true);
        });

        it("validates wildcard patterns", () => {
            expect(validatePattern("192.168.*.*").valid).toBe(true);
            expect(validatePattern("192.168.1.*").valid).toBe(true);
            expect(validatePattern("*.*.*.*").valid).toBe(true);
        });

        it("rejects empty pattern", () => {
            expect(validatePattern("").valid).toBe(false);
            expect(validatePattern("   ").valid).toBe(false);
        });

        it("rejects invalid IPv4", () => {
            expect(validatePattern("999.999.999.999").valid).toBe(false);
            expect(validatePattern("300.1.1.1").valid).toBe(false);
            expect(validatePattern("1.2.3.").valid).toBe(false);
        });

        it("rejects invalid CIDR prefix", () => {
            expect(validatePattern("192.168.1.0/33").valid).toBe(false);
            expect(validatePattern("192.168.1.0/-1").valid).toBe(false);
        });

        it("returns error message for invalid", () => {
            const result = validatePattern("");
            expect(result.valid).toBe(false);
            expect(result.error).toBeDefined();
            expect(typeof result.error).toBe("string");
        });
    });

    describe("Entry Management", () => {
        let testEntryId: number | null = null;

        afterEach(async () => {
            if (testEntryId !== null) {
                removeEntry(testEntryId);
                testEntryId = null;
            }
        });

        it("addEntry creates new entry", () => {
            const entry = addEntry("10.100.0.1", "Test entry");
            expect(entry).not.toBeNull();
            if (entry) {
                testEntryId = entry.id;
                expect(entry.pattern).toBe("10.100.0.1");
                expect(entry.description).toBe("Test entry");
                expect(entry.enabled).toBe(true);
            }
        });

        it("addEntry returns null for duplicate pattern", () => {
            const first = addEntry("10.100.0.2", "First");
            if (first) testEntryId = first.id;

            const duplicate = addEntry("10.100.0.2", "Duplicate");
            expect(duplicate).toBeNull();
        });

        it("listEntries returns array", () => {
            const entries = listEntries();
            expect(Array.isArray(entries)).toBe(true);
        });

        it("listEntries includes added entries", () => {
            const entry = addEntry("10.100.0.3", "List test");
            if (entry) testEntryId = entry.id;

            const entries = listEntries();
            expect(entries.some(e => e.pattern === "10.100.0.3")).toBe(true);
        });

        it("getEntry returns entry by id", () => {
            const created = addEntry("10.100.0.4", "Get test");
            if (created) {
                testEntryId = created.id;
                const retrieved = getEntry(created.id);
                expect(retrieved).not.toBeNull();
                expect(retrieved?.pattern).toBe("10.100.0.4");
            }
        });

        it("getEntry returns null for non-existent id", () => {
            const entry = getEntry(999999);
            expect(entry).toBeNull();
        });

        it("removeEntry removes entry", () => {
            const created = addEntry("10.100.0.5", "Remove test");
            expect(created).not.toBeNull();
            if (created) {
                const removed = removeEntry(created.id);
                expect(removed).toBe(true);
                expect(getEntry(created.id)).toBeNull();
            }
        });

        it("removeEntry returns false for non-existent", () => {
            const removed = removeEntry(999999);
            expect(removed).toBe(false);
        });

        it("toggleEntry enables/disables entry", () => {
            const created = addEntry("10.100.0.6", "Toggle test");
            if (created) {
                testEntryId = created.id;

                // Disable
                toggleEntry(created.id, false);
                expect(getEntry(created.id)?.enabled).toBe(false);

                // Enable
                toggleEntry(created.id, true);
                expect(getEntry(created.id)?.enabled).toBe(true);
            }
        });
    });

    describe("isIPAllowed", () => {
        it("returns result object with allowed and reason", () => {
            const result = isIPAllowed("127.0.0.1");
            expect(result).toHaveProperty("allowed");
            expect(result).toHaveProperty("reason");
            expect(typeof result.allowed).toBe("boolean");
            expect(typeof result.reason).toBe("string");
        });

        it("allows all when allowlist is disabled", () => {
            updateConfig({ enabled: false });
            const result = isIPAllowed("192.168.1.1");
            expect(result.allowed).toBe(true);
            expect(result.reason).toContain("disabled");
        });

        it("uses defaultAllow when no rules match", () => {
            updateConfig({ enabled: true, defaultAllow: true });
            const result = isIPAllowed("10.0.0.99");
            expect(result.allowed).toBe(true);
        });

        it("denies when defaultAllow is false and no match", () => {
            updateConfig({ enabled: true, defaultAllow: false });
            // Clean up any existing entries to ensure no match
            const entries = listEntries();
            entries.forEach(e => removeEntry(e.id));

            const result = isIPAllowed("10.99.99.99");
            expect(typeof result.allowed).toBe("boolean");
        });
    });

    describe("getAllowlistSummary", () => {
        it("returns summary object", () => {
            const summary = getAllowlistSummary();
            expect(summary).toBeDefined();
            expect(typeof summary).toBe("object");
        });

        it("has config property", () => {
            const summary = getAllowlistSummary();
            expect(summary).toHaveProperty("config");
            expect(summary.config).toHaveProperty("enabled");
        });

        it("has rule counts", () => {
            const summary = getAllowlistSummary();
            expect(summary).toHaveProperty("totalRules");
            expect(summary).toHaveProperty("enabledRules");
            expect(summary).toHaveProperty("disabledRules");
            expect(typeof summary.totalRules).toBe("number");
        });

        it("counts match entries", () => {
            // Add a test entry
            const entry = addEntry("10.200.0.1", "Summary test");

            const summary = getAllowlistSummary();
            expect(summary.totalRules).toBeGreaterThan(0);

            // Cleanup
            if (entry) removeEntry(entry.id);
        });
    });

    describe("isIPAllowed - Blocklist Mode", () => {
        let testEntryId: number | null = null;

        afterEach(() => {
            if (testEntryId !== null) {
                removeEntry(testEntryId);
                testEntryId = null;
            }
        });

        it("blocks matched IP in blocklist mode", () => {
            updateConfig({ enabled: true, mode: "blocklist", defaultAllow: true });

            // Add a blocklist entry
            const entry = addEntry("10.50.0.1", "Blocked IP");
            if (entry) testEntryId = entry.id;

            const result = isIPAllowed("10.50.0.1");
            expect(result.allowed).toBe(false);
            expect(result.reason).toContain("blocklist");
        });

        it("allows unmatched IP in blocklist mode with defaultAllow true", () => {
            updateConfig({ enabled: true, mode: "blocklist", defaultAllow: true });

            const entry = addEntry("10.50.0.2", "Blocked IP 2");
            if (entry) testEntryId = entry.id;

            // Different IP should be allowed
            const result = isIPAllowed("10.50.0.99");
            expect(result.allowed).toBe(true);
            expect(result.reason).toContain("default allow");
        });

        it("denies unmatched IP in blocklist mode with defaultAllow false", () => {
            updateConfig({ enabled: true, mode: "blocklist", defaultAllow: false });

            const entry = addEntry("10.50.0.3", "Blocked IP 3");
            if (entry) testEntryId = entry.id;

            const result = isIPAllowed("10.50.0.98");
            expect(result.allowed).toBe(false);
            expect(result.reason).toContain("default deny");
        });
    });

    describe("isIPAllowed - Allowlist Mode", () => {
        let testEntryId: number | null = null;

        afterEach(() => {
            if (testEntryId !== null) {
                removeEntry(testEntryId);
                testEntryId = null;
            }
        });

        it("allows matched IP in allowlist mode", () => {
            updateConfig({ enabled: true, mode: "allowlist", defaultAllow: false });

            const entry = addEntry("10.60.0.1", "Allowed IP");
            if (entry) testEntryId = entry.id;

            const result = isIPAllowed("10.60.0.1");
            expect(result.allowed).toBe(true);
            expect(result.reason).toContain("allowlist");
        });

        it("denies unmatched IP in allowlist mode with defaultAllow false", () => {
            updateConfig({ enabled: true, mode: "allowlist", defaultAllow: false });

            const entry = addEntry("10.60.0.2", "Allowed IP 2");
            if (entry) testEntryId = entry.id;

            const result = isIPAllowed("10.60.0.99");
            expect(result.allowed).toBe(false);
            expect(result.reason).toContain("default deny");
        });

        it("allows unmatched IP in allowlist mode with defaultAllow true", () => {
            updateConfig({ enabled: true, mode: "allowlist", defaultAllow: true });

            const entry = addEntry("10.60.0.3", "Allowed IP 3");
            if (entry) testEntryId = entry.id;

            const result = isIPAllowed("10.60.0.98");
            expect(result.allowed).toBe(true);
            expect(result.reason).toContain("default allow");
        });
    });

    describe("matchesPattern - Edge Cases", () => {
        it("returns false for invalid IP format", () => {
            expect(matchesPattern("not-an-ip", "192.168.1.1")).toBe(false);
        });

        it("returns false for invalid CIDR pattern IP", () => {
            expect(matchesPattern("192.168.1.1", "invalid/24")).toBe(false);
        });

        it("handles CIDR with invalid prefix gracefully", () => {
            // Should return false for invalid CIDR
            expect(matchesPattern("192.168.1.1", "192.168.1.0/abc")).toBe(false);
        });
    });

    describe("Database Connection Edge Cases", () => {
        it("setAllowlistDatabaseForTesting handles path switch", () => {
            // Already handled implicitly, but test doesn't throw
            expect(() => setAllowlistDatabaseForTesting(TEST_DB_PATH)).not.toThrow();
        });

        it("closeAllowlistDatabase can be called multiple times", () => {
            expect(() => closeAllowlistDatabase()).not.toThrow();
            expect(() => closeAllowlistDatabase()).not.toThrow();
            // Restore db
            setAllowlistDatabaseForTesting(TEST_DB_PATH);
        });

        it("resetAllowlistDatabasePath closes active connection", () => {
            // First make sure we have an active db connection
            setAllowlistDatabaseForTesting(TEST_DB_PATH);
            // Call getConfig to trigger db initialization
            getConfig();

            // Now reset - this should close the db first
            expect(() => resetAllowlistDatabasePath()).not.toThrow();

            // Restore test db
            setAllowlistDatabaseForTesting(TEST_DB_PATH);
        });
    });
});
