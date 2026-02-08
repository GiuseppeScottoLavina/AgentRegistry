/* 
 * Copyright 2026 Giuseppe Scotto Lavina
 *
 * Package Allowlist Module Tests
 */

import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { Database } from "bun:sqlite";
import { mkdtempSync, rmSync } from "fs";
import { join } from "path";
import {
    setPackageAllowlistDatabaseForTesting,
    resetPackageAllowlistDatabasePath,
    closePackageAllowlistDatabase,
    getPackageAllowlistConfig,
    updatePackageAllowlistConfig,
    addPackageToAllowlist,
    removeFromAllowlist,
    togglePackageAllowlistEntry,
    listPackageAllowlist,
    getPackageAllowlistEntry,
    getPackageAllowlistCategories,
    isPackageAllowlisted,
    matchesPackagePattern,
    getPackageAllowlistSummary,
    reseedDefaultPackages
} from "../src/package-allowlist";

describe("Package Allowlist Module", () => {
    let testDir: string;
    let testDbPath: string;

    beforeEach(() => {
        // Use unique isolated test database per test
        testDir = mkdtempSync("/tmp/pkg-allowlist-test-");
        testDbPath = join(testDir, "test.db");
        setPackageAllowlistDatabaseForTesting(testDbPath);
    });

    afterEach(() => {
        closePackageAllowlistDatabase();
        // CRITICAL: Reset to default path so other tests use production database
        resetPackageAllowlistDatabasePath();
        try {
            rmSync(testDir, { recursive: true, force: true });
        } catch {
            // Ignore cleanup errors
        }
    });

    describe("matchesPackagePattern", () => {
        it("matches exact package names", () => {
            expect(matchesPackagePattern("lodash", "lodash")).toBe(true);
            expect(matchesPackagePattern("lodash", "underscore")).toBe(false);
        });

        it("matches scoped package prefixes", () => {
            expect(matchesPackagePattern("@opentelemetry/api", "@opentelemetry/")).toBe(true);
            expect(matchesPackagePattern("@opentelemetry/core", "@opentelemetry/")).toBe(true);
            expect(matchesPackagePattern("@sentry/node", "@opentelemetry/")).toBe(false);
        });

        it("matches dash suffix patterns", () => {
            expect(matchesPackagePattern("sentry-node", "sentry-")).toBe(true);
            expect(matchesPackagePattern("sentry-core", "sentry-")).toBe(true);
            expect(matchesPackagePattern("other-package", "sentry-")).toBe(false);
        });

        it("matches package name prefix with dash boundary", () => {
            expect(matchesPackagePattern("lodash-es", "lodash")).toBe(true);
            expect(matchesPackagePattern("lodash", "lodash")).toBe(true);
            expect(matchesPackagePattern("lodash-merge", "lodash")).toBe(true);
            // Should NOT match lodashfake (no dash boundary)
            expect(matchesPackagePattern("lodashfake", "lodash")).toBe(false);
        });

        it("is case-insensitive", () => {
            expect(matchesPackagePattern("LODASH", "lodash")).toBe(true);
            expect(matchesPackagePattern("Lodash", "LODASH")).toBe(true);
        });
    });

    describe("Configuration", () => {
        it("returns default config (enabled: true)", () => {
            const config = getPackageAllowlistConfig();
            expect(config.enabled).toBe(true);
        });

        it("updates config", () => {
            updatePackageAllowlistConfig({ enabled: false });
            const config = getPackageAllowlistConfig();
            expect(config.enabled).toBe(false);
        });
    });

    describe("Entry Management", () => {
        it("lists default entries on first access", () => {
            const entries = listPackageAllowlist();
            expect(entries.length).toBeGreaterThan(40); // Has 50+ defaults
        });

        it("contains expected default packages", () => {
            const entries = listPackageAllowlist();
            const patterns = entries.map(e => e.pattern);

            expect(patterns).toContain("lodash");
            expect(patterns).toContain("@opentelemetry/");
            expect(patterns).toContain("esbuild");
            expect(patterns).toContain("jest");
        });

        it("adds custom entries", () => {
            const entry = addPackageToAllowlist("my-custom-pkg", "Custom package", "custom");
            expect(entry).not.toBeNull();
            expect(entry?.pattern).toBe("my-custom-pkg");
            expect(entry?.is_default).toBe(false);
            expect(entry?.category).toBe("custom");
        });

        it("prevents duplicate entries", () => {
            addPackageToAllowlist("unique-pkg", "First add");
            const duplicate = addPackageToAllowlist("unique-pkg", "Second add");
            expect(duplicate).toBeNull();
        });

        it("toggles entry enabled status", () => {
            const entries = listPackageAllowlist();
            const firstEntry = entries[0];

            togglePackageAllowlistEntry(firstEntry.id, false);
            const updated = getPackageAllowlistEntry(firstEntry.id);
            expect(updated?.enabled).toBe(false);

            togglePackageAllowlistEntry(firstEntry.id, true);
            const reEnabled = getPackageAllowlistEntry(firstEntry.id);
            expect(reEnabled?.enabled).toBe(true);
        });

        it("removes custom entries", () => {
            const entry = addPackageToAllowlist("removable-pkg", "To be removed");
            expect(entry).not.toBeNull();

            const removed = removeFromAllowlist(entry!.id);
            expect(removed).toBe(true);

            const notFound = getPackageAllowlistEntry(entry!.id);
            expect(notFound).toBeNull();
        });

        it("prevents deletion of default entries", () => {
            const entries = listPackageAllowlist();
            const defaultEntry = entries.find(e => e.is_default);
            expect(defaultEntry).toBeDefined();

            const removed = removeFromAllowlist(defaultEntry!.id);
            expect(removed).toBe(false);

            // Entry should still exist
            const stillExists = getPackageAllowlistEntry(defaultEntry!.id);
            expect(stillExists).not.toBeNull();
        });
    });

    describe("isPackageAllowlisted", () => {
        it("returns true for allowlisted packages", () => {
            expect(isPackageAllowlisted("lodash")).toBe(true);
            expect(isPackageAllowlisted("@opentelemetry/api")).toBe(true);
        });

        it("returns false for non-allowlisted packages", () => {
            expect(isPackageAllowlisted("malicious-package-xyz")).toBe(false);
            expect(isPackageAllowlisted("unknown-package")).toBe(false);
        });

        it("returns false when allowlist is disabled", () => {
            updatePackageAllowlistConfig({ enabled: false });
            expect(isPackageAllowlisted("lodash")).toBe(false);
        });

        it("respects enabled/disabled entries", () => {
            const entries = listPackageAllowlist();
            const lodashEntry = entries.find(e => e.pattern === "lodash");
            expect(lodashEntry).toBeDefined();

            // Disable lodash
            togglePackageAllowlistEntry(lodashEntry!.id, false);
            expect(isPackageAllowlisted("lodash")).toBe(false);

            // Re-enable lodash
            togglePackageAllowlistEntry(lodashEntry!.id, true);
            expect(isPackageAllowlisted("lodash")).toBe(true);
        });
    });

    describe("Categories", () => {
        it("returns list of categories", () => {
            const categories = getPackageAllowlistCategories();
            expect(categories).toContain("build-tools");
            expect(categories).toContain("testing");
            expect(categories).toContain("observability");
            expect(categories).toContain("verified");
        });
    });

    describe("Summary", () => {
        it("returns comprehensive summary", () => {
            const summary = getPackageAllowlistSummary();
            expect(summary.config).toBeDefined();
            expect(summary.totalEntries).toBeGreaterThan(0);
            expect(summary.defaultEntries).toBeGreaterThan(0);
            expect(summary.categories.length).toBeGreaterThan(0);
        });
    });

    describe("Reseed", () => {
        it("does not duplicate existing defaults", () => {
            const beforeCount = listPackageAllowlist().length;
            const added = reseedDefaultPackages();
            const afterCount = listPackageAllowlist().length;

            expect(added).toBe(0); // All defaults already exist
            expect(afterCount).toBe(beforeCount);
        });
    });
});
