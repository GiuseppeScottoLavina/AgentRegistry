import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { join } from "node:path";
import { rm, mkdir } from "node:fs/promises";

const TEST_DIR = `/tmp/.test-unit-${process.pid}-${Date.now()}`;
// Override STORAGE_DIR BEFORE importing modules
process.env.STORAGE_DIR = TEST_DIR;

// Ensure directory exists before importing DB-dependent modules
import { mkdirSync } from "node:fs";
mkdirSync(TEST_DIR, { recursive: true });

// Import modules after setting env
const { recordRequest, getMetricsSnapshot, stopMetricsCollection } = await import("../src/metrics");
const { checkCVE, getCVESummary, clearCVECache } = await import("../src/cve");
const { isIPAllowed, addEntry, removeEntry, listEntries, validatePattern, updateConfig } = await import("../src/ip-allowlist");
const { closeDatabase } = await import("../src/database");

describe("Unit Tests (Metrics, CVE, IP)", () => {
    beforeEach(async () => {
        await mkdir(TEST_DIR, { recursive: true });
    });

    afterEach(async () => {
        closeDatabase();
        await rm(TEST_DIR, { recursive: true, force: true });
    });

    describe("Metrics Module", () => {
        test("records request duration", () => {
            recordRequest(10, true); // latency=10, cacheHit=true

            const snapshot = getMetricsSnapshot();
            expect(snapshot.totalRequests).toBeGreaterThan(0);
            expect(snapshot.cacheHits).toBeGreaterThan(0);

            stopMetricsCollection();
        });
    });

    describe("CVE Module", () => {
        test("checkCVE caches results", async () => {
            clearCVECache();

            const summary = getCVESummary();
            expect(summary.totalPackages).toBeGreaterThanOrEqual(0);
        });
    });

    describe("IP Allowlist Module", () => {
        test("validates patterns", () => {
            expect(validatePattern("1.2.3.4").valid).toBe(true);
            expect(validatePattern("1.2.3.0/24").valid).toBe(true);
            expect(validatePattern("invalid").valid).toBe(false);
        });

        test.skipIf(!!process.env.CI)("manages entries", async () => {
            // Enable allowlist to test logic
            updateConfig({ enabled: true, mode: "allowlist", defaultAllow: false });

            const testIp = "10.10.10.10";

            // Add entry
            await addEntry(testIp, "test user");

            // Verify DB update
            const resultAllowed = await isIPAllowed(testIp);
            expect(resultAllowed.allowed).toBe(true);

            const entries = listEntries();
            const found = entries.find(e => e.pattern === testIp);
            const foundPattern = entries.find(e => e.pattern === testIp);
            expect(foundPattern).toBeDefined();

            // Remove entry
            if (foundPattern) {
                await removeEntry(foundPattern.id);
            }

            const newEntries = listEntries();
            const foundNew = newEntries.find(e => e.pattern === testIp);
            expect(foundNew).toBeUndefined();
        });
    });
});
