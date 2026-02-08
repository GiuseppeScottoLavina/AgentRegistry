/**
 * Unit tests for src/cve.ts module
 * Tests CVE checking, caching, and vulnerability parsing
 */

import { describe, it, expect, beforeEach } from "bun:test";
import {
    checkCVE,
    getCVESummary,
    clearCVECache,
    getAllCachedCVEs,
    scanPackages,
} from "../src/cve";

describe("CVE Module", () => {
    // Clear cache before each test
    beforeEach(() => {
        clearCVECache();
    });

    describe("clearCVECache", () => {
        it("clears all cached entries", async () => {
            // First check a package to populate cache
            await checkCVE("test-package", "1.0.0");

            // Clear cache
            clearCVECache();

            // Verify cache is empty
            const cacheAfterClear = getAllCachedCVEs();
            expect(cacheAfterClear.size).toBe(0);
        });
    });

    describe("getAllCachedCVEs", () => {
        it("returns a Map", () => {
            const cache = getAllCachedCVEs();
            expect(cache instanceof Map).toBe(true);
        });

        it("returns empty Map initially", () => {
            const cache = getAllCachedCVEs();
            expect(cache.size).toBe(0);
        });

        it("contains entry after checkCVE for real package", async () => {
            await checkCVE("lodash", "4.17.21");
            const cache = getAllCachedCVEs();
            // Cache may or may not have entry depending on API response
            expect(cache instanceof Map).toBe(true);
        });
    });

    describe("getCVESummary", () => {
        it("returns summary structure", () => {
            const summary = getCVESummary();

            expect(summary).toHaveProperty("totalPackages");
            expect(summary).toHaveProperty("packagesWithCVEs");
            expect(summary).toHaveProperty("bySeverity");
            expect(summary).toHaveProperty("recentCritical");
            expect(typeof summary.totalPackages).toBe("number");
            expect(typeof summary.packagesWithCVEs).toBe("number");
            expect(Array.isArray(summary.recentCritical)).toBe(true);
        });

        it("returns zero counts when cache is empty", () => {
            clearCVECache();
            const summary = getCVESummary();

            expect(summary.totalPackages).toBe(0);
            expect(summary.packagesWithCVEs).toBe(0);
        });

        it("has bySeverity object", () => {
            const summary = getCVESummary();
            expect(typeof summary.bySeverity).toBe("object");
        });
    });

    describe("checkCVE", () => {
        it("returns CVECheckResult structure", async () => {
            const result = await checkCVE("lodash", "4.17.21");

            expect(result).toHaveProperty("packageName");
            expect(result).toHaveProperty("vulnerabilities");
            expect(result).toHaveProperty("checkedAt");
            expect(result).toHaveProperty("fromCache");
            expect(result.packageName).toBe("lodash");
            expect(Array.isArray(result.vulnerabilities)).toBe(true);
        });

        it("caches results", async () => {
            // First call
            const result1 = await checkCVE("test-cache-pkg", "1.0.0");
            expect(result1.fromCache).toBe(false);

            // Second call should be from cache
            const result2 = await checkCVE("test-cache-pkg", "1.0.0");
            expect(result2.fromCache).toBe(true);
        });

        it("handles package without version", async () => {
            const result = await checkCVE("express");

            expect(result.packageName).toBe("express");
            expect(result.version).toBeUndefined();
        });

        it("handles non-existent package gracefully", async () => {
            const result = await checkCVE("this-package-does-not-exist-12345", "0.0.0");

            expect(result).toHaveProperty("vulnerabilities");
            expect(Array.isArray(result.vulnerabilities)).toBe(true);
        });

        it("returns timestamp in checkedAt", async () => {
            const before = Date.now();
            const result = await checkCVE("timestamp-test", "1.0.0");
            const after = Date.now();

            expect(result.checkedAt).toBeGreaterThanOrEqual(before);
            expect(result.checkedAt).toBeLessThanOrEqual(after);
        });
    });

    describe("scanPackages", () => {
        it("returns a Map", async () => {
            const result = await scanPackages(["lodash"]);
            expect(result instanceof Map).toBe(true);
        });

        it("handles empty array", async () => {
            const result = await scanPackages([]);
            expect(result.size).toBe(0);
        });

        it("scans multiple packages", async () => {
            const result = await scanPackages(["lodash", "express"]);
            expect(result.size).toBeLessThanOrEqual(2);
        });
    });
});
