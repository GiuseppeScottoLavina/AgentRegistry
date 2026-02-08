/**
 * Upstream Module Tests
 * 
 * Tests for upstream proxy functions with dependency injection.
 * Run with: bun test tests/upstream.test.ts
 */

import { describe, it, expect, beforeEach } from "bun:test";
import {
    fetchFromUpstream,
    prefetchDependencies,
    fetchTarballFromUpstream,
    getScanResultFromCache,
    setScanResultInCache,
    type UpstreamContext
} from "../src/upstream";
import type { PackageMetadata } from "../src/types";
import type { ScanResult } from "../src/security";

describe("Upstream Module", () => {
    // Mock context for testing
    let mockContext: UpstreamContext;
    let mockScanResultsCache: Map<string, ScanResult>;
    let savedPackages: PackageMetadata[];
    let loadedPackages: Map<string, PackageMetadata>;
    let trackedScans: number[];

    beforeEach(() => {
        mockScanResultsCache = new Map();
        savedPackages = [];
        loadedPackages = new Map();
        trackedScans = [];

        mockContext = {
            scanResultsCache: mockScanResultsCache,
            savePackage: async (pkg: PackageMetadata) => {
                savedPackages.push(pkg);
            },
            loadPackage: async (name: string) => {
                return loadedPackages.get(name) || null;
            },
            trackScan: (scanTimeMs: number) => {
                trackedScans.push(scanTimeMs);
            }
        };
    });

    describe("UpstreamContext Interface", () => {
        it("UpstreamContext has all required properties", () => {
            expect(mockContext.scanResultsCache).toBeInstanceOf(Map);
            expect(typeof mockContext.savePackage).toBe("function");
            expect(typeof mockContext.loadPackage).toBe("function");
            expect(typeof mockContext.trackScan).toBe("function");
        });

        it("scanResultsCache can store and retrieve ScanResult", () => {
            const mockResult: ScanResult = {
                safe: true,
                issues: [],
                filesScanned: 5,
                scanTimeMs: 10
            };

            mockScanResultsCache.set("test@1.0.0", mockResult);
            expect(mockScanResultsCache.get("test@1.0.0")).toEqual(mockResult);
        });

        it("trackScan callback records scan times", () => {
            mockContext.trackScan(15);
            mockContext.trackScan(25);

            expect(trackedScans).toEqual([15, 25]);
        });
    });

    describe("getScanResultFromCache", () => {
        it("returns undefined for non-existent cache key", () => {
            const result = getScanResultFromCache("nonexistent@1.0.0");
            expect(result).toBeUndefined();
        });

        it("returns undefined from custom empty cache", () => {
            const customCache = new Map<string, ScanResult>();
            const result = getScanResultFromCache("anything@1.0.0", customCache);
            expect(result).toBeUndefined();
        });

        it("retrieves from custom cache when provided", () => {
            const customCache = new Map<string, ScanResult>();
            const mockResult: ScanResult = {
                safe: true,
                issues: [],
                filesScanned: 10,
                scanTimeMs: 5
            };
            customCache.set("custom-pkg@1.0.0", mockResult);

            const result = getScanResultFromCache("custom-pkg@1.0.0", customCache);
            expect(result).toBeDefined();
            expect(result?.safe).toBe(true);
            expect(result?.filesScanned).toBe(10);
        });
    });

    describe("setScanResultInCache", () => {
        it("stores scan result in default cache", () => {
            const mockResult: ScanResult = {
                safe: false,
                issues: [{ severity: "high", description: "Test issue", file: "test.js", line: 1 }],
                filesScanned: 3,
                scanTimeMs: 50
            };

            setScanResultInCache("test-pkg@2.0.0", mockResult);
            const retrieved = getScanResultFromCache("test-pkg@2.0.0");

            expect(retrieved).toBeDefined();
            expect(retrieved?.safe).toBe(false);
            expect(retrieved?.issues.length).toBe(1);
        });

        it("stores scan result in custom cache", () => {
            const customCache = new Map<string, ScanResult>();
            const mockResult: ScanResult = {
                safe: true,
                issues: [],
                filesScanned: 8,
                scanTimeMs: 12
            };

            setScanResultInCache("custom-write@3.0.0", mockResult, customCache);

            // Default cache should NOT have it
            expect(getScanResultFromCache("custom-write@3.0.0")).toBeUndefined();

            // Custom cache should have it
            expect(customCache.get("custom-write@3.0.0")).toBeDefined();
            expect(customCache.get("custom-write@3.0.0")?.safe).toBe(true);
        });

        it("overwrites existing result in cache", () => {
            const cache = new Map<string, ScanResult>();

            const first: ScanResult = { safe: true, issues: [], filesScanned: 1, scanTimeMs: 5 };
            const second: ScanResult = { safe: false, issues: [{ severity: "critical", description: "evil", file: "x.js" }], filesScanned: 2, scanTimeMs: 10 };

            setScanResultInCache("overwrite@1.0.0", first, cache);
            expect(cache.get("overwrite@1.0.0")?.safe).toBe(true);

            setScanResultInCache("overwrite@1.0.0", second, cache);
            expect(cache.get("overwrite@1.0.0")?.safe).toBe(false);
            expect(cache.get("overwrite@1.0.0")?.issues).toHaveLength(1);
        });
    });

    describe("fetchFromUpstream", () => {
        it("is an async function", () => {
            expect(typeof fetchFromUpstream).toBe("function");
            // isPrefetch has a default value, so JS length is 3 (not 4)
            expect(fetchFromUpstream.length).toBe(3);
        });

        it("accepts a savePackage callback", async () => {
            const mockSavePackage: (pkg: PackageMetadata) => Promise<void> = async () => { };
            // Just verify it can be called (behavior depends on UPSTREAM_REGISTRY)
            const result = await fetchFromUpstream(
                "test-pkg",
                "http://localhost:4873",
                mockSavePackage,
                true // prefetch mode
            );
            // Either null (no upstream) or a Response (if upstream is configured)
            expect(result === null || result instanceof Response).toBe(true);
        });
    });

    describe("prefetchDependencies", () => {
        it("is an async function that accepts 3 parameters", () => {
            expect(typeof prefetchDependencies).toBe("function");
            expect(prefetchDependencies.length).toBe(3); // pkg, baseUrl, savePackage
        });

        it("handles package without dist-tags.latest", async () => {
            const pkg: PackageMetadata = {
                name: "no-latest-pkg",
                "dist-tags": {},
                versions: {},
                time: { created: "", modified: "" },
                _id: "no-latest-pkg",
                _rev: "1-abc"
            } as PackageMetadata;

            const mockSave = async () => { };
            // Should return without errors (early return on line 103)
            await expect(prefetchDependencies(pkg, "http://localhost:4873", mockSave))
                .resolves.toBeUndefined();
        });

        it("handles package with latest but no dependencies", async () => {
            const pkg: PackageMetadata = {
                name: "no-deps-pkg",
                "dist-tags": { latest: "1.0.0" },
                versions: {
                    "1.0.0": {
                        name: "no-deps-pkg",
                        version: "1.0.0",
                        dist: { tarball: "", shasum: "" }
                        // No dependencies field
                    }
                },
                time: { created: "", modified: "" },
                _id: "no-deps-pkg",
                _rev: "1-abc"
            } as unknown as PackageMetadata;

            const mockSave = async () => { };
            // Should return without errors (early return on line 106)
            await expect(prefetchDependencies(pkg, "http://localhost:4873", mockSave))
                .resolves.toBeUndefined();
        });

        it("handles package with empty dependencies object", async () => {
            const pkg: PackageMetadata = {
                name: "empty-deps-pkg",
                "dist-tags": { latest: "1.0.0" },
                versions: {
                    "1.0.0": {
                        name: "empty-deps-pkg",
                        version: "1.0.0",
                        dependencies: {},
                        dist: { tarball: "", shasum: "" }
                    }
                },
                time: { created: "", modified: "" },
                _id: "empty-deps-pkg",
                _rev: "1-abc"
            } as unknown as PackageMetadata;

            const mockSave = async () => { };
            // Should return without errors (early return on line 109 — empty deps)
            await expect(prefetchDependencies(pkg, "http://localhost:4873", mockSave))
                .resolves.toBeUndefined();
        });
    });

    describe("fetchTarballFromUpstream", () => {
        it("function exists and accepts UpstreamContext", () => {
            expect(typeof fetchTarballFromUpstream).toBe("function");
            // Verify signature by checking function length (parameters)
            // name, version, tarballPath, ctx = 4 params
            expect(fetchTarballFromUpstream.length).toBe(4);
        });

        it("returns false when UPSTREAM_REGISTRY is not set", async () => {
            // With empty config, should return false immediately
            // We test this by verifying no side effects on our mock
            const result = await fetchTarballFromUpstream(
                "nonexistent-pkg",
                "1.0.0",
                "/tmp/nonexistent.tgz",
                mockContext
            );

            // Should return false (no upstream) and not modify cache
            expect(result).toBe(false);
            expect(savedPackages.length).toBe(0);
            expect(trackedScans.length).toBe(0);
        });

        it("does not pollute scan cache when upstream is disabled", async () => {
            const result = await fetchTarballFromUpstream(
                "another-pkg",
                "2.0.0",
                "/tmp/another.tgz",
                mockContext
            );

            expect(result).toBe(false);
            expect(mockScanResultsCache.size).toBe(0);
        });
    });
});
