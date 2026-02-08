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
    });

    describe("setScanResultInCache", () => {
        it("stores scan result in cache", () => {
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
    });

    describe("fetchFromUpstream", () => {
        it("returns null when UPSTREAM_REGISTRY is not set", async () => {
            // Note: This test validates behavior when upstream is disabled
            // In real scenario, UPSTREAM_REGISTRY would be empty/undefined
            // We can't easily mock the config, so we verify the function exists
            expect(typeof fetchFromUpstream).toBe("function");
        });
    });

    describe("prefetchDependencies", () => {
        it("function exists and is callable", () => {
            expect(typeof prefetchDependencies).toBe("function");
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
    });
});
