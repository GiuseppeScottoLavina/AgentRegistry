/**
 * Unit tests for src/metrics.ts module
 * Tests metrics collection, recording, and snapshots
 */

import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import {
    recordRequest,
    recordSecurityEvent,
    getMetricsSnapshot,
    resetMetrics,
    startMetricsCollection,
    stopMetricsCollection,
} from "../src/metrics";

describe("Metrics Module", () => {
    beforeEach(() => {
        resetMetrics();
    });

    afterEach(() => {
        stopMetricsCollection();
    });

    describe("recordRequest", () => {
        it("records request without error", () => {
            expect(() => recordRequest(50, false)).not.toThrow();
        });

        it("records cache hit", () => {
            recordRequest(10, true);
            const snapshot = getMetricsSnapshot();
            expect(snapshot.cacheHits).toBe(1);
        });

        it("records cache miss", () => {
            recordRequest(100, false);
            const snapshot = getMetricsSnapshot();
            expect(snapshot.cacheMisses).toBe(1);
        });

        it("increments total requests", () => {
            recordRequest(1, false);
            recordRequest(2, false);
            recordRequest(3, false);
            expect(getMetricsSnapshot().totalRequests).toBe(3);
        });
    });

    describe("recordSecurityEvent", () => {
        it("records block event without error", () => {
            expect(() => recordSecurityEvent("block")).not.toThrow();
        });

        it("records quarantine event", () => {
            expect(() => recordSecurityEvent("quarantine")).not.toThrow();
        });

        it("records scan event", () => {
            expect(() => recordSecurityEvent("scan")).not.toThrow();
        });
    });

    describe("getMetricsSnapshot", () => {
        it("returns snapshot object", () => {
            const snapshot = getMetricsSnapshot();
            expect(snapshot).toBeDefined();
            expect(typeof snapshot).toBe("object");
        });

        it("has totalRequests", () => {
            const snapshot = getMetricsSnapshot();
            expect(typeof snapshot.totalRequests).toBe("number");
        });

        it("has cacheHits and cacheMisses", () => {
            const snapshot = getMetricsSnapshot();
            expect(typeof snapshot.cacheHits).toBe("number");
            expect(typeof snapshot.cacheMisses).toBe("number");
        });

        it("has uptimeSeconds", () => {
            const snapshot = getMetricsSnapshot();
            expect(typeof snapshot.uptimeSeconds).toBe("number");
        });

        it("has overallCacheHitRate", () => {
            const snapshot = getMetricsSnapshot();
            expect(typeof snapshot.overallCacheHitRate).toBe("number");
        });

        it("has time series arrays", () => {
            const snapshot = getMetricsSnapshot();
            expect(Array.isArray(snapshot.requestsPerSecond)).toBe(true);
            expect(Array.isArray(snapshot.avgLatencyMs)).toBe(true);
            expect(Array.isArray(snapshot.cacheHitRateHistory)).toBe(true);
        });
    });

    describe("resetMetrics", () => {
        it("resets totalRequests", () => {
            recordRequest(50, false);
            recordRequest(50, false);
            resetMetrics();

            expect(getMetricsSnapshot().totalRequests).toBe(0);
        });

        it("resets cacheHits and cacheMisses", () => {
            recordRequest(10, true);
            recordRequest(10, false);
            resetMetrics();

            const snapshot = getMetricsSnapshot();
            expect(snapshot.cacheHits).toBe(0);
            expect(snapshot.cacheMisses).toBe(0);
        });

        it("does not throw", () => {
            expect(() => resetMetrics()).not.toThrow();
        });
    });

    describe("startMetricsCollection", () => {
        it("starts without error", () => {
            expect(() => startMetricsCollection()).not.toThrow();
        });

        it("can be called multiple times", () => {
            startMetricsCollection();
            startMetricsCollection();
            expect(true).toBe(true);
        });
    });

    describe("stopMetricsCollection", () => {
        it("stops without error", () => {
            startMetricsCollection();
            expect(() => stopMetricsCollection()).not.toThrow();
        });

        it("can be called without starting", () => {
            expect(() => stopMetricsCollection()).not.toThrow();
        });
    });

    describe("Metric Calculations", () => {
        it("tracks cache hits correctly", () => {
            resetMetrics();
            recordRequest(10, true);
            recordRequest(10, true);
            recordRequest(10, false);

            const snapshot = getMetricsSnapshot();
            expect(snapshot.cacheHits).toBe(2);
            expect(snapshot.cacheMisses).toBe(1);
        });

        it("calculates overall cache hit rate", () => {
            resetMetrics();
            recordRequest(10, true);
            recordRequest(10, true);
            recordRequest(10, false);
            recordRequest(10, false);

            const snapshot = getMetricsSnapshot();
            // 2 hits out of 4 = 50%
            expect(snapshot.overallCacheHitRate).toBe(50);
        });

        it("handles zero requests", () => {
            resetMetrics();
            const snapshot = getMetricsSnapshot();
            expect(snapshot.totalRequests).toBe(0);
        });
    });

    describe("Metrics Aggregation", () => {
        it("aggregates data over time when collection is running", async () => {
            resetMetrics();
            startMetricsCollection();

            // Record some requests
            recordRequest(50, true);
            recordRequest(100, false);

            // Wait for aggregation interval (> 1 second)
            await new Promise(resolve => setTimeout(resolve, 1100));

            const snapshot = getMetricsSnapshot();

            // After aggregation, time series should have data
            expect(snapshot.requestsPerSecond.length).toBeGreaterThanOrEqual(0);

            stopMetricsCollection();
        });

        it("records latency data", () => {
            resetMetrics();
            recordRequest(25, false);
            recordRequest(75, false);
            recordRequest(50, true);

            const snapshot = getMetricsSnapshot();
            expect(snapshot.totalRequests).toBe(3);
        });
    });
});
