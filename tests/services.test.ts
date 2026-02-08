/**
 * Services Unit Tests
 * 
 * Tests for broadcast.ts and cache.ts service modules.
 * Pure unit tests — no running server required.
 * 
 * Run with: bun test tests/services.test.ts
 */

import { describe, test, expect, beforeEach, afterAll } from "bun:test";
import { TARBALL_CACHE_MAX_SIZE } from "../src/config";
import {
    setAdminWs,
    broadcastToAdmin,
    getUptimeSeconds,
    SERVER_START_TIME
} from "../src/services/broadcast";
import {
    getTarballFromCache,
    setTarballInCache,
    deleteTarballFromCache,
    getTarballCacheSize,
    getScanResultFromCache,
    setScanResultInCache,
    checkRateLimit,
    rateLimitStore
} from "../src/services/cache";

// ============================================================================
// Broadcast Service Tests
// ============================================================================

describe("Broadcast Service", () => {

    describe("getUptimeSeconds", () => {
        test("returns a non-negative number", () => {
            const uptime = getUptimeSeconds();
            expect(uptime).toBeGreaterThanOrEqual(0);
        });

        test("is computed from SERVER_START_TIME", () => {
            const expected = Math.floor((Date.now() - SERVER_START_TIME) / 1000);
            const actual = getUptimeSeconds();
            // Allow 1 second tolerance
            expect(Math.abs(actual - expected)).toBeLessThanOrEqual(1);
        });
    });

    describe("setAdminWs", () => {
        test("accepts null without error", () => {
            expect(() => setAdminWs(null)).not.toThrow();
        });

        test("accepts a mock WebSocket-like object", () => {
            const mockWs = {
                readyState: 1,
                send: () => { },
                close: () => { }
            } as any;
            expect(() => setAdminWs(mockWs)).not.toThrow();
        });

        test("closes previous session when setting new one", () => {
            let closeCalled = false;
            let closeCode: number | undefined;
            let closeReason: string | undefined;

            const oldWs = {
                readyState: 1,
                send: () => { },
                close: (code?: number, reason?: string) => {
                    closeCalled = true;
                    closeCode = code;
                    closeReason = reason;
                }
            } as any;

            const newWs = {
                readyState: 1,
                send: () => { },
                close: () => { }
            } as any;

            // Set old connection
            setAdminWs(oldWs);
            // Replace with new — should close old
            setAdminWs(newWs);

            expect(closeCalled).toBe(true);
            expect(closeCode).toBe(4001);
            expect(closeReason).toBe("Session replaced");

            // Cleanup
            setAdminWs(null);
        });

        test("same WebSocket does not close itself", () => {
            let closeCalled = false;
            const ws = {
                readyState: 1,
                send: () => { },
                close: () => { closeCalled = true; }
            } as any;

            setAdminWs(ws);
            setAdminWs(ws); // Same ws again

            expect(closeCalled).toBe(false);

            // Cleanup
            setAdminWs(null);
        });

        test("handles close() errors gracefully", () => {
            const oldWs = {
                readyState: 1,
                send: () => { },
                close: () => { throw new Error("close failed"); }
            } as any;

            const newWs = {
                readyState: 1,
                send: () => { },
                close: () => { }
            } as any;

            setAdminWs(oldWs);
            // Should not throw even if close() throws
            expect(() => setAdminWs(newWs)).not.toThrow();

            // Cleanup
            setAdminWs(null);
        });
    });

    describe("broadcastToAdmin", () => {
        test("does nothing when no WebSocket is set", () => {
            setAdminWs(null);
            // Should not throw
            expect(() => broadcastToAdmin("test_event", { key: "value" })).not.toThrow();
        });

        test("sends JSON message when WebSocket is connected (readyState=1)", () => {
            let sentData: string | undefined;
            const mockWs = {
                readyState: 1,
                send: (data: string) => { sentData = data; },
                close: () => { }
            } as any;

            setAdminWs(mockWs);
            broadcastToAdmin("package_published", { name: "test-pkg", version: "1.0.0" });

            expect(sentData).toBeDefined();
            const parsed = JSON.parse(sentData!);
            expect(parsed.type).toBe("broadcast");
            expect(parsed.event).toBe("package_published");
            expect(parsed.data.name).toBe("test-pkg");
            expect(parsed.data.version).toBe("1.0.0");
            expect(parsed.timestamp).toBeGreaterThan(0);

            // Cleanup
            setAdminWs(null);
        });

        test("does not send when WebSocket readyState is not 1", () => {
            let sendCalled = false;
            const mockWs = {
                readyState: 0, // CONNECTING, not OPEN
                send: () => { sendCalled = true; },
                close: () => { }
            } as any;

            setAdminWs(mockWs);
            broadcastToAdmin("test_event", {});

            expect(sendCalled).toBe(false);

            // Cleanup
            setAdminWs(null);
        });

        test("handles send() errors gracefully", () => {
            const mockWs = {
                readyState: 1,
                send: () => { throw new Error("send failed"); },
                close: () => { }
            } as any;

            setAdminWs(mockWs);
            // Should not throw even if send() throws
            expect(() => broadcastToAdmin("test_event", {})).not.toThrow();

            // Cleanup
            setAdminWs(null);
        });
    });
});

// ============================================================================
// Cache Service Tests
// ============================================================================

describe("Cache Service", () => {

    describe("Tarball Cache", () => {
        beforeEach(() => {
            // Clear cache by deleting any known keys
            // (The module doesn't export a clear method, so we work around it)
        });

        test("returns undefined for missing key", () => {
            expect(getTarballFromCache("nonexistent-key")).toBeUndefined();
        });

        test("stores and retrieves a tarball buffer", () => {
            const key = `test-tarball-${Date.now()}`;
            const data = Buffer.from("test-tarball-data");

            setTarballInCache(key, data);
            const result = getTarballFromCache(key);

            expect(result).toBeDefined();
            expect(result!.toString()).toBe("test-tarball-data");

            // Cleanup
            deleteTarballFromCache(key);
        });

        test("delete removes a cached tarball", () => {
            const key = `test-delete-${Date.now()}`;
            const data = Buffer.from("to-delete");

            setTarballInCache(key, data);
            expect(getTarballFromCache(key)).toBeDefined();

            deleteTarballFromCache(key);
            expect(getTarballFromCache(key)).toBeUndefined();
        });

        test("getTarballCacheSize returns current cache size", () => {
            const initialSize = getTarballCacheSize();
            const key = `test-size-${Date.now()}`;

            setTarballInCache(key, Buffer.from("data"));
            expect(getTarballCacheSize()).toBe(initialSize + 1);

            deleteTarballFromCache(key);
            expect(getTarballCacheSize()).toBe(initialSize);
        });

        test("LRU eviction when cache is full", () => {
            const baseName = `lru-evict-${Date.now()}`;
            const keys: string[] = [];

            // Fill cache to exact max capacity
            const initialSize = getTarballCacheSize();
            const toAdd = TARBALL_CACHE_MAX_SIZE - initialSize;

            for (let i = 0; i < toAdd; i++) {
                const key = `${baseName}-${i}`;
                keys.push(key);
                setTarballInCache(key, Buffer.from(`data-${i}`));
            }

            expect(getTarballCacheSize()).toBe(TARBALL_CACHE_MAX_SIZE);

            // First key should still be there
            expect(getTarballFromCache(keys[0])).toBeDefined();

            // Add one more — should evict the oldest (first key we added, or an older existing key)
            const overflowKey = `${baseName}-overflow`;
            setTarballInCache(overflowKey, Buffer.from("overflow-data"));

            // Cache size should remain at max (not exceed)
            expect(getTarballCacheSize()).toBe(TARBALL_CACHE_MAX_SIZE);

            // The overflow entry should be present
            expect(getTarballFromCache(overflowKey)).toBeDefined();

            // Cleanup
            deleteTarballFromCache(overflowKey);
            for (const key of keys) {
                deleteTarballFromCache(key);
            }
        });
    });

    describe("Scan Results Cache", () => {
        test("returns undefined for missing hash", () => {
            expect(getScanResultFromCache("nonexistent-hash")).toBeUndefined();
        });

        test("stores and retrieves scan result", () => {
            const hash = `test-hash-${Date.now()}`;
            const scanResult = {
                safe: true,
                issues: [],
                filesScanned: 5,
                scanTimeMs: 42
            };

            setScanResultInCache(hash, scanResult);
            const result = getScanResultFromCache(hash);

            expect(result).toBeDefined();
            expect(result!.safe).toBe(true);
            expect(result!.filesScanned).toBe(5);
            expect(result!.scanTimeMs).toBe(42);
        });

        test("stores unsafe scan result with issues", () => {
            const hash = `test-unsafe-${Date.now()}`;
            const scanResult = {
                safe: false,
                issues: [
                    { file: "index.js", severity: "critical", description: "eval detected" }
                ],
                filesScanned: 3,
                scanTimeMs: 15
            };

            setScanResultInCache(hash, scanResult);
            const result = getScanResultFromCache(hash);

            expect(result).toBeDefined();
            expect(result!.safe).toBe(false);
            expect(result!.issues).toHaveLength(1);
            expect(result!.issues[0].severity).toBe("critical");
        });
    });

    describe("Rate Limiting", () => {
        beforeEach(() => {
            rateLimitStore.clear();
        });

        test("allows first request from new IP", () => {
            const result = checkRateLimit("192.168.1.100", 10, 60000);
            expect(result.allowed).toBe(true);
            expect(result.remaining).toBe(9);
        });

        test("decrements remaining on subsequent requests", () => {
            checkRateLimit("192.168.1.101", 10, 60000);
            const result = checkRateLimit("192.168.1.101", 10, 60000);
            expect(result.allowed).toBe(true);
            expect(result.remaining).toBe(8);
        });

        test("blocks when rate limit exceeded", () => {
            const ip = "192.168.1.102";
            // Exhaust the limit
            for (let i = 0; i < 5; i++) {
                checkRateLimit(ip, 5, 60000);
            }

            const result = checkRateLimit(ip, 5, 60000);
            expect(result.allowed).toBe(false);
            expect(result.remaining).toBe(0);
        });

        test("resets after window expires", () => {
            const ip = "192.168.1.103";
            // Use a very short window (1ms)
            checkRateLimit(ip, 5, 1);

            // Wait for window to expire
            const start = Date.now();
            while (Date.now() - start < 5) { /* spin */ }

            const result = checkRateLimit(ip, 5, 1);
            expect(result.allowed).toBe(true);
            expect(result.remaining).toBe(4);
        });

        test("tracks different IPs independently", () => {
            checkRateLimit("10.0.0.1", 2, 60000);
            checkRateLimit("10.0.0.1", 2, 60000);
            const blocked = checkRateLimit("10.0.0.1", 2, 60000);
            expect(blocked.allowed).toBe(false);

            // Different IP should be unaffected
            const allowed = checkRateLimit("10.0.0.2", 2, 60000);
            expect(allowed.allowed).toBe(true);
        });
    });
});
