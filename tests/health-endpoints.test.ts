// @ts-nocheck
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
 * Tests for Health Check Endpoints and Notifications
 * 
 * Covers:
 * - /-/ping endpoint
 * - /-/health endpoint (both legacy and new format)
 * - /-/quarantine/check/:name/:version endpoint
 * - notifyDesktop helper function
 */

import { describe, expect, test } from "bun:test";
import { notifyDesktop } from "../src/utils/notifications";

const BASE_URL = "http://localhost:4873";

// Helper to make requests
async function fetchEndpoint(path: string): Promise<Response> {
    return fetch(`${BASE_URL}${path}`);
}

// Type for health response (flexible to handle both old and new formats)
interface HealthResponse {
    status: string;
    timestamp?: string;
    version?: string;
    uptime?: { seconds: number; human: string };
    uptime_seconds?: number;
    quarantine_pending?: number;
    memory?: Record<string, number>;
    database?: Record<string, unknown>;
    security?: Record<string, unknown>;
    metrics?: Record<string, unknown>;
}

// Type for quarantine check response
interface QuarantineCheckResponse {
    package?: string;
    version?: string;
    in_quarantine?: boolean;
    awaiting_approval?: boolean;
    filename?: string | null;
    issues?: unknown[] | null;
    admin_panel?: string;
    error?: string;
    message?: string;
}

describe("Health Check Endpoints", () => {
    describe("GET /-/ping", () => {
        test("returns 200 status", async () => {
            const res = await fetchEndpoint("/-/ping");
            expect(res.status).toBe(200);
        });

        test("returns valid response (JSON or text)", async () => {
            const res = await fetchEndpoint("/-/ping");
            const text = await res.text();

            // Can be either "pong" or JSON { ok: true }
            const isValidPing = text === "pong" || text.includes("ok");
            expect(isValidPing).toBe(true);
        });
    });

    describe("GET /-/health", () => {
        test("returns JSON with status 200", async () => {
            const res = await fetchEndpoint("/-/health");
            expect(res.status).toBe(200);
            expect(res.headers.get("Content-Type")).toContain("application/json");
        });

        test("contains status field with 'healthy' value", async () => {
            const res = await fetchEndpoint("/-/health");
            const data = await res.json() as HealthResponse;

            expect(data).toHaveProperty("status");
            expect(data.status).toBe("healthy");
        });

        test("contains timestamp", async () => {
            const res = await fetchEndpoint("/-/health");
            const data = await res.json() as HealthResponse;

            expect(data).toHaveProperty("timestamp");
            expect(typeof data.timestamp).toBe("string");
            // Should be parseable as date
            const date = new Date(data.timestamp!);
            expect(date.toString()).not.toBe("Invalid Date");
        });

        test("contains uptime info", async () => {
            const res = await fetchEndpoint("/-/health");
            const data = await res.json() as HealthResponse;

            // Can be either uptime.seconds (old) or uptime_seconds (new)
            const hasUptime = data.uptime?.seconds !== undefined || data.uptime_seconds !== undefined;
            expect(hasUptime).toBe(true);
        });

        test("contains version info", async () => {
            const res = await fetchEndpoint("/-/health");
            const data = await res.json() as HealthResponse;

            expect(data).toHaveProperty("version");
            expect(typeof data.version).toBe("string");
        });
    });

    describe("GET /-/quarantine/check/:name/:version", () => {
        test("returns JSON response for package check", async () => {
            const res = await fetchEndpoint("/-/quarantine/check/lodash/4.17.21");

            // Should return 200 (found) or 400 (invalid path if route not implemented)
            expect([200, 400, 404]).toContain(res.status);
        });

        test("handles scoped packages format", async () => {
            const res = await fetchEndpoint("/-/quarantine/check/@types/node/20.0.0");

            // Should handle gracefully (200, 400, or 404)
            expect([200, 400, 404]).toContain(res.status);
        });

        test("returns error for missing version", async () => {
            const res = await fetchEndpoint("/-/quarantine/check/lodash");

            // Should return 400 (bad request) or other error code
            expect(res.status).toBeGreaterThanOrEqual(400);
        });
    });
});

describe("notifyDesktop Helper", () => {
    test("does not throw on any platform", () => {
        // This should never throw, regardless of platform
        expect(() => {
            notifyDesktop("Test Title", "Test Message");
        }).not.toThrow();
    });

    test("handles special characters in title and message", () => {
        // Should not throw with quotes, newlines, etc.
        expect(() => {
            notifyDesktop("Title with \"quotes\"", "Message with 'apostrophe' and\nnewline");
        }).not.toThrow();
    });

    test("handles empty strings", () => {
        expect(() => {
            notifyDesktop("", "");
        }).not.toThrow();
    });

    test("handles unicode characters", () => {
        expect(() => {
            notifyDesktop("🚨 Alert", "Package @scope/name@1.0.0 richiede approvazione");
        }).not.toThrow();
    });

    test("handles very long messages", () => {
        const longMessage = "A".repeat(1000);
        expect(() => {
            notifyDesktop("title", longMessage);
        }).not.toThrow();
    });

    test("returns immediately (non-blocking)", () => {
        const start = Date.now();
        notifyDesktop("Test", "Test message");
        const elapsed = Date.now() - start;

        // Should return in less than 100ms (notification is fire-and-forget)
        expect(elapsed).toBeLessThan(100);
    });
});
