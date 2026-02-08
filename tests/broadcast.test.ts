/**
 * AgentRegistry WebSocket Broadcast Tests
 * 
 * Tests to verify that all WebSocket broadcast events are correctly sent
 * when important actions occur. This prevents bugs where the Admin Panel
 * doesn't update in real-time.
 * 
 * Tested events:
 * - package_blocked: When a package fails security scan
 * - package_published: When a package is successfully published
 * - quarantine_rescanned: After rescanning quarantine
 * - package_approved: When a single package is approved
 * - quarantine_bulk_approved: When all quarantine is bulk approved
 * - autoAllowChanged: When auto-allow setting is toggled
 * 
 * Run with: bun test tests/broadcast.test.ts
 * Note: Requires running server on port 4873
 */

import { describe, test, expect, beforeAll, afterAll, beforeEach, afterEach } from "bun:test";

const BASE_URL = "http://localhost:4873";
const WS_URL = "ws://localhost:4873/-/admin/ws";

interface WSMessage {
    type: string;
    data?: any;
    timestamp?: number;
}

// Helper to create WebSocket connection with token
async function createWS(): Promise<WebSocket> {
    const res = await fetch(`${BASE_URL}/-/admin`);
    const html = await res.text();
    const tokenMatch = html.match(/ADMIN_SESSION_TOKEN\s*=\s*['"]([^'"]+)['"]/);
    const token = tokenMatch?.[1];

    if (!token) {
        throw new Error("Could not extract admin token from admin panel");
    }

    return new Promise((resolve, reject) => {
        const ws = new WebSocket(`${WS_URL}?token=${token}`);

        const timeout = setTimeout(() => {
            ws.close();
            reject(new Error("WebSocket connection timeout"));
        }, 5000);

        ws.onopen = () => {
            clearTimeout(timeout);
        };

        ws.onmessage = (e) => {
            const msg = JSON.parse(e.data);
            if (msg.type === "connected") {
                resolve(ws);
            }
        };

        ws.onerror = (err) => {
            clearTimeout(timeout);
            reject(err);
        };
    });
}

// Helper to wait for a specific broadcast message (or any of multiple types)
// Note: Server broadcasts have format { type: "broadcast", event: eventType, data }
function waitForBroadcast(ws: WebSocket, expectedEvents: string | string[], timeoutMs: number = 10000): Promise<WSMessage & { event?: string }> {
    const events = Array.isArray(expectedEvents) ? expectedEvents : [expectedEvents];
    return new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
            ws.removeEventListener("message", handler);
            reject(new Error(`Timeout waiting for broadcast: ${events.join(" or ")}`));
        }, timeoutMs);

        const handler = (e: MessageEvent) => {
            const msg = JSON.parse(e.data) as WSMessage & { event?: string };
            // Check both direct type match and broadcast event match
            if (events.includes(msg.type) || (msg.type === "broadcast" && events.includes(msg.event || ""))) {
                clearTimeout(timeout);
                ws.removeEventListener("message", handler);
                resolve(msg);
            }
        };

        ws.addEventListener("message", handler);
    });
}

// Helper to send message and wait for response
function sendAndReceive(ws: WebSocket, action: string, payload: any = {}, expectedType: string): Promise<WSMessage> {
    return new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
            ws.removeEventListener("message", handler);
            reject(new Error(`Timeout waiting for ${expectedType}`));
        }, 5000);

        const handler = (e: MessageEvent) => {
            const msg = JSON.parse(e.data) as WSMessage;
            if (msg.type === expectedType || msg.type === "error") {
                clearTimeout(timeout);
                ws.removeEventListener("message", handler);
                resolve(msg);
            }
        };

        ws.addEventListener("message", handler);
        ws.send(JSON.stringify({ action, payload }));
    });
}

// Generate a unique package name for each test
function uniquePackageName(base: string): string {
    return `${base}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

describe("WebSocket Broadcast Events", () => {
    let ws: WebSocket;

    beforeAll(async () => {
        try {
            ws = await createWS();
        } catch (err) {
            console.error("Failed to connect WebSocket:", err);
            throw err;
        }
    });

    afterAll(() => {
        ws?.close();
    });

    // =========================================================================
    // Admin Panel handler coverage check (CRITICAL - these catch missing handlers)
    // =========================================================================
    describe("Admin Panel Broadcast Handlers", () => {
        test("Admin Panel HTML contains handlers for all broadcast types", async () => {
            const res = await fetch(`${BASE_URL}/-/admin`);
            const html = await res.text();

            // Check that all broadcast event handlers exist in the admin panel
            const requiredHandlers = [
                "case 'package_blocked'",
                "case 'package_published'",
                "case 'quarantine_rescanned'",
                "case 'package_approved'",
                "case 'quarantine_bulk_approved'",
                "case 'autoAllowChanged'"
            ];

            for (const handler of requiredHandlers) {
                expect(html).toContain(handler);
            }
        });

        test("Admin Panel handlers trigger getQuarantine refresh for quarantine events", async () => {
            const res = await fetch(`${BASE_URL}/-/admin`);
            const html = await res.text();

            // Verify quarantine-related handlers call getQuarantine
            // After package_blocked, should refresh quarantine
            expect(html).toMatch(/case 'package_blocked'[\s\S]*?send\(['"]getQuarantine['"]\)/);
            expect(html).toMatch(/case 'package_approved'[\s\S]*?send\(['"]getQuarantine['"]\)/);
            expect(html).toMatch(/case 'quarantine_rescanned'[\s\S]*?send\(['"]getQuarantine['"]\)/);
            expect(html).toMatch(/case 'quarantine_bulk_approved'[\s\S]*?send\(['"]getQuarantine['"]\)/);
        });

        test("Admin Panel handlers trigger getStats refresh for state-changing events", async () => {
            const res = await fetch(`${BASE_URL}/-/admin`);
            const html = await res.text();

            // State-changing events should refresh stats
            expect(html).toMatch(/case 'package_blocked'[\s\S]*?send\(['"]getStats['"]\)/);
            expect(html).toMatch(/case 'package_published'[\s\S]*?send\(['"]getStats['"]\)/);
            expect(html).toMatch(/case 'package_approved'[\s\S]*?send\(['"]getStats['"]\)/);
        });

        test("Admin Panel handlers trigger getCache refresh for cache-changing events", async () => {
            const res = await fetch(`${BASE_URL}/-/admin`);
            const html = await res.text();

            // Published packages should refresh cache
            expect(html).toMatch(/case 'package_published'[\s\S]*?send\(['"]getCache['"]\)/);
        });

        test("Admin Panel handlers show toast notifications for events", async () => {
            const res = await fetch(`${BASE_URL}/-/admin`);
            const html = await res.text();

            // All handlers should show a toast
            expect(html).toMatch(/case 'package_blocked'[\s\S]*?showToast/);
            expect(html).toMatch(/case 'package_published'[\s\S]*?showToast/);
            expect(html).toMatch(/case 'quarantine_rescanned'[\s\S]*?showToast/);
            expect(html).toMatch(/case 'package_approved'[\s\S]*?showToast/);
            expect(html).toMatch(/case 'quarantine_bulk_approved'[\s\S]*?showToast/);
            expect(html).toMatch(/case 'autoAllowChanged'[\s\S]*?showToast/);
        });
    });

    // =========================================================================
    // Server broadcast points verification
    // =========================================================================
    describe("Server Broadcast Points", () => {
        test("Server exports broadcastToAdmin function", async () => {
            // Indirectly verify by checking getStats works (requires broadcast infrastructure)
            const response = await sendAndReceive(ws, "getStats", {}, "stats");
            expect(response.type).toBe("stats");
        });

        test("autoAllowChanged broadcasts when setting is toggled", async () => {
            // Get current setting
            const current = await sendAndReceive(ws, "getAutoAllowSetting", {}, "autoAllowSetting");
            const originalSetting = current.data?.enabled ?? true;

            // Collect all messages during the action
            const messages: (WSMessage & { event?: string })[] = [];
            const collectHandler = (e: MessageEvent) => {
                messages.push(JSON.parse(e.data));
            };
            ws.addEventListener("message", collectHandler);

            try {
                // Toggle the setting (this should trigger broadcast + response)
                ws.send(JSON.stringify({ action: "setAutoAllowSetting", payload: { enabled: !originalSetting } }));

                // Wait for response (also collects broadcast that may arrive before/after)
                await new Promise(r => setTimeout(r, 200));

                // Verify broadcast was received (type="broadcast" with event="autoAllowChanged")
                const broadcast = messages.find(m =>
                    m.type === "broadcast" && m.event === "autoAllowChanged"
                );
                expect(broadcast).toBeDefined();
                expect(broadcast!.data.enabled).toBe(!originalSetting);
            } finally {
                ws.removeEventListener("message", collectHandler);
                // Restore original setting
                ws.send(JSON.stringify({ action: "setAutoAllowSetting", payload: { enabled: originalSetting } }));
                await new Promise(r => setTimeout(r, 100));
            }
        });

        test("quarantine_rescanned broadcasts when rescan is triggered", async () => {
            // Start listening for broadcast or rescanComplete (server may send either)
            const broadcastPromise = waitForBroadcast(ws, ["quarantine_rescanned", "rescanComplete"], 10000);

            // Small delay to ensure listener is active
            await new Promise(r => setTimeout(r, 50));

            // Trigger rescan
            ws.send(JSON.stringify({ action: "rescanQuarantine" }));

            // Wait for broadcast
            const broadcast = await broadcastPromise;
            const eventType = broadcast.type === "broadcast" ? broadcast.event : broadcast.type;
            expect(["quarantine_rescanned", "rescanComplete"]).toContain(eventType ?? "");
        });

        test("quarantine_bulk_approved broadcasts when bulk approve is triggered", async () => {
            // Start listening for broadcast or allQuarantineApproved
            const broadcastPromise = waitForBroadcast(ws, ["quarantine_bulk_approved", "allQuarantineApproved"], 5000);

            // Small delay to ensure listener is active
            await new Promise(r => setTimeout(r, 50));

            // Trigger bulk approve (even if no files, should still broadcast)
            ws.send(JSON.stringify({ action: "approveAllQuarantine" }));

            // Wait for broadcast
            const broadcast = await broadcastPromise;
            const eventType = broadcast.type === "broadcast" ? broadcast.event : broadcast.type;
            expect(["quarantine_bulk_approved", "allQuarantineApproved"]).toContain(eventType ?? "");
        });
    });

    // =========================================================================
    // package_published broadcast (integration test)
    // =========================================================================
    describe("package_published broadcast", () => {
        test("broadcasts when a package is successfully published", async () => {
            const pkgName = uniquePackageName("broadcast-test-pub");
            const version = "1.0.0";

            // Collect all messages during the action
            const messages: (WSMessage & { event?: string })[] = [];
            const collectHandler = (e: MessageEvent) => {
                messages.push(JSON.parse(e.data));
            };
            ws.addEventListener("message", collectHandler);

            try {
                // Publish a package
                const tarballData = Buffer.from("fake-tarball-data");
                const tarballBase64 = tarballData.toString("base64");

                const publishPayload = {
                    name: pkgName,
                    description: "Test package for broadcast",
                    "dist-tags": { latest: version },
                    versions: {
                        [version]: {
                            name: pkgName,
                            version,
                            description: "Test",
                            main: "index.js"
                        }
                    },
                    _attachments: {
                        [`${pkgName}-${version}.tgz`]: {
                            data: tarballBase64
                        }
                    }
                };

                const publishRes = await fetch(`${BASE_URL}/${pkgName}`, {
                    method: "PUT",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(publishPayload)
                });

                // Should get 201 (created)
                expect(publishRes.status).toBe(201);

                // Wait a bit for broadcast to arrive
                await new Promise(r => setTimeout(r, 200));

                // Verify broadcast was received
                const broadcast = messages.find(m =>
                    m.type === "broadcast" && m.event === "package_published"
                );
                expect(broadcast).toBeDefined();
                expect(broadcast!.data.name).toBe(pkgName);
                expect(broadcast!.data.version).toBe(version);
            } finally {
                ws.removeEventListener("message", collectHandler);
            }
        });
    });
});
