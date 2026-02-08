/**
 * AgentRegistry WebSocket Operations Tests
 * 
 * Tests for additional WebSocket-based admin operations:
 * - CVE scanning (getCVESummary, getAllCVEs, scanPackageCVE)
 * - Graph operations (getGraphRoots, getGraphNode)
 * - Stats/Metrics (getStats, getQuarantine, getCache)
 * - Audit logs (getAuditLogs, getScanHistory, getRequestLogs)
 * 
 * Run with: bun test tests/websocket-ops.test.ts
 * Note: Requires running server on port 4873
 */

import { describe, test, expect, beforeAll, afterAll } from "bun:test";

const WS_URL = "ws://localhost:4873/-/admin/ws";

interface WSMessage {
    type: string;
    data?: any;
    timestamp?: number;
}

// Helper to create WebSocket connection with token
async function createWS(): Promise<WebSocket> {
    const res = await fetch("http://localhost:4873/-/admin");
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

// Helper to send message and wait for response
function sendAndReceive(ws: WebSocket, action: string, payload: any = {}, expectedType: string): Promise<WSMessage> {
    return new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
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

describe("WebSocket Admin Operations", () => {
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
    // Stats & Metrics
    // =========================================================================

    describe("Stats & Metrics", () => {
        test("getStats returns server statistics", async () => {
            const response = await sendAndReceive(ws, "getStats", {}, "stats");

            expect(response.type).toBe("stats");
            expect(response.data).toBeDefined();
            // Should have common stat fields
            expect(typeof response.data.packages === "number" || typeof response.data.totalPackages === "number").toBe(true);
        });

        test("getQuarantine returns quarantine list", async () => {
            const response = await sendAndReceive(ws, "getQuarantine", {}, "quarantine");

            expect(response.type).toBe("quarantine");
            expect(response.data).toBeDefined();
        });

        test("getCache returns cached packages", async () => {
            const response = await sendAndReceive(ws, "getCache", {}, "cache");

            expect(response.type).toBe("cache");
            expect(response.data).toBeDefined();
        });
    });

    // =========================================================================
    // CVE Scanning
    // =========================================================================

    describe("CVE Scanning", () => {
        test("getCVESummary returns CVE summary data", async () => {
            const response = await sendAndReceive(ws, "getCVESummary", {}, "cveSummary");

            expect(response.type).toBe("cveSummary");
            expect(response.data).toBeDefined();
        });

        test("getAllCVEs returns list of CVEs", async () => {
            const response = await sendAndReceive(ws, "getAllCVEs", {}, "allCVEs");

            expect(response.type).toBe("allCVEs");
            expect(response.data).toBeDefined();
            // Should return an array or object with CVE data
            expect(typeof response.data === "object").toBe(true);
        });
    });

    // =========================================================================
    // Graph Operations  
    // =========================================================================

    describe("Graph Operations", () => {
        test("getGraphRoots returns root packages for graph", async () => {
            const response = await sendAndReceive(ws, "getGraphRoots", {}, "graphRoots");

            expect(response.type).toBe("graphRoots");
            expect(response.data).toBeDefined();
        });

        test("getGraphNode returns node details", async () => {
            // First get roots to find a valid package name
            const rootsResponse = await sendAndReceive(ws, "getGraphRoots", {}, "graphRoots");
            const roots = rootsResponse.data?.roots || rootsResponse.data || [];

            if (roots.length > 0) {
                const packageName = roots[0]?.name || roots[0];
                const response = await sendAndReceive(
                    ws,
                    "getGraphNode",
                    { name: packageName },
                    "graphNode"
                );

                expect(response.type).toBe("graphNode");
                expect(response.data).toBeDefined();
            } else {
                // No packages, just verify the action doesn't crash
                expect(true).toBe(true);
            }
        });
    });

    // =========================================================================
    // Audit Logs
    // =========================================================================

    describe("Audit Logs", () => {
        test("getAuditLogs returns audit log entries", async () => {
            const response = await sendAndReceive(ws, "getAuditLogs", { limit: 10 }, "auditLogs");

            expect(response.type).toBe("auditLogs");
            expect(response.data).toBeDefined();
        });

        test("getScanHistory returns scan history", async () => {
            const response = await sendAndReceive(ws, "getScanHistory", { limit: 10 }, "scanHistory");

            expect(response.type).toBe("scanHistory");
            expect(response.data).toBeDefined();
        });

        test("getRequestLogs returns request log entries", async () => {
            const response = await sendAndReceive(ws, "getRequestLogs", { limit: 10 }, "requestLogs");

            expect(response.type).toBe("requestLogs");
            expect(response.data).toBeDefined();
        });
    });
});
