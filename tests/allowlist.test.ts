/**
 * AgentRegistry Allowlist WebSocket Tests
 * 
 * Tests for WebSocket-based IP allowlist operations:
 * - getAllowlist
 * - updateAllowlistConfig
 * - addAllowlistEntry
 * - removeAllowlistEntry
 * - toggleAllowlistEntry
 * - testIP
 * 
 * Run with: bun test tests/allowlist.test.ts
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
    // Get admin token from admin panel
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
            // Wait for connected message
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

describe("Allowlist WebSocket Operations", () => {
    let ws: WebSocket;
    let testEntryId: number | undefined;

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
    // getAllowlist - Main test that verifies Security tab fix
    // =========================================================================

    test("getAllowlist returns config and entries via WebSocket", async () => {
        const response = await sendAndReceive(ws, "getAllowlist", {}, "allowlist");

        expect(response.type).toBe("allowlist");
        expect(response.data).toBeDefined();
        expect(response.data.config).toBeDefined();
        expect(typeof response.data.config.enabled).toBe("boolean");
        expect(typeof response.data.config.mode).toBe("string");
        expect(Array.isArray(response.data.entries)).toBe(true);
    });

    // =========================================================================
    // updateAllowlistConfig
    // =========================================================================

    test("updateAllowlistConfig updates enabled state", async () => {
        // First, get current state
        const initial = await sendAndReceive(ws, "getAllowlist", {}, "allowlist");
        const wasEnabled = initial.data.config.enabled;

        // Toggle it
        const response = await sendAndReceive(
            ws,
            "updateAllowlistConfig",
            { enabled: !wasEnabled, mode: "allowlist" },
            "allowlistConfigUpdated"
        );

        expect(response.type).toBe("allowlistConfigUpdated");
        expect(response.data.config.enabled).toBe(!wasEnabled);

        // Restore original state
        await sendAndReceive(
            ws,
            "updateAllowlistConfig",
            { enabled: wasEnabled, mode: "allowlist" },
            "allowlistConfigUpdated"
        );
    });

    // =========================================================================
    // addAllowlistEntry
    // =========================================================================

    test("addAllowlistEntry adds valid IP pattern", async () => {
        // Use unique pattern to avoid duplicate conflicts
        const randomOctet = Math.floor(Math.random() * 250) + 1;
        const testPattern = `10.0.0.${randomOctet}`;
        const testDescription = "Test entry from allowlist.test.ts";

        const response = await sendAndReceive(
            ws,
            "addAllowlistEntry",
            { pattern: testPattern, description: testDescription },
            "allowlistEntryAdded"
        );

        expect(response.type).toBe("allowlistEntryAdded");
        expect(response.data.entry).toBeDefined();
        expect(response.data.entry.pattern).toBe(testPattern);
        expect(response.data.entry.description).toBe(testDescription);

        // Save ID for cleanup
        testEntryId = response.data.entry.id;
    });

    test("addAllowlistEntry rejects invalid pattern", async () => {
        const response = await sendAndReceive(
            ws,
            "addAllowlistEntry",
            { pattern: "not-a-valid-ip" },
            "error"
        );

        expect(response.type).toBe("error");
        expect(response.data.message).toBeDefined();
    });

    // =========================================================================
    // toggleAllowlistEntry
    // =========================================================================

    test("toggleAllowlistEntry disables entry", async () => {
        if (!testEntryId) {
            console.warn("Skipping toggle test - no entry ID");
            return;
        }

        const response = await sendAndReceive(
            ws,
            "toggleAllowlistEntry",
            { id: testEntryId, enabled: false },
            "allowlistEntryToggled"
        );

        expect(response.type).toBe("allowlistEntryToggled");
        expect(response.data.enabled).toBe(false);
    });

    // =========================================================================
    // testIP
    // =========================================================================

    test("testIP checks IP access and returns result", async () => {
        const response = await sendAndReceive(
            ws,
            "testIP",
            { ip: "127.0.0.1" },
            "ipTestResult"
        );

        expect(response.type).toBe("ipTestResult");
        expect(response.data.ip).toBe("127.0.0.1");
        expect(typeof response.data.allowed).toBe("boolean");
        expect(typeof response.data.reason).toBe("string");
    });

    test("testIP without ip returns error", async () => {
        const response = await sendAndReceive(
            ws,
            "testIP",
            {},
            "error"
        );

        expect(response.type).toBe("error");
        expect(response.data.message).toContain("ip");
    });

    // =========================================================================
    // removeAllowlistEntry
    // =========================================================================

    test("removeAllowlistEntry removes entry by id", async () => {
        if (!testEntryId) {
            console.warn("Skipping remove test - no entry ID");
            return;
        }

        const response = await sendAndReceive(
            ws,
            "removeAllowlistEntry",
            { id: testEntryId },
            "allowlistEntryRemoved"
        );

        expect(response.type).toBe("allowlistEntryRemoved");
        expect(response.data.id).toBe(testEntryId);

        // Verify it's gone
        const listResponse = await sendAndReceive(ws, "getAllowlist", {}, "allowlist");
        const remaining = listResponse.data.entries.find((e: any) => e.id === testEntryId);
        expect(remaining).toBeUndefined();
    });
});
