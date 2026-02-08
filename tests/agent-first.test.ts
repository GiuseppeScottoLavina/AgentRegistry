// @ts-nocheck — res.json() returns unknown in Bun's TS, causing TS18046 on all property access
/**
 * Tests for Agent-First endpoints:
 * - GET /llms.txt
 * - GET /openapi.json
 * - GET /-/capabilities
 */

import { describe, it, expect, beforeAll } from "bun:test";

const BASE_URL = process.env.TEST_URL || "http://localhost:4873";

describe("Agent-First API", () => {
    beforeAll(async () => {
        // Check server is running
        try {
            await fetch(`${BASE_URL}/-/ping`);
        } catch {
            console.error("⚠️ Server not running, tests will fail");
        }
    });

    describe("/-/capabilities endpoint", () => {
        it("returns valid JSON", async () => {
            const res = await fetch(`${BASE_URL}/-/capabilities`);
            expect(res.status).toBe(200);
            expect(res.headers.get("content-type")).toContain("application/json");
        });

        it("has required fields", async () => {
            const res = await fetch(`${BASE_URL}/-/capabilities`);
            const data = await res.json();

            expect(data.name).toBe("AgentRegistry");
            expect(data.version).toBeDefined();
            expect(data.agent_optimized).toBe(true);
        });

        it("lists tools array", async () => {
            const res = await fetch(`${BASE_URL}/-/capabilities`);
            const data = await res.json();

            expect(Array.isArray(data.tools)).toBe(true);
            expect(data.tools.length).toBeGreaterThan(0);
        });

        it("each tool has name and description", async () => {
            const res = await fetch(`${BASE_URL}/-/capabilities`);
            const data = await res.json();

            for (const tool of data.tools) {
                expect(tool.name).toBeDefined();
                expect(tool.description).toBeDefined();
            }
        });

        it("includes publish_package tool", async () => {
            const res = await fetch(`${BASE_URL}/-/capabilities`);
            const data = await res.json();

            const publishTool = data.tools.find((t: any) => t.name === "publish_package");
            expect(publishTool).toBeDefined();
            expect(publishTool.method).toBe("PUT");
        });

        it("includes search_packages tool", async () => {
            const res = await fetch(`${BASE_URL}/-/capabilities`);
            const data = await res.json();

            const searchTool = data.tools.find((t: any) => t.name === "search_packages");
            expect(searchTool).toBeDefined();
            expect(searchTool.parameters).toBeDefined();
        });

        it("has discovery links", async () => {
            const res = await fetch(`${BASE_URL}/-/capabilities`);
            const data = await res.json();

            expect(data.discovery).toBeDefined();
            expect(data.discovery.openapi).toBe("/openapi.json");
            expect(data.discovery.llms_txt).toBe("/llms.txt");
        });

        it("has security info", async () => {
            const res = await fetch(`${BASE_URL}/-/capabilities`);
            const data = await res.json();

            expect(data.security).toBeDefined();
            expect(data.security.scan_on_publish).toBe(true);
            expect(data.security.localhost_only).toBe(true);
        });

        it("has error example", async () => {
            const res = await fetch(`${BASE_URL}/-/capabilities`);
            const data = await res.json();

            expect(data.errors).toBeDefined();
            expect(data.errors.structured).toBe(true);
            expect(data.errors.example).toBeDefined();
            expect(data.errors.example.admin_url).toContain("/-/admin");
        });
    });

    describe("/openapi.json endpoint", () => {
        it("returns valid JSON", async () => {
            const res = await fetch(`${BASE_URL}/openapi.json`);
            expect(res.status).toBe(200);
            expect(res.headers.get("content-type")).toContain("application/json");
        });

        it("has OpenAPI 3.0 structure", async () => {
            const res = await fetch(`${BASE_URL}/openapi.json`);
            const data = await res.json();

            expect(data.openapi).toMatch(/^3\./);
            expect(data.info).toBeDefined();
            expect(data.paths).toBeDefined();
        });

        it("has correct info section", async () => {
            const res = await fetch(`${BASE_URL}/openapi.json`);
            const data = await res.json();

            expect(data.info.title).toContain("AgentRegistry");
            expect(data.info.version).toBeDefined();
            expect(data.info.description).toBeDefined();
        });

        it("defines package endpoints", async () => {
            const res = await fetch(`${BASE_URL}/openapi.json`);
            const data = await res.json();

            expect(data.paths["/{packageName}"]).toBeDefined();
            expect(data.paths["/{packageName}"].get).toBeDefined();
            expect(data.paths["/{packageName}"].put).toBeDefined();
        });

        it("defines search endpoint", async () => {
            const res = await fetch(`${BASE_URL}/openapi.json`);
            const data = await res.json();

            expect(data.paths["/-/v1/search"]).toBeDefined();
            expect(data.paths["/-/v1/search"].get).toBeDefined();
        });

        it("defines capabilities endpoint", async () => {
            const res = await fetch(`${BASE_URL}/openapi.json`);
            const data = await res.json();

            expect(data.paths["/-/capabilities"]).toBeDefined();
        });

        it("has components/schemas", async () => {
            const res = await fetch(`${BASE_URL}/openapi.json`);
            const data = await res.json();

            expect(data.components).toBeDefined();
            expect(data.components.schemas).toBeDefined();
            expect(data.components.schemas.PackageMetadata).toBeDefined();
        });

        it("has error responses", async () => {
            const res = await fetch(`${BASE_URL}/openapi.json`);
            const data = await res.json();

            expect(data.components.responses).toBeDefined();
            expect(data.components.responses.NotFound).toBeDefined();
            expect(data.components.responses.SecurityBlocked).toBeDefined();
        });
    });

    describe("/llms.txt endpoint", () => {
        it("returns text content", async () => {
            const res = await fetch(`${BASE_URL}/llms.txt`);
            expect(res.status).toBe(200);
            expect(res.headers.get("content-type")).toContain("text/plain");
        });

        it("contains AgentRegistry info", async () => {
            const res = await fetch(`${BASE_URL}/llms.txt`);
            const text = await res.text();

            expect(text).toContain("AgentRegistry");
        });

        it("contains API discovery links", async () => {
            const res = await fetch(`${BASE_URL}/llms.txt`);
            const text = await res.text();

            expect(text).toContain("/openapi.json");
            expect(text).toContain("/-/capabilities");
        });

        it("documents core operations", async () => {
            const res = await fetch(`${BASE_URL}/llms.txt`);
            const text = await res.text();

            expect(text).toContain("Publish");
            expect(text).toContain("Search");
            expect(text).toContain("GET");
            expect(text).toContain("PUT");
        });

        it("mentions admin operations", async () => {
            const res = await fetch(`${BASE_URL}/llms.txt`);
            const text = await res.text();

            expect(text).toContain("Admin");
            expect(text).toContain("WebSocket");
        });

        it("includes security notes", async () => {
            const res = await fetch(`${BASE_URL}/llms.txt`);
            const text = await res.text();

            expect(text).toContain("security");
            expect(text).toContain("quarantine");
        });
    });

    describe("Discovery consistency", () => {
        it("capabilities links match actual endpoints", async () => {
            const capRes = await fetch(`${BASE_URL}/-/capabilities`);
            const cap = await capRes.json();

            // Verify linked endpoints exist
            const openapiRes = await fetch(`${BASE_URL}${cap.discovery.openapi}`);
            expect(openapiRes.status).toBe(200);

            const llmsRes = await fetch(`${BASE_URL}${cap.discovery.llms_txt}`);
            expect(llmsRes.status).toBe(200);
        });

        it("tool paths are valid", async () => {
            const res = await fetch(`${BASE_URL}/-/capabilities`);
            const data = await res.json();

            for (const tool of data.tools) {
                if (tool.path) {
                    // Path should start with /
                    expect(tool.path.startsWith("/") || tool.path.startsWith("{")).toBe(true);
                }
            }
        });
    });
});
