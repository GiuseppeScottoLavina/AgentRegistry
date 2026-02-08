// @ts-nocheck
import { describe, it, expect, beforeAll } from "bun:test";

const TEST_PORT = 4873;
const BASE_URL = `http://localhost:${TEST_PORT}`;

describe("Documentation Site", () => {
    beforeAll(async () => {
        // Check server is running
        try {
            await fetch(`${BASE_URL}/-/ping`);
        } catch {
            console.warn("⚠️ Server not running on port 4873. Start with: bun start");
        }
    });

    describe("Main Pages", () => {
        it("serves /docs/ index page", async () => {
            const res = await fetch(`${BASE_URL}/docs/`);
            expect(res.status).toBe(200);
            expect(res.headers.get("Content-Type")).toContain("text/html");
            const html = await res.text();
            expect(html).toContain("AgentRegistry");
        });

        it("serves /docs/index.html explicitly", async () => {
            const res = await fetch(`${BASE_URL}/docs/index.html`);
            expect(res.status).toBe(200);
            const html = await res.text();
            expect(html).toContain("AgentRegistry");
        });

        it("redirects /docs to /docs/", async () => {
            const res = await fetch(`${BASE_URL}/docs`, { redirect: "manual" });
            expect(res.status).toBe(301);
            expect(res.headers.get("Location")).toBe("/docs/");
        });

        it("serves /-/docs/ alias (200 or redirect)", async () => {
            // /-/docs should work (either directly or via redirect)
            const res = await fetch(`${BASE_URL}/-/docs/`);
            // Could be 200 (direct) or 301 (redirect to /docs/)
            expect([200, 301]).toContain(res.status);
        });

        it("serves getting-started page", async () => {
            const res = await fetch(`${BASE_URL}/docs/getting-started/`);
            expect(res.status).toBe(200);
            const html = await res.text();
            expect(html).toContain("Getting Started");
        });

        it("serves API reference page", async () => {
            const res = await fetch(`${BASE_URL}/docs/api/`);
            expect(res.status).toBe(200);
            const html = await res.text();
            expect(html).toContain("API");
        });

        it("serves admin-panel page", async () => {
            const res = await fetch(`${BASE_URL}/docs/admin-panel/`);
            expect(res.status).toBe(200);
            const html = await res.text();
            expect(html).toContain("Admin Panel");
        });

        it("serves security page", async () => {
            const res = await fetch(`${BASE_URL}/docs/security/`);
            expect(res.status).toBe(200);
            const html = await res.text();
            expect(html).toContain("Security");
        });

        it("serves websocket-api page", async () => {
            const res = await fetch(`${BASE_URL}/docs/websocket-api/`);
            expect(res.status).toBe(200);
            const html = await res.text();
            expect(html).toContain("WebSocket");
        });

        it("serves errors page", async () => {
            const res = await fetch(`${BASE_URL}/docs/errors/`);
            expect(res.status).toBe(200);
            const html = await res.text();
            expect(html).toContain("Error Codes");
        });
    });

    describe("Examples Subdirectory", () => {
        it("serves /docs/examples/ with index.html fallback", async () => {
            const res = await fetch(`${BASE_URL}/docs/examples/`);
            expect(res.status).toBe(200);
            const html = await res.text();
            expect(html).toContain("Examples");
        });

        it("serves /docs/examples/index.html explicitly", async () => {
            const res = await fetch(`${BASE_URL}/docs/examples/index.html`);
            expect(res.status).toBe(200);
        });

        it("serves /docs/examples (without trailing slash)", async () => {
            const res = await fetch(`${BASE_URL}/docs/examples`);
            // Should serve index.html or redirect
            expect([200, 301]).toContain(res.status);
        });
    });

    describe("Static Assets", () => {
        it("serves CSS file", async () => {
            const res = await fetch(`${BASE_URL}/docs/styles.css`);
            expect(res.status).toBe(200);
            expect(res.headers.get("Content-Type")).toContain("text/css");
        });

        it("serves favicon", async () => {
            const res = await fetch(`${BASE_URL}/docs/assets/favicon.webp`);
            expect(res.status).toBe(200);
            expect(res.headers.get("Content-Type")).toContain("image/webp");
        });

        it("has Cache-Control header", async () => {
            const res = await fetch(`${BASE_URL}/docs/styles.css`);
            expect(res.headers.get("Cache-Control")).toContain("max-age");
        });
    });

    describe("Security", () => {
        it("rejects path traversal in raw request", async () => {
            // Note: fetch() normalizes paths, so we can only test server-side URL parsing
            // The server checks for ".." in the docPath after prefix removal
            const res = await fetch(`${BASE_URL}/docs/..%2Fpackage.json`);
            // URL-encoded .. should still be blocked or return 404
            expect([400, 404]).toContain(res.status);
        });

        it("returns 404 for non-existent pages", async () => {
            const res = await fetch(`${BASE_URL}/docs/nonexistent-page.html`);
            expect(res.status).toBe(404);
        });
    });

    describe("Navigation Links", () => {
        const expectedNavItems = [
            'getting-started/',
            'admin-panel/',
            'api/',
            'websocket-api/',
            'security/',
            'errors/',
            'examples/'
        ];

        it("index page has all navigation links", async () => {
            const res = await fetch(`${BASE_URL}/docs/index.html`);
            const html = await res.text();

            for (const item of expectedNavItems) {
                expect(html).toContain(`href="${item}"`);
            }
        });

        it("api page has all navigation links", async () => {
            const res = await fetch(`${BASE_URL}/docs/api/`);
            const html = await res.text();

            // Subpages use ../ relative paths
            const expectedRelativeItems = expectedNavItems.map(i => `../${i}`);
            for (const item of expectedRelativeItems) {
                expect(html).toContain(`href="${item}"`);
            }
        });

        it("security page has all navigation links", async () => {
            const res = await fetch(`${BASE_URL}/docs/security/`);
            const html = await res.text();

            const expectedRelativeItems = expectedNavItems.map(i => `../${i}`);
            for (const item of expectedRelativeItems) {
                expect(html).toContain(`href="${item}"`);
            }
        });

        it("websocket page has all navigation links", async () => {
            const res = await fetch(`${BASE_URL}/docs/websocket-api/`);
            const html = await res.text();

            const expectedRelativeItems = expectedNavItems.map(i => `../${i}`);
            for (const item of expectedRelativeItems) {
                expect(html).toContain(`href="${item}"`);
            }
        });

        it("errors page has all navigation links", async () => {
            const res = await fetch(`${BASE_URL}/docs/errors/`);
            const html = await res.text();

            const expectedRelativeItems = expectedNavItems.map(i => `../${i}`);
            for (const item of expectedRelativeItems) {
                expect(html).toContain(`href="${item}"`);
            }
        });

        it("examples page has all navigation links (relative paths)", async () => {
            const res = await fetch(`${BASE_URL}/docs/examples/index.html`);
            const html = await res.text();

            // Examples page uses ../ relative paths with clean URLs
            const expectedRelativeItems = [
                '../getting-started/',
                '../admin-panel/',
                '../api/',
                '../websocket-api/',
                '../security/',
                '../errors/',
            ];
            for (const item of expectedRelativeItems) {
                expect(html).toContain(`href="${item}"`);
            }
            // Self-link uses ./
            expect(html).toContain('href="./"');
        });

        it("index page has theme toggle button", async () => {
            const res = await fetch(`${BASE_URL}/docs/index.html`);
            const html = await res.text();

            expect(html).toContain('theme-toggle');
            expect(html).toContain('toggleTheme');
        });
    });

    describe("Admin Panel Link", () => {
        it("admin panel has link to documentation", async () => {
            const res = await fetch(`${BASE_URL}/-/admin`);
            const html = await res.text();

            expect(html).toContain('href="/docs/"');
            expect(html).toContain('Docs'); // SVG icon replaced emoji
        });
    });
});
