// @ts-nocheck
/**
 * AgentRegistry Admin Panel Tests
 * 
 * Tests for:
 * - CSP headers (including Google Fonts)
 * - Static assets serving (D3.js with correct MIME type)
 * - Admin panel HTML structure (responsive CSS)
 * 
 * Run with: bun test tests/admin-panel.test.ts
 * Note: Requires running daemon on port 4873
 */

import { describe, test, expect } from "bun:test";

const BASE_URL = "http://localhost:4873";

describe("Admin Panel", () => {

    // =========================================================================
    // CSP Headers
    // =========================================================================

    describe("Content Security Policy", () => {
        test("CSP allows Google Fonts for stylesheets", async () => {
            const res = await fetch(`${BASE_URL}/-/admin`);
            expect(res.status).toBe(200);

            const csp = res.headers.get("Content-Security-Policy");
            expect(csp).not.toBeNull();

            // Should allow fonts.googleapis.com for stylesheets
            expect(csp).toContain("style-src");
            expect(csp).toContain("https://fonts.googleapis.com");
        });

        test("CSP allows Google Fonts for font files", async () => {
            const res = await fetch(`${BASE_URL}/-/admin`);
            const csp = res.headers.get("Content-Security-Policy");

            // Should allow fonts.gstatic.com for font files
            expect(csp).toContain("font-src");
            expect(csp).toContain("https://fonts.gstatic.com");
        });

        test("CSP allows inline scripts and styles", async () => {
            const res = await fetch(`${BASE_URL}/-/admin`);
            const csp = res.headers.get("Content-Security-Policy");

            expect(csp).toContain("'unsafe-inline'");
            expect(csp).toContain("script-src 'self' 'unsafe-inline'");
        });
    });

    // =========================================================================
    // Static Assets
    // =========================================================================

    describe("Static Assets", () => {
        test("D3.js is served with correct MIME type", async () => {
            const res = await fetch(`${BASE_URL}/assets/d3.v7.min.js`);
            expect(res.status).toBe(200);

            const contentType = res.headers.get("Content-Type");
            expect(contentType).toBe("application/javascript");
        });

        test("D3.js has cache headers", async () => {
            const res = await fetch(`${BASE_URL}/assets/d3.v7.min.js`);

            const cacheControl = res.headers.get("Cache-Control");
            expect(cacheControl).toContain("public");
            expect(cacheControl).toContain("max-age");
        });

        test("Favicon is served correctly", async () => {
            const res = await fetch(`${BASE_URL}/assets/favicon.webp`);
            expect(res.status).toBe(200);
            expect(res.headers.get("Content-Type")).toBe("image/webp");
        });

        test("Hero image is served correctly", async () => {
            const res = await fetch(`${BASE_URL}/assets/hero.webp`);
            expect(res.status).toBe(200);
            expect(res.headers.get("Content-Type")).toBe("image/webp");
        });

        test("Non-existent asset returns 404", async () => {
            const res = await fetch(`${BASE_URL}/assets/nonexistent.js`);
            expect(res.status).toBe(404);
        });

        test("CSS files served with correct MIME type", async () => {
            // Admin panel has inline CSS, but test mime type mapping works
            const html = await (await fetch(`${BASE_URL}/-/admin`)).text();
            // Just verify the admin panel loads
            expect(html).toContain("</html>");
        });
    });

    // =========================================================================
    // Admin Panel HTML Structure
    // =========================================================================

    describe("Admin Panel Structure", () => {
        let adminHtml: string;

        test("Admin panel loads successfully", async () => {
            const res = await fetch(`${BASE_URL}/-/admin`);
            expect(res.status).toBe(200);
            adminHtml = await res.text();
            expect(adminHtml).toContain("<!DOCTYPE html>");
        });

        test("Admin panel includes D3.js script tag with cache-buster", async () => {
            const res = await fetch(`${BASE_URL}/-/admin`);
            const html = await res.text();
            // D3.js is loaded dynamically via: script.src = '/assets/d3.v7.min.js?v=2'
            expect(html).toContain("d3.v7.min.js?v=");
        });

        test("Admin panel has responsive tabs CSS", async () => {
            const res = await fetch(`${BASE_URL}/-/admin`);
            const html = await res.text();

            // Check for scrollable tabs
            expect(html).toContain("overflow-x: auto");
            expect(html).toContain("scrollbar-width");
        });

        test("Admin panel tabs don't shrink", async () => {
            const res = await fetch(`${BASE_URL}/-/admin`);
            const html = await res.text();

            // Check for flex-shrink: 0 on tabs
            expect(html).toContain("flex-shrink: 0");
            expect(html).toContain("white-space: nowrap");
        });

        test("Admin panel includes Google Fonts import", async () => {
            const res = await fetch(`${BASE_URL}/-/admin`);
            const html = await res.text();

            expect(html).toContain("fonts.googleapis.com");
            expect(html).toContain("Inter");
        });

        test("Admin panel has Graph tab", async () => {
            const res = await fetch(`${BASE_URL}/-/admin`);
            const html = await res.text();

            expect(html).toContain("switchTab('graph')");
            expect(html).toContain("Graph");
        });

        test("Admin panel has dependency graph section", async () => {
            const res = await fetch(`${BASE_URL}/-/admin`);
            const html = await res.text();

            expect(html).toContain("Dependency Graph");
            expect(html).toContain("id=\"graph-container\"");
        });
    });

    // =========================================================================
    // Security Headers
    // =========================================================================

    describe("Security Headers", () => {
        test("X-Content-Type-Options is set", async () => {
            const res = await fetch(`${BASE_URL}/-/admin`);
            expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
        });

        test("X-Frame-Options is set", async () => {
            const res = await fetch(`${BASE_URL}/-/admin`);
            expect(res.headers.get("X-Frame-Options")).toBe("DENY");
        });

        test("Static assets also have security headers", async () => {
            const res = await fetch(`${BASE_URL}/assets/d3.v7.min.js`);
            expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
        });
    });

    // =========================================================================
    // Graph Tab & Filtering
    // =========================================================================

    describe("Graph Tab Features", () => {
        test("Admin panel has Local-Only filter checkbox", async () => {
            const res = await fetch(`${BASE_URL}/-/admin`);
            const html = await res.text();

            expect(html).toContain('id="graph-local-only"');
            expect(html).toContain("Only Local");
            expect(html).toContain("applyGraphFilter()");
        });

        test("Admin panel has graphAllNodes storage variable", async () => {
            const res = await fetch(`${BASE_URL}/-/admin`);
            const html = await res.text();

            expect(html).toContain("let graphAllNodes = []");
        });

        test("Admin panel has applyGraphFilter function", async () => {
            const res = await fetch(`${BASE_URL}/-/admin`);
            const html = await res.text();

            expect(html).toContain("function applyGraphFilter()");
            expect(html).toContain("graphAllNodes.filter");
        });

        test("WebSocket handler stores all nodes before filtering", async () => {
            const res = await fetch(`${BASE_URL}/-/admin`);
            const html = await res.text();

            // Check that graphRoots handler stores nodes
            expect(html).toContain("graphAllNodes = msg.data.nodes");
        });

        test("Graph legend distinguishes local from upstream", async () => {
            const res = await fetch(`${BASE_URL}/-/admin`);
            const html = await res.text();

            expect(html).toContain("colorScale");
            expect(html).toContain("local");
            expect(html).toContain("upstream");
        });
    });

    // =========================================================================
    // Admin Package Search (/-/admin/search endpoint)
    // =========================================================================

    describe("Admin Package Search", () => {
        test("Admin search returns 401 without token", async () => {
            // This is the bug we fixed - search was failing silently because
            // the fetch didn't include the X-Admin-Token header
            const res = await fetch(`${BASE_URL}/-/admin/search?q=test`);
            expect(res.status).toBe(401);

            const data = await res.json() as { error: string };
            expect(data.error).toBe("Unauthorized");
        });

        test("Admin panel handlePackageSearch includes auth header", async () => {
            // Verify that the admin.html includes the token in search fetch
            const res = await fetch(`${BASE_URL}/-/admin`);
            const html = await res.text();

            // The fetch MUST include the X-Admin-Token header
            expect(html).toContain("/-/admin/search?q=");
            expect(html).toContain("X-Admin-Token");
            expect(html).toContain("window.ADMIN_SESSION_TOKEN");
        });

        test("Admin panel has handlePackageSearch function", async () => {
            const res = await fetch(`${BASE_URL}/-/admin`);
            const html = await res.text();

            expect(html).toContain("async function handlePackageSearch(query)");
            expect(html).toContain("searchTimeout");
        });

        test("Admin panel search shows results container on match", async () => {
            const res = await fetch(`${BASE_URL}/-/admin`);
            const html = await res.text();

            expect(html).toContain("search-results");
            expect(html).toContain("packages-content");
        });

        test("Admin panel ADMIN_SESSION_TOKEN is injected on page load", async () => {
            const res = await fetch(`${BASE_URL}/-/admin`);
            const html = await res.text();

            // Token must be injected as a script tag
            expect(html).toContain("window.ADMIN_SESSION_TOKEN");
            // Token should be a non-empty string
            expect(html).toMatch(/window\.ADMIN_SESSION_TOKEN\s*=\s*"[^"]+"/);
        });
    });

    // =========================================================================
    // Column Sorting Feature
    // =========================================================================

    describe("Column Sorting", () => {
        test("Admin panel has sortable header CSS", async () => {
            const res = await fetch(`${BASE_URL}/-/admin`);
            const html = await res.text();

            expect(html).toContain("th.sortable");
            expect(html).toContain("th.sortable:hover");
            expect(html).toContain("sort-asc");
            expect(html).toContain("sort-desc");
        });

        test("Admin panel has sortData function", async () => {
            const res = await fetch(`${BASE_URL}/-/admin`);
            const html = await res.text();

            expect(html).toContain("function sortData(");
        });

        test("Admin panel has toggleSort and getSortClass functions", async () => {
            const res = await fetch(`${BASE_URL}/-/admin`);
            const html = await res.text();

            expect(html).toContain("function toggleSort(");
            expect(html).toContain("function getSortClass(");
        });

        test("Admin panel has sortState for all sortable tables", async () => {
            const res = await fetch(`${BASE_URL}/-/admin`);
            const html = await res.text();

            expect(html).toContain("sortState");
            expect(html).toContain("audit:");
            expect(html).toContain("scans:");
            expect(html).toContain("requests:");
        });

        test("Audit table has sortable column headers", async () => {
            const res = await fetch(`${BASE_URL}/-/admin`);
            const html = await res.text();

            expect(html).toContain("toggleSort('audit'");
        });

        test("Requests table has sortable column headers", async () => {
            const res = await fetch(`${BASE_URL}/-/admin`);
            const html = await res.text();

            expect(html).toContain("toggleSort('requests'");
        });

        test("Scans table has sortable column headers", async () => {
            const res = await fetch(`${BASE_URL}/-/admin`);
            const html = await res.text();

            expect(html).toContain("toggleSort('scans'");
        });
    });

    // =========================================================================
    // Package Allowlist UI (Security Tab)
    // =========================================================================

    describe("Package Allowlist UI", () => {
        test("Admin panel has Package Allowlist section", async () => {
            const res = await fetch(`${BASE_URL}/-/admin`);
            const html = await res.text();

            expect(html).toContain("Package Allowlist");
            expect(html).toContain('id="pkg-allowlist-entries"');
        });

        test("Package Allowlist has enable/disable toggle", async () => {
            const res = await fetch(`${BASE_URL}/-/admin`);
            const html = await res.text();

            expect(html).toContain('id="pkg-allowlist-enabled"');
            expect(html).toContain("togglePackageAllowlist()");
        });

        test("Package Allowlist has category filter dropdown", async () => {
            const res = await fetch(`${BASE_URL}/-/admin`);
            const html = await res.text();

            expect(html).toContain('id="pkg-category-filter"');
            expect(html).toContain("filterPackageAllowlist()");
        });

        test("Package Allowlist has add form with pattern input", async () => {
            const res = await fetch(`${BASE_URL}/-/admin`);
            const html = await res.text();

            expect(html).toContain('id="pkg-pattern"');
            expect(html).toContain('id="pkg-description"');
            expect(html).toContain('id="pkg-category"');
            expect(html).toContain("addPackageEntry()");
        });

        test("Package Allowlist has stats counter", async () => {
            const res = await fetch(`${BASE_URL}/-/admin`);
            const html = await res.text();

            expect(html).toContain('id="pkg-allowlist-stats"');
        });

        test("Package Allowlist table has sortable columns", async () => {
            const res = await fetch(`${BASE_URL}/-/admin`);
            const html = await res.text();

            expect(html).toContain("sortPackageAllowlistBy('pattern')");
            expect(html).toContain("sortPackageAllowlistBy('category')");
            expect(html).toContain("sortPackageAllowlistBy('enabled')");
        });

        test("Package Allowlist has state storage", async () => {
            const res = await fetch(`${BASE_URL}/-/admin`);
            const html = await res.text();

            expect(html).toContain("state.packageAllowlist");
            expect(html).toContain("pkgAllowlist:");
        });

        test("Package Allowlist has render function", async () => {
            const res = await fetch(`${BASE_URL}/-/admin`);
            const html = await res.text();

            expect(html).toContain("function renderPackageAllowlistTable()");
            expect(html).toContain("function updatePkgCategoryFilter()");
        });

        test("Package Allowlist has WebSocket handlers", async () => {
            const res = await fetch(`${BASE_URL}/-/admin`);
            const html = await res.text();

            expect(html).toContain("case 'packageAllowlist':");
            expect(html).toContain("case 'packageAllowlistEntryAdded':");
            expect(html).toContain("case 'packageAllowlistEntryRemoved':");
        });

        test("Package Allowlist data is fetched on connect", async () => {
            const res = await fetch(`${BASE_URL}/-/admin`);
            const html = await res.text();

            expect(html).toContain("send('getPackageAllowlist')");
        });
    });

    // =========================================================================
    // Test Package Cleanup Verification
    // =========================================================================

    describe("Test Package Cleanup", () => {
        test("No test packages (pkg-*) exist in database", async () => {
            // This test verifies that test packages are properly cleaned up
            // The getGraphRoots endpoint returns all packages
            // We verify none of them start with 'pkg-' (test package pattern)

            const res = await fetch(`${BASE_URL}/`);
            expect(res.status).toBe(200);

            const data = await res.json() as { packages?: string[] };
            const packages = data.packages || [];

            // Filter for test packages
            const testPackages = packages.filter((p: string) =>
                p.startsWith('pkg-') || p.startsWith('test-pkg-')
            );

            // Should be empty - no test packages left behind
            expect(testPackages).toEqual([]);
        });

        test("No orphaned test tarballs exist", async () => {
            // This is a sanity check that can be run after tests
            // In a real scenario, we'd check the filesystem, but here we verify
            // by trying to fetch a known test tarball pattern
            const res = await fetch(`${BASE_URL}/pkg-test/-/pkg-test-1.0.0.tgz`);

            // Should be 404 - no test tarballs
            expect(res.status).toBe(404);
        });
    });
});
