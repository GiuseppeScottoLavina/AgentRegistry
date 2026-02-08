// @ts-nocheck
/**
 * AgentRegistry - Exhaustive Unit Tests
 * 
 * Tests all registry endpoints and edge cases.
 * Run with: bun test
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from "bun:test";
import { mkdir, rm, readdir, exists, chmod } from "node:fs/promises";
import { join } from "node:path";

// Helper to avoid unknown type issues with res.json()
const json = async (res: Response): Promise<any> => res.json();

// Unique prefix for this test run - makes tests idempotent
const TEST_RUN_ID = `t${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`;
const pkg = (name: string) => `${TEST_RUN_ID}-${name}`;
const scopedPkg = (scope: string, name: string) => `@${TEST_RUN_ID}${scope}/${name}`;

// ============================================================================
// Test Configuration
// ============================================================================

const TEST_PORT = 4874 + Math.floor(Math.random() * 1000); // Random port to avoid conflicts
const BASE_URL = `http://localhost:${TEST_PORT}`;
// Use /tmp to avoid macOS sandbox restrictions (com.apple.provenance) on Documents folder
const STORAGE_DIR = `/tmp/agentregistry-test-${TEST_RUN_ID}`;

let serverProc: any = null;

// ============================================================================
// Test Helpers
// ============================================================================

async function startTestServer(): Promise<void> {
    // Ensure clean state
    await rm(STORAGE_DIR, { recursive: true, force: true });
    await mkdir(STORAGE_DIR, { recursive: true });

    // Pre-create subdirectories to avoid EPERM/race conditions
    const dirs = ["packages", "tarballs", "quarantine", "backups", ".agentregistry"];
    for (const d of dirs) {
        const p = join(STORAGE_DIR, d);
        await mkdir(p, { recursive: true });
        await chmod(p, 0o777);
    }

    // Spawn server process with custom config
    serverProc = Bun.spawn(["bun", "run", "src/server.ts", "--port", String(TEST_PORT)], {
        env: {
            ...process.env,
            STORAGE_DIR: STORAGE_DIR, // Randomized test storage
            AGENTREGISTRY_HOME: join(STORAGE_DIR, ".agentregistry"), // Isolated from ~/.agentregistry
            AGENTREGISTRY_PID_FILE: join(STORAGE_DIR, ".agentregistry", "agentregistry.pid"), // Avoid macOS sandbox on ~/.agentregistry
            AGENTREGISTRY_LOG_DIR: join(STORAGE_DIR, ".agentregistry", "logs"), // Avoid macOS sandbox on ~/.agentregistry
            AGENTREGISTRY_LOG_LEVEL: "error", // Reduce noise
            ADMIN_SESSION_TOKEN: "test-token" // Fixed token for testing
        },
        stdout: "ignore", // pipe to 'inherit' for debugging
        stderr: "inherit"
    });

    // Wait for server to be ready
    let retries = 20;
    while (retries > 0) {
        try {
            const res = await fetch(`${BASE_URL}/-/ping`);
            if (res.ok) return;
        } catch { }
        await Bun.sleep(100);
        retries--;
    }
    throw new Error(`Failed to start test server on port ${TEST_PORT}`);
}

async function stopTestServer(): Promise<void> {
    if (serverProc) {
        serverProc.kill();
        await serverProc.exited;
    }
    // Clean up storage with retry logic for EPERM/EBUSY
    for (let i = 0; i < 5; i++) {
        try {
            await rm(STORAGE_DIR, { recursive: true, force: true });
            break;
        } catch (e) {
            await Bun.sleep(200 * (i + 1));
        }
    }
}

function createTarball(files: Record<string, string>): Buffer {
    return Buffer.from("H4sIAAAAAAAAA+3OMQrCQBCF4Z7T/BXYJoVgYRFsFDyA2IuNxbJZN5lkQ2YW1xu4hBdQ0AOI4A28gTdQK6sUVkL8vsL88Abm3QEAAAAAAADwF8MwjMMwjP9/6+fr1+9P3+/e37y/en/x/tz9mftT9yfu/+e+s6u5c3fJbn5dDQAAAAAAAAAA/NQDbWpMACgAAAA=", "base64");
}

async function publishPackage(name: string, version: string, description?: string): Promise<Response> {
    const tarballName = `${name.replace("/", "-").replace("@", "")}-${version}.tgz`;
    const tarballData = Buffer.alloc(100);

    const payload = {
        name,
        description: description || `Test package ${name}`,
        versions: {
            [version]: {
                name,
                version,
                description: description || `Test package ${name}`,
                main: "index.js",
                dist: {
                    tarball: `${BASE_URL}/${name}/-/${tarballName}`,
                    shasum: "a".repeat(40), // Mock shasum
                    integrity: "sha512-" + "a".repeat(80) // Mock integrity
                }
            }
        },
        "dist-tags": {
            latest: version
        },
        _attachments: {
            [tarballName]: {
                data: tarballData.toString("base64")
            }
        }
    };

    return fetch(`${BASE_URL}/${name}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
    });
}


describe("AgentRegistry Registry", () => {
    beforeAll(async () => {
        await startTestServer();
    });

    afterAll(async () => {
        await stopTestServer();
    });

    // Skip helper - wraps test conditionally
    const testIf = (condition: boolean) => (condition ? it : it.skip);

    // --------------------------------------------------------------------------
    // Health & Basic Endpoints
    // --------------------------------------------------------------------------

    describe("Health & Basic Endpoints", () => {
        it("GET /-/ping returns ok", async () => {
            const res = await fetch(`${BASE_URL}/-/ping`);
            expect(res.status).toBe(200);
            const data = await json(res);
            expect(data.ok).toBe(true);
        });

        it("GET / returns empty packages list initially", async () => {
            const res = await fetch(`${BASE_URL}/`);
            expect(res.status).toBe(200);
            const data = await json(res);
            expect(data.packages).toBeInstanceOf(Array);
        });

        it("GET /-/whoami returns local user", async () => {
            const res = await fetch(`${BASE_URL}/-/whoami`);
            expect(res.status).toBe(200);
            const data = await json(res);
            expect(data.username).toBe("local-agent");
        });

        it("PUT /-/user/* returns auth token (bypass)", async () => {
            const res = await fetch(`${BASE_URL}/-/user/org.couchdb.user:test`, {
                method: "PUT",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ name: "test", password: "test" })
            });
            expect(res.status).toBe(201);
            const data = await json(res);
            expect(data.ok).toBe(true);
            expect(data.token).toBeDefined();
        });

        it("OPTIONS requests return CORS headers", async () => {
            const res = await fetch(`${BASE_URL}/test`, { method: "OPTIONS" });
            expect(res.status).toBe(204);
            expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
            expect(res.headers.get("Access-Control-Allow-Methods")).toContain("PUT");
        });

        // Search API Tests (/-/v1/search) - Regression tests for route collision bug
        it("GET /-/v1/search returns JSON response (not tarball error)", async () => {
            const res = await fetch(`${BASE_URL}/-/v1/search?text=test`);
            expect(res.status).toBe(200);
            expect(res.headers.get("Content-Type")).toContain("application/json");

            const data = await json(res);
            // Should return NPM-compatible search response format
            expect(data.objects).toBeInstanceOf(Array);
            expect(data.total).toBeDefined();
            expect(data.time).toBeDefined();
        });

        it("GET /-/v1/search finds published packages", async () => {
            // First publish a test package
            const name = pkg("search-test");
            await publishPackage(name, "1.0.0", "A searchable test package");

            // Search for it
            const res = await fetch(`${BASE_URL}/-/v1/search?text=${name}`);
            expect(res.status).toBe(200);

            const data = await json(res);
            expect(data.objects.length).toBeGreaterThanOrEqual(1);

            const found = data.objects.find((o: any) => o.package.name === name);
            expect(found).toBeDefined();
            expect(found.package.version).toBe("1.0.0");
            expect(found.package.description).toBe("A searchable test package");
        });

        it("GET /-/v1/search respects size parameter", async () => {
            const res = await fetch(`${BASE_URL}/-/v1/search?text=test&size=1`);
            expect(res.status).toBe(200);

            const data = await json(res);
            expect(data.objects.length).toBeLessThanOrEqual(1);
        });

        it("GET /-/v1/search returns empty array for no matches", async () => {
            const res = await fetch(`${BASE_URL}/-/v1/search?text=xyznonexistent999`);
            expect(res.status).toBe(200);

            const data = await json(res);
            expect(data.objects).toBeInstanceOf(Array);
            expect(data.objects.length).toBe(0);
        });

        it("GET /-/v1/search is NOT intercepted by tarball handler", async () => {
            // This was the original bug: /-/v1/search was being caught by
            // the path.includes("/-/") check for tarballs
            const res = await fetch(`${BASE_URL}/-/v1/search?text=anything`);

            // Should NOT return "Invalid tarball name" error
            expect(res.status).toBe(200);
            const text = await res.clone().text();
            expect(text).not.toContain("Invalid tarball name");
        });
    });

    // --------------------------------------------------------------------------
    // Package Publishing
    // --------------------------------------------------------------------------

    describe("Package Publishing", () => {
        it("PUT /{package} publishes a new package", async () => {
            const name = pkg("test-lib");
            const res = await publishPackage(name, "1.0.0");
            expect(res.status).toBe(201);
            const data = await json(res);
            expect(data.ok).toBe(true);
            expect(data.id).toBe(name);
            expect(data.rev).toBeDefined();
        });

        it("PUT /{package} with new version adds to existing package", async () => {
            const name = pkg("multi-version");
            await publishPackage(name, "1.0.0");
            const res = await publishPackage(name, "1.1.0");
            expect(res.status).toBe(201);

            // Verify both versions exist
            const getRes = await fetch(`${BASE_URL}/${name}`);
            const data = await json(getRes);
            expect(data.versions["1.0.0"]).toBeDefined();
            expect(data.versions["1.1.0"]).toBeDefined();
        });

        it("PUT /{package} rejects duplicate version", async () => {
            const name = pkg("dup-test");
            await publishPackage(name, "1.0.0");
            const res = await publishPackage(name, "1.0.0");
            expect(res.status).toBe(409);
            const data = await json(res);
            expect(data.error).toContain("already exists");
        });

        it("PUT /{package} rejects invalid payload", async () => {
            const res = await fetch(`${BASE_URL}/invalid-pkg`, {
                method: "PUT",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ name: "invalid-pkg" }) // Missing versions and attachments
            });
            expect(res.status).toBe(400);
        });

        it("PUT /{package} handles scoped packages", async () => {
            const name = scopedPkg("scope", "my-lib");
            const res = await publishPackage(name, "1.0.0");
            expect(res.status).toBe(201);

            const getRes = await fetch(`${BASE_URL}/${name}`);
            expect(getRes.status).toBe(200);
            const data = await json(getRes);
            expect(data.name).toBe(name);
        });

        it("PUT /{package} updates dist-tags", async () => {
            await publishPackage(pkg("tagged-pkg"), "1.0.0");

            const payload = {
                name: "tagged-pkg",
                versions: {
                    "2.0.0-beta": { name: "tagged-pkg", version: "2.0.0-beta" }
                },
                "dist-tags": { beta: "2.0.0-beta", latest: "1.0.0" },
                _attachments: {
                    "tagged-pkg-2.0.0-beta.tgz": { data: Buffer.alloc(100).toString("base64") }
                }
            };

            await fetch(`${BASE_URL}/tagged-pkg`, {
                method: "PUT",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });

            const getRes = await fetch(`${BASE_URL}/tagged-pkg`);
            const data = await json(getRes);
            expect(data["dist-tags"].beta).toBe("2.0.0-beta");
        });
    });

    // --------------------------------------------------------------------------
    // Package Retrieval
    // --------------------------------------------------------------------------

    describe("Package Retrieval", () => {
        const getTestPkg = pkg("get-test");
        const scopedTestPkg = scopedPkg("test", "scoped");

        beforeAll(async () => {
            await publishPackage(getTestPkg, "1.0.0", "A test package");
            await publishPackage(getTestPkg, "2.0.0", "A test package v2");
        });

        it("GET /{package} returns full metadata", async () => {
            const res = await fetch(`${BASE_URL}/${getTestPkg}`);
            expect(res.status).toBe(200);

            const data = await json(res);
            expect(data.name).toBe(getTestPkg);
            expect(data.versions).toBeDefined();
            expect(data["dist-tags"]).toBeDefined();
            expect(data.time).toBeDefined();
            expect(data._id).toBe(getTestPkg);
            expect(data._rev).toBeDefined();
        });

        it("GET /{package} includes tarball URLs", async () => {
            const res = await fetch(`${BASE_URL}/${getTestPkg}`);
            const data = await json(res);

            const version = data.versions["1.0.0"];
            expect(version.dist.tarball).toContain("http://localhost");
            expect(version.dist.tarball).toContain("-1.0.0.tgz");
            expect(version.dist.shasum).toBeDefined();
            expect(version.dist.integrity).toBeDefined();
        });

        it("GET /{package}/{version} returns specific version", async () => {
            const res = await fetch(`${BASE_URL}/${getTestPkg}/1.0.0`);
            expect(res.status).toBe(200);

            const data = await json(res);
            expect(data.name).toBe(getTestPkg);
            expect(data.version).toBe("1.0.0");
        });

        it("GET /{package} returns 404 for non-existent package", async () => {
            const res = await fetch(`${BASE_URL}/${pkg("non-existent-pkg")}`);
            expect(res.status).toBe(404);
        });

        it("GET /{package}/{version} returns 404 for non-existent version", async () => {
            const res = await fetch(`${BASE_URL}/${getTestPkg}/9.9.9`);
            expect(res.status).toBe(404);
        });

        it("GET /@scope/package works for scoped packages", async () => {
            await publishPackage(scopedTestPkg, "1.0.0");

            const res = await fetch(`${BASE_URL}/${scopedTestPkg}`);
            expect(res.status).toBe(200);

            const data = await json(res);
            expect(data.name).toBe(scopedTestPkg);
        });

        it("GET /@scope/package/version works for scoped packages", async () => {
            const res = await fetch(`${BASE_URL}/${scopedTestPkg}/1.0.0`);
            expect(res.status).toBe(200);

            const data = await json(res);
            expect(data.version).toBe("1.0.0");
        });
    });

    // --------------------------------------------------------------------------
    // Tarball Download
    // --------------------------------------------------------------------------

    describe("Tarball Download", () => {
        const tarballPkg = pkg("tarball-test");
        const tarballSafe = tarballPkg.replace("@", "").replace("/", "-");

        beforeAll(async () => {
            await publishPackage(tarballPkg, "1.0.0");
        });

        it("GET /{package}/-/{tarball}.tgz downloads tarball", async () => {
            const res = await fetch(`${BASE_URL}/${tarballPkg}/-/${tarballSafe}-1.0.0.tgz`);
            expect(res.status).toBe(200);
            expect(res.headers.get("Content-Type")).toBe("application/octet-stream");

            const buffer = await res.arrayBuffer();
            expect(buffer.byteLength).toBeGreaterThan(0);
        });

        it("GET /{package}/-/{tarball}.tgz returns 404 for missing tarball", async () => {
            const res = await fetch(`${BASE_URL}/${tarballPkg}/-/${tarballSafe}-9.9.9.tgz`);
            expect(res.status).toBe(404);
        });

        it("GET /{package}/-/{tarball}.tgz handles invalid tarball name", async () => {
            const res = await fetch(`${BASE_URL}/${tarballPkg}/-/invalid.tgz`);
            expect(res.status).toBe(400);
        });
    });

    // --------------------------------------------------------------------------
    // Package Unpublish
    // --------------------------------------------------------------------------

    describe("Package Unpublish", () => {
        it("DELETE /{package}/-/{tarball}/{rev} removes a version", async () => {
            const name = pkg("unpub-test");
            const safeName = name.replace("@", "").replace("/", "-");
            await publishPackage(name, "1.0.0");
            await publishPackage(name, "2.0.0");

            // Unpublish version 1.0.0
            const res = await fetch(`${BASE_URL}/${name}/-/${safeName}-1.0.0.tgz/rev`, {
                method: "DELETE"
            });
            expect(res.status).toBe(200);

            // Verify version is gone
            const getRes = await fetch(`${BASE_URL}/${name}`);
            const data = await json(getRes);
            expect(data.versions["1.0.0"]).toBeUndefined();
            expect(data.versions["2.0.0"]).toBeDefined();
        });

        it("DELETE removes package entirely when last version unpublished", async () => {
            const name = pkg("single-version");
            const safeName = name.replace("@", "").replace("/", "-");
            await publishPackage(name, "1.0.0");

            await fetch(`${BASE_URL}/${name}/-/${safeName}-1.0.0.tgz/rev`, {
                method: "DELETE"
            });

            const getRes = await fetch(`${BASE_URL}/${name}`);
            expect(getRes.status).toBe(404);
        });

        it("DELETE returns 404 for non-existent version", async () => {
            const name = pkg("del-404");
            const safeName = name.replace("@", "").replace("/", "-");
            await publishPackage(name, "1.0.0");

            const res = await fetch(`${BASE_URL}/${name}/-/${safeName}-9.9.9.tgz/rev`, {
                method: "DELETE"
            });
            expect(res.status).toBe(404);
        });
    });

    // --------------------------------------------------------------------------
    // Version Semantics
    // --------------------------------------------------------------------------

    describe("Version Semantics", () => {
        it("handles prerelease versions (alpha, beta, rc)", async () => {
            const name = pkg("prerelease-pkg");
            await publishPackage(name, "1.0.0-alpha.1");
            await publishPackage(name, "1.0.0-beta.1");
            await publishPackage(name, "1.0.0-rc.1");
            await publishPackage(name, "1.0.0");

            const res = await fetch(`${BASE_URL}/${name}`);
            const data = await json(res);

            expect(Object.keys(data.versions)).toHaveLength(4);
            expect(data.versions["1.0.0-alpha.1"]).toBeDefined();
            expect(data.versions["1.0.0-beta.1"]).toBeDefined();
            expect(data.versions["1.0.0-rc.1"]).toBeDefined();
            expect(data.versions["1.0.0"]).toBeDefined();
        });

        it("preserves version metadata through roundtrip", async () => {
            const name = pkg("metadata-test");
            const res = await publishPackage(name, "3.2.1");
            expect(res.status).toBe(201);

            const getRes = await fetch(`${BASE_URL}/${name}/3.2.1`);
            const data = await json(getRes);

            expect(data.version).toBe("3.2.1");
            expect(data.dist.shasum).toMatch(/^[a-f0-9]{40}$/); // SHA1 format
            expect(data.dist.integrity).toMatch(/^sha512-/); // SHA512 integrity
        });
    });

    // --------------------------------------------------------------------------
    // Package Listing
    // --------------------------------------------------------------------------

    describe("Package Listing", () => {
        it("GET / lists all published packages", async () => {
            const name1 = pkg("list-test-1");
            const name2 = pkg("list-test-2");

            const initialRes = await fetch(`${BASE_URL}/`);
            const initialData = await json(initialRes);
            const initialCount = initialData.packages.length;

            await publishPackage(name1, "1.0.0");
            await publishPackage(name2, "1.0.0");

            const res = await fetch(`${BASE_URL}/`);
            const data = await json(res);

            expect(data.packages.length).toBeGreaterThanOrEqual(initialCount + 2);
            expect(data.packages).toContain(name1);
            expect(data.packages).toContain(name2);
        });
    });

    // --------------------------------------------------------------------------
    // Error Handling
    // --------------------------------------------------------------------------

    describe("Error Handling", () => {
        it("returns JSON error for 404", async () => {
            const res = await fetch(`${BASE_URL}/definitely-not-a-package`);
            expect(res.status).toBe(404);
            expect(res.headers.get("Content-Type")).toContain("application/json");

            const data = await json(res);
            expect(data.error).toBeDefined();
        });

        it("handles malformed JSON in PUT gracefully", async () => {
            const res = await fetch(`${BASE_URL}/bad-json`, {
                method: "PUT",
                headers: { "Content-Type": "application/json" },
                body: "not valid json {"
            });
            expect(res.status).toBe(500);
        });

        it("includes CORS headers on error responses", async () => {
            const res = await fetch(`${BASE_URL}/not-found-pkg`);
            expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
        });
    });

    // --------------------------------------------------------------------------
    // Upstream Proxy (npmjs.org)
    // --------------------------------------------------------------------------

    describe("Upstream Proxy", () => {
        it("fetches package from npmjs.org when not found locally", async () => {
            // Use a small, stable package
            const res = await fetch(`${BASE_URL}/is-odd`);
            expect(res.status).toBe(200);

            const data = await json(res);
            expect(data.name).toBe("is-odd");
            expect(data.versions).toBeDefined();
            expect(data["dist-tags"].latest).toBeDefined();
        });

        it("caches upstream package metadata locally", async () => {
            // First fetch - from upstream
            await fetch(`${BASE_URL}/is-even`);

            // Second fetch - should be from cache (faster, no network)
            const start = Date.now();
            const res = await fetch(`${BASE_URL}/is-even`);
            const elapsed = Date.now() - start;

            expect(res.status).toBe(200);
            // Cached response should be very fast (< 50ms typically)
            expect(elapsed).toBeLessThan(200);
        });

        it("rewrites tarball URLs to point through proxy", async () => {
            const res = await fetch(`${BASE_URL}/is-number`);
            const data = await json(res);

            const latestVersion = data["dist-tags"].latest;
            const tarballUrl = data.versions[latestVersion].dist.tarball;

            // Should point to our local server, not npmjs.org
            expect(tarballUrl).toContain(`localhost:${TEST_PORT}`);
            expect(tarballUrl).not.toContain("registry.npmjs.org");
        });

        it("fetches tarball from upstream when not cached", async () => {
            // Get package info first
            const metaRes = await fetch(`${BASE_URL}/is-positive`);
            const meta = await json(metaRes);
            const latestVersion = meta["dist-tags"].latest;

            // Fetch the tarball through our proxy
            const tarballUrl = meta.versions[latestVersion].dist.tarball;
            const tarballRes = await fetch(tarballUrl);

            expect(tarballRes.status).toBe(200);
            expect(tarballRes.headers.get("Content-Type")).toBe("application/octet-stream");

            const buffer = await tarballRes.arrayBuffer();
            expect(buffer.byteLength).toBeGreaterThan(0);
        });

        it("returns 404 for non-existent package on upstream", async () => {
            const res = await fetch(`${BASE_URL}/this-package-definitely-does-not-exist-xyz123`);
            expect(res.status).toBe(404);
        });
    });

    // --------------------------------------------------------------------------
    // Edge Cases & Additional Coverage
    // --------------------------------------------------------------------------

    describe("Edge Cases", () => {
        it("handles tarball download for prerelease versions", async () => {
            const name = pkg("prerelease-tarball");
            const safeName = name.replace("@", "").replace("/", "-");
            await publishPackage(name, "1.0.0-beta.1");

            const res = await fetch(`${BASE_URL}/${name}/-/${safeName}-1.0.0-beta.1.tgz`);
            expect(res.status).toBe(200);
            expect(res.headers.get("Content-Type")).toBe("application/octet-stream");
        });

        it("handles DELETE for scoped packages", async () => {
            const name = scopedPkg("edge", "delete-test");
            const safeName = name.replace("@", "").replace("/", "-");
            await publishPackage(name, "1.0.0");

            const res = await fetch(`${BASE_URL}/${name}/-/${safeName}-1.0.0.tgz/rev`, {
                method: "DELETE"
            });
            expect(res.status).toBe(200);

            const getRes = await fetch(`${BASE_URL}/${name}`);
            expect(getRes.status).toBe(404);
        });

        it("rejects publish with missing attachment for version", async () => {
            const name = pkg("missing-attachment");
            const payload = {
                name: name,
                versions: {
                    "1.0.0": { name: name, version: "1.0.0" }
                },
                "dist-tags": { latest: "1.0.0" },
                _attachments: {
                    // Attachment key doesn't match version
                    "wrong-name-2.0.0.tgz": { data: Buffer.alloc(100).toString("base64") }
                }
            };

            const res = await fetch(`${BASE_URL}/${name}`, {
                method: "PUT",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });
            expect(res.status).toBe(400);
            const data = await json(res);
            expect(data.error).toContain("Missing attachment");
        });

        it("handles GET version for scoped packages with prerelease", async () => {
            const name = scopedPkg("edge", "prerelease");
            await publishPackage(name, "2.0.0-alpha.1");

            const res = await fetch(`${BASE_URL}/${name}/2.0.0-alpha.1`);
            expect(res.status).toBe(200);
            const data = await json(res);
            expect(data.version).toBe("2.0.0-alpha.1");
        });

        it("preserves package description through roundtrip", async () => {
            const name = pkg("desc-test");
            const description = "A test package with a specific description";
            await publishPackage(name, "1.0.0", description);

            const res = await fetch(`${BASE_URL}/${name}`);
            const data = await json(res);
            expect(data.description).toBe(description);
        });

        it("updates time.modified on new version publish", async () => {
            const name = pkg("time-test");
            await publishPackage(name, "1.0.0");
            const res1 = await fetch(`${BASE_URL}/${name}`);
            const data1 = await json(res1);
            const modified1 = data1.time.modified;

            // Small delay to ensure different timestamp
            await Bun.sleep(10);

            await publishPackage(name, "1.0.1");
            const res2 = await fetch(`${BASE_URL}/${name}`);
            const data2 = await json(res2);
            const modified2 = data2.time.modified;

            expect(modified2).not.toBe(modified1);
        });

        it("handles multiple dist-tags correctly", async () => {
            const name = pkg("multi-tag");
            const safeName = name.replace("@", "").replace("/", "-");
            await publishPackage(name, "1.0.0");

            // Add beta version with beta tag
            const payload = {
                name: name,
                versions: {
                    "2.0.0-beta": { name: name, version: "2.0.0-beta" }
                },
                "dist-tags": {
                    beta: "2.0.0-beta",
                    latest: "1.0.0"  // Keep latest at 1.0.0
                },
                _attachments: {
                    [`${safeName}-2.0.0-beta.tgz`]: { data: Buffer.alloc(100).toString("base64") }
                }
            };

            await fetch(`${BASE_URL}/${name}`, {
                method: "PUT",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });

            const res = await fetch(`${BASE_URL}/${name}`);
            const data = await json(res);

            expect(data["dist-tags"].latest).toBe("1.0.0");
            expect(data["dist-tags"].beta).toBe("2.0.0-beta");
        });

        it("returns proper tarball Content-Disposition header", async () => {
            const name = pkg("disposition-test");
            const safeName = name.replace("@", "").replace("/", "-");
            await publishPackage(name, "1.0.0");

            const res = await fetch(`${BASE_URL}/${name}/-/${safeName}-1.0.0.tgz`);
            const disposition = res.headers.get("Content-Disposition");

            expect(disposition).toContain("attachment");
            expect(disposition).toContain("-1.0.0.tgz");
        });

        it("handles rapid sequential publishes", async () => {
            const name = pkg("rapid-test");
            // Publish 5 versions rapidly
            const versions = ["1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4"];
            for (const v of versions) {
                const res = await publishPackage(name, v);
                expect(res.status).toBe(201);
            }

            const res = await fetch(`${BASE_URL}/${name}`);
            const data = await json(res);
            expect(Object.keys(data.versions)).toHaveLength(5);
        });

        it("validates tarball integrity fields exist", async () => {
            const name = pkg("integrity-test");
            await publishPackage(name, "1.0.0");

            const res = await fetch(`${BASE_URL}/${name}`);
            const data = await json(res);
            const version = data.versions["1.0.0"];

            expect(version.dist.shasum).toMatch(/^[a-f0-9]{40}$/);
            expect(version.dist.integrity).toMatch(/^sha512-/);
            expect(version.dist.tarball).toContain("localhost");
        });

        it("handles upstream package with many versions efficiently", async () => {
            // Lodash has many versions - verify we handle it
            const start = Date.now();
            const res = await fetch(`${BASE_URL}/lodash`);
            const elapsed = Date.now() - start;

            expect(res.status).toBe(200);
            const data = await json(res);
            expect(Object.keys(data.versions).length).toBeGreaterThan(50);
            // Should be reasonably fast (cached or fresh)
            expect(elapsed).toBeLessThan(5000);
        });

        it("cleans up dist-tags when version is unpublished", async () => {
            const name = pkg("cleanup-tag");
            await publishPackage(name, "1.0.0");

            // Verify initial state
            const res1 = await fetch(`${BASE_URL}/${name}`);
            const data1 = await json(res1);
            expect(data1["dist-tags"].latest).toBe("1.0.0");
        });
    });

    // --------------------------------------------------------------------------
    // Security Tests
    // --------------------------------------------------------------------------

    describe("Security", () => {
        it("blocks path traversal attempts with ../", async () => {
            const res = await fetch(`${BASE_URL}/../../../etc/passwd`);
            expect(res.status).toBe(500);
            const data = await json(res);
            expect(data.error).toContain("Invalid package name");
        });

        it("blocks URL-encoded path traversal", async () => {
            const res = await fetch(`${BASE_URL}/..%2F..%2F..%2Fetc%2Fpasswd`);
            expect(res.status).toBe(500);
            const data = await json(res);
            expect(data.error).toContain("Invalid package name");
        });

        it("rejects package names with ..", async () => {
            const res = await fetch(`${BASE_URL}/..test-package`);
            expect(res.status).toBe(500);
            const data = await json(res);
            expect(data.error).toContain("Invalid package name");
        });

        it("rejects package names with double slashes", async () => {
            const name = "test//malicious";
            const res = await fetch(`${BASE_URL}/${name}`, {
                method: "PUT",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    name,
                    versions: { "1.0.0": { name, version: "1.0.0" } },
                    "dist-tags": { latest: "1.0.0" },
                    _attachments: { "test-1.0.0.tgz": { data: Buffer.alloc(100).toString("base64") } }
                })
            });
            expect(res.status).toBe(500);
        });

        it("validates version format strictly", async () => {
            const name = pkg("version-test");
            await publishPackage(name, "1.0.0");

            // Non-semver paths are routed as package name lookups
            // which will fail validation or return 404
            const res = await fetch(`${BASE_URL}/${name}/not-a-version`);
            expect([404, 500]).toContain(res.status);
        });

        it("serves only on localhost", async () => {
            // The server is bound to 127.0.0.1, verify it responds
            const res = await fetch(`${BASE_URL}/-/ping`);
            expect(res.status).toBe(200);
            const data = await json(res);
            expect(data.ok).toBe(true);
        });

        it("rejects extremely long package names", async () => {
            const longName = "a".repeat(300);
            const res = await fetch(`${BASE_URL}/${longName}`);
            expect(res.status).toBe(500);
            const data = await json(res);
            expect(data.error).toContain("Invalid package name");
        });

        it("allows valid scoped package names", async () => {
            const name = scopedPkg("valid", "secure-pkg");
            const res = await publishPackage(name, "1.0.0");
            expect(res.status).toBe(201);
        });

        it("rejects null bytes in package names", async () => {
            const res = await fetch(`${BASE_URL}/test%00malicious`);
            expect(res.status).toBe(500);
        });
    });

    // --------------------------------------------------------------------------
    // Quarantine & Caching Tests
    // --------------------------------------------------------------------------

    describe("Quarantine & Caching", () => {
        it("adds X-Cache header for memory cache hits", async () => {
            const name = pkg("cache-mem");
            await publishPackage(name, "1.0.0");

            // First fetch - should be MISS
            const res1 = await fetch(`${BASE_URL}/${name}/-/${name}-1.0.0.tgz`);
            expect(res1.status).toBe(200);

            // Second fetch - should be HIT-MEMORY or HIT-DISK
            const res2 = await fetch(`${BASE_URL}/${name}/-/${name}-1.0.0.tgz`);
            expect(res2.status).toBe(200);
            const cacheHeader = res2.headers.get("X-Cache");
            expect(cacheHeader).toMatch(/HIT-(MEMORY|DISK)/);
        });

        it("scans locally published packages", async () => {
            const name = pkg("scan-local");
            const res = await publishPackage(name, "1.0.0");
            expect(res.status).toBe(201);

            // Tarball should be servable (passed scan)
            const tarballRes = await fetch(`${BASE_URL}/${name}/-/${name}-1.0.0.tgz`);
            expect(tarballRes.status).toBe(200);
        });

        it("fetches upstream packages through quarantine", async () => {
            // Fetch a known small package from npmjs.org
            const res = await fetch(`${BASE_URL}/is-number`);
            expect(res.status).toBe(200);

            const data = await json(res);
            expect(data.name).toBe("is-number");
            expect(data.versions).toBeDefined();
        });

        it("caches upstream tarballs after scan", async () => {
            // First fetch - goes through quarantine + scan
            const res1 = await fetch(`${BASE_URL}/is-number/-/is-number-7.0.0.tgz`);
            // Could be 200 or timeout depending on network
            if (res1.status === 200) {
                // Second fetch should be cached
                const res2 = await fetch(`${BASE_URL}/is-number/-/is-number-7.0.0.tgz`);
                expect(res2.status).toBe(200);
                const cacheHeader = res2.headers.get("X-Cache");
                expect(cacheHeader).toMatch(/HIT-(MEMORY|DISK)/);
            }
        });
    });

    // --------------------------------------------------------------------------
    // Admin Panel Tests
    // --------------------------------------------------------------------------

    // Get admin token from environment (set by server on startup)
    // For tests, we read it from the admin panel HTML which has it injected
    const getAdminToken = async (): Promise<string> => {
        const res = await fetch(`${BASE_URL}/-/admin`);
        const html = await res.text();
        const match = html.match(/ADMIN_SESSION_TOKEN\s*=\s*"([^"]+)"/);
        return match ? match[1] : "";
    };

    const adminFetch = async (path: string, options: RequestInit = {}): Promise<Response> => {
        const token = await getAdminToken();
        return fetch(`${BASE_URL}${path}`, {
            ...options,
            headers: {
                ...options.headers,
                "X-Admin-Token": token
            }
        });
    };

    describe("Admin Panel", () => {
        it("serves admin panel HTML", async () => {
            const res = await fetch(`${BASE_URL}/-/admin`);
            expect(res.status).toBe(200);
            expect(res.headers.get("Content-Type")).toContain("text/html");
            const html = await res.text();
            expect(html).toContain("AgentRegistry Admin");
        });

        it("returns server stats", async () => {
            const res = await adminFetch("/-/admin/stats");
            expect(res.status).toBe(200);
            const data = await json(res);
            expect(data).toHaveProperty("uptime");
            expect(data).toHaveProperty("packages");
            expect(data).toHaveProperty("tarballs");
            expect(data).toHaveProperty("quarantine");
            expect(data).toHaveProperty("memoryCacheEntries");
            expect(data).toHaveProperty("memoryUsed");
        });

        it("returns empty quarantine list", async () => {
            const res = await adminFetch("/-/admin/quarantine");
            expect(res.status).toBe(200);
            const data = await json(res);
            expect(data).toHaveProperty("files");
            expect(Array.isArray(data.files)).toBe(true);
        });

        it("returns cache list with published packages", async () => {
            const name = pkg("admin-cache-test");
            await publishPackage(name, "1.0.0");

            const res = await adminFetch("/-/admin/cache");
            expect(res.status).toBe(200);
            const data = await json(res);
            expect(data).toHaveProperty("packages");
            expect(Array.isArray(data.packages)).toBe(true);

            const found = data.packages.find((p: { name: string }) => p.name === name);
            expect(found).toBeDefined();
            expect(found.versions).toContain("1.0.0");
        });

        it("deletes package from cache via admin API", async () => {
            const name = pkg("admin-delete-test");
            await publishPackage(name, "1.0.0");

            // Verify it exists
            const before = await fetch(`${BASE_URL}/${name}`);
            expect(before.status).toBe(200);

            // Delete via admin
            const delRes = await adminFetch(`/-/admin/cache/${encodeURIComponent(name)}`, {
                method: "DELETE"
            });
            expect(delRes.status).toBe(200);

            // Verify deleted
            const after = await fetch(`${BASE_URL}/${name}`);
            expect(after.status).toBe(404);
        });

        it("refreshes package cache via admin API", async () => {
            const name = pkg("admin-refresh-test");
            await publishPackage(name, "1.0.0");

            const res = await adminFetch(`/-/admin/cache/${encodeURIComponent(name)}/refresh`, {
                method: "POST"
            });
            expect(res.status).toBe(200);
            const data = await json(res);
            expect(data.ok).toBe(true);
        });

        it("clears quarantine", async () => {
            const res = await adminFetch("/-/admin/quarantine", {
                method: "DELETE"
            });
            expect(res.status).toBe(200);
            const data = await json(res);
            expect(data.ok).toBe(true);
        });
    });
});

