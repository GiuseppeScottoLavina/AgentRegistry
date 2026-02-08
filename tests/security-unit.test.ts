/**
 * Comprehensive security tests for src/security.ts module
 * Uses pre-built tarball fixtures from /tmp/agentregistry-security-fixtures
 * 
 * Fixtures must be generated first with: node tests/fixtures/create-fixtures.mjs
 */

import { describe, it, expect, beforeAll, afterAll } from "bun:test";
import { scanTarball } from "../src/security";
import { join } from "path";
import { existsSync, mkdirSync, rmSync } from "fs";
// Database isolation (both main DB and allowlist DB)
import { setDatabaseForTesting, resetDatabasePath, closeDatabase } from "../src/database";
import { setPackageAllowlistDatabaseForTesting, resetPackageAllowlistDatabasePath, closePackageAllowlistDatabase, getPackageAllowlistConfig } from "../src/package-allowlist";
import { execSync } from "child_process";

// Fixtures directory in /tmp (avoids macOS sandbox issues)
const FIXTURES_DIR = "/tmp/agentregistry-security-fixtures";
// Isolated test DBs in /tmp (avoids race conditions with other test files)
const TEST_DB_DIR = `/tmp/agentregistry-sectest-${process.pid}`;
const TEST_DB_PATH = join(TEST_DB_DIR, "sectest.db");
const TEST_ALLOWLIST_DB_PATH = join(TEST_DB_DIR, "sectest-allowlist.db");

function fixture(name: string): string {
    return join(FIXTURES_DIR, `${name}-1.0.0.tgz`);
}

describe("Security Module - Full Coverage", () => {
    beforeAll(() => {
        // Generate fixtures if missing
        if (!existsSync(FIXTURES_DIR)) {
            const scriptPath = join(__dirname, "fixtures", "create-fixtures.mjs");
            if (!existsSync(scriptPath)) {
                throw new Error(
                    "Fixture creation script not found at: " + scriptPath
                );
            }
            execSync(`node "${scriptPath}"`, { stdio: "pipe" });
        }
        // Isolate BOTH databases to avoid race conditions with parallel test files
        mkdirSync(TEST_DB_DIR, { recursive: true });
        setDatabaseForTesting(TEST_DB_PATH);
        setPackageAllowlistDatabaseForTesting(TEST_ALLOWLIST_DB_PATH);
        // Force initialization of package allowlist database with defaults
        getPackageAllowlistConfig();
    });

    afterAll(() => {
        // Cleanup: close and reset both DBs, remove test artifacts
        closePackageAllowlistDatabase();
        resetPackageAllowlistDatabasePath();
        closeDatabase();
        resetDatabasePath();
        rmSync(TEST_DB_DIR, { recursive: true, force: true });
        rmSync(FIXTURES_DIR, { recursive: true, force: true });
    });

    describe("scanTarball - Return Structure", () => {
        it("returns ScanResult with all fields", async () => {
            const result = await scanTarball(fixture("clean-pkg"));

            expect(result).toHaveProperty("safe");
            expect(result).toHaveProperty("issues");
            expect(result).toHaveProperty("filesScanned");
            expect(result).toHaveProperty("scanTimeMs");
            expect(typeof result.safe).toBe("boolean");
            expect(Array.isArray(result.issues)).toBe(true);
            expect(typeof result.filesScanned).toBe("number");
            expect(typeof result.scanTimeMs).toBe("number");
        });

        it("records scan time", async () => {
            const result = await scanTarball(fixture("clean-pkg"));
            expect(result.scanTimeMs).toBeGreaterThanOrEqual(0);
        });

        it("counts scanned files", async () => {
            const result = await scanTarball(fixture("filecount"));
            expect(result.filesScanned).toBeGreaterThanOrEqual(3);
        });
    });

    describe("scanTarball - Clean Packages", () => {
        it("passes clean package", async () => {
            const result = await scanTarball(fixture("clean-pkg"));
            expect(result.safe).toBe(true);
            expect(result.issues.length).toBe(0);
        });

        it("passes empty package", async () => {
            const result = await scanTarball(fixture("empty-pkg"));
            expect(result.safe).toBe(true);
        });
    });

    describe("scanTarball - Code Execution Patterns (Critical)", () => {
        it("detects eval() usage", async () => {
            const result = await scanTarball(fixture("eval-pkg"));
            expect(result.safe).toBe(false);
            expect(result.issues.some(i => i.severity === "critical")).toBe(true);
            expect(result.issues.some(i => i.description.includes("eval"))).toBe(true);
        });

        it("detects new Function()", async () => {
            const result = await scanTarball(fixture("function-pkg"));
            expect(result.safe).toBe(false);
            expect(result.issues.some(i => i.description.includes("Function constructor"))).toBe(true);
        });
    });

    describe("scanTarball - Child Process Patterns (High)", () => {
        it("detects child_process require", async () => {
            const result = await scanTarball(fixture("childproc-pkg"));
            expect(result.safe).toBe(false);
            expect(result.issues.some(i => i.description.includes("child_process"))).toBe(true);
        });

        it("detects exec() calls", async () => {
            const result = await scanTarball(fixture("exec-pkg"));
            expect(result.safe).toBe(false);
        });

        it("detects execSync() calls", async () => {
            const result = await scanTarball(fixture("execsync-pkg"));
            expect(result.safe).toBe(false);
        });

        it("detects spawn() calls", async () => {
            const result = await scanTarball(fixture("spawn-pkg"));
            // spawn is medium severity, so may still be "safe"
            expect(result.issues.some(i => i.description.includes("spawn"))).toBe(true);
        });
    });

    describe("scanTarball - Credential Access Patterns", () => {
        it("detects .ssh access", async () => {
            const result = await scanTarball(fixture("ssh-pkg"));
            expect(result.safe).toBe(false);
            expect(result.issues.some(i => i.description.includes("SSH"))).toBe(true);
        });

        it("detects .npmrc access", async () => {
            const result = await scanTarball(fixture("npmrc-pkg"));
            expect(result.safe).toBe(false);
        });

        it("detects NPM_TOKEN access", async () => {
            const result = await scanTarball(fixture("npmtoken-pkg"));
            expect(result.safe).toBe(false);
            expect(result.issues.some(i => i.description.includes("NPM token"))).toBe(true);
        });

        it("detects GITHUB_TOKEN access", async () => {
            const result = await scanTarball(fixture("ghtoken-pkg"));
            expect(result.safe).toBe(false);
        });

        it("detects AWS credentials access", async () => {
            const result = await scanTarball(fixture("aws-pkg"));
            expect(result.safe).toBe(false);
        });
    });

    describe("scanTarball - Remote Code Patterns", () => {
        it("detects remote require", async () => {
            const result = await scanTarball(fixture("remote-require"));
            expect(result.safe).toBe(false);
            expect(result.issues.some(i => i.description.includes("Remote code"))).toBe(true);
        });

        it("detects remote dynamic import", async () => {
            const result = await scanTarball(fixture("remote-import"));
            expect(result.safe).toBe(false);
        });
    });

    describe("scanTarball - package.json Lifecycle Scripts", () => {
        it("detects curl in postinstall", async () => {
            const result = await scanTarball(fixture("curl-install"));
            expect(result.safe).toBe(false);
            expect(result.issues.some(i => i.file === "package.json")).toBe(true);
        });

        it("detects wget in preinstall", async () => {
            const result = await scanTarball(fixture("wget-install"));
            expect(result.safe).toBe(false);
        });

        it("detects piping to shell", async () => {
            const result = await scanTarball(fixture("pipe-shell"));
            expect(result.safe).toBe(false);
        });

        it("detects node inline execution", async () => {
            const result = await scanTarball(fixture("node-e"));
            expect(result.safe).toBe(false);
        });

        it("detects URL dependencies", async () => {
            const result = await scanTarball(fixture("url-dep"));
            expect(result.safe).toBe(false);
            expect(result.issues.some(i => i.description.includes("URL instead of version"))).toBe(true);
        });
    });

    describe("scanTarball - Obfuscation Patterns", () => {
        it("detects large base64 payloads", async () => {
            const result = await scanTarball(fixture("base64-pkg"));
            expect(result.issues.some(i => i.description.includes("base64"))).toBe(true);
        });

        it("detects hex-encoded strings", async () => {
            const result = await scanTarball(fixture("hex-pkg"));
            expect(result.issues.some(i => i.description.includes("Hex-encoded"))).toBe(true);
        });
    });

    describe("scanTarball - Whitelisted Packages", () => {
        it("skips whitelisted package (lodash)", async () => {
            const result = await scanTarball(fixture("lodash"));
            expect(result.safe).toBe(true);
            expect(result.filesScanned).toBe(0);
        });

        it("skips whitelisted @opentelemetry/ scoped package", async () => {
            const result = await scanTarball(fixture("opentelemetry-core"));
            // Since tarball name is opentelemetry-core-1.0.0.tgz, it matches opentelemetry- prefix
            expect(result.safe).toBe(true);
        });
    });

    describe("scanTarball - Multiple Issues", () => {
        it("detects multiple issues in one file", async () => {
            const result = await scanTarball(fixture("multi-issue"));
            expect(result.safe).toBe(false);
            expect(result.issues.length).toBeGreaterThan(2);
        });

        it("scans nested directories", async () => {
            const result = await scanTarball(fixture("nested-pkg"));
            expect(result.safe).toBe(false);
            expect(result.filesScanned).toBeGreaterThanOrEqual(2);
        });
    });

    describe("scanTarball - Error Handling", () => {
        it("handles non-existent file", async () => {
            try {
                await scanTarball("/nonexistent/path/to/file.tgz");
                expect(true).toBe(false); // Should throw
            } catch (error) {
                expect(error).toBeDefined();
            }
        });

        it("handles invalid tarball gracefully", async () => {
            const result = await scanTarball(join(FIXTURES_DIR, "invalid.tgz"));
            expect(result.safe).toBe(true); // Invalid tarballs treated as safe
        });

        it("handles invalid JSON in package.json", async () => {
            const result = await scanTarball(fixture("invalid-json-pkg"));
            // Should report an issue about invalid JSON
            expect(result.issues.some(i => i.description.includes("Invalid JSON"))).toBe(true);
        });
    });

    describe("scanTarball - Issue Details", () => {
        it("includes line numbers in issues", async () => {
            const result = await scanTarball(fixture("lineno-pkg"));
            expect(result.issues.some(i => i.line !== undefined && i.line > 0)).toBe(true);
        });

        it("includes CWE in applicable issues", async () => {
            const result = await scanTarball(fixture("cwe-pkg"));
            expect(result.issues.some(i => i.cwe !== undefined)).toBe(true);
        });

        it("limits issues to 20", async () => {
            const result = await scanTarball(fixture("many-issues"));
            expect(result.issues.length).toBeLessThanOrEqual(20);
        });
    });
});
