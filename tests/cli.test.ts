// @ts-nocheck
import { describe, test, expect, afterAll } from "bun:test";
import { spawn } from "bun";
import { rm, mkdir } from "node:fs/promises";
import { join } from "node:path";

const CLI_PATH = join(import.meta.dir, "../src/cli.ts");
const TEST_PKG_DIR = join("/tmp", "test-cli-pkg");

async function runCli(args: string[]): Promise<{ stdout: string; stderr: string; exitCode: number }> {
    const proc = spawn({
        cmd: ["bun", "run", CLI_PATH, ...args],
        stdout: "pipe",
        stderr: "pipe",
    });

    const stdout = await new Response(proc.stdout).text();
    const stderr = await new Response(proc.stderr).text();
    const exitCode = await proc.exited;

    return { stdout, stderr, exitCode };
}

describe("CLI Integration", () => {
    afterAll(async () => {
        await rm(TEST_PKG_DIR, { recursive: true, force: true });
    });

    test("help command prints usage", async () => {
        const { stdout, exitCode } = await runCli(["help"]);
        expect(exitCode).toBe(0);
        expect(stdout).toContain("AgentRegistry CLI");
        expect(stdout).toContain("Usage:");
    });

    test("status command when not running", async () => {
        // Ensure daemon is not running or handled gracefully
        // We assume test environment might not have daemon running
        // This test just checks it runs without error
        const { stdout, exitCode } = await runCli(["status"]);
        expect(exitCode).toBe(0);
        expect(stdout).toContain("AgentRegistry");
    });

    test("create command generates package", async () => {
        await rm(TEST_PKG_DIR, { recursive: true, force: true });

        // We need to run create in a temp dir
        // Since CLI uses process.cwd(), we might need to spawn with cwd option
        // But runCli helper doesn't support cwd yet. 
        // Let's modify runCli or just pass absolute path? 
        // cli.ts joins process.cwd() with name.

        // Let's rely on cli.ts `cmdCreate` using `join(process.cwd(), name)`
        // We'll spawn with cwd set to tests/ directory

        const proc = spawn({
            cmd: ["bun", "run", CLI_PATH, "create", "test-cli-pkg"],
            cwd: "/tmp", // create inside /tmp
            stdout: "pipe",
            stderr: "pipe",
        });

        const exitCode = await proc.exited;
        expect(exitCode).toBe(0);

        const pkgJson = Bun.file(join(TEST_PKG_DIR, "package.json"));
        expect(await pkgJson.exists()).toBe(true);
        const content = await pkgJson.json();
        expect(content.name).toBe("test-cli-pkg");
    });

    test("doctor command runs diagnostics", async () => {
        const { stdout, exitCode } = await runCli(["doctor"]);
        // It might run successfully or fail depending on if server is running
        // But we just check if it prints the header
        expect(stdout).toContain("diagnostics");
    });

    test("publish command checks for package.json", async () => {
        // Run in a temp dir without package.json
        const proc = spawn({
            cmd: ["bun", "run", CLI_PATH, "publish"],
            cwd: "/tmp", // use /tmp
            stdout: "pipe",
            stderr: "pipe",
        });

        // We know we are running in /tests/, but we want to be sure specific error is shown
        // If tests/ has package.json (unlikely), this test might try to publish.
        // Let's force a safe empty dir.

        await rm(TEST_PKG_DIR, { recursive: true, force: true });
        await mkdir(TEST_PKG_DIR, { recursive: true });

        const proc2 = spawn({
            cmd: ["bun", "run", CLI_PATH, "publish"],
            cwd: TEST_PKG_DIR,
            stdout: "pipe",
            stderr: "pipe",
        });

        const stdout = await new Response(proc2.stdout).text();
        const exitCode = await proc2.exited;

        expect(exitCode).toBe(1);
        expect(stdout).toContain("No package.json");
    });

    test("unknown command returns error", async () => {
        const { stdout, exitCode } = await runCli(["unknown-cmd"]);
        expect(exitCode).toBe(1);
        expect(stdout).toContain("Unknown command");
    });
});
