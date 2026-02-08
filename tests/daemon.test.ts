/**
 * AgentRegistry Daemon Module Tests
 * 
 * Tests for daemon infrastructure functionality.
 * Uses direct file operations to test in isolation.
 */

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { exists, unlink, mkdir, rm } from "node:fs/promises";
import { join } from "node:path";

// Isolated test directory
const TEST_DIR = `/tmp/.test-daemon-${process.pid}-${Date.now()}`;
const TEST_PID_FILE = join(TEST_DIR, "test.pid");

describe("Daemon Module - Core Functions", () => {
    beforeEach(async () => {
        await mkdir(TEST_DIR, { recursive: true });
    });

    afterEach(async () => {
        await rm(TEST_DIR, { recursive: true, force: true });
    });

    describe("PID file operations", () => {
        test("can write and read PID file", async () => {
            const testPid = process.pid;
            await Bun.write(TEST_PID_FILE, String(testPid));

            const content = await Bun.file(TEST_PID_FILE).text();
            expect(parseInt(content.trim())).toBe(testPid);
        });

        test("can delete PID file", async () => {
            await Bun.write(TEST_PID_FILE, "12345");
            expect(await exists(TEST_PID_FILE)).toBe(true);

            await unlink(TEST_PID_FILE);
            expect(await exists(TEST_PID_FILE)).toBe(false);
        });

        test("PID file contains only numeric content", async () => {
            await Bun.write(TEST_PID_FILE, String(process.pid));

            const content = await Bun.file(TEST_PID_FILE).text();
            expect(content.trim()).toMatch(/^\d+$/);
        });
    });

    describe("Process detection", () => {
        function isProcessRunning(pid: number): boolean {
            try {
                process.kill(pid, 0);
                return true;
            } catch {
                return false;
            }
        }

        test("detects current process as running", () => {
            expect(isProcessRunning(process.pid)).toBe(true);
        });

        test("detects non-existent PID as not running", () => {
            expect(isProcessRunning(999999999)).toBe(false);
        });
    });

    describe("Stale PID detection", () => {
        async function getPidFromFile(path: string): Promise<number | null> {
            try {
                if (await exists(path)) {
                    const content = await Bun.file(path).text();
                    const pid = parseInt(content.trim(), 10);
                    return isNaN(pid) ? null : pid;
                }
            } catch { }
            return null;
        }

        test("returns null for non-existent PID file", async () => {
            const pid = await getPidFromFile(join(TEST_DIR, "nonexistent.pid"));
            expect(pid).toBeNull();
        });

        test("returns null for empty PID file", async () => {
            const emptyFile = join(TEST_DIR, "empty.pid");
            await Bun.write(emptyFile, "");

            const pid = await getPidFromFile(emptyFile);
            expect(pid).toBeNull();
        });

        test("returns null for corrupted PID file", async () => {
            const corruptFile = join(TEST_DIR, "corrupt.pid");
            await Bun.write(corruptFile, "not-a-number");

            const pid = await getPidFromFile(corruptFile);
            expect(pid).toBeNull();
        });

        test("returns valid PID from file", async () => {
            await Bun.write(TEST_PID_FILE, "12345");

            const pid = await getPidFromFile(TEST_PID_FILE);
            expect(pid).toBe(12345);
        });
    });

    describe("Directory creation", () => {
        test("mkdir recursive creates nested directories", async () => {
            const nested = join(TEST_DIR, "a", "b", "c");
            await mkdir(nested, { recursive: true });

            expect(await exists(nested)).toBe(true);
        });

        test("mkdir recursive is idempotent", async () => {
            const dir = join(TEST_DIR, "idempotent");
            await mkdir(dir, { recursive: true });
            await mkdir(dir, { recursive: true });
            await mkdir(dir, { recursive: true });

            expect(await exists(dir)).toBe(true);
        });
    });
});

describe("Signal Handling", () => {
    test("process.kill with signal 0 checks process existence", () => {
        // This is a core Unix feature we rely on
        let exists = false;
        try {
            process.kill(process.pid, 0);
            exists = true;
        } catch {
            exists = false;
        }
        expect(exists).toBe(true);
    });

    test("process.kill with signal 0 returns false for non-existent process", () => {
        let exists = false;
        try {
            process.kill(999999999, 0);
            exists = true;
        } catch {
            exists = false;
        }
        expect(exists).toBe(false);
    });
});
