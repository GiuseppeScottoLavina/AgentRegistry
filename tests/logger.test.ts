/**
 * AgentRegistry Logger Module Tests
 * 
 * Tests for logging infrastructure.
 * Uses Bun's mock system to hijack config paths and test the actual logger implementation.
 */

import { describe, test, expect, beforeEach, afterEach, mock } from "bun:test";
import { exists, readdir, rm, mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";

// Isolated test directory
const TEST_DIR = `/tmp/.test-logger-real-${process.pid}-${Date.now()}`;
const TEST_LOG_DIR = join(TEST_DIR, "logs");
const TEST_LOG_FILE = join(TEST_LOG_DIR, "agentregistry.log");

// Mock the config module BEFORE importing logger
mock.module("../src/config", () => {
    return {
        LOG_DIR: TEST_LOG_DIR,
        LOG_FILE: TEST_LOG_FILE,
        LOG_LEVEL: "info",
        LOG_MAX_FILES: 3,
        LOG_ROTATE_SIZE_MB: 0.0001, // Very small for testing rotation (approx 100 bytes)
        // Dummy values for other exports if needed by other transitive imports (though logger only needs above)
        PORT: 0,
        STORAGE_DIR: TEST_DIR,
        PACKAGES_DIR: join(TEST_DIR, "packages"),
        TARBALLS_DIR: join(TEST_DIR, "tarballs"),
        QUARANTINE_DIR: join(TEST_DIR, "quarantine"),
        BACKUP_DIR: join(TEST_DIR, "backups"),
        WEB_DIR: join(TEST_DIR, "web"), // Not used
        LOCALHOST_ONLY: true,
        ALLOWED_HOSTS: ["localhost"],
        MAX_TARBALL_SIZE: 1024,
        SCAN_TIMEOUT_MS: 1000,
        RATE_LIMIT_WINDOW_MS: 1000,
        RATE_LIMIT_MAX_REQUESTS: 100,
        SECURITY_HEADERS: {},
        TARBALL_CACHE_MAX_SIZE: 10,
        UPSTREAM_REGISTRY: "https://example.com",
        ADMIN_SESSION_TOKEN: "test-token",
        AGENTREGISTRY_HOME: TEST_DIR,
        PID_FILE: join(TEST_DIR, "pid"),
        CLUSTER_MODE: false,
        DAEMON_MODE: false
    };
});

// Import logger AFTER mocking
import * as logger from "../src/logger";

describe("Logger Module - Real Implementation", () => {
    beforeEach(async () => {
        await mkdir(TEST_LOG_DIR, { recursive: true });
        // Reset logger state
        await logger.closeLogger();
        await logger.initLogger({ toFile: true, toConsole: false, level: "debug" });
    });

    afterEach(async () => {
        await logger.closeLogger();
        await rm(TEST_DIR, { recursive: true, force: true });
    });

    describe("Core Logging", () => {
        test("log() writes to file", async () => {
            logger.info("Test message");
            await logger.closeLogger(); // Flush

            const content = await readFile(TEST_LOG_FILE, "utf-8");
            const entry = JSON.parse(content.trim());

            expect(entry.level).toBe("info");
            expect(entry.message).toBe("Test message");
            expect(entry.timestamp).toBeDefined();
        });

        test("log levels filtering", async () => {
            await logger.initLogger({ toFile: true, toConsole: false, level: "warn" });

            logger.info("Hidden info");
            logger.warn("Visible warn");
            logger.error("Visible error");
            await logger.closeLogger();

            const content = await readFile(TEST_LOG_FILE, "utf-8");
            const lines = content.trim().split("\n");

            expect(lines.length).toBe(2);
            expect(JSON.parse(lines[0]).message).toBe("Visible warn");
            expect(JSON.parse(lines[1]).message).toBe("Visible error");
        });

        test("log data serialization", async () => {
            const data = { foo: "bar", count: 123 };
            logger.info("With data", data);
            await logger.closeLogger();

            const content = await readFile(TEST_LOG_FILE, "utf-8");
            const entry = JSON.parse(content);

            expect(entry.data).toEqual(data);
        });

        test("convenience methods work", async () => {
            logger.debug("Debug msg");
            logger.info("Info msg");
            logger.warn("Warn msg");
            logger.error("Error msg");
            await logger.closeLogger();

            const content = await readFile(TEST_LOG_FILE, "utf-8");
            const lines = content.trim().split("\n");

            // initLogger in beforeEach set level to 'debug'
            expect(lines.length).toBe(4);
            expect(JSON.parse(lines[0]).level).toBe("debug");
            expect(JSON.parse(lines[3]).level).toBe("error");
        });
    });

    describe("Log Rotation", () => {
        test("rotateLogs() explicitly rotates files", async () => {
            // Write initial log
            logger.info("Log 1");
            await logger.closeLogger();

            // Rotate
            await logger.rotateLogs();

            // Check if file moved
            expect(await exists(`${TEST_LOG_FILE}.1`)).toBe(true);

            // Current file matches what we expect from rotateLogs implementation 
            // implementation details: rename returns void, then re-init writer on LOG_FILE.
            // But verify LOG_FILE exists as empty or new
            expect(await exists(TEST_LOG_FILE)).toBe(true);

            const rotatedContent = await readFile(`${TEST_LOG_FILE}.1`, "utf-8");
            expect(rotatedContent).toContain("Log 1");
        });

        test("rotateLogsIfNeeded() triggers on size limit", async () => {
            // Write enough data to exceed 0.0001 MB (~104 bytes)
            const hugeMessage = "A".repeat(200);
            logger.info(hugeMessage);
            await logger.closeLogger();

            await logger.rotateLogsIfNeeded();

            expect(await exists(`${TEST_LOG_FILE}.1`)).toBe(true);
        });

        test("respects LOG_MAX_FILES", async () => {
            // Create dummy rotated files
            await Bun.write(`${TEST_LOG_FILE}.1`, "old 1");
            await Bun.write(`${TEST_LOG_FILE}.2`, "old 2");
            // Max files is 3, so .3 is allowed
            await Bun.write(`${TEST_LOG_FILE}.3`, "old 3");

            // Trigger rotation
            await logger.rotateLogs();

            // .3 should potentially be deleted or moved? 
            // impl: loops logFiles, if length >= MAX, delete oldest.
            // sorting: .sort().reverse() -> log.3, log.2, log.1
            // if we add current to it, we drift?

            // Let's rely on behavior:
            // Log.1 -> Log.2
            // Log.2 -> Log.3
            // Log.3 -> Deleted (since we want MAX_FILES=3 backups? Or implementation details?)

            // Implementation:
            // files = readdir -> filter -> sort -> reverse (descending order)
            // While length >= MAX, delete oldest (largest number usually)

            // So if we have .1, .2, .3, and we rotate:
            // .3 should be deleted if existing count >= max
            // Then .2 -> .3
            // .1 -> .2
            // current -> .1

            expect(await exists(`${TEST_LOG_FILE}.4`)).toBe(false);
            expect(await exists(`${TEST_LOG_FILE}.3`)).toBe(true);
            expect(await exists(`${TEST_LOG_FILE}.2`)).toBe(true);
            expect(await exists(`${TEST_LOG_FILE}.1`)).toBe(true);
        });
    });

    describe("Tail Logs", () => {
        test("tailLogs returns last N lines", async () => {
            for (let i = 0; i < 10; i++) {
                logger.info(`Line ${i}`);
            }
            await logger.closeLogger();

            const lines = await logger.tailLogs(3);
            expect(lines.length).toBe(3);
            expect(JSON.parse(lines[2]).message).toBe("Line 9");
            expect(JSON.parse(lines[0]).message).toBe("Line 7");
        });

        test("tailLogs handles missing file gracefully", async () => {
            await rm(TEST_LOG_FILE, { force: true });
            const lines = await logger.tailLogs(5);
            expect(lines).toEqual([]);
        });
    });
});
