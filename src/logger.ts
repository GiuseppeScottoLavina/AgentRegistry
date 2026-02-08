/* 
 * Copyright 2026 Giuseppe Scotto Lavina
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * AgentRegistry Logger Module
 * 
 * Structured logging with file output and rotation support.
 * 
 * @module logger
 */

import { mkdir, readdir, unlink, rename, stat } from "node:fs/promises";
import { join } from "node:path";
import { LOG_DIR, LOG_FILE, LOG_LEVEL, LOG_MAX_FILES, LOG_ROTATE_SIZE_MB } from "./config";

// ============================================================================
// Types
// ============================================================================

export type LogLevel = "debug" | "info" | "warn" | "error";

interface LogEntry {
    timestamp: string;
    level: LogLevel;
    message: string;
    data?: object;
}

// ============================================================================
// Log Level Ordering
// ============================================================================

const LOG_LEVELS: Record<LogLevel, number> = {
    debug: 0,
    info: 1,
    warn: 2,
    error: 3
};

const LOG_COLORS: Record<LogLevel, string> = {
    debug: "\x1b[90m",  // Gray
    info: "\x1b[36m",   // Cyan
    warn: "\x1b[33m",   // Yellow
    error: "\x1b[31m"   // Red
};

const RESET = "\x1b[0m";

// ============================================================================
// State
// ============================================================================

let logFileHandle: Bun.FileSink | null = null;
let currentLogLevel: LogLevel = LOG_LEVEL;
let logToFile = false;
let logToConsole = true;

// ============================================================================
// Initialization
// ============================================================================

/**
 * Initializes the logger with file output.
 */
export async function initLogger(options?: {
    toFile?: boolean;
    toConsole?: boolean;
    level?: LogLevel;
}): Promise<void> {
    if (options?.level) currentLogLevel = options.level;
    if (options?.toConsole !== undefined) logToConsole = options.toConsole;
    if (options?.toFile !== undefined) logToFile = options.toFile;

    if (logToFile) {
        await mkdir(LOG_DIR, { recursive: true });
        await rotateLogsIfNeeded();

        const writer = Bun.file(LOG_FILE).writer();
        logFileHandle = writer;
    }
}

/**
 * Closes the logger and flushes any pending writes.
 */
export async function closeLogger(): Promise<void> {
    if (logFileHandle) {
        await logFileHandle.flush();
        await logFileHandle.end();
        logFileHandle = null;
    }
}

// ============================================================================
// Core Logging
// ============================================================================

/**
 * Logs a message at the specified level.
 */
export function log(level: LogLevel, message: string, data?: object): void {
    // Check log level
    if (LOG_LEVELS[level] < LOG_LEVELS[currentLogLevel]) {
        return;
    }

    const entry: LogEntry = {
        timestamp: new Date().toISOString(),
        level,
        message,
        ...(data && { data })
    };

    // Console output with colors
    if (logToConsole) {
        const color = LOG_COLORS[level];
        const levelStr = level.toUpperCase().padEnd(5);
        const dataStr = data ? ` ${JSON.stringify(data)}` : "";
        console.log(`${color}[${entry.timestamp}] ${levelStr}${RESET} ${message}${dataStr}`);
    }

    // File output as JSON lines
    if (logToFile && logFileHandle) {
        logFileHandle.write(JSON.stringify(entry) + "\n");
    }
}

// Convenience methods
export const debug = (msg: string, data?: object) => log("debug", msg, data);
export const info = (msg: string, data?: object) => log("info", msg, data);
export const warn = (msg: string, data?: object) => log("warn", msg, data);
export const error = (msg: string, data?: object) => log("error", msg, data);

// ============================================================================
// Log Rotation
// ============================================================================

/**
 * Rotates log files if the current log exceeds the size limit.
 */
export async function rotateLogsIfNeeded(): Promise<void> {
    try {
        const logStat = await stat(LOG_FILE).catch(() => null);
        if (!logStat) return;

        const sizeMB = logStat.size / (1024 * 1024);
        if (sizeMB < LOG_ROTATE_SIZE_MB) return;

        await rotateLogs();
    } catch {
        // Ignore rotation errors
    }
}

/**
 * Performs log rotation by renaming current log and removing old ones.
 */
export async function rotateLogs(): Promise<void> {
    // Close current file handle
    if (logFileHandle) {
        await logFileHandle.flush();
        await logFileHandle.end();
        logFileHandle = null;
    }

    // Find existing rotated logs
    const files = await readdir(LOG_DIR);
    const logFiles = files
        .filter(f => f.startsWith("agentregistry.log") && f !== "agentregistry.log")
        .map(f => ({ name: f, num: parseInt(f.split('.').pop() || "0") }))
        .sort((a, b) => b.num - a.num); // Descending: .3, .2, .1

    // Remove oldest files if over limit
    // We keep MAX_FILES rotated logs.
    while (logFiles.length >= LOG_MAX_FILES) {
        const oldest = logFiles.shift(); // Remove largest number (oldest)
        if (oldest) {
            await unlink(join(LOG_DIR, oldest.name)).catch(() => { });
        }
    }

    // Rotate existing files
    for (const file of logFiles) {
        // e.g. agentregistry.log.2 -> agentregistry.log.3
        const newNum = file.num + 1;
        await rename(
            join(LOG_DIR, file.name),
            join(LOG_DIR, `agentregistry.log.${newNum}`)
        ).catch(() => { });
    }

    // Rename current log
    await rename(LOG_FILE, join(LOG_DIR, "agentregistry.log.1")).catch(() => { });

    // Reopen file handle
    if (logToFile) {
        const writer = Bun.file(LOG_FILE).writer();
        logFileHandle = writer;
    }
}

/**
 * Gets the last N lines from the log file.
 */
export async function tailLogs(lines: number = 50): Promise<string[]> {
    try {
        const content = await Bun.file(LOG_FILE).text();
        const allLines = content.trim().split("\n");
        return allLines.slice(-lines);
    } catch {
        return [];
    }
}
