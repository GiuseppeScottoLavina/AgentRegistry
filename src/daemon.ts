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
 * AgentRegistry Daemon Module
 * 
 * Handles PID file management, signal handling, and daemon lifecycle.
 * 
 * @module daemon
 */

import { mkdir, unlink, exists } from "node:fs/promises";
import { dirname } from "node:path";
import { PID_FILE, AGENTREGISTRY_HOME, LOG_DIR } from "./config";

// ============================================================================
// PID File Management
// ============================================================================

/**
 * Writes the current process ID to the PID file.
 * Creates the directory if it doesn't exist.
 */
export async function writePidFile(): Promise<void> {
    await mkdir(dirname(PID_FILE), { recursive: true });
    await Bun.write(PID_FILE, String(process.pid));
}

/**
 * Removes the PID file on shutdown.
 */
export async function removePidFile(): Promise<void> {
    try {
        if (await exists(PID_FILE)) {
            await unlink(PID_FILE);
        }
    } catch {
        // Ignore errors on cleanup
    }
}

/**
 * Reads the PID from the PID file.
 * @returns The PID if running, null otherwise
 */
export async function getPid(): Promise<number | null> {
    try {
        if (await exists(PID_FILE)) {
            const content = await Bun.file(PID_FILE).text();
            const pid = parseInt(content.trim(), 10);
            return isNaN(pid) ? null : pid;
        }
    } catch {
        // File doesn't exist or can't be read
    }
    return null;
}

/**
 * Checks if a process with the given PID is running.
 */
export function isProcessRunning(pid: number): boolean {
    try {
        // Sending signal 0 checks if process exists without killing it
        process.kill(pid, 0);
        return true;
    } catch {
        return false;
    }
}

/**
 * Checks if AgentRegistry daemon is currently running.
 */
export async function isDaemonRunning(): Promise<{ running: boolean; pid: number | null }> {
    const pid = await getPid();
    if (pid === null) {
        return { running: false, pid: null };
    }

    const running = isProcessRunning(pid);
    if (!running) {
        // Stale PID file, clean it up
        await removePidFile();
        return { running: false, pid: null };
    }

    return { running: true, pid };
}

/**
 * Stops the running daemon by sending SIGTERM.
 */
export async function stopDaemon(): Promise<boolean> {
    const { running, pid } = await isDaemonRunning();
    if (!running || pid === null) {
        return false;
    }

    try {
        process.kill(pid, "SIGTERM");

        // Wait for process to exit (max 5 seconds)
        for (let i = 0; i < 50; i++) {
            await Bun.sleep(100);
            if (!isProcessRunning(pid)) {
                await removePidFile();
                return true;
            }
        }

        // Force kill if still running
        process.kill(pid, "SIGKILL");
        await removePidFile();
        return true;
    } catch {
        return false;
    }
}

// ============================================================================
// Directory Initialization
// ============================================================================

/**
 * Ensures all daemon directories exist.
 */
export async function ensureDaemonDirs(): Promise<void> {
    await mkdir(AGENTREGISTRY_HOME, { recursive: true });
    await mkdir(LOG_DIR, { recursive: true });
}

// ============================================================================
// Uptime
// ============================================================================

/**
 * Gets daemon uptime in seconds based on PID file modification time.
 */
export async function getDaemonUptime(): Promise<number | null> {
    try {
        if (await exists(PID_FILE)) {
            const stat = await Bun.file(PID_FILE).stat();
            if (stat) {
                return Math.floor((Date.now() - stat.mtime.getTime()) / 1000);
            }
        }
    } catch {
        // Ignore
    }
    return null;
}
