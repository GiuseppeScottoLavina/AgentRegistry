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
 * AgentRegistry Helper Utilities
 * 
 * General-purpose helper functions for the AgentRegistry server.
 * 
 * @module utils/helpers
 */

import { createHash } from "node:crypto";
import { join } from "node:path";
import { PACKAGES_DIR, TARBALLS_DIR } from "../config";
import { pathContains } from "./validation";

// ============================================================================
// ID Generation
// ============================================================================

/**
 * Generates a CouchDB-style revision ID.
 * Format: {incrementNumber}-{randomHex}
 * 
 * @param increment - Revision number (starts at 1)
 * @returns Revision string like "1-abc123def456"
 */
export function generateRev(increment: number = 1): string {
    const random = Math.random().toString(16).slice(2, 14);
    return `${increment}-${random}`;
}

/**
 * Generates a unique request ID for logging and tracing.
 * 
 * @returns 8-character hex request ID
 */
export function generateRequestId(): string {
    return Math.random().toString(16).slice(2, 10);
}

// ============================================================================
// Hash Functions
// ============================================================================

/**
 * Computes SHA-256 hash of data.
 * 
 * @param data - Buffer or string to hash
 * @returns Hex-encoded SHA-256 hash
 */
export function sha256(data: Buffer | string): string {
    return createHash("sha256").update(data).digest("hex");
}

/**
 * Computes SHA-512 hash (shasum) of data.
 * Used for npm integrity checks.
 * 
 * @param data - Buffer or string to hash
 * @returns Base64-encoded SHA-512 hash with prefix
 */
export function computeShasum(data: Buffer): string {
    return createHash("sha512").update(data).digest("base64");
}

/**
 * Computes SHA-256 hash of a file.
 * Used for TOCTOU protection in quarantine approval.
 * 
 * @param path - Absolute path to file
 * @returns Hex-encoded SHA-256 hash, or null if file doesn't exist
 */
export async function sha256File(path: string): Promise<string | null> {
    try {
        const file = Bun.file(path);
        const buffer = await file.arrayBuffer();
        return createHash("sha256").update(Buffer.from(buffer)).digest("hex");
    } catch {
        return null;
    }
}

// ============================================================================
// Path Helpers
// ============================================================================

/**
 * Gets the file path for a package's metadata JSON.
 * Validates path to prevent traversal attacks.
 * 
 * @param packageName - Package name (may be scoped)
 * @returns Absolute path to package JSON file
 * @throws Error if path validation fails
 */
export function getPackagePath(packageName: string): string {
    const safeName = packageName.replace(/\//g, "%2f");
    const path = join(PACKAGES_DIR, `${safeName}.json`);
    if (!pathContains(PACKAGES_DIR, path)) {
        throw new Error("Invalid package path");
    }
    return path;
}

/**
 * Gets the file path for a tarball.
 * Validates path to prevent traversal attacks.
 * 
 * @param tarballName - Tarball filename
 * @returns Absolute path to tarball file
 * @throws Error if path validation fails
 */
export function getTarballPath(tarballName: string): string {
    const path = join(TARBALLS_DIR, tarballName);
    if (!pathContains(TARBALLS_DIR, path)) {
        throw new Error("Invalid tarball path");
    }
    return path;
}

// ============================================================================
// Formatting
// ============================================================================

/**
 * Formats uptime in seconds to human-readable string.
 * 
 * @param seconds - Uptime in seconds
 * @returns Formatted string like "2h 30m 15s"
 */
export function formatUptime(seconds: number): string {
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = Math.floor(seconds % 60);
    return `${h}h ${m}m ${s}s`;
}
