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
 * AgentRegistry Configuration Module
 * 
 * Centralized configuration for the AgentRegistry registry server.
 * All constants, environment variables, and security settings.
 * 
 * @module config
 */

import { join } from "node:path";

// ============================================================================
// Server Configuration
// ============================================================================

/** Server port, configurable via --port flag or defaults to 4873 */
export const PORT = parseInt(Bun.argv.find((_, i, arr) => arr[i - 1] === "--port") ?? "4873");

/** 
 * Root storage directory for all AgentRegistry data.
 * Default: ~/.agentregistry/storage for persistence across reboots.
 * Use STORAGE_DIR=/tmp/... for development/testing to avoid sandbox issues.
 */
export const STORAGE_DIR = process.env.STORAGE_DIR || `${process.env.HOME}/.agentregistry/storage`;

/** Directory for package metadata JSON files */
export const PACKAGES_DIR = join(STORAGE_DIR, "packages");

/** Directory for approved tarball files */
export const TARBALLS_DIR = join(STORAGE_DIR, "tarballs");

/** Directory for quarantined (blocked) packages */
export const QUARANTINE_DIR = join(STORAGE_DIR, "quarantine");

/** Directory for backup files */
export const BACKUP_DIR = join(STORAGE_DIR, "backups");


/** Directory for web assets - always use src/web */
export const WEB_DIR = process.env.WEB_DIR || join(import.meta.dir, "web");

/** Project root directory (where openapi.json, docs/, llms.txt live) */
export const PROJECT_DIR = join(import.meta.dir, "..");

/** Directory for documentation site */
export const DOCS_DIR = join(PROJECT_DIR, "docs");

// ============================================================================
// Security Configuration
// ============================================================================

/** Restrict server to localhost only (recommended for security) */
export const LOCALHOST_ONLY = true;

/** Allowed host values for localhost-only mode */
export const ALLOWED_HOSTS = ["localhost", "127.0.0.1", "[::1]"];

/** Maximum tarball size in bytes (50MB) */
export const MAX_TARBALL_SIZE = 50 * 1024 * 1024;

/** Security scan timeout in milliseconds (30 seconds) */
export const SCAN_TIMEOUT_MS = 30 * 1000;

/** Rate limit window in milliseconds (1 minute) */
export const RATE_LIMIT_WINDOW_MS = 60 * 1000;

/** Maximum requests per rate limit window */
export const RATE_LIMIT_MAX_REQUESTS = 1000; // High limit to support testing

/**
 * HTTP Security Headers applied to all responses.
 * Follows OWASP security best practices.
 */
export const SECURITY_HEADERS: Record<string, string> = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()"
};

// ============================================================================
// Cache Configuration
// ============================================================================

/** Maximum number of tarballs to keep in memory cache */
export const TARBALL_CACHE_MAX_SIZE = 100;

/** Upstream NPM registry URL for proxy fallback */
export const UPSTREAM_REGISTRY = "https://registry.npmjs.org";

// ============================================================================
// Admin Configuration
// ============================================================================

/**
 * Cryptographically secure session token for WebSocket admin authentication.
 * Generated fresh on each server start, or inherited from environment in cluster mode.
 */
export const ADMIN_SESSION_TOKEN = process.env.ADMIN_SESSION_TOKEN || generateSecureToken();

/**
 * Generates a cryptographically secure random token.
 * @returns 32-character hex token
 */
function generateSecureToken(): string {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

// ============================================================================
// Daemon Configuration
// ============================================================================

/** 
 * Home directory for AgentRegistry daemon data (PID, logs).
 * Default: ~/.agentregistry for persistence across reboots.
 */
export const AGENTREGISTRY_HOME = process.env.AGENTREGISTRY_HOME || `${process.env.HOME}/.agentregistry`;

/** PID file location */
export const PID_FILE = process.env.AGENTREGISTRY_PID_FILE || join(AGENTREGISTRY_HOME, "agentregistry.pid");

/** Log directory */
export const LOG_DIR = process.env.AGENTREGISTRY_LOG_DIR || join(AGENTREGISTRY_HOME, "logs");

/** Log file path */
export const LOG_FILE = join(LOG_DIR, "agentregistry.log");

/** Log level: debug, info, warn, error */
export const LOG_LEVEL = (process.env.AGENTREGISTRY_LOG_LEVEL || "info") as "debug" | "info" | "warn" | "error";

/** Maximum number of rotated log files to keep */
export const LOG_MAX_FILES = 7;

/** Maximum log file size in MB before rotation */
export const LOG_ROTATE_SIZE_MB = 10;

/** Whether to run in daemon mode (background) */
export const DAEMON_MODE = Bun.argv.includes("--daemon");

/** Enable multi-worker cluster mode */
export const CLUSTER_MODE = Bun.argv.includes("--cluster") || process.env.CLUSTER_MODE === "true";

