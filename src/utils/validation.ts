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
 * AgentRegistry Validation Utilities
 * 
 * Security-critical validation functions for package names, paths, and inputs.
 * 
 * @module utils/validation
 */

// ============================================================================
// Package Name Validation
// ============================================================================

/** Valid NPM package name pattern (includes scoped packages) */
const VALID_PACKAGE_NAME = /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/;

/**
 * Validates an NPM package name according to npm naming rules.
 * 
 * @param name - Package name to validate (e.g., "lodash" or "@scope/package")
 * @returns true if valid, false otherwise
 * 
 * @example
 * validatePackageName("lodash") // true
 * validatePackageName("@types/node") // true
 * validatePackageName("../evil") // false
 */
export function validatePackageName(name: string): boolean {
    if (!name || typeof name !== "string") return false;
    if (name.length > 214) return false;
    if (name.startsWith(".") || name.startsWith("_")) return false;
    if (name.includes("..")) return false;
    return VALID_PACKAGE_NAME.test(name);
}

// ============================================================================
// Path Security
// ============================================================================

/**
 * Checks if a resolved path is contained within a base directory.
 * Prevents path traversal attacks.
 * 
 * @param basePath - The allowed base directory
 * @param targetPath - The path to validate
 * @returns true if targetPath is within basePath
 * 
 * @example
 * pathContains("/storage", "/storage/packages/lodash.json") // true
 * pathContains("/storage", "/etc/passwd") // false
 */
export function pathContains(basePath: string, targetPath: string): boolean {
    const normalizedBase = basePath.endsWith("/") ? basePath : basePath + "/";
    return targetPath.startsWith(normalizedBase) || targetPath === basePath;
}

/**
 * Extracts package name from a tarball filename.
 * Handles scoped packages correctly.
 * 
 * @param tarballName - Tarball filename (e.g., "lodash-4.17.21.tgz")
 * @returns Package name without version
 * 
 * @example
 * extractPackageNameFromTarball("lodash-4.17.21.tgz") // "lodash"
 * extractPackageNameFromTarball("types-node-18.0.0.tgz") // "types-node"
 */
export function extractPackageNameFromTarball(tarballName: string): string {
    const match = tarballName.match(/^(.+)-\d+\.\d+.*\.tgz$/);
    return match ? match[1] : tarballName.replace(".tgz", "");
}

// ============================================================================
// JSON Security
// ============================================================================

/**
 * Safely parses JSON with prototype pollution protection.
 * Removes dangerous __proto__ and constructor properties.
 * 
 * @param text - JSON string to parse
 * @returns Parsed object or null on error
 * 
 * @example
 * safeJsonParse('{"name": "test"}') // { name: "test" }
 * safeJsonParse('{"__proto__": {}}') // { } (dangerous props removed)
 */
export function safeJsonParse<T = any>(text: string): T | null {
    try {
        return JSON.parse(text, (key, value) => {
            if (key === "__proto__" || key === "constructor") return undefined;
            return value;
        });
    } catch {
        return null;
    }
}
