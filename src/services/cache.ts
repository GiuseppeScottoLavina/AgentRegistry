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
 * AgentRegistry Cache Service
 * 
 * In-memory caching for tarballs, packages, and scan results.
 * Improves performance by avoiding repeated disk reads.
 * 
 * @module services/cache
 */

import { TARBALL_CACHE_MAX_SIZE } from "../config";
import type { ScanResult } from "../security";

// ============================================================================
// Tarball Cache
// ============================================================================

/** In-memory cache for validated tarball buffers */
const TARBALL_CACHE = new Map<string, Buffer>();

/**
 * Gets a tarball from cache.
 * 
 * @param key - Tarball filename
 * @returns Cached buffer or undefined
 */
export function getTarballFromCache(key: string): Buffer | undefined {
    return TARBALL_CACHE.get(key);
}

/**
 * Stores a tarball in cache with LRU eviction.
 * 
 * @param key - Tarball filename
 * @param data - Tarball buffer
 */
export function setTarballInCache(key: string, data: Buffer): void {
    if (TARBALL_CACHE.size >= TARBALL_CACHE_MAX_SIZE) {
        const firstKey = TARBALL_CACHE.keys().next().value;
        if (firstKey) TARBALL_CACHE.delete(firstKey);
    }
    TARBALL_CACHE.set(key, data);
}

/**
 * Removes a tarball from cache.
 * 
 * @param key - Tarball filename
 */
export function deleteTarballFromCache(key: string): void {
    TARBALL_CACHE.delete(key);
}

/** Gets current tarball cache size */
export function getTarballCacheSize(): number {
    return TARBALL_CACHE.size;
}

// ============================================================================
// Scan Results Cache
// ============================================================================

/** In-memory cache for security scan results (by hash) */
const SCAN_RESULTS_CACHE = new Map<string, ScanResult>();

/**
 * Gets cached scan result by tarball hash.
 * 
 * @param hash - SHA-256 hash of tarball
 * @returns Cached scan result or undefined
 */
export function getScanResultFromCache(hash: string): ScanResult | undefined {
    return SCAN_RESULTS_CACHE.get(hash);
}

/**
 * Stores scan result in cache.
 * 
 * @param hash - SHA-256 hash of tarball
 * @param result - Scan result
 */
export function setScanResultInCache(hash: string, result: ScanResult): void {
    SCAN_RESULTS_CACHE.set(hash, result);
}

// ============================================================================
// Rate Limiting Store
// ============================================================================

/** In-memory rate limit tracking per IP */
const rateLimitStore = new Map<string, { count: number; resetTime: number }>();

/**
 * Checks rate limit for an IP address.
 * 
 * @param ip - Client IP address
 * @param maxRequests - Maximum requests allowed
 * @param windowMs - Time window in milliseconds
 * @returns Object with allowed status and remaining requests
 */
export function checkRateLimit(
    ip: string,
    maxRequests: number,
    windowMs: number
): { allowed: boolean; remaining: number } {
    const now = Date.now();
    const record = rateLimitStore.get(ip);

    if (!record || now > record.resetTime) {
        rateLimitStore.set(ip, { count: 1, resetTime: now + windowMs });
        return { allowed: true, remaining: maxRequests - 1 };
    }

    if (record.count >= maxRequests) {
        return { allowed: false, remaining: 0 };
    }

    record.count++;
    return { allowed: true, remaining: maxRequests - record.count };
}

/** Exports the rate limit store for direct access (admin stats) */
export { rateLimitStore };
