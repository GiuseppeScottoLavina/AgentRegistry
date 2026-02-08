/**
 * HTTP Utilities
 * 
 * ETag generation for HTTP caching.
 */

import { createHash } from "node:crypto";

/**
 * Generate an ETag for HTTP caching based on content hash.
 */
export function generateETag(content: string): string {
    return `"${createHash("md5").update(content).digest("hex").slice(0, 16)}"`;
}

// Note: generateRequestId is in helpers.ts

