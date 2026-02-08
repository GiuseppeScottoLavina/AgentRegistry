/**
 * HTTP Compression Utilities
 * 
 * Brotli and Gzip compression for large HTTP responses.
 */

import { brotliCompressSync } from "node:zlib";

/**
 * Compress response body with Brotli or Gzip based on Accept-Encoding header.
 * Skips compression for responses smaller than 1KB.
 */
export function compressResponse(
    body: string,
    headers: Record<string, string>,
    acceptEncoding: string | null
): { body: string | Uint8Array; headers: Record<string, string> } {
    // Skip small responses (<1KB) or if no encoding accepted
    if (!acceptEncoding || body.length < 1024) {
        return { body, headers };
    }

    const buffer = Buffer.from(body);

    // Prefer Brotli if supported
    if (acceptEncoding.includes("br")) {
        try {
            const compressed = brotliCompressSync(buffer);
            return {
                body: compressed,
                headers: { ...headers, "Content-Encoding": "br", "Vary": "Accept-Encoding" }
            };
        } catch {
            // Fallback to gzip on error
        }
    }

    // Fallback to Gzip
    if (acceptEncoding.includes("gzip")) {
        const compressed = Bun.gzipSync(buffer);
        return {
            body: compressed,
            headers: { ...headers, "Content-Encoding": "gzip", "Vary": "Accept-Encoding" }
        };
    }

    // No matching compression supported
    return { body, headers };
}
