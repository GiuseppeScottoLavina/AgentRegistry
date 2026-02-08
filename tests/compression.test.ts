/**
 * Compression Utility Tests
 * 
 * Tests for HTTP compression (Brotli/Gzip) utilities.
 * 
 * Run with: bun test tests/compression.test.ts
 */

import { describe, test, expect } from "bun:test";
import { compressResponse } from "../src/utils/compression";

describe("compressResponse", () => {

    test("skips compression for small responses (<1KB)", () => {
        const body = "small body";
        const headers = { "Content-Type": "application/json" };

        const result = compressResponse(body, headers, "br, gzip");

        expect(result.body).toBe(body); // Unchanged
        expect(result.headers["Content-Encoding"]).toBeUndefined();
    });

    test("skips compression when acceptEncoding is null", () => {
        const body = "x".repeat(2000); // >1KB
        const headers = { "Content-Type": "application/json" };

        const result = compressResponse(body, headers, null);

        expect(result.body).toBe(body);
        expect(result.headers["Content-Encoding"]).toBeUndefined();
    });

    test("compresses with Brotli when 'br' is accepted", () => {
        const body = "x".repeat(2000); // >1KB
        const headers = { "Content-Type": "application/json" };

        const result = compressResponse(body, headers, "br, gzip, deflate");

        expect(result.body).not.toBe(body); // Should be compressed
        expect(result.headers["Content-Encoding"]).toBe("br");
        expect(result.headers["Vary"]).toBe("Accept-Encoding");
    });

    test("falls back to Gzip when only 'gzip' is accepted", () => {
        const body = "x".repeat(2000); // >1KB
        const headers = { "Content-Type": "application/json" };

        const result = compressResponse(body, headers, "gzip, deflate");

        expect(result.body).not.toBe(body);
        expect(result.headers["Content-Encoding"]).toBe("gzip");
        expect(result.headers["Vary"]).toBe("Accept-Encoding");
    });

    test("returns uncompressed when no matching encoding", () => {
        const body = "x".repeat(2000); // >1KB
        const headers = { "Content-Type": "application/json" };

        const result = compressResponse(body, headers, "deflate");

        expect(result.body).toBe(body);
        expect(result.headers["Content-Encoding"]).toBeUndefined();
    });

    test("Brotli compressed output is smaller than original", () => {
        // Highly compressible repeated data
        const body = "Hello World! ".repeat(200);
        const headers = { "Content-Type": "text/plain" };

        const result = compressResponse(body, headers, "br");

        expect(result.body).not.toBe(body);
        expect((result.body as Uint8Array).byteLength).toBeLessThan(body.length);
    });

    test("Gzip compressed output is smaller than original", () => {
        const body = "Hello World! ".repeat(200);
        const headers = { "Content-Type": "text/plain" };

        const result = compressResponse(body, headers, "gzip");

        expect(result.body).not.toBe(body);
        expect((result.body as Uint8Array).byteLength).toBeLessThan(body.length);
    });

    test("preserves existing headers alongside compression headers", () => {
        const body = "x".repeat(2000);
        const headers = { "Content-Type": "application/json", "X-Custom": "value" };

        const result = compressResponse(body, headers, "br");

        expect(result.headers["Content-Type"]).toBe("application/json");
        expect(result.headers["X-Custom"]).toBe("value");
        expect(result.headers["Content-Encoding"]).toBe("br");
    });

    test("prefers Brotli over Gzip when both accepted", () => {
        const body = "x".repeat(2000);
        const headers = { "Content-Type": "application/json" };

        const result = compressResponse(body, headers, "gzip, br");

        expect(result.headers["Content-Encoding"]).toBe("br");
    });
});
