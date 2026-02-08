/**
 * Validation Utility Tests
 * 
 * Tests for utils/validation.ts functions.
 * 
 * Run with: bun test tests/validation.test.ts
 */

import { describe, test, expect } from "bun:test";
import {
    validatePackageName,
    pathContains,
    extractPackageNameFromTarball,
    safeJsonParse
} from "../src/utils/validation";

// ============================================================================
// Package Name Validation
// ============================================================================

describe("validatePackageName", () => {
    test("accepts simple valid names", () => {
        expect(validatePackageName("lodash")).toBe(true);
        expect(validatePackageName("express")).toBe(true);
        expect(validatePackageName("my-package")).toBe(true);
        expect(validatePackageName("my.package")).toBe(true);
        expect(validatePackageName("my_package")).toBe(true);
    });

    test("accepts scoped packages", () => {
        expect(validatePackageName("@types/node")).toBe(true);
        expect(validatePackageName("@scope/my-package")).toBe(true);
        expect(validatePackageName("@babel/core")).toBe(true);
    });

    test("rejects empty or null names", () => {
        expect(validatePackageName("")).toBe(false);
        expect(validatePackageName(null as any)).toBe(false);
        expect(validatePackageName(undefined as any)).toBe(false);
    });

    test("rejects non-string input", () => {
        expect(validatePackageName(123 as any)).toBe(false);
        expect(validatePackageName({} as any)).toBe(false);
    });

    test("rejects names longer than 214 characters", () => {
        const longName = "a".repeat(215);
        expect(validatePackageName(longName)).toBe(false);
    });

    test("accepts names exactly 214 characters", () => {
        const maxName = "a".repeat(214);
        expect(validatePackageName(maxName)).toBe(true);
    });

    test("rejects names starting with dot", () => {
        expect(validatePackageName(".hidden")).toBe(false);
    });

    test("rejects names starting with underscore", () => {
        expect(validatePackageName("_private")).toBe(false);
    });

    test("rejects path traversal", () => {
        expect(validatePackageName("../evil")).toBe(false);
        expect(validatePackageName("package/../etc/passwd")).toBe(false);
    });
});

// ============================================================================
// Path Containment
// ============================================================================

describe("pathContains", () => {
    test("returns true when target is inside base", () => {
        expect(pathContains("/storage", "/storage/packages/lodash.json")).toBe(true);
    });

    test("returns true when target equals base", () => {
        expect(pathContains("/storage", "/storage")).toBe(true);
    });

    test("returns false when target is outside base", () => {
        expect(pathContains("/storage", "/etc/passwd")).toBe(false);
    });

    test("returns false for prefix attack", () => {
        // /storage-evil starts with /storage but is not inside it
        expect(pathContains("/storage", "/storage-evil/file")).toBe(false);
    });

    test("handles base with trailing slash", () => {
        expect(pathContains("/storage/", "/storage/file.txt")).toBe(true);
    });

    test("handles nested paths", () => {
        expect(pathContains("/a/b", "/a/b/c/d/e.txt")).toBe(true);
    });
});

// ============================================================================
// Tarball Name Extraction
// ============================================================================

describe("extractPackageNameFromTarball", () => {
    test("extracts simple package name", () => {
        expect(extractPackageNameFromTarball("lodash-4.17.21.tgz")).toBe("lodash");
    });

    test("extracts scoped package name", () => {
        expect(extractPackageNameFromTarball("types-node-18.0.0.tgz")).toBe("types-node");
    });

    test("handles prerelease versions", () => {
        expect(extractPackageNameFromTarball("my-pkg-1.0.0-beta.1.tgz")).toBe("my-pkg");
    });

    test("handles package without version match", () => {
        expect(extractPackageNameFromTarball("unknown.tgz")).toBe("unknown");
    });

    test("handles hyphenated package names", () => {
        expect(extractPackageNameFromTarball("my-cool-package-2.0.0.tgz")).toBe("my-cool-package");
    });
});

// ============================================================================
// Safe JSON Parse
// ============================================================================

describe("safeJsonParse", () => {
    test("parses valid JSON", () => {
        const result = safeJsonParse('{"name": "test", "version": "1.0.0"}');
        expect(result).toEqual({ name: "test", version: "1.0.0" });
    });

    test("returns null for invalid JSON", () => {
        expect(safeJsonParse("not json")).toBeNull();
        expect(safeJsonParse("{broken")).toBeNull();
        expect(safeJsonParse("")).toBeNull();
    });

    test("strips __proto__ property (prototype pollution protection)", () => {
        const result = safeJsonParse('{"name": "test", "__proto__": {"admin": true}}');
        expect(result).toBeDefined();
        expect((result as any).__proto__?.admin).toBeUndefined();
    });

    test("strips constructor property", () => {
        const result = safeJsonParse('{"name": "test", "constructor": "evil"}');
        expect(result).toBeDefined();
        expect((result as any).constructor).not.toBe("evil");
    });

    test("handles nested objects", () => {
        const result = safeJsonParse('{"a": {"b": {"c": 42}}}');
        expect(result).toEqual({ a: { b: { c: 42 } } });
    });

    test("handles arrays", () => {
        const result = safeJsonParse('[1, 2, 3]');
        expect(result).toEqual([1, 2, 3]);
    });

    test("handles null values", () => {
        const result = safeJsonParse('{"key": null}');
        expect(result).toEqual({ key: null });
    });

    test("typed generic", () => {
        interface Pkg { name: string; version: string; }
        const result = safeJsonParse<Pkg>('{"name": "foo", "version": "1.0.0"}');
        expect(result?.name).toBe("foo");
        expect(result?.version).toBe("1.0.0");
    });
});
