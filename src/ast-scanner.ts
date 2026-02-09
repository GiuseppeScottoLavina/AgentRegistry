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
 * AST Deep Scanner — Structural Code Analysis for Security
 * 
 * Optional deep scanning module that uses acorn AST parser to detect
 * obfuscated malicious patterns that regex-based scanning cannot catch.
 * 
 * Activated manually via: agentregistry scan --deep <package@version>
 * Does NOT run during npm publish (fast path is unaffected).
 */

import * as acorn from "acorn";

// ============================================================================
// Types
// ============================================================================

export interface DeepScanFinding {
    file: string;
    line: number;
    column: number;
    severity: "critical" | "high" | "medium";
    pattern: string;
    description: string;
    code: string;
}

export interface DeepScanResult {
    findings: DeepScanFinding[];
    filesAnalyzed: number;
    parseErrors: number;
    scanTimeMs: number;
}

/** Resolved constant values tracked during analysis */
interface ConstantMap {
    [name: string]: string;
}

// ============================================================================
// AST Walker
// ============================================================================

type VisitorFn = (node: acorn.Node, ancestors: acorn.Node[]) => void;

interface Visitors {
    [nodeType: string]: VisitorFn;
}

/**
 * Simple recursive AST walker. Calls visitor for matching node types.
 * Tracks ancestor chain for context analysis.
 */
function walkAST(node: acorn.Node, visitors: Visitors, ancestors: acorn.Node[] = []): void {
    if (!node || typeof node !== "object") return;

    const type = (node as any).type;
    if (!type) return;

    const currentAncestors = [...ancestors, node];

    if (visitors[type]) {
        visitors[type](node, ancestors);
    }

    // Walk all child nodes
    for (const key of Object.keys(node)) {
        if (key === "type" || key === "start" || key === "end") continue;
        const child = (node as any)[key];
        if (child && typeof child === "object") {
            if (Array.isArray(child)) {
                for (const item of child) {
                    if (item && typeof item.type === "string") {
                        walkAST(item, visitors, currentAncestors);
                    }
                }
            } else if (typeof child.type === "string") {
                walkAST(child, visitors, currentAncestors);
            }
        }
    }
}

// ============================================================================
// Source Code Helpers
// ============================================================================

/** Extract a code snippet around the given node for context */
function extractSnippet(source: string, node: acorn.Node, maxLen: number = 80): string {
    const start = (node as any).start as number;
    const end = (node as any).end as number;
    const snippet = source.slice(start, Math.min(end, start + maxLen));
    return snippet.length < end - start ? snippet + "…" : snippet;
}

/** Get line and column from an acorn node */
function getLocation(node: acorn.Node): { line: number; column: number } {
    const loc = (node as any).loc;
    if (loc?.start) {
        return { line: loc.start.line, column: loc.start.column };
    }
    return { line: 0, column: 0 };
}

// ============================================================================
// Constant Propagation (Lightweight)
// ============================================================================

/**
 * First pass: collect all `const name = "literal"` declarations.
 * Only tracks simple string literals assigned to const variables.
 */
function collectConstants(ast: acorn.Node): ConstantMap {
    const constants: ConstantMap = {};

    walkAST(ast, {
        VariableDeclaration(node: acorn.Node) {
            const decl = node as any;
            if (decl.kind !== "const") return;

            for (const declarator of decl.declarations) {
                if (
                    declarator.id?.type === "Identifier" &&
                    declarator.init?.type === "Literal" &&
                    typeof declarator.init.value === "string"
                ) {
                    constants[declarator.id.name] = declarator.init.value;
                }
            }
        }
    });

    return constants;
}

/**
 * Try to resolve an expression node to a string value using constant propagation.
 * Handles: string literals, identifier references, binary + concatenation.
 */
function resolveToString(node: any, constants: ConstantMap): string | null {
    if (!node) return null;

    // String literal
    if (node.type === "Literal" && typeof node.value === "string") {
        return node.value;
    }

    // Identifier → lookup in constants
    if (node.type === "Identifier" && node.name in constants) {
        return constants[node.name];
    }

    // Binary "+" → concatenation
    if (node.type === "BinaryExpression" && node.operator === "+") {
        const left = resolveToString(node.left, constants);
        const right = resolveToString(node.right, constants);
        if (left !== null && right !== null) {
            return left + right;
        }
    }

    // Template literal with no expressions
    if (node.type === "TemplateLiteral" && node.expressions.length === 0 && node.quasis.length === 1) {
        return node.quasis[0].value.cooked;
    }

    return null;
}

// ============================================================================
// Dangerous Names Detection
// ============================================================================

const DANGEROUS_EXEC_NAMES = new Set(["eval", "Function"]);
const DANGEROUS_SHELL_NAMES = new Set(["exec", "execSync", "spawn", "spawnSync"]);

function isDangerousExecName(value: string): boolean {
    return DANGEROUS_EXEC_NAMES.has(value) || DANGEROUS_SHELL_NAMES.has(value);
}

// ============================================================================
// Pattern Detection Visitors
// ============================================================================

/**
 * Pattern: obfuscated_eval
 * Detects eval accessed via bracket notation on global objects:
 *   globalThis["eval"](...), window["eval"](...), global["eval"](...)
 * Also detects eval reconstructed via concatenation:
 *   globalThis["ev" + "al"](...)
 */
function detectObfuscatedEval(
    source: string,
    constants: ConstantMap,
    findings: DeepScanFinding[],
    filename: string
): Visitors {
    return {
        CallExpression(node: acorn.Node) {
            const call = node as any;
            const callee = call.callee;

            if (callee?.type !== "MemberExpression" || !callee.computed) return;

            // Check if the object is a global-like identifier
            const obj = callee.object;
            if (obj?.type !== "Identifier") return;
            const globalNames = new Set(["globalThis", "window", "global", "self"]);
            if (!globalNames.has(obj.name)) return;

            // Try to resolve the property to a string
            const propValue = resolveToString(callee.property, constants);
            if (propValue && isDangerousExecName(propValue)) {
                const loc = getLocation(node);
                findings.push({
                    file: filename,
                    line: loc.line,
                    column: loc.column,
                    severity: "critical",
                    pattern: "obfuscated_eval",
                    description: `Obfuscated ${propValue}() via computed property on ${obj.name}`,
                    code: extractSnippet(source, node)
                });
            }
        }
    };
}

/**
 * Pattern: dynamic_require
 * Detects require() with non-literal argument:
 *   require(variable), require(a + b), require(getPath())
 */
function detectDynamicRequire(
    source: string,
    constants: ConstantMap,
    findings: DeepScanFinding[],
    filename: string
): Visitors {
    return {
        CallExpression(node: acorn.Node) {
            const call = node as any;
            const callee = call.callee;

            // require(...)
            if (callee?.type !== "Identifier" || callee.name !== "require") return;
            if (!call.arguments || call.arguments.length === 0) return;

            const arg = call.arguments[0];
            // Skip string literals (safe static requires)
            if (arg.type === "Literal" && typeof arg.value === "string") return;
            // Skip template literals with no expressions (safe static)
            if (arg.type === "TemplateLiteral" && arg.expressions.length === 0) return;

            // Check if constant propagation resolves to a safe value
            const resolved = resolveToString(arg, constants);
            if (resolved !== null && !resolved.startsWith("http")) return;

            const loc = getLocation(node);
            findings.push({
                file: filename,
                line: loc.line,
                column: loc.column,
                severity: "high",
                pattern: "dynamic_require",
                description: "require() with runtime-computed argument",
                code: extractSnippet(source, node)
            });
        }
    };
}

/**
 * Pattern: dynamic_import
 * Detects import() with non-literal argument:
 *   import(variable), import(getUrl())
 */
function detectDynamicImport(
    source: string,
    constants: ConstantMap,
    findings: DeepScanFinding[],
    filename: string
): Visitors {
    return {
        ImportExpression(node: acorn.Node) {
            const imp = node as any;
            const arg = imp.source;

            // Skip string literals
            if (arg?.type === "Literal" && typeof arg.value === "string") return;
            if (arg?.type === "TemplateLiteral" && arg.expressions.length === 0) return;

            // Check if constant propagation resolves to a safe value
            const resolved = resolveToString(arg, constants);
            if (resolved !== null && !resolved.startsWith("http")) return;

            const loc = getLocation(node);
            findings.push({
                file: filename,
                line: loc.line,
                column: loc.column,
                severity: "high",
                pattern: "dynamic_import",
                description: "Dynamic import() with runtime-computed argument",
                code: extractSnippet(source, node)
            });
        }
    };
}

/**
 * Pattern: computed_member_exec
 * Detects obj[expr]() where expr resolves to dangerous function names:
 *   this[name](), obj[getMethod()]()
 * Broader than obfuscated_eval — catches any object, not just globalThis.
 */
function detectComputedMemberExec(
    source: string,
    constants: ConstantMap,
    findings: DeepScanFinding[],
    filename: string
): Visitors {
    return {
        CallExpression(node: acorn.Node) {
            const call = node as any;
            const callee = call.callee;

            if (callee?.type !== "MemberExpression" || !callee.computed) return;

            // Skip if already caught by obfuscated_eval (globalThis/window/global/self)
            if (callee.object?.type === "Identifier") {
                const globalNames = new Set(["globalThis", "window", "global", "self"]);
                if (globalNames.has(callee.object.name)) return;
            }

            const propValue = resolveToString(callee.property, constants);
            if (propValue && isDangerousExecName(propValue)) {
                const loc = getLocation(node);
                findings.push({
                    file: filename,
                    line: loc.line,
                    column: loc.column,
                    severity: "high",
                    pattern: "computed_member_exec",
                    description: `Computed method call resolves to ${propValue}()`,
                    code: extractSnippet(source, node)
                });
            }
        }
    };
}

/**
 * Pattern: string_reconstruction
 * Detects String.fromCharCode() with 6+ numeric arguments (payload reconstruction).
 */
function detectStringReconstruction(
    source: string,
    _constants: ConstantMap,
    findings: DeepScanFinding[],
    filename: string
): Visitors {
    return {
        CallExpression(node: acorn.Node) {
            const call = node as any;
            const callee = call.callee;

            // String.fromCharCode(...) pattern
            if (
                callee?.type === "MemberExpression" &&
                callee.object?.type === "Identifier" &&
                callee.object.name === "String" &&
                callee.property?.type === "Identifier" &&
                callee.property.name === "fromCharCode"
            ) {
                // Only flag if 6+ arguments (threshold to reduce false positives)
                if (call.arguments && call.arguments.length >= 6) {
                    const loc = getLocation(node);
                    findings.push({
                        file: filename,
                        line: loc.line,
                        column: loc.column,
                        severity: "high",
                        pattern: "string_reconstruction",
                        description: `String.fromCharCode() with ${call.arguments.length} arguments (payload reconstruction)`,
                        code: extractSnippet(source, node)
                    });
                }
            }
        }
    };
}

/**
 * Pattern: fetch_with_env
 * Detects fetch/axios/http.request where process.env is used in URL or body.
 * This is a common exfiltration pattern.
 */
function detectFetchWithEnv(
    source: string,
    _constants: ConstantMap,
    findings: DeepScanFinding[],
    filename: string
): Visitors {
    /** Check if an AST subtree contains a process.env reference */
    function containsProcessEnv(node: any): boolean {
        if (!node || typeof node !== "object") return false;
        if (
            node.type === "MemberExpression" &&
            node.object?.type === "Identifier" &&
            node.object.name === "process" &&
            node.property?.type === "Identifier" &&
            node.property.name === "env"
        ) {
            return true;
        }
        for (const key of Object.keys(node)) {
            if (key === "type" || key === "start" || key === "end") continue;
            const child = node[key];
            if (child && typeof child === "object") {
                if (Array.isArray(child)) {
                    for (const item of child) {
                        if (item && typeof item.type === "string" && containsProcessEnv(item)) return true;
                    }
                } else if (typeof child.type === "string" && containsProcessEnv(child)) {
                    return true;
                }
            }
        }
        return false;
    }

    return {
        CallExpression(node: acorn.Node) {
            const call = node as any;
            const callee = call.callee;

            let funcName: string | null = null;

            // fetch(...), axios.post(...), axios.get(...), http.request(...)
            if (callee?.type === "Identifier") {
                if (callee.name === "fetch") funcName = "fetch";
            } else if (callee?.type === "MemberExpression") {
                const objName = callee.object?.name;
                const propName = callee.property?.name;
                if (objName === "axios" && propName) funcName = `axios.${propName}`;
                if ((objName === "http" || objName === "https") && propName === "request") {
                    funcName = `${objName}.request`;
                }
            }

            if (!funcName) return;

            // Check if any argument contains process.env
            for (const arg of call.arguments || []) {
                if (containsProcessEnv(arg)) {
                    const loc = getLocation(node);
                    findings.push({
                        file: filename,
                        line: loc.line,
                        column: loc.column,
                        severity: "critical",
                        pattern: "fetch_with_env",
                        description: `${funcName}() with process.env data (potential exfiltration)`,
                        code: extractSnippet(source, node)
                    });
                    break;
                }
            }
        }
    };
}

/**
 * Pattern: encoded_payload_exec
 * Detects eval(atob(...)) or new Function(Buffer.from(..., "base64").toString())
 */
function detectEncodedPayloadExec(
    source: string,
    _constants: ConstantMap,
    findings: DeepScanFinding[],
    filename: string
): Visitors {
    /** Check if node is an atob() or Buffer.from().toString() call */
    function isDecodingCall(node: any): boolean {
        if (!node || node.type !== "CallExpression") return false;
        const callee = node.callee;
        // atob(...)
        if (callee?.type === "Identifier" && callee.name === "atob") return true;
        // Buffer.from(...).toString(...)
        if (
            callee?.type === "MemberExpression" &&
            callee.property?.name === "toString" &&
            callee.object?.type === "CallExpression" &&
            callee.object.callee?.type === "MemberExpression" &&
            callee.object.callee.object?.name === "Buffer" &&
            callee.object.callee.property?.name === "from"
        ) {
            return true;
        }
        return false;
    }

    return {
        CallExpression(node: acorn.Node) {
            const call = node as any;
            const callee = call.callee;

            // eval(decodingCall) or Function(decodingCall)
            const isEval = callee?.type === "Identifier" && callee.name === "eval";
            const isFunction = callee?.type === "Identifier" && callee.name === "Function";

            if (!isEval && !isFunction) return;
            if (!call.arguments || call.arguments.length === 0) return;

            const targetArg = isFunction
                ? call.arguments[call.arguments.length - 1]
                : call.arguments[0];

            if (isDecodingCall(targetArg)) {
                const loc = getLocation(node);
                findings.push({
                    file: filename,
                    line: loc.line,
                    column: loc.column,
                    severity: "critical",
                    pattern: "encoded_payload_exec",
                    description: `${isEval ? "eval" : "Function"}() with decoded payload (atob/Buffer.from)`,
                    code: extractSnippet(source, node)
                });
            }
        },
        NewExpression(node: acorn.Node) {
            const expr = node as any;
            if (expr.callee?.type === "Identifier" && expr.callee.name === "Function") {
                if (expr.arguments?.length > 0 && isDecodingCall(expr.arguments[expr.arguments.length - 1])) {
                    const loc = getLocation(node);
                    findings.push({
                        file: filename,
                        line: loc.line,
                        column: loc.column,
                        severity: "critical",
                        pattern: "encoded_payload_exec",
                        description: "new Function() with decoded payload (atob/Buffer.from)",
                        code: extractSnippet(source, node)
                    });
                }
            }
        }
    };
}

/**
 * Pattern: prototype_pollution
 * Detects assignment to __proto__ or constructor.prototype via computed property.
 */
function detectPrototypePollution(
    source: string,
    constants: ConstantMap,
    findings: DeepScanFinding[],
    filename: string
): Visitors {
    return {
        AssignmentExpression(node: acorn.Node) {
            const assign = node as any;
            const left = assign.left;

            if (left?.type !== "MemberExpression") return;

            // obj.__proto__ = ...
            if (
                !left.computed &&
                left.property?.type === "Identifier" &&
                left.property.name === "__proto__"
            ) {
                const loc = getLocation(node);
                findings.push({
                    file: filename,
                    line: loc.line,
                    column: loc.column,
                    severity: "medium",
                    pattern: "prototype_pollution",
                    description: "Direct assignment to __proto__",
                    code: extractSnippet(source, node)
                });
                return;
            }

            // obj[expr] = ... where expr resolves to "__proto__" or "prototype"
            if (left.computed) {
                const propValue = resolveToString(left.property, constants);
                if (propValue === "__proto__" || propValue === "prototype") {
                    const loc = getLocation(node);
                    findings.push({
                        file: filename,
                        line: loc.line,
                        column: loc.column,
                        severity: "medium",
                        pattern: "prototype_pollution",
                        description: `Computed property assignment resolves to "${propValue}"`,
                        code: extractSnippet(source, node)
                    });
                }
            }
        }
    };
}

/**
 * Pattern: timer_obfuscation
 * Detects setTimeout/setInterval with string first argument (implicit eval).
 */
function detectTimerObfuscation(
    source: string,
    _constants: ConstantMap,
    findings: DeepScanFinding[],
    filename: string
): Visitors {
    return {
        CallExpression(node: acorn.Node) {
            const call = node as any;
            const callee = call.callee;

            if (callee?.type !== "Identifier") return;
            if (callee.name !== "setTimeout" && callee.name !== "setInterval") return;
            if (!call.arguments || call.arguments.length === 0) return;

            const firstArg = call.arguments[0];
            // String literal as first arg = implicit eval
            if (firstArg.type === "Literal" && typeof firstArg.value === "string") {
                const loc = getLocation(node);
                findings.push({
                    file: filename,
                    line: loc.line,
                    column: loc.column,
                    severity: "high",
                    pattern: "timer_obfuscation",
                    description: `${callee.name}() with string argument (implicit eval)`,
                    code: extractSnippet(source, node)
                });
            }
            // Template literal with no expressions as first arg = also implicit eval
            if (firstArg.type === "TemplateLiteral" && firstArg.quasis?.length >= 1) {
                const loc = getLocation(node);
                findings.push({
                    file: filename,
                    line: loc.line,
                    column: loc.column,
                    severity: "high",
                    pattern: "timer_obfuscation",
                    description: `${callee.name}() with template literal string (implicit eval)`,
                    code: extractSnippet(source, node)
                });
            }
        }
    };
}

// ============================================================================
// File Parsing
// ============================================================================

/**
 * Attempt to strip TypeScript-specific syntax to make code parseable by acorn.
 * This is a lightweight approach - strips type annotations, interfaces, enums.
 * For complex TS files, parsing may fail gracefully.
 */
function stripTypeScriptSyntax(code: string): string {
    let stripped = code;
    // Remove type imports: import type { X } from '...'
    stripped = stripped.replace(/import\s+type\s+\{[^}]*\}\s+from\s+['"][^'"]*['"];?/g, "");
    // Remove type-only exports: export type { X }
    stripped = stripped.replace(/export\s+type\s+\{[^}]*\};?/g, "");
    // Remove interface declarations
    stripped = stripped.replace(/\binterface\s+\w+\s*(\{[^}]*\}|<[^>]*>\s*\{[^}]*\})/g, "");
    // Remove type aliases: type X = ...;
    stripped = stripped.replace(/\btype\s+\w+\s*(<[^>]*>)?\s*=\s*[^;]+;/g, "");
    // Remove type annotations after : in parameters and variables (basic)
    stripped = stripped.replace(/:\s*(string|number|boolean|void|any|never|unknown|null|undefined)\b/g, "");
    // Remove as casts
    stripped = stripped.replace(/\bas\s+\w+/g, "");
    return stripped;
}

interface ParseResult {
    ast: acorn.Node | null;
    error: string | null;
}

/**
 * Parse a file into an AST. Handles both JS and TS (via stripping).
 * Returns null AST on parse errors.
 */
function parseFile(code: string, filename: string): ParseResult {
    let source = code;

    // Strip TypeScript syntax for .ts files
    if (filename.endsWith(".ts") || filename.endsWith(".mts") || filename.endsWith(".cts")) {
        source = stripTypeScriptSyntax(code);
    }

    try {
        const ast = acorn.parse(source, {
            ecmaVersion: "latest",
            sourceType: "module",
            locations: true,
            // Allow import/export in any position
            allowImportExportEverywhere: true,
            // Be lenient about reserved words
            allowReserved: true,
        });
        return { ast, error: null };
    } catch (e) {
        // Try as script (CommonJS)
        try {
            const ast = acorn.parse(source, {
                ecmaVersion: "latest",
                sourceType: "script",
                locations: true,
                allowReserved: true,
            });
            return { ast, error: null };
        } catch (e2) {
            return {
                ast: null,
                error: `Parse error: ${(e2 as Error).message}`
            };
        }
    }
}

// ============================================================================
// Main Scanner Entry Point
// ============================================================================

/** All pattern detectors */
const PATTERN_DETECTORS = [
    detectObfuscatedEval,
    detectDynamicRequire,
    detectDynamicImport,
    detectComputedMemberExec,
    detectStringReconstruction,
    detectFetchWithEnv,
    detectEncodedPayloadExec,
    detectPrototypePollution,
    detectTimerObfuscation,
];

/**
 * Scan a single file's source code using AST analysis.
 */
export function deepScanFile(source: string, filename: string): { findings: DeepScanFinding[]; parseError: boolean } {
    const { ast, error } = parseFile(source, filename);

    if (!ast) {
        return { findings: [], parseError: true };
    }

    const findings: DeepScanFinding[] = [];
    const constants = collectConstants(ast);

    // Run all pattern detectors
    for (const detector of PATTERN_DETECTORS) {
        const visitors = detector(source, constants, findings, filename);
        walkAST(ast, visitors);
    }

    return { findings, parseError: false };
}

/**
 * Scan multiple files using AST deep analysis.
 * Main entry point for the deep scanner.
 * 
 * @param files Map of filename → source code
 * @returns Aggregated scan results
 */
export function deepScanFiles(files: Map<string, string>): DeepScanResult {
    const start = Date.now();
    const allFindings: DeepScanFinding[] = [];
    let filesAnalyzed = 0;
    let parseErrors = 0;

    for (const [filename, source] of files) {
        // Only scan JS/TS files
        const ext = filename.toLowerCase();
        const isJsTs = [".js", ".mjs", ".cjs", ".ts", ".mts", ".cts"].some(e => ext.endsWith(e));
        if (!isJsTs) continue;

        const { findings, parseError } = deepScanFile(source, filename);
        allFindings.push(...findings);
        filesAnalyzed++;
        if (parseError) parseErrors++;
    }

    // Deduplicate findings by file:line:pattern
    const unique = Array.from(
        new Map(
            allFindings.map(f => [`${f.file}:${f.line}:${f.pattern}`, f])
        ).values()
    );

    // Sort by severity
    const severityOrder = { critical: 0, high: 1, medium: 2 };
    unique.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

    return {
        findings: unique,
        filesAnalyzed,
        parseErrors,
        scanTimeMs: Date.now() - start
    };
}
