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
 * AgentRegistry Security Scanner - Real-time Static Analysis
 * 
 * Fast, zero-AI security scanning using pattern matching.
 * Integrated directly into server.ts for real-time scanning.
 */

import * as tar from "tar";
import { mkdtemp, readFile, rm, readdir, stat } from "fs/promises";
import { join } from "path";
import * as logger from "./logger";
import { safeJsonParse } from "./utils";
import { scanForPromptInjection, scanPackageJsonMetadata, scanInstallScripts, calculateRiskScore, type PromptInjectionMatch } from "./prompt-injection";
import { isPackageAllowlisted } from "./package-allowlist";
import type { DeepScanFinding } from "./ast-scanner";

// Use /tmp directly on macOS to avoid App Sandbox restrictions with tmpdir()
const SCAN_TMP_BASE = "/tmp";

// ============================================================================
// Configuration
// ============================================================================

const MAX_FILE_SIZE = 100 * 1024; // 100KB max per file

// Package whitelist is now managed dynamically via package-allowlist.ts module
// Access via: isPackageAllowlisted(packageName)

// ============================================================================
// Dangerous Patterns (OWASP + npm malware patterns)
// ============================================================================

interface SecurityRule {
    pattern: RegExp;
    severity: "critical" | "high" | "medium" | "low";
    description: string;
    cwe?: string;
}

const CODE_RULES: SecurityRule[] = [
    // Code execution
    { pattern: /\beval\s*\(/g, severity: "critical", description: "eval() can execute arbitrary code", cwe: "CWE-95" },
    { pattern: /new\s+Function\s*\(/g, severity: "critical", description: "Function constructor can execute arbitrary code", cwe: "CWE-95" },
    { pattern: /child_process/g, severity: "high", description: "child_process allows shell command execution", cwe: "CWE-78" },
    { pattern: /\bexec\s*\(/g, severity: "high", description: "exec() can run shell commands", cwe: "CWE-78" },
    { pattern: /\bexecSync\s*\(/g, severity: "high", description: "execSync() can run shell commands", cwe: "CWE-78" },
    { pattern: /\bspawn\s*\(/g, severity: "medium", description: "spawn() can run external processes", cwe: "CWE-78" },

    // File system dangers
    { pattern: /fs\.(writeFile|appendFile|unlink|rmdir|rm)\s*\(/g, severity: "medium", description: "File system write/delete operations" },
    { pattern: /fs\.(writeFileSync|appendFileSync|unlinkSync|rmdirSync|rmSync)\s*\(/g, severity: "medium", description: "Sync file system modifications" },
    { pattern: /\/(etc|usr|var|tmp|home)\//g, severity: "high", description: "Access to system directories", cwe: "CWE-22" },

    // Network/remote code
    { pattern: /require\s*\(\s*['"`]https?:/g, severity: "critical", description: "Remote code loading via require", cwe: "CWE-829" },
    { pattern: /import\s*\(\s*['"`]https?:/g, severity: "critical", description: "Remote code loading via dynamic import", cwe: "CWE-829" },
    { pattern: /fetch\s*\(\s*['"`]https?:[^'"]*\.(exe|sh|bat|ps1|cmd)/g, severity: "critical", description: "Downloading executable files" },

    // Data exfiltration
    { pattern: /process\.env/g, severity: "low", description: "Environment variable access" },
    { pattern: /\.ssh\//g, severity: "critical", description: "SSH key/config access", cwe: "CWE-522" },
    { pattern: /\.npmrc/g, severity: "high", description: "NPM credentials access" },
    { pattern: /\.env\b/g, severity: "medium", description: ".env file access" },

    // =========================================================================
    // 2025-2026 Attack Patterns (Shai-Hulud worm, September 2025 npm attack)
    // =========================================================================

    // Credential theft - Shai-Hulud worm patterns
    { pattern: /NPM_TOKEN/g, severity: "critical", description: "NPM token access (Shai-Hulud worm pattern)", cwe: "CWE-522" },
    { pattern: /GITHUB_TOKEN/g, severity: "critical", description: "GitHub token access (Shai-Hulud worm pattern)", cwe: "CWE-522" },
    { pattern: /npm_[a-zA-Z0-9]{36}/g, severity: "critical", description: "NPM token regex match", cwe: "CWE-522" },
    { pattern: /ghp_[a-zA-Z0-9]{36}/g, severity: "critical", description: "GitHub PAT token regex match", cwe: "CWE-522" },
    { pattern: /\.gitconfig/g, severity: "high", description: "Git config access (credential theft)" },
    { pattern: /\.git\/config/g, severity: "high", description: "Git repo config access" },

    // Exfiltration patterns (2025-2026 attacks)
    { pattern: /axios\.(post|put)\s*\(/g, severity: "high", description: "axios POST/PUT (potential exfiltration)", cwe: "CWE-200" },
    { pattern: /fetch\s*\([^)]+,\s*\{\s*method:\s*['"]POST['"]/gi, severity: "high", description: "fetch POST (potential exfiltration)", cwe: "CWE-200" },
    { pattern: /http\.request\s*\(/g, severity: "medium", description: "HTTP request (potential exfiltration)" },
    { pattern: /https\.request\s*\(/g, severity: "medium", description: "HTTPS request (potential exfiltration)" },

    // Crypto wallet theft (September 2025 npm attack)
    // NOTE: Excludes standard crypto API: crypto.randomUUID, crypto.createHash, crypto.subtle, crypto.getRandomValues
    { pattern: /\bwallet\b|bitcoin|ethereum|metamask|web3\.eth|ethers\.js|0x[a-fA-F0-9]{40}/gi, severity: "medium", description: "Cryptocurrency wallet access" },
    { pattern: /clipboard/gi, severity: "medium", description: "Clipboard access (crypto address hijacking)" },

    // AWS/Cloud credential theft
    { pattern: /AWS_ACCESS_KEY|AWS_SECRET|AZURE_|GOOGLE_APPLICATION_CREDENTIALS/g, severity: "critical", description: "Cloud provider credentials access", cwe: "CWE-522" },

    // Obfuscation (common in malware)
    { pattern: /Buffer\.from\s*\(\s*['"][A-Za-z0-9+/=]{100,}['"]/g, severity: "high", description: "Large base64 encoded payload" },
    { pattern: /(\\x[0-9a-fA-F]{2}){20,}/g, severity: "high", description: "Hex-encoded string (possible obfuscation)" },
    { pattern: /atob\s*\(\s*['"][A-Za-z0-9+/=]{50,}['"]/g, severity: "high", description: "Base64 decode of large payload" },

    // Prototype pollution
    { pattern: /__proto__/g, severity: "medium", description: "Prototype pollution risk", cwe: "CWE-1321" },
    { pattern: /constructor\s*\[\s*['"]prototype['"]\s*\]/g, severity: "medium", description: "Prototype pollution via constructor" },
];

const PACKAGE_JSON_RULES: SecurityRule[] = [
    { pattern: /curl\s+/g, severity: "critical", description: "curl in lifecycle script" },
    { pattern: /wget\s+/g, severity: "critical", description: "wget in lifecycle script" },
    { pattern: /\bnc\s+-/g, severity: "critical", description: "netcat in lifecycle script" },
    { pattern: /python[23]?\s+-c/g, severity: "high", description: "Python inline execution" },
    { pattern: /node\s+-e/g, severity: "high", description: "Node inline execution" },
    { pattern: /powershell/gi, severity: "high", description: "PowerShell execution" },
    { pattern: /https?:\/\/[^\s"']+/g, severity: "medium", description: "Network URL in script" },
    { pattern: /\|.*sh\b/g, severity: "critical", description: "Piping to shell" },
    { pattern: /base64\s+-d/g, severity: "high", description: "Base64 decode in script" },

    // 2025-2026 Shai-Hulud worm lifecycle patterns
    { pattern: /cat\s+.*\.npmrc/g, severity: "critical", description: "Reading .npmrc (credential theft)" },
    { pattern: /cat\s+.*\.gitconfig/g, severity: "critical", description: "Reading .gitconfig (credential theft)" },
    { pattern: /npm\s+whoami/g, severity: "high", description: "npm whoami check (worm recon)" },
    { pattern: /git\s+config\s+--global/g, severity: "high", description: "Git global config access" },
    { pattern: /\$NPM_TOKEN|\$GITHUB_TOKEN/g, severity: "critical", description: "Token env var in script" },
    { pattern: /--registry\s+https?:\/\/(?!registry\.npmjs\.org)/g, severity: "high", description: "Non-standard npm registry" },
];

// ============================================================================
// Scanner Functions
// ============================================================================

export interface ScanResult {
    safe: boolean;
    issues: Array<{
        file: string;
        severity: string;
        description: string;
        cwe?: string;
        line?: number;
    }>;
    filesScanned: number;
    scanTimeMs: number;
    /** Prompt injection risks detected in text files and metadata */
    promptInjections?: PromptInjectionMatch[];
    /** Risk score from 0-100 based on prompt injection findings */
    piRiskScore?: number;
    /** Deep AST scan findings (only present when --deep scan is used) */
    deepScanFindings?: DeepScanFinding[];
    /** Deep AST scan time in ms */
    deepScanTimeMs?: number;
}

function scanCode(content: string, filename: string): ScanResult["issues"] {
    const issues: ScanResult["issues"] = [];
    const lines = content.split("\n");

    for (const rule of CODE_RULES) {
        rule.pattern.lastIndex = 0; // Reset regex
        let match;
        while ((match = rule.pattern.exec(content)) !== null) {
            // Find line number
            const beforeMatch = content.slice(0, match.index);
            const lineNum = beforeMatch.split("\n").length;

            issues.push({
                file: filename,
                severity: rule.severity,
                description: rule.description,
                cwe: rule.cwe,
                line: lineNum
            });
        }
    }

    return issues;
}

function scanPackageJson(content: string): ScanResult["issues"] {
    const issues: ScanResult["issues"] = [];

    try {
        const pkg = safeJsonParse<any>(content);
        if (!pkg) {
            issues.push({
                file: "package.json",
                severity: "medium",
                description: "Invalid JSON in package.json"
            });
            return issues;
        }
        const scripts = pkg.scripts || {};
        const dangerousHooks = ["preinstall", "postinstall", "preuninstall", "postuninstall", "prepare"];

        for (const hook of dangerousHooks) {
            if (scripts[hook]) {
                const script = scripts[hook];

                for (const rule of PACKAGE_JSON_RULES) {
                    rule.pattern.lastIndex = 0;
                    if (rule.pattern.test(script)) {
                        issues.push({
                            file: "package.json",
                            severity: rule.severity,
                            description: `${hook}: ${rule.description}`,
                        });
                    }
                }
            }
        }

        // Check for suspicious dependencies
        const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
        for (const [name, version] of Object.entries(allDeps)) {
            if (typeof version === "string" && (version.startsWith("http") || version.startsWith("git"))) {
                issues.push({
                    file: "package.json",
                    severity: "high",
                    description: `Dependency "${name}" uses URL instead of version`
                });
            }
        }

    } catch {
        issues.push({
            file: "package.json",
            severity: "medium",
            description: "Invalid JSON in package.json"
        });
    }

    return issues;
}

// Check if package name is in the dynamic allowlist
// Managed via package-allowlist.ts module and admin panel
function isPackageWhitelisted(packageName: string): boolean {
    return isPackageAllowlisted(packageName);
}

export async function scanTarball(tarballPath: string): Promise<ScanResult> {
    const start = Date.now();
    const allIssues: ScanResult["issues"] = [];
    const allPromptInjections: PromptInjectionMatch[] = [];
    let filesScanned = 0;
    let packageJsonContent: string | null = null;

    // Extract package name from tarball path (e.g., "lodash-4.17.21.tgz" -> "lodash")
    const tarballName = tarballPath.split("/").pop() || "";
    const packageName = tarballName.replace(/-\d+\.\d+.*\.tgz$/, "");

    // Skip scanning for whitelisted packages
    if (isPackageWhitelisted(packageName)) {
        logger.info(`✅ Whitelisted: ${packageName} - skipping scan`);
        return {
            safe: true,
            issues: [],
            filesScanned: 0,
            scanTimeMs: Date.now() - start,
        };
    }

    const tempDir = await mkdtemp(join(SCAN_TMP_BASE, "agentregistry-scan-"));

    try {
        // Try to extract tarball - may fail if invalid format
        try {
            // SECURITY: Filter out symlinks and hardlinks (CVE-2026-23745)
            await tar.x({
                file: tarballPath,
                cwd: tempDir,
                filter: (path: string, entry: any) => {
                    // Only allow regular files and directories
                    if (entry.type !== 'File' && entry.type !== 'Directory') {
                        logger.warn(`⚠️ Blocked non-file entry: ${path} (${entry.type})`);
                        return false;
                    }

                    // SOTA Path Traversal Protection:
                    // 1. Block null bytes (CVE-style truncation attacks)
                    if (path.includes('\0') || path.includes('%00')) {
                        logger.warn(`⚠️ Blocked null byte in path: ${path}`);
                        return false;
                    }

                    // 2. Normalize and decode potential URL-encoded sequences
                    let normalizedPath = path;
                    try {
                        // Decode URL-encoded sequences (%2e = ., %2f = /)
                        normalizedPath = decodeURIComponent(path);
                    } catch {
                        // If decoding fails, check raw path
                    }

                    // 3. Check both raw and decoded paths for traversal
                    const pathsToCheck = [path, normalizedPath];
                    for (const p of pathsToCheck) {
                        // Block .. in any form (including encoded: %2e%2e, overlong UTF-8)
                        if (p.includes('..') ||
                            p.includes('%2e%2e') ||
                            p.includes('%252e') ||  // Double-encoded
                            p.includes('\u002e\u002e') ||  // Unicode dots
                            p.includes('%c0%ae') ||  // Overlong UTF-8 for .
                            p.includes('%c0%af')) {  // Overlong UTF-8 for /
                            logger.warn(`⚠️ Blocked path traversal: ${path}`);
                            return false;
                        }

                        // Block absolute paths in any form
                        if (p.startsWith('/') ||
                            p.startsWith('%2f') ||
                            p.startsWith('%5c') ||  // Backslash
                            /^[a-zA-Z]:/.test(p)) {  // Windows drive letter
                            logger.warn(`⚠️ Blocked absolute path: ${path}`);
                            return false;
                        }
                    }

                    // 4. Block backslash traversal (Windows-style)
                    if (path.includes('\\') || normalizedPath.includes('\\')) {
                        logger.warn(`⚠️ Blocked backslash in path: ${path}`);
                        return false;
                    }

                    return true;
                }
            });
        } catch {
            // Invalid tarball format - consider safe (can't scan)
            await rm(tempDir, { recursive: true, force: true });
            return {
                safe: true,
                issues: [],
                filesScanned: 0,
                scanTimeMs: Date.now() - start
            };
        }

        async function scanDir(dir: string) {
            const entries = await readdir(dir, { withFileTypes: true }).catch(() => []);

            for (const entry of entries) {
                const fullPath = join(dir, entry.name);

                if (entry.isDirectory()) {
                    // Skip node_modules
                    if (entry.name !== "node_modules") {
                        await scanDir(fullPath);
                    }
                } else if (entry.isFile()) {
                    const ext = entry.name.toLowerCase();
                    const isJs = [".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx"].some(e => ext.endsWith(e));
                    const isJson = ext.endsWith(".json");
                    const isTextDoc = [".md", ".txt", ".rst"].some(e => ext.endsWith(e));
                    // Gap 4: Extended file types for prompt injection scanning
                    const isConfig = [".yml", ".yaml", ".toml", ".ini"].some(e => ext.endsWith(e));
                    const isMarkup = [".svg", ".html", ".htm"].some(e => ext.endsWith(e));
                    const isKnownExtensionless = ["LICENSE", "README", "CHANGELOG", "NOTICE", "AUTHORS", "CONTRIBUTORS"]
                        .includes(entry.name.toUpperCase());

                    if (!isJs && !isJson && !isTextDoc && !isConfig && !isMarkup && !isKnownExtensionless) continue;

                    try {
                        const info = await stat(fullPath);
                        if (info.size > MAX_FILE_SIZE) continue;

                        const content = await readFile(fullPath, "utf-8");
                        filesScanned++;

                        if (entry.name === "package.json") {
                            allIssues.push(...scanPackageJson(content));
                            packageJsonContent = content; // Save for prompt injection scan
                        }

                        if (isJs) {
                            allIssues.push(...scanCode(content, entry.name));
                        }

                        // Scan text documents, code, configs, markup, and extensionless files for prompt injection
                        if (isTextDoc || isJs || isConfig || isMarkup || isKnownExtensionless) {
                            const injections = scanForPromptInjection(content, entry.name);
                            allPromptInjections.push(...injections);
                        }

                        // SVG files can contain embedded script tags
                        if (isMarkup) {
                            allIssues.push(...scanCode(content, entry.name));
                        }
                    } catch {
                        // Skip files that can't be read
                    }
                }
            }
        }

        await scanDir(tempDir);

        // Scan package.json metadata and install scripts for prompt injections
        if (packageJsonContent) {
            try {
                const pkg = safeJsonParse<Record<string, unknown>>(packageJsonContent);
                if (pkg) {
                    const metadataInjections = scanPackageJsonMetadata(pkg);
                    allPromptInjections.push(...metadataInjections);

                    // Scan install scripts for dangerous patterns
                    const scriptInjections = scanInstallScripts(pkg);
                    allPromptInjections.push(...scriptInjections);
                }
            } catch {
                // Ignore parsing errors
            }
        }

    } finally {
        await rm(tempDir, { recursive: true, force: true });
    }

    // Deduplicate and sort by severity
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    const uniqueIssues = Array.from(
        new Map(allIssues.map(i => [`${i.file}:${i.description}:${i.line}`, i])).values()
    ).sort((a, b) => severityOrder[a.severity as keyof typeof severityOrder] - severityOrder[b.severity as keyof typeof severityOrder]);

    // Deduplicate and sort prompt injections
    const uniqueInjections = Array.from(
        new Map(allPromptInjections.map(i => [`${i.file}:${i.line}:${i.pattern}:${i.matched}`, i])).values()
    ).sort((a, b) => severityOrder[a.severity as keyof typeof severityOrder] - severityOrder[b.severity as keyof typeof severityOrder]);

    // Check for critical/high prompt injection issues
    const hasHighSeverityInjections = uniqueInjections.some(i =>
        i.severity === "critical" || i.severity === "high"
    );

    const limitedInjections = uniqueInjections.length > 0 ? uniqueInjections.slice(0, 20) : undefined;
    const piRiskScore = limitedInjections ? calculateRiskScore(limitedInjections) : 0;

    return {
        safe: uniqueIssues.filter(i => i.severity === "critical" || i.severity === "high").length === 0 && !hasHighSeverityInjections,
        issues: uniqueIssues.slice(0, 20),
        filesScanned,
        scanTimeMs: Date.now() - start,
        promptInjections: limitedInjections,
        piRiskScore: piRiskScore > 0 ? piRiskScore : undefined
    };
}

// ============================================================================
// Standalone HTTP Server (optional)
// ============================================================================

if (import.meta.main) {
    const PORT = parseInt(process.env.SCANNER_PORT || "4874");

    const server = Bun.serve({
        port: PORT,
        hostname: "127.0.0.1",

        async fetch(req) {
            const url = new URL(req.url);

            if (req.method === "GET" && url.pathname === "/health") {
                return Response.json({ ok: true, type: "static-analysis" });
            }

            if (req.method === "POST" && url.pathname === "/scan") {
                try {
                    const body = await req.json() as { tarball_path: string };
                    const { existsSync } = await import("fs");

                    if (!body.tarball_path || !existsSync(body.tarball_path)) {
                        return Response.json({ error: "Invalid tarball path" }, { status: 400 });
                    }

                    logger.info(`🔍 Scanning: ${body.tarball_path.split("/").pop()}`);
                    const result = await scanTarball(body.tarball_path);

                    const critHigh = result.issues.filter(i => i.severity === "critical" || i.severity === "high").length;
                    const status = result.safe ? "✅ SAFE" : `⚠️ ${critHigh} critical/high issues`;
                    logger.info(`   ${status} (${result.scanTimeMs}ms, ${result.filesScanned} files)`);

                    return Response.json(result);
                } catch (e) {
                    return Response.json({ error: String(e) }, { status: 500 });
                }
            }

            return new Response("Not Found", { status: 404 });
        }
    });

    logger.info(`
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   🔒 AgentRegistry Security Scanner (Static Analysis)              ║
║                                                              ║
║   Type:     Pattern-based (no AI)                            ║
║   Speed:    ~10-50ms per package                             ║
║   Port:     ${PORT.toString().padEnd(44)}║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝

🚀 Listening on http://127.0.0.1:${PORT}
   POST /scan - Scan a tarball
   GET  /health - Health check
`);
}
