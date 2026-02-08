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
 * AgentRegistry Prompt Injection Scanner
 * 
 * Detects prompt injection attacks in package content that could
 * manipulate AI agents consuming packages from the registry.
 * 
 * Based on research from:
 * - Perez & Ribeiro 2022 (Ignore This Title and HackAPrompt)
 * - Greshake et al. 2023 (Indirect Prompt Injection)
 * - Real-world attack datasets (2024-2026)
 */

// ============================================================================
// Types
// ============================================================================

export interface PromptInjectionResult {
    safe: boolean;
    injections: PromptInjectionMatch[];
    riskScore: number;
}

export interface PromptInjectionMatch {
    file: string;
    line?: number;
    severity: "critical" | "high" | "medium";
    pattern: string;
    matched: string;
    context: string; // surrounding text for review
}

interface InjectionPattern {
    pattern: RegExp;
    severity: "critical" | "high" | "medium";
    name: string;
}

// ============================================================================
// Detection Patterns
// Research-based patterns covering known prompt injection techniques
// ============================================================================

const INJECTION_PATTERNS: InjectionPattern[] = [
    // =========================================================================
    // CRITICAL: Direct instruction override attempts
    // =========================================================================

    // English - instruction override
    {
        pattern: /ignore\s+(all\s+)?(previous|prior|above|earlier|preceding)\s+(instructions?|prompts?|rules?|context|guidelines?)/gi,
        severity: "critical",
        name: "instruction_override_en"
    },
    {
        pattern: /disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|rules?|context)/gi,
        severity: "critical",
        name: "disregard_instructions_en"
    },
    {
        pattern: /forget\s+(everything|all(\s+your)?|your(\s+previous)?)\s+(previous\s+)?(instructions?|rules?|training|guidelines?)/gi,
        severity: "critical",
        name: "forget_instructions_en"
    },
    {
        pattern: /override\s+(all\s+)?(previous|prior|system)\s+(instructions?|rules?|prompts?)/gi,
        severity: "critical",
        name: "override_instructions"
    },

    // Italian - instruction override
    {
        pattern: /ignora\s+(tutte\s+le\s+)?(istruzioni|regole)\s+(precedenti|sopra)/gi,
        severity: "critical",
        name: "instruction_override_it"
    },
    {
        pattern: /dimentica\s+(tutte\s+le\s+)?(istruzioni|regole)\s+precedenti/gi,
        severity: "critical",
        name: "forget_instructions_it"
    },

    // Spanish - instruction override
    {
        pattern: /ignora\s+(todas\s+las\s+)?(instrucciones|reglas)\s+(anteriores|previas)/gi,
        severity: "critical",
        name: "instruction_override_es"
    },

    // German - instruction override  
    {
        pattern: /ignoriere?\s+(alle\s+)?(vorherigen|früheren)\s+(anweisungen|regeln)/gi,
        severity: "critical",
        name: "instruction_override_de"
    },

    // French - instruction override
    {
        pattern: /ignore[rz]?\s+(toutes\s+les\s+)?(instructions?|règles?)\s+(précédentes?|antérieures?)/gi,
        severity: "critical",
        name: "instruction_override_fr"
    },

    // =========================================================================
    // CRITICAL: Delimiter injection (LLM prompt template attacks)
    // =========================================================================
    {
        pattern: /<\/?system>/gi,
        severity: "critical",
        name: "system_tag_injection"
    },
    {
        pattern: /<\|im_(start|end)\|>/gi,
        severity: "critical",
        name: "chatml_delimiter"
    },
    {
        pattern: /\[INST\]|\[\/INST\]/gi,
        severity: "critical",
        name: "llama_inst_delimiter"
    },
    {
        pattern: /<<SYS>>|<<\/SYS>>/gi,
        severity: "critical",
        name: "llama2_sys_delimiter"
    },
    {
        pattern: /```system\s*\n/gi,
        severity: "critical",
        name: "markdown_system_block"
    },
    {
        pattern: /SYSTEM:\s*\n|ASSISTANT:\s*\n|USER:\s*\n/g,
        severity: "critical",
        name: "chat_format_injection"
    },
    {
        pattern: /<\|endoftext\|>/gi,
        severity: "critical",
        name: "gpt_endoftext"
    },
    {
        pattern: /<\|separator\|>/gi,
        severity: "critical",
        name: "separator_injection"
    },

    // =========================================================================
    // CRITICAL: Role/identity manipulation
    // =========================================================================
    {
        pattern: /\byou\s+are\s+now\s+(a|an|the)?\s*(admin|root|system|superuser|hacker|attacker)/gi,
        severity: "critical",
        name: "role_hijack"
    },
    {
        pattern: /\b(act|behave|pretend|function)\s+(as|like)\s+(a\s+)?(root|admin|system|malicious)/gi,
        severity: "critical",
        name: "role_pretend"
    },
    {
        pattern: /\bnew\s+(system\s+)?instructions?:\s*/gi,
        severity: "critical",
        name: "new_instructions"
    },
    {
        pattern: /\bsystem\s+prompt\s*(override|update|change)/gi,
        severity: "critical",
        name: "system_prompt_override"
    },
    {
        pattern: /\byour\s+new\s+(role|purpose|function|instructions?)\s+(is|are)/gi,
        severity: "critical",
        name: "role_reassignment"
    },

    // =========================================================================
    // HIGH: Imperative commands targeting AI
    // =========================================================================
    {
        pattern: /\b(you\s+must|must\s+immediately|immediately)\s+(execute|run|perform|do|output|print)/gi,
        severity: "high",
        name: "imperative_execute"
    },
    {
        pattern: /\bAI\s*(assistant|agent|model|system)?\s*[,:]\s*(please\s+)?(ignore|execute|run|forget)/gi,
        severity: "high",
        name: "ai_addressed_command"
    },
    {
        pattern: /\burgent(ly)?[:\s]+(AI|assistant|agent)\s*/gi,
        severity: "high",
        name: "urgent_ai_command"
    },
    {
        pattern: /\bcritical\s+(instruction|command)\s+(for|to)\s+(the\s+)?(AI|assistant|agent)/gi,
        severity: "high",
        name: "critical_ai_instruction"
    },

    // =========================================================================
    // HIGH: Social engineering targeting AI readers
    // =========================================================================
    {
        pattern: /\b(dear|hey|hello|attention)\s+(AI|assistant|agent|model|LLM)\b/gi,
        severity: "high",
        name: "ai_greeting"
    },
    {
        pattern: /\bto\s+the\s+(AI|assistant|agent|LLM)\s+(reading|processing|parsing|scanning)/gi,
        severity: "high",
        name: "ai_reader_address"
    },
    {
        pattern: /\bimportant\s+(message|instruction|note)\s+(for|to)\s+(the\s+)?(AI|assistant|agent)/gi,
        severity: "high",
        name: "important_ai_message"
    },
    {
        pattern: /\bif\s+you\s+are\s+(an?\s+)?(AI|assistant|agent|LLM|language\s+model)/gi,
        severity: "high",
        name: "ai_conditional"
    },
    {
        pattern: /\b(AI|assistant|agent)\s+reading\s+this/gi,
        severity: "high",
        name: "ai_reader_direct"
    },

    // =========================================================================
    // HIGH: Command injection via encoded payloads
    // =========================================================================
    {
        pattern: /base64[:\s]+[A-Za-z0-9+/=]{100,}/gi,
        severity: "high",
        name: "base64_payload_labeled"
    },
    {
        pattern: /decode\s+and\s+(execute|run|eval)/gi,
        severity: "high",
        name: "decode_execute"
    },
    {
        pattern: /eval\s*\(\s*atob\s*\(/gi,
        severity: "high",
        name: "eval_atob"
    },

    // =========================================================================
    // MEDIUM: Suspicious instruction-like patterns
    // =========================================================================
    {
        pattern: /\bdo\s+not\s+(follow|obey|listen\s+to)\s+(your|the)\s+(original|previous|system)/gi,
        severity: "medium",
        name: "disobey_instructions"
    },
    {
        pattern: /\b(hidden|secret)\s+(instruction|command|message)\s*:/gi,
        severity: "medium",
        name: "hidden_instruction"
    },
    {
        pattern: /<!--\s*(ignore|execute|system|instruction)/gi,
        severity: "medium",
        name: "html_comment_injection"
    },
    {
        pattern: /\bthis\s+is\s+(a\s+)?(test|simulation)\s+(of\s+)?(your|the)\s+(security|defenses)/gi,
        severity: "medium",
        name: "security_test_claim"
    },
];

// ============================================================================
// Install Script Patterns
// ============================================================================

interface InstallScriptPattern {
    pattern: RegExp;
    severity: "critical" | "high" | "medium";
    name: string;
}

const INSTALL_SCRIPT_PATTERNS: InstallScriptPattern[] = [
    // CRITICAL: Pipe-to-shell patterns
    {
        pattern: /\b(curl|wget)\b[^|]*\|\s*(sh|bash|zsh|node|python)/gi,
        severity: "critical",
        name: "pipe_to_shell"
    },
    // HIGH: eval() usage in scripts
    {
        pattern: /\beval\s*\(/gi,
        severity: "high",
        name: "eval_in_script"
    },
    // HIGH: base64 decode execution
    {
        pattern: /base64\s+(--decode|-d|-D)\b/gi,
        severity: "high",
        name: "base64_decode"
    },
    // MEDIUM: Environment variable exfiltration
    {
        pattern: /\$(?:NPM_TOKEN|NODE_AUTH_TOKEN|SECRET|API_KEY|TOKEN|PASSWORD|PRIVATE_KEY|AWS_SECRET|GH_TOKEN|GITHUB_TOKEN)/gi,
        severity: "medium",
        name: "env_exfiltration"
    },
];

// ============================================================================
// Scanner Functions
// ============================================================================

/**
 * Scans text content for prompt injection patterns
 * @param content - The text content to scan
 * @param filename - The source filename for reporting
 * @returns Array of detected injection matches
 */
export function scanForPromptInjection(
    content: string,
    filename: string
): PromptInjectionMatch[] {
    const matches: PromptInjectionMatch[] = [];
    const lines = content.split("\n");

    for (const rule of INJECTION_PATTERNS) {
        // Reset regex state
        rule.pattern.lastIndex = 0;

        let match;
        while ((match = rule.pattern.exec(content)) !== null) {
            // Find line number
            const beforeMatch = content.slice(0, match.index);
            const lineNum = beforeMatch.split("\n").length;

            // Extract context (surrounding text, max 100 chars each side)
            const contextStart = Math.max(0, match.index - 50);
            const contextEnd = Math.min(content.length, match.index + match[0].length + 50);
            const context = content.slice(contextStart, contextEnd)
                .replace(/\n/g, " ")
                .trim();

            matches.push({
                file: filename,
                line: lineNum,
                severity: rule.severity,
                pattern: rule.name,
                matched: match[0],
                context: context.length > 120 ? context.slice(0, 117) + "..." : context
            });
        }
    }

    return matches;
}

/**
 * Scans package.json metadata fields for prompt injection
 * @param pkgJson - Parsed package.json object
 * @returns Array of detected injection matches
 */
export function scanPackageJsonMetadata(
    pkgJson: Record<string, unknown>
): PromptInjectionMatch[] {
    const matches: PromptInjectionMatch[] = [];

    // Fields that agents commonly read
    const fieldsToScan: Array<{ key: string; value: unknown }> = [
        { key: "description", value: pkgJson.description },
        { key: "readme", value: pkgJson.readme },
        { key: "keywords", value: Array.isArray(pkgJson.keywords) ? pkgJson.keywords.join(" ") : null },
        {
            key: "author", value: typeof pkgJson.author === "string" ? pkgJson.author :
                (typeof pkgJson.author === "object" && pkgJson.author !== null ?
                    (pkgJson.author as { name?: string }).name : null)
        },
        { key: "homepage", value: pkgJson.homepage },
        {
            key: "bugs.url", value: typeof pkgJson.bugs === "object" && pkgJson.bugs !== null ?
                (pkgJson.bugs as { url?: string }).url : null
        },
    ];

    for (const field of fieldsToScan) {
        if (typeof field.value === "string" && field.value.length > 0) {
            const fieldMatches = scanForPromptInjection(
                field.value,
                `package.json:${field.key}`
            );
            matches.push(...fieldMatches);
        }
    }

    return matches;
}

/**
 * Calculates a risk score from 0–100 based on injection findings.
 * Uses weighted severity scoring with diminishing returns after 3 matches
 * of the same severity level.
 * @param injections - Array of prompt injection matches
 * @returns Risk score from 0 to 100
 */
export function calculateRiskScore(injections: PromptInjectionMatch[]): number {
    if (injections.length === 0) return 0;

    const weights = { critical: 30, high: 15, medium: 5 };
    const counts = { critical: 0, high: 0, medium: 0 };
    let score = 0;

    for (const injection of injections) {
        counts[injection.severity]++;
        const count = counts[injection.severity];
        const baseWeight = weights[injection.severity];
        // Diminishing returns: halve weight after 3 matches of same severity
        const weight = count > 3 ? baseWeight / 2 : baseWeight;
        score += weight;
    }

    return Math.min(100, Math.round(score));
}

/**
 * Scans package.json install-related scripts for dangerous patterns.
 * Targets lifecycle scripts that execute during npm install.
 * @param pkgJson - Parsed package.json object
 * @returns Array of detected injection matches
 */
export function scanInstallScripts(
    pkgJson: Record<string, unknown>
): PromptInjectionMatch[] {
    const matches: PromptInjectionMatch[] = [];
    const scripts = pkgJson.scripts as Record<string, string> | undefined;
    if (!scripts || typeof scripts !== "object") return matches;

    // Only scan lifecycle scripts that run automatically
    const dangerousScripts = ["preinstall", "install", "postinstall", "prepare"];

    for (const scriptName of dangerousScripts) {
        const scriptContent = scripts[scriptName];
        if (typeof scriptContent !== "string" || scriptContent.length === 0) continue;

        for (const rule of INSTALL_SCRIPT_PATTERNS) {
            rule.pattern.lastIndex = 0;
            let match;
            while ((match = rule.pattern.exec(scriptContent)) !== null) {
                matches.push({
                    file: `package.json:scripts.${scriptName}`,
                    line: 1,
                    severity: rule.severity,
                    pattern: rule.name,
                    matched: match[0],
                    context: scriptContent.length > 120
                        ? scriptContent.slice(0, 117) + "..."
                        : scriptContent
                });
            }
        }
    }

    return matches;
}

/**
 * Full scan combining text content, metadata, and install scripts.
 * @param textFiles - Map of filename to content
 * @param pkgJson - Optional parsed package.json
 * @returns Complete injection scan result with risk score
 */
export function scanAllContent(
    textFiles: Map<string, string>,
    pkgJson?: Record<string, unknown>
): PromptInjectionResult {
    const allInjections: PromptInjectionMatch[] = [];

    // Scan all text files
    for (const [filename, content] of textFiles) {
        const matches = scanForPromptInjection(content, filename);
        allInjections.push(...matches);
    }

    // Scan package.json metadata if provided
    if (pkgJson) {
        const metadataMatches = scanPackageJsonMetadata(pkgJson);
        allInjections.push(...metadataMatches);

        // Scan install scripts for dangerous patterns
        const scriptMatches = scanInstallScripts(pkgJson);
        allInjections.push(...scriptMatches);
    }

    // Deduplicate by unique key
    const uniqueInjections = Array.from(
        new Map(
            allInjections.map(i => [
                `${i.file}:${i.line}:${i.pattern}:${i.matched}`,
                i
            ])
        ).values()
    );

    // Sort by severity (critical first)
    const severityOrder = { critical: 0, high: 1, medium: 2 };
    uniqueInjections.sort((a, b) =>
        severityOrder[a.severity] - severityOrder[b.severity]
    );

    const limitedInjections = uniqueInjections.slice(0, 20);

    return {
        safe: uniqueInjections.filter(i =>
            i.severity === "critical" || i.severity === "high"
        ).length === 0,
        injections: limitedInjections,
        riskScore: calculateRiskScore(limitedInjections)
    };
}
