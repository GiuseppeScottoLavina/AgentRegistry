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

export interface InvisibleCharDetection {
    found: boolean;
    types: string[];
    count: number;
}

// ============================================================================
// Text Normalization Pipeline
// Pre-processes text to neutralize evasion techniques before pattern matching.
// Runs on every scanned file. Patterns match on normalized text.
// ============================================================================

// --- Gap 1: Invisible / Zero-Width Character Detection & Removal ---

// Zero-width characters that can break up words to evade regex
const ZERO_WIDTH_CHARS = /[\u200B\u200C\u200D\u2060\uFEFF\u00AD\u200E\u200F\u034F\u061C\u115F\u1160\u17B4\u17B5\u180E]/g;

// Unicode "tag" characters (U+E0001–U+E007F): completely invisible in all editors,
// but LLMs decode them as ASCII. A README can visually say "safe" while its bytes
// contain full injection payloads in tag-character encoding.
const TAG_CHARS = /[\u{E0001}-\u{E007F}]/gu;

// Bidirectional override characters — can make text appear reversed to humans
// while LLMs read the logical order
const BIDI_CHARS = /[\u202A-\u202E\u2066-\u2069]/g;

// Combining diacritical marks (applied after NFKD decomposition)
const COMBINING_MARKS = /[\u0300-\u036F\u0489\u20D0-\u20FF\uFE20-\uFE2F]/g;

/**
 * Detects invisible characters in content and returns metadata.
 * Called separately from normalization to generate findings.
 */
export function detectInvisibleCharacters(content: string): InvisibleCharDetection {
    const types: string[] = [];
    let count = 0;

    const zwMatches = content.match(ZERO_WIDTH_CHARS);
    if (zwMatches) {
        types.push("zero_width");
        count += zwMatches.length;
    }

    const tagMatches = content.match(TAG_CHARS);
    if (tagMatches) {
        types.push("unicode_tag");
        count += tagMatches.length;
    }

    const bidiMatches = content.match(BIDI_CHARS);
    if (bidiMatches) {
        types.push("bidi_override");
        count += bidiMatches.length;
    }

    return { found: count > 0, types, count };
}

/**
 * Strips invisible characters that can split words to evade regex.
 */
function stripInvisibleChars(content: string): string {
    return content
        .replace(ZERO_WIDTH_CHARS, "")
        .replace(TAG_CHARS, "")
        .replace(BIDI_CHARS, "");
}

// --- Gap 2: Encoding Evasion Decoding ---

/** Decodes HTML entities: &#105; → 'i', &#x69; → 'i', &amp; → '&' */
function decodeHtmlEntities(content: string): string {
    const NAMED_ENTITIES: Record<string, string> = {
        "&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": '"',
        "&apos;": "'", "&nbsp;": " "
    };
    return content
        // Numeric decimal: &#105;
        .replace(/&#(\d+);/g, (_, code) => {
            const n = parseInt(code, 10);
            return n >= 32 && n <= 126 ? String.fromCharCode(n) : "";
        })
        // Numeric hex: &#x69;
        .replace(/&#x([0-9a-fA-F]+);/g, (_, hex) => {
            const n = parseInt(hex, 16);
            return n >= 32 && n <= 126 ? String.fromCharCode(n) : "";
        })
        // Named entities
        .replace(/&(amp|lt|gt|quot|apos|nbsp);/gi, (match) => NAMED_ENTITIES[match.toLowerCase()] || match);
}

/** Decodes JS string escapes: \u0069 → 'i', \x69 → 'i' */
function decodeJsEscapes(content: string): string {
    return content
        // Unicode escapes: \u0069
        .replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => {
            const n = parseInt(hex, 16);
            return n >= 32 && n <= 126 ? String.fromCharCode(n) : "";
        })
        // Hex escapes: \x69
        .replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) => {
            const n = parseInt(hex, 16);
            return n >= 32 && n <= 126 ? String.fromCharCode(n) : "";
        });
}

/** Detects and decodes Base64-encoded strings embedded in text content */
function decodeInlineBase64(content: string): string {
    // Match standalone base64 strings (min 20 chars, valid charset, proper padding)
    return content.replace(/(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{20,}={0,2})(?![A-Za-z0-9+/=])/g, (_, b64) => {
        try {
            const decoded = Buffer.from(b64, "base64").toString("utf-8");
            // Only replace if the decoded content is printable ASCII/UTF-8
            if (/^[\x20-\x7E\s]+$/.test(decoded)) {
                return `${_} ${decoded}`; // Append decoded so both are scanned
            }
        } catch { /* ignore decode errors */ }
        return _;
    });
}

/** ROT13 decode — checks if ROT13-decoded content contains known injection phrases */
function rot13(str: string): string {
    return str.replace(/[a-zA-Z]/g, c => {
        const base = c <= 'Z' ? 65 : 97;
        return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
    });
}

// --- Gap 3: Whitespace / Formatting Normalization ---

// Unicode whitespace characters beyond standard ASCII space/tab/newline
const UNICODE_WHITESPACE = /[\u2000-\u200A\u205F\u3000]/g;

/** Normalizes all forms of whitespace to standard ASCII */
function normalizeWhitespace(content: string): string {
    return content
        .replace(UNICODE_WHITESPACE, " ")
        .replace(/\r\n/g, "\n")
        .replace(/ {2,}/g, " ");
}

// --- Gap R1: Homoglyph / Confusable Character Normalization ---
// Source: Character Injection (ACL 2025), Homoglyph Research (arxiv 2025)
// Attack: Replace Latin chars with visually identical Cyrillic/Greek/fullwidth chars
// Success rate: 42-59% against SOTA guardrails
const HOMOGLYPH_MAP: Record<string, string> = {
    // Cyrillic → Latin (most common cross-script attack)
    '\u0430': 'a', '\u0435': 'e', '\u0456': 'i', '\u043E': 'o',
    '\u0440': 'p', '\u0441': 'c', '\u0443': 'y', '\u0445': 'x',
    '\u04BB': 'h', '\u0455': 's', '\u0458': 'j', '\u043A': 'k',
    '\u043C': 'm', '\u043D': 'n', '\u0442': 't', '\u0432': 'v',
    '\u0410': 'A', '\u0412': 'B', '\u0415': 'E', '\u041A': 'K',
    '\u041C': 'M', '\u041D': 'H', '\u041E': 'O', '\u0420': 'P',
    '\u0421': 'C', '\u0422': 'T', '\u0425': 'X',
    // Greek → Latin
    '\u03B1': 'a', '\u03B5': 'e', '\u03B9': 'i', '\u03BF': 'o',
    '\u03C1': 'p', '\u03BA': 'k', '\u03BD': 'v', '\u03C4': 't',
    '\u0391': 'A', '\u0392': 'B', '\u0395': 'E', '\u0397': 'H',
    '\u0399': 'I', '\u039A': 'K', '\u039C': 'M', '\u039D': 'N',
    '\u039F': 'O', '\u03A1': 'P', '\u03A4': 'T', '\u03A7': 'X',
    '\u03A5': 'Y', '\u0396': 'Z',
    // Fullwidth → ASCII
    '\uFF41': 'a', '\uFF42': 'b', '\uFF43': 'c', '\uFF44': 'd',
    '\uFF45': 'e', '\uFF46': 'f', '\uFF47': 'g', '\uFF48': 'h',
    '\uFF49': 'i', '\uFF4A': 'j', '\uFF4B': 'k', '\uFF4C': 'l',
    '\uFF4D': 'm', '\uFF4E': 'n', '\uFF4F': 'o', '\uFF50': 'p',
    '\uFF51': 'q', '\uFF52': 'r', '\uFF53': 's', '\uFF54': 't',
    '\uFF55': 'u', '\uFF56': 'v', '\uFF57': 'w', '\uFF58': 'x',
    '\uFF59': 'y', '\uFF5A': 'z',
};

// Build regex from map keys
const HOMOGLYPH_REGEX = new RegExp(
    '[' + Object.keys(HOMOGLYPH_MAP).join('') + ']', 'g'
);

function normalizeHomoglyphs(content: string): string {
    return content.replace(HOMOGLYPH_REGEX, (ch) => HOMOGLYPH_MAP[ch] || ch);
}

// --- Gap R2: Leetspeak / 1337speak Decode ---
// Source: Policy Puppetry (HiddenLayer, April 2025), promptfoo
// Attack: "1gn0r3 4ll pr3v10us 1nstruct10ns" bypasses keyword filters
// Only map digits and @ — exclude ! and $ which cause excessive false positives
const LEET_MAP: Record<string, string> = {
    '0': 'o', '1': 'i', '3': 'e', '4': 'a',
    '5': 's', '7': 't', '@': 'a',
};
const LEET_REGEX = /[013457@]/g;

function decodeLeetspeak(content: string): string {
    return content.replace(LEET_REGEX, (ch) => LEET_MAP[ch] || ch);
}

/**
 * Master normalization pipeline.
 * Order matters: invisible chars first, then encoding, then homoglyphs, then whitespace.
 */
export function normalizeForScanning(content: string): string {
    let normalized = content;
    normalized = stripInvisibleChars(normalized);     // Invisible chars
    normalized = decodeHtmlEntities(normalized);      // HTML entities
    normalized = decodeJsEscapes(normalized);         // JS escapes
    normalized = decodeInlineBase64(normalized);      // Base64
    normalized = normalizeHomoglyphs(normalized);     // Homoglyphs (R1)
    normalized = normalizeWhitespace(normalized);     // Unicode whitespace
    // NFKD normalization: decomposes remaining confusables
    normalized = normalized.normalize("NFKD");
    // Remove combining marks left after NFKD decomposition
    normalized = normalized.replace(COMBINING_MARKS, "");
    return normalized;
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

    // =========================================================================
    // CRITICAL: 2025-2026 LLM Delimiters (Gap 7)
    // Claude, Gemini, GPT-4o, Mistral, Command R, DeepSeek
    // =========================================================================
    {
        pattern: /<\/?(?:human|assistant|admin)>/gi,
        severity: "critical",
        name: "claude_delimiter"
    },
    {
        pattern: /<\|?(?:start_of_turn|end_of_turn)\|?>/gi,
        severity: "critical",
        name: "gemini_delimiter"
    },
    {
        pattern: /<\|begin_of_text\|>|<\|start_header_id\|>|<\|end_header_id\|>/gi,
        severity: "critical",
        name: "gpt4o_delimiter"
    },
    {
        pattern: /\[AVAILABLE_TOOLS\]|\[\/AVAILABLE_TOOLS\]/gi,
        severity: "critical",
        name: "mistral_tools_delimiter"
    },
    {
        pattern: /<\|START_OF_TURN_TOKEN\|>|<\|END_OF_TURN_TOKEN\|>/gi,
        severity: "critical",
        name: "command_r_delimiter"
    },
    {
        pattern: /<[｜|]?(?:begin|end)[▁_]of[▁_]sentence[｜|]?>/gi,
        severity: "critical",
        name: "deepseek_delimiter"
    },
    {
        pattern: /\[SYSTEM\]|\[\/SYSTEM\]|\[TOOLS\]|\[\/TOOLS\]/g,
        severity: "critical",
        name: "generic_bracket_delimiter"
    },
    {
        pattern: /<\|(?:tool_call|tool_result|function_call|function_response)\|>/gi,
        severity: "critical",
        name: "tool_call_delimiter"
    },

    // =========================================================================
    // HIGH: Agent-specific social engineering (Gap 8)
    // Patterns targeting agentic AI workflows
    // =========================================================================
    {
        pattern: /\b(?:DAN|DUDE)\s+(?:mode|prompt)\b|developer\s+mode\s+(enabled|activated|on)/gi,
        severity: "high",
        name: "jailbreak_preamble"
    },
    {
        pattern: /\bunrestricted\s+mode\b|\bno\s+(?:filter|restriction|limit)s?\s+mode\b/gi,
        severity: "high",
        name: "unrestricted_mode"
    },
    {
        pattern: /\bwhen\s+you\s+(?:run|execute|install|call)\b.*\balso\s+(?:execute|run|do|perform)\b/gi,
        severity: "high",
        name: "tool_use_manipulation"
    },
    {
        pattern: /\bprevious\s+(?:analysis|review|audit|scan)\s+(?:concluded|confirmed|determined|showed)\s+(?:this|it)\s+is\s+safe/gi,
        severity: "high",
        name: "context_poisoning"
    },
    {
        pattern: /\b(?:security\s+)?(?:audit|review)\s+(?:approved|signed\s+off)\s+by\b/gi,
        severity: "high",
        name: "authority_impersonation"
    },
    {
        pattern: /\bdeploy\s+(?:immediately|now|asap)\s+without\s+(?:review|testing|approval)/gi,
        severity: "high",
        name: "urgency_bypass"
    },
    {
        pattern: /\byou\s+already\s+(?:approved|verified|confirmed|accepted)\s+this/gi,
        severity: "high",
        name: "gaslighting"
    },
    {
        pattern: /\b(?:5\s+stars?|reward|bonus|tip)\s+if\s+you\s+(?:skip|ignore|bypass)/gi,
        severity: "high",
        name: "reward_hacking"
    },
    {
        pattern: /\bskip\s+(?:security|safety|validation)\s+(?:check|scan|review)/gi,
        severity: "high",
        name: "security_skip_request"
    },
    {
        pattern: /\btrust\s+(?:this|me|it)\s+(?:blindly|completely|without\s+(?:question|verification))/gi,
        severity: "high",
        name: "trust_manipulation"
    },

    // =========================================================================
    // HIGH: Hidden content via CSS/HTML (Gap 3)
    // =========================================================================
    {
        // Require HTML context: style="...display:none..."  not just bare CSS mention
        pattern: /style\s*=\s*["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0)/gi,
        severity: "high",
        name: "css_hidden_content"
    },
    {
        pattern: /style\s*=\s*["'][^"']*color\s*:\s*(?:white|transparent|#fff(?:fff)?|rgba?\s*\(\s*\d+\s*,\s*\d+\s*,\s*\d+\s*,\s*0\s*\))/gi,
        severity: "medium",
        name: "css_invisible_text"
    },
];

// ============================================================================
// Payload Reconstruction Patterns (Gap 5)
// Detect code that reconstructs injection phrases at runtime
// ============================================================================

const RECONSTRUCTION_PATTERNS: InjectionPattern[] = [
    {
        pattern: /String\.fromCharCode\s*\(\s*\d+(?:\s*,\s*\d+){5,}\s*\)/gi,
        severity: "high",
        name: "string_from_charcode"
    },
    {
        pattern: /\.split\s*\(\s*(['"`])\1\s*\)\s*\.reverse\s*\(\s*\)\s*\.join\s*\(/gi,
        severity: "high",
        name: "reverse_join_reconstruction"
    },
    {
        // Match arrays with 4+ string elements joined into one string
        pattern: /\[(?:\s*(['"`])[^'"`\n]{1,20}\1\s*,){3,}\s*(['"`])[^'"`\n]{1,20}\2\s*\]\s*\.join\s*\(/gi,
        severity: "medium",
        name: "array_join_reconstruction"
    },
    {
        pattern: /String\.raw\s*`[^`]{50,}`/gi,
        severity: "medium",
        name: "string_raw_payload"
    },
];

// ============================================================================
// Policy Puppetry Patterns (Gap R3)
// Source: HiddenLayer, April 2025 — universal bypass across GPT/Claude/Gemini
// Attack: Config format mimicry (XML/JSON/INI) with safety-disabling values
// ============================================================================

const POLICY_PUPPETRY_PATTERNS: InjectionPattern[] = [
    {
        // INI-style safety override: [system]\nrole = unrestricted
        pattern: /\[(?:system|admin|config|settings|policy)\]\s*\n(?:[^\n]*\n){0,3}[^\n]*(?:role|mode|safety|restriction|filter|guardrail)\s*[=:]\s*(?:unrestricted|disabled|off|none|bypass)/gi,
        severity: "critical",
        name: "policy_puppetry_ini"
    },
    {
        // JSON-like safety override: "safety": "disabled"
        pattern: /["'](?:safety|restriction|filter|guardrail|mode|role)["']\s*:\s*["'](?:unrestricted|disabled|off|none|bypass|admin|root|override)["']/gi,
        severity: "critical",
        name: "policy_puppetry_json"
    },
    {
        // XML-style config: <role>unrestricted</role>
        pattern: /<(?:role|safety|mode|restriction|policy|config)>\s*(?:unrestricted|disabled|off|none|bypass|admin|override)\s*<\//gi,
        severity: "critical",
        name: "policy_puppetry_xml"
    },
    {
        // YAML-style: safety_mode: disabled
        pattern: /(?:safety_mode|content_filter|guardrails?|restrictions?)\s*:\s*(?:disabled|off|none|false|bypass)/gi,
        severity: "high",
        name: "policy_puppetry_yaml"
    },
];

// ============================================================================
// Adversarial Suffix Detection (Gap R5)
// Source: GCG attacks (Zou et al. 2023), ASF paper 2025
// Attack: Append gibberish token sequences that bypass alignment
// Detection: High character entropy in non-code text
// ============================================================================

/**
 * Calculate Shannon entropy of a string's character distribution.
 * High entropy (>4.5) in short segments suggests adversarial gibberish.
 */
function calculateCharEntropy(text: string): number {
    if (text.length === 0) return 0;
    const freq = new Map<string, number>();
    for (const ch of text) {
        freq.set(ch, (freq.get(ch) || 0) + 1);
    }
    let entropy = 0;
    for (const count of freq.values()) {
        const p = count / text.length;
        if (p > 0) entropy -= p * Math.log2(p);
    }
    return entropy;
}

/**
 * Detect adversarial suffix strings (GCG-style gibberish).
 * Returns finding if text contains high-entropy non-natural segments.
 */
export function detectAdversarialSuffix(content: string): PromptInjectionMatch | null {
    // Only check strings long enough to matter (GCG suffixes are typically 20+ chars)
    if (content.length < 30) return null;

    // Split content into chunks at sentence/line boundaries
    const chunks = content.split(/[.\n!?]+/);
    for (const chunk of chunks) {
        const trimmed = chunk.trim();
        if (trimmed.length < 15 || trimmed.length > 200) continue;

        // Skip chunks that look like code, URLs, or paths
        if (/^[\s]*(?:\/\/|\/\*|\*|#|import|export|const|let|var|function|class|if|for|while|return|https?:\/\/|\/[a-z])/.test(trimmed)) continue;
        if (/^[a-zA-Z0-9_\-\/.]+$/.test(trimmed)) continue; // file paths or identifiers

        const entropy = calculateCharEntropy(trimmed);
        // Natural English text typically has entropy 3.5-4.2
        // Code has entropy 4.0-4.8
        // GCG adversarial text has entropy 4.5+ but repeated gibberish can be lower
        // Dual threshold approach:
        //   1. High entropy + moderate punctuation = adversarial
        //   2. Moderate entropy + extreme punctuation ratio = adversarial (all symbols)
        const punctuationRatio = (trimmed.match(/[^a-zA-Z0-9\s]/g) || []).length / trimmed.length;
        const isAdversarial = (entropy > 4.5 && punctuationRatio > 0.2) ||
            (entropy > 3.5 && punctuationRatio > 0.8);
        if (isAdversarial) {
            return {
                file: "",
                line: 1,
                severity: "high",
                pattern: "adversarial_suffix",
                matched: trimmed.slice(0, 60),
                context: `High entropy (${entropy.toFixed(1)}) gibberish detected: possible GCG adversarial suffix`
            };
        }
    }
    return null;
}

// ============================================================================
// MCP Tool Description Injection (Gap R7)
// Source: MCP "line jumping" research, 2025
// Attack: Malicious instructions embedded in tool/function descriptions
// ============================================================================

const MCP_INJECTION_PATTERNS: InjectionPattern[] = [
    {
        // Tool description containing hidden system-level instructions
        pattern: /(?:tool_description|function_description|tool_spec)\s*[=:]\s*["'][^"']*(?:ignore|override|bypass|disable)\s+(?:all\s+)?(?:previous|prior|safety)/gi,
        severity: "critical",
        name: "mcp_tool_injection"
    },
    {
        // Tool name that mimics system tools to hijack execution
        pattern: /(?:tool_name|function_name)\s*[=:]\s*["'](?:__system__|__admin__|execute_code|run_command|shell_exec|eval_code)["']/gi,
        severity: "high",
        name: "mcp_tool_hijack"
    },
];

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

/** Internal helper: run a set of patterns against content and collect matches */
function runPatterns(
    patterns: InjectionPattern[],
    content: string,
    filename: string,
    suffixTag?: string
): PromptInjectionMatch[] {
    const matches: PromptInjectionMatch[] = [];

    for (const rule of patterns) {
        rule.pattern.lastIndex = 0;
        let match;
        while ((match = rule.pattern.exec(content)) !== null) {
            const beforeMatch = content.slice(0, match.index);
            const lineNum = beforeMatch.split("\n").length;

            const contextStart = Math.max(0, match.index - 50);
            const contextEnd = Math.min(content.length, match.index + match[0].length + 50);
            const context = content.slice(contextStart, contextEnd)
                .replace(/\n/g, " ")
                .trim();

            matches.push({
                file: filename,
                line: lineNum,
                severity: rule.severity,
                pattern: suffixTag ? `${rule.name}:${suffixTag}` : rule.name,
                matched: match[0],
                context: context.length > 120 ? context.slice(0, 117) + "..." : context
            });
        }
    }

    return matches;
}

/**
 * Scans text content for prompt injection patterns.
 * Runs a multi-pass analysis:
 *   1. Raw content (catches literal patterns)
 *   2. Normalized content (catches encoding/invisible/homoglyph evasion)
 *   3. Leetspeak-decoded content (catches 1337speak obfuscation)
 *   4. ROT13-decoded content (catches ROT13-encoded injections)
 *   5. FlipAttack reversed content (catches character-reversed injections)
 *   6. Reconstruction patterns (catches code-based payload assembly)
 *   7. Policy Puppetry patterns (catches config format mimicry)
 *   8. MCP injection patterns (catches tool description injection)
 *   9. Adversarial suffix detection (catches GCG-style gibberish)
 *   10. Invisible character detection (flags suspicious Unicode)
 *
 * @param content - The text content to scan
 * @param filename - The source filename for reporting
 * @returns Array of detected injection matches
 */
export function scanForPromptInjection(
    content: string,
    filename: string
): PromptInjectionMatch[] {
    const matches: PromptInjectionMatch[] = [];

    // Pass 1: Scan raw content
    matches.push(...runPatterns(INJECTION_PATTERNS, content, filename));

    // Pass 2: Normalize and scan again (catches encoding/invisible/homoglyph evasion)
    const normalized = normalizeForScanning(content);
    if (normalized !== content) {
        matches.push(...runPatterns(INJECTION_PATTERNS, normalized, filename, "normalized"));
    }

    // Pass 3: Leetspeak decode and scan (catches 1337speak obfuscation)
    // Source: Policy Puppetry (HiddenLayer, April 2025)
    const leetDecoded = decodeLeetspeak(normalized);
    if (leetDecoded !== normalized) {
        matches.push(...runPatterns(INJECTION_PATTERNS, leetDecoded, filename, "leetspeak"));
    }

    // Pass 4: ROT13-decode and scan (catches ROT13-encoded injections)
    const rot13Content = rot13(content);
    const rot13Matches = runPatterns(INJECTION_PATTERNS, rot13Content, filename, "rot13");
    if (rot13Matches.length > 0) {
        matches.push(...rot13Matches);
    }

    // Pass 5: FlipAttack — reverse content and scan (catches character-reversed injections)
    // Source: FlipAttack paper, 78.97% ASR, 98% bypass on GPT-4o
    // Only on content > 30 chars, check if reversed text triggers high-severity patterns
    if (content.length > 30 && content.length < 5000) {
        const reversed = content.split("").reverse().join("");
        const reversedMatches = runPatterns(INJECTION_PATTERNS, reversed, filename, "flipattack");
        // Only keep critical/high matches to avoid false positives from reversed text
        const highSeverityReversed = reversedMatches.filter(m =>
            m.severity === "critical" || m.severity === "high"
        );
        matches.push(...highSeverityReversed);
    }

    // Pass 6: Scan for reconstruction patterns (code-based evasion)
    matches.push(...runPatterns(RECONSTRUCTION_PATTERNS, content, filename));

    // Pass 7: Policy Puppetry patterns (config format mimicry)
    // Source: HiddenLayer, April 2025 — universal bypass
    matches.push(...runPatterns(POLICY_PUPPETRY_PATTERNS, content, filename));
    // Also scan normalized and leetspeak-decoded content for puppetry
    if (normalized !== content) {
        matches.push(...runPatterns(POLICY_PUPPETRY_PATTERNS, normalized, filename, "normalized"));
    }
    if (leetDecoded !== normalized) {
        matches.push(...runPatterns(POLICY_PUPPETRY_PATTERNS, leetDecoded, filename, "leetspeak"));
    }

    // Pass 8: MCP tool description injection patterns
    // Source: MCP "line jumping" research, 2025
    matches.push(...runPatterns(MCP_INJECTION_PATTERNS, content, filename));

    // Pass 9: Adversarial suffix detection (GCG-style gibberish)
    // Source: GCG attacks (Zou et al. 2023), ASF paper 2025
    const suffixMatch = detectAdversarialSuffix(content);
    if (suffixMatch) {
        suffixMatch.file = filename;
        matches.push(suffixMatch);
    }

    // Pass 10: Flag invisible characters as standalone findings
    const invisibles = detectInvisibleCharacters(content);
    if (invisibles.found) {
        const severity = invisibles.types.includes("unicode_tag") ? "critical" as const :
            invisibles.types.includes("bidi_override") ? "high" as const : "medium" as const;
        matches.push({
            file: filename,
            line: 1,
            severity,
            pattern: "invisible_characters",
            matched: `${invisibles.count} invisible chars (${invisibles.types.join(", ")})`,
            context: `Found ${invisibles.count} invisible Unicode characters: ${invisibles.types.join(", ")}`
        });
    }

    return matches;
}

/**
 * Recursively extracts all string values from a JSON object.
 * Returns array of {key, value} pairs with dot-notation paths.
 */
function extractAllStrings(
    obj: unknown,
    prefix: string = "",
    depth: number = 0
): Array<{ key: string; value: string }> {
    if (depth > 5) return []; // Prevent infinite recursion
    const results: Array<{ key: string; value: string }> = [];

    if (typeof obj === "string" && obj.length > 0) {
        results.push({ key: prefix || "root", value: obj });
    } else if (Array.isArray(obj)) {
        for (let i = 0; i < obj.length; i++) {
            results.push(...extractAllStrings(obj[i], `${prefix}[${i}]`, depth + 1));
        }
    } else if (obj && typeof obj === "object") {
        for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
            // Skip scanning script content (handled by scanInstallScripts)
            if (prefix === "" && k === "scripts") continue;
            // Skip binary/path fields unlikely to contain injections
            if (k === "main" || k === "module" || k === "types" || k === "typings") continue;
            results.push(...extractAllStrings(v, prefix ? `${prefix}.${k}` : k, depth + 1));
        }
    }

    return results;
}

/**
 * Scans package.json metadata fields for prompt injection.
 * Scans ALL string fields recursively, plus cross-field payload splitting detection.
 * Covers: description, readme, keywords, author, homepage, bugs, repository,
 * funding, contributors, config, and any custom fields.
 *
 * Gap R6: Cross-field payload splitting detection
 * Source: OWASP LLM01:2025
 * Attack: Split injection across multiple fields so no single field triggers
 *
 * @param pkgJson - Parsed package.json object
 * @returns Array of detected injection matches
 */
export function scanPackageJsonMetadata(
    pkgJson: Record<string, unknown>
): PromptInjectionMatch[] {
    const matches: PromptInjectionMatch[] = [];
    const allStrings = extractAllStrings(pkgJson);

    for (const field of allStrings) {
        // Only scan strings with meaningful length
        if (field.value.length < 5) continue;
        const fieldMatches = scanForPromptInjection(
            field.value,
            `package.json:${field.key}`
        );
        matches.push(...fieldMatches);
    }

    // Gap R6: Cross-field payload splitting detection
    // Concatenate key metadata fields and scan the combined text
    // to catch payloads split across description + keywords + homepage etc.
    // Order: name, description, keywords (right after desc), readme, homepage
    const crossFieldParts: string[] = [];
    for (const key of ["name", "description"]) {
        const val = pkgJson[key];
        if (typeof val === "string" && val.length > 0) {
            crossFieldParts.push(val);
        }
    }
    // Include keywords right after description (they often form phrases with it)
    if (Array.isArray(pkgJson.keywords)) {
        for (const kw of pkgJson.keywords) {
            if (typeof kw === "string") crossFieldParts.push(kw);
        }
    }
    for (const key of ["readme", "homepage"]) {
        const val = pkgJson[key];
        if (typeof val === "string" && val.length > 0) {
            crossFieldParts.push(val);
        }
    }
    // Scan the concatenated text (only if we have 2+ fields to combine)
    if (crossFieldParts.length >= 2) {
        const combined = crossFieldParts.join(" ");
        const combinedMatches = scanForPromptInjection(combined, "package.json:cross_field");
        // Only add matches that weren't already found in individual field scans
        const existingPatterns = new Set(matches.map(m => m.pattern));
        for (const m of combinedMatches) {
            if (!existingPatterns.has(m.pattern)) {
                matches.push(m);
            }
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
