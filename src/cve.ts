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
 * AgentRegistry CVE Module
 * 
 * Checks packages against the OSV (Open Source Vulnerabilities) database.
 * Uses Google's OSV API for npm ecosystem vulnerability data.
 * 
 * @module cve
 */

// ============================================================================
// Types
// ============================================================================

export interface Vulnerability {
    id: string;                    // CVE-2024-xxxx or GHSA-xxxx
    severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | "UNKNOWN";
    summary: string;
    details?: string;
    affectedVersions: string;
    fixedIn?: string;
    references: string[];
    published: string;
}

export interface CVECheckResult {
    packageName: string;
    version?: string;
    vulnerabilities: Vulnerability[];
    checkedAt: number;
    fromCache: boolean;
}

interface OSVResponse {
    vulns?: OSVVulnerability[];
}

interface OSVVulnerability {
    id: string;
    summary?: string;
    details?: string;
    severity?: { type: string; score: string }[];
    database_specific?: { severity: string };
    affected?: {
        package: { name: string; ecosystem: string };
        ranges?: { type: string; events: { introduced?: string; fixed?: string }[] }[];
        versions?: string[];
    }[];
    references?: { type: string; url: string }[];
    published?: string;
}

// ============================================================================
// CVE Cache (in-memory, with TTL)
// ============================================================================

const CVE_CACHE = new Map<string, { data: Vulnerability[]; timestamp: number }>();
const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

function getCacheKey(packageName: string, version?: string): string {
    return version ? `${packageName}@${version}` : packageName;
}

// ============================================================================
// OSV API Integration
// ============================================================================

const OSV_API_URL = "https://api.osv.dev/v1/query";

/**
 * Checks a package against the OSV vulnerability database.
 */
export async function checkCVE(packageName: string, version?: string): Promise<CVECheckResult> {
    const cacheKey = getCacheKey(packageName, version);

    // Check cache first
    const cached = CVE_CACHE.get(cacheKey);
    if (cached && Date.now() - cached.timestamp < CACHE_TTL_MS) {
        return {
            packageName,
            version,
            vulnerabilities: cached.data,
            checkedAt: cached.timestamp,
            fromCache: true
        };
    }

    try {
        const body: any = {
            package: {
                name: packageName,
                ecosystem: "npm"
            }
        };

        if (version) {
            body.version = version;
        }

        const response = await fetch(OSV_API_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
            signal: AbortSignal.timeout(10000) // 10s timeout
        });

        if (!response.ok) {
            console.error(`OSV API error: ${response.status}`);
            return {
                packageName,
                version,
                vulnerabilities: [],
                checkedAt: Date.now(),
                fromCache: false
            };
        }

        const data = await response.json() as OSVResponse;
        const vulnerabilities = parseOSVResponse(data);

        // Cache results
        CVE_CACHE.set(cacheKey, {
            data: vulnerabilities,
            timestamp: Date.now()
        });

        return {
            packageName,
            version,
            vulnerabilities,
            checkedAt: Date.now(),
            fromCache: false
        };
    } catch (error) {
        console.error(`CVE check failed for ${packageName}:`, error);
        return {
            packageName,
            version,
            vulnerabilities: [],
            checkedAt: Date.now(),
            fromCache: false
        };
    }
}

/**
 * Parses OSV API response into our Vulnerability format.
 */
function parseOSVResponse(data: OSVResponse): Vulnerability[] {
    if (!data.vulns || data.vulns.length === 0) {
        return [];
    }

    return data.vulns.map(vuln => {
        // Determine severity
        let severity: Vulnerability["severity"] = "UNKNOWN";
        if (vuln.database_specific?.severity) {
            severity = normalizeSeverity(vuln.database_specific.severity);
        } else if (vuln.severity && vuln.severity.length > 0) {
            const score = parseFloat(vuln.severity[0].score);
            severity = scoreToSeverity(score);
        }

        // Get affected versions
        let affectedVersions = "unknown";
        let fixedIn: string | undefined;

        if (vuln.affected && vuln.affected.length > 0) {
            const affected = vuln.affected[0];
            if (affected.versions) {
                affectedVersions = affected.versions.join(", ");
            } else if (affected.ranges && affected.ranges.length > 0) {
                const range = affected.ranges[0];
                const events = range.events || [];
                const introduced = events.find(e => e.introduced)?.introduced;
                const fixed = events.find(e => e.fixed)?.fixed;

                if (introduced && fixed) {
                    affectedVersions = `>=${introduced} <${fixed}`;
                    fixedIn = fixed;
                } else if (introduced) {
                    affectedVersions = `>=${introduced}`;
                }
            }
        }

        // Get references
        const references = (vuln.references || [])
            .filter(r => r.url)
            .map(r => r.url);

        return {
            id: vuln.id,
            severity,
            summary: vuln.summary || "No summary available",
            details: vuln.details,
            affectedVersions,
            fixedIn,
            references,
            published: vuln.published || new Date().toISOString()
        };
    });
}

function normalizeSeverity(severity: string): Vulnerability["severity"] {
    const upper = severity.toUpperCase();
    if (upper === "CRITICAL") return "CRITICAL";
    if (upper === "HIGH") return "HIGH";
    if (upper === "MEDIUM" || upper === "MODERATE") return "MEDIUM";
    if (upper === "LOW") return "LOW";
    return "UNKNOWN";
}

function scoreToSeverity(score: number): Vulnerability["severity"] {
    if (score >= 9.0) return "CRITICAL";
    if (score >= 7.0) return "HIGH";
    if (score >= 4.0) return "MEDIUM";
    if (score > 0) return "LOW";
    return "UNKNOWN";
}

// ============================================================================
// Batch Operations
// ============================================================================

/**
 * Scans multiple packages for CVEs.
 */
export async function scanPackages(packages: string[]): Promise<Map<string, Vulnerability[]>> {
    const results = new Map<string, Vulnerability[]>();

    // Process in batches of 10 to avoid overwhelming the API
    const batchSize = 10;
    for (let i = 0; i < packages.length; i += batchSize) {
        const batch = packages.slice(i, i + batchSize);
        const promises = batch.map(pkg => checkCVE(pkg));
        const batchResults = await Promise.all(promises);

        for (const result of batchResults) {
            results.set(result.packageName, result.vulnerabilities);
        }

        // Small delay between batches
        if (i + batchSize < packages.length) {
            await new Promise(resolve => setTimeout(resolve, 100));
        }
    }

    return results;
}

/**
 * Gets CVE summary statistics.
 */
export function getCVESummary(): {
    totalPackages: number;
    packagesWithCVEs: number;
    bySeverity: Record<string, number>;
    recentCritical: Vulnerability[];
} {
    let packagesWithCVEs = 0;
    const bySeverity: Record<string, number> = {
        CRITICAL: 0,
        HIGH: 0,
        MEDIUM: 0,
        LOW: 0,
        UNKNOWN: 0
    };
    const recentCritical: Vulnerability[] = [];

    for (const [, cached] of CVE_CACHE) {
        if (cached.data.length > 0) {
            packagesWithCVEs++;
            for (const vuln of cached.data) {
                bySeverity[vuln.severity]++;
                if (vuln.severity === "CRITICAL") {
                    recentCritical.push(vuln);
                }
            }
        }
    }

    return {
        totalPackages: CVE_CACHE.size,
        packagesWithCVEs,
        bySeverity,
        recentCritical: recentCritical.slice(0, 10)
    };
}

/**
 * Clears the CVE cache.
 */
export function clearCVECache(): void {
    CVE_CACHE.clear();
}

/**
 * Gets all cached CVE data.
 */
export function getAllCachedCVEs(): Map<string, Vulnerability[]> {
    const result = new Map<string, Vulnerability[]>();
    for (const [key, cached] of CVE_CACHE) {
        if (cached.data.length > 0) {
            result.set(key, cached.data);
        }
    }
    return result;
}
