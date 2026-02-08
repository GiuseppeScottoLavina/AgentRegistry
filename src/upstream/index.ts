/**
 * Upstream Registry Proxy
 * 
 * Handles fetching packages from npmjs.org with prefetching and quarantine.
 */

import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { rename } from "node:fs/promises";
import { createHash } from "node:crypto";
import { UPSTREAM_REGISTRY, QUARANTINE_DIR } from "../config";
import { scanTarball, type ScanResult } from "../security";
import { saveScanResult, loadPackageFromDB } from "../database";
import { setTarballInCache } from "../services/cache";
import { broadcastToAdmin } from "../services/broadcast";
import { notifyDesktop } from "../utils/notifications";
import * as logger from "../logger";
import type { PackageMetadata } from "../types";

const PREFETCH_CONCURRENCY = 5;

// Callback type for tracking scans
type TrackScanFn = (scanTimeMs: number) => void;
type SavePackageFn = (pkg: PackageMetadata) => Promise<void>;
type LoadPackageFn = (name: string) => Promise<PackageMetadata | null>;

/**
 * Context for upstream operations - allows dependency injection
 */
export interface UpstreamContext {
    scanResultsCache: Map<string, ScanResult>;
    savePackage: SavePackageFn;
    loadPackage: LoadPackageFn;
    trackScan: TrackScanFn;
}

// Module-level cache for scan results (will be removed after integration)
const SCAN_RESULTS_CACHE = new Map<string, ScanResult>();

/**
 * Fetch package metadata from upstream registry (npmjs.org)
 */
export async function fetchFromUpstream(
    name: string,
    baseUrl: string,
    savePackage: SavePackageFn,
    isPrefetch: boolean = false
): Promise<Response | null> {
    if (!UPSTREAM_REGISTRY) return null;

    try {
        const logPrefix = isPrefetch ? "🔮 Prefetching" : "🔍 Fetching";
        if (!isPrefetch) logger.info(`${logPrefix} from upstream: ${name}`);

        const upstreamUrl = `${UPSTREAM_REGISTRY}/${encodeURIComponent(name).replace("%40", "@")}`;
        const res = await fetch(upstreamUrl);

        if (!res.ok) return null;

        const pkg = await res.json() as PackageMetadata;

        // Rewrite tarball URLs to point through our proxy
        for (const version of Object.values(pkg.versions)) {
            const tarballName = `${pkg.name.replace("/", "-").replace("@", "")}-${version.version}.tgz`;
            version.dist.tarball = `${baseUrl}/${pkg.name}/-/${tarballName}`;
        }

        // Mark as upstream package
        (pkg as PackageMetadata & { _source?: string })._source = "upstream";

        // Cache the metadata locally
        await savePackage(pkg);
        if (!isPrefetch) logger.info(`📦 Cached from upstream: ${name}`);

        // Trigger prefetch of dependencies (non-blocking) only for direct user requests
        if (!isPrefetch) {
            prefetchDependencies(pkg, baseUrl, savePackage).catch(err =>
                console.error("Prefetch error:", err)
            );
        }

        return new Response(JSON.stringify(pkg), {
            headers: { "Content-Type": "application/json" }
        });
    } catch (error) {
        console.error(`Failed to fetch from upstream: ${error}`);
        return null;
    }
}

/**
 * Prefetch dependencies of a package in the background
 */
export async function prefetchDependencies(
    pkg: PackageMetadata,
    baseUrl: string,
    savePackage: SavePackageFn
): Promise<void> {
    if (!UPSTREAM_REGISTRY) return;

    try {
        const latest = pkg["dist-tags"]?.latest;
        if (!latest) return;

        const versionData = pkg.versions[latest];
        if (!versionData || !versionData.dependencies) return;

        const deps = Object.keys(versionData.dependencies);
        if (deps.length === 0) return;

        // Filter out existing packages
        const neededDeps = deps.filter(dep => !loadPackageFromDB(dep));

        if (neededDeps.length === 0) return;

        console.log(`🚀 Prefetching ${neededDeps.length} dependencies for ${pkg.name}...`);

        // Process in chunks to limit concurrency
        for (let i = 0; i < neededDeps.length; i += PREFETCH_CONCURRENCY) {
            const chunk = neededDeps.slice(i, i + PREFETCH_CONCURRENCY);
            await Promise.all(chunk.map(dep => fetchFromUpstream(dep, baseUrl, savePackage, true)));
        }
    } catch (err) {
        console.error(`Prefetch error for ${pkg.name}:`, err);
    }
}

/**
 * Fetch and scan tarball from upstream registry
 */
export async function fetchTarballFromUpstream(
    name: string,
    version: string,
    tarballPath: string,
    ctx: UpstreamContext
): Promise<boolean> {
    const { scanResultsCache, trackScan, loadPackage, savePackage } = ctx;
    if (!UPSTREAM_REGISTRY) return false;

    const cacheKey = `${name}@${version}`;

    try {
        // First get package metadata to find the original tarball URL
        const metaUrl = `${UPSTREAM_REGISTRY}/${encodeURIComponent(name).replace("%40", "@")}`;
        const metaRes = await fetch(metaUrl);
        if (!metaRes.ok) return false;

        const pkg = await metaRes.json() as PackageMetadata;
        const versionData = pkg.versions[version];
        if (!versionData?.dist?.tarball) return false;

        console.log(`🔍 Fetching tarball from upstream: ${name}@${version}`);
        const tarballRes = await fetch(versionData.dist.tarball);
        if (!tarballRes.ok) return false;

        const tarballData = Buffer.from(await tarballRes.arrayBuffer());

        // Step 1: Write to quarantine first
        const quarantinePath = join(QUARANTINE_DIR, `${name.replace("/", "-").replace("@", "")}-${version}.tgz`);
        writeFileSync(quarantinePath, tarballData);
        console.log(`🔒 Quarantined: ${name}@${version}`);

        // Step 2: Security scan
        const scanResult = await scanTarball(quarantinePath);
        scanResultsCache.set(cacheKey, scanResult);
        trackScan(scanResult.scanTimeMs);

        // Persist scan result to SQLite
        const tarballHash = createHash("sha256").update(tarballData).digest("hex");
        saveScanResult({
            package_name: name,
            version,
            tarball_hash: tarballHash,
            safe: scanResult.safe,
            issues_count: scanResult.issues.length,
            issues: scanResult.issues,
            files_scanned: scanResult.filesScanned,
            scan_time_ms: scanResult.scanTimeMs,
            pi_score: scanResult.piRiskScore ?? 0,
            pi_count: scanResult.promptInjections?.length ?? 0,
            pi_findings: scanResult.promptInjections ?? []
        });

        if (!scanResult.safe) {
            console.log(`🚨 BLOCKED: ${name}@${version} - ${scanResult.issues.length} security issues found (${scanResult.scanTimeMs}ms)`);
            for (const issue of scanResult.issues.slice(0, 3)) {
                console.log(`   ❌ [${issue.severity}] ${issue.description}`);
            }
            // Broadcast to Admin Panel for real-time update
            broadcastToAdmin("package_blocked", { name, version, issues: scanResult.issues.length });
            // Desktop notification for user (macOS only)
            notifyDesktop("AgentRegistry Quarantine", `${name}@${version} richiede approvazione`);
            // Leave in quarantine, don't cache
            return false;
        }

        console.log(`✅ SAFE: ${name}@${version} (${scanResult.scanTimeMs}ms, ${scanResult.filesScanned} files)`);

        // Step 3: Move from quarantine to cache
        await rename(quarantinePath, tarballPath);

        // Step 4: Add to memory cache
        setTarballInCache(cacheKey, tarballData);

        // Also cache metadata if not already cached
        if (!(await loadPackage(name))) {
            await savePackage(pkg);
        }

        console.log(`📦 Cached tarball: ${name}@${version}`);
        return true;
    } catch (error) {
        console.error(`Failed to fetch tarball from upstream: ${error}`);
        return false;
    }
}

/**
 * Get cached scan result
 * @param cache - Optional cache to use (defaults to module-level for backward compatibility)
 */
export function getScanResultFromCache(
    cacheKey: string,
    cache: Map<string, ScanResult> = SCAN_RESULTS_CACHE
): ScanResult | undefined {
    return cache.get(cacheKey);
}

/**
 * Set scan result in cache
 * @param cache - Optional cache to use (defaults to module-level for backward compatibility)
 */
export function setScanResultInCache(
    cacheKey: string,
    result: ScanResult,
    cache: Map<string, ScanResult> = SCAN_RESULTS_CACHE
): void {
    cache.set(cacheKey, result);
}
