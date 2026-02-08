/**
 * Admin HTTP Handlers
 * 
 * Handles admin panel HTTP API endpoints for stats, quarantine, cache management.
 */

import { readdir, unlink, exists, rename } from "node:fs/promises";
import { join } from "node:path";
import { sha256File } from "../utils/helpers";
import {
    PACKAGES_DIR, TARBALLS_DIR, QUARANTINE_DIR
} from "../config";
import {
    getDatabase,
    getComprehensiveStats,
    getRecentAuditLogs,
    deletePackageFromDB
} from "../database";
import { getTarballCacheSize, deleteTarballFromCache } from "../services/cache";
import type { PackageMetadata } from "../types";
import type { ScanResult } from "../security";

// Dependency types for injection
export interface AdminContext {
    loadPackage: (name: string) => Promise<PackageMetadata | null>;
    getPackagePath: (name: string) => string;
    getTarballPath: (name: string, version: string) => string;
    scanResultsCache: Map<string, ScanResult>;
    packageCache: Map<string, { data: PackageMetadata; timestamp: number }>;
    serverStartTime: number;
    scansPerformed: number;
    totalScanTime: number;
}

/**
 * GET /-/admin/stats - Server statistics
 */
export async function handleAdminStats(ctx: AdminContext): Promise<Response> {
    const memoryUsage = process.memoryUsage();
    const dbStats = getComprehensiveStats();

    // Count packages
    const packageFiles = await readdir(PACKAGES_DIR).catch(() => []);
    const packagesCount = packageFiles.filter(f => f.endsWith(".json")).length;

    // Count and size tarballs
    const tarballFiles = await readdir(TARBALLS_DIR).catch(() => []);
    let tarballsSize = 0;
    for (const file of tarballFiles) {
        const stat = await Bun.file(join(TARBALLS_DIR, file)).size;
        tarballsSize += stat;
    }

    // Count quarantine
    const quarantineFiles = await readdir(QUARANTINE_DIR).catch(() => []);

    return new Response(JSON.stringify({
        uptime: Math.floor((Date.now() - ctx.serverStartTime) / 1000),
        packages: packagesCount,
        tarballs: tarballFiles.length,
        tarballsSize,
        quarantine: quarantineFiles.length,
        memoryCacheEntries: getTarballCacheSize(),
        memoryUsed: memoryUsage.heapUsed,
        memoryTotal: memoryUsage.heapTotal,
        scansPerformed: ctx.scansPerformed,
        avgScanTime: ctx.scansPerformed > 0 ? Math.round(ctx.totalScanTime / ctx.scansPerformed) : 0,
        database: dbStats.database,
        scanStats: dbStats.scans,
        requestStats: dbStats.requests,
        packageStats: dbStats.packages
    }), {
        headers: { "Content-Type": "application/json" }
    });
}

/**
 * GET /-/admin/audit-logs - Recent audit logs
 */
export async function handleAdminAuditLogs(): Promise<Response> {
    const logs = getRecentAuditLogs(100);
    return new Response(JSON.stringify({ logs }), {
        headers: { "Content-Type": "application/json" }
    });
}

/**
 * GET /-/admin/scan-history - Recent scan results
 */
export async function handleAdminScanHistory(): Promise<Response> {
    const db = getDatabase();
    const scans = db.prepare(`
        SELECT package_name, version, safe, issues_count, scan_time_ms, scanned_at 
        FROM scan_results 
        ORDER BY scanned_at DESC 
        LIMIT 100
    `).all();
    return new Response(JSON.stringify({ scans }), {
        headers: { "Content-Type": "application/json" }
    });
}

/**
 * GET /-/admin/request-logs - Recent HTTP requests
 */
export async function handleAdminRequestLogs(): Promise<Response> {
    const db = getDatabase();
    const requests = db.prepare(`
        SELECT request_id, method, path, status_code, duration_ms, created_at 
        FROM request_logs 
        ORDER BY created_at DESC 
        LIMIT 100
    `).all();
    return new Response(JSON.stringify({ requests }), {
        headers: { "Content-Type": "application/json" }
    });
}

/**
 * GET /-/admin/quarantine - List quarantined packages
 */
export async function handleAdminQuarantineList(
    scanResultsCache: Map<string, ScanResult>
): Promise<Response> {
    const files = await readdir(QUARANTINE_DIR).catch(() => []);
    const result = [];

    for (const filename of files) {
        if (!filename.endsWith(".tgz")) continue;

        const filepath = join(QUARANTINE_DIR, filename);
        const stat = await Bun.file(filepath).stat();

        // Try to get cached scan result
        const match = filename.match(/^(.+)-(\d+\.\d+\.\d+(?:-[a-zA-Z0-9.]+)?).tgz$/);
        const name = match ? match[1].replace("-", "/").replace(/^([^@])/, "@$1").replace(/^@@/, "") : filename;
        const version = match ? match[2] : "unknown";
        const cacheKey = `${name}@${version}`;
        const scanResult = scanResultsCache.get(cacheKey);

        result.push({
            filename,
            name,
            version,
            size: stat.size,
            quarantinedAt: stat.mtime,
            issues: scanResult?.issues || []
        });
    }

    return new Response(JSON.stringify({ files: result }), {
        headers: { "Content-Type": "application/json" }
    });
}

/**
 * DELETE /-/admin/quarantine/:filename - Delete a quarantined file
 */
export async function handleAdminQuarantineDelete(filename: string): Promise<Response> {
    const filepath = join(QUARANTINE_DIR, filename);
    if (await exists(filepath)) {
        await unlink(filepath);
        return new Response(JSON.stringify({ ok: true }), {
            headers: { "Content-Type": "application/json" }
        });
    }
    return new Response(JSON.stringify({ error: "Not found" }), {
        status: 404,
        headers: { "Content-Type": "application/json" }
    });
}

/**
 * DELETE /-/admin/quarantine - Clear all quarantine
 */
export async function handleAdminQuarantineClear(): Promise<Response> {
    const files = await readdir(QUARANTINE_DIR).catch(() => []);
    for (const file of files) {
        await unlink(join(QUARANTINE_DIR, file)).catch(() => { });
    }
    return new Response(JSON.stringify({ ok: true, deleted: files.length }), {
        headers: { "Content-Type": "application/json" }
    });
}

/**
 * POST /-/admin/quarantine/:filename/approve - Approve a quarantined package
 * 
 * SECURITY: Implements TOCTOU protection via hash verification.
 * Computes hash before rename and verifies after to detect file tampering.
 */
export async function handleAdminQuarantineApprove(filename: string): Promise<Response> {
    const quarantinePath = join(QUARANTINE_DIR, filename);
    if (!(await exists(quarantinePath))) {
        return new Response(JSON.stringify({ error: "Not found" }), {
            status: 404,
            headers: { "Content-Type": "application/json" }
        });
    }

    // SECURITY: Hash verification for TOCTOU protection
    const hashBefore = await sha256File(quarantinePath);
    if (!hashBefore) {
        return new Response(JSON.stringify({ error: "Failed to read file" }), {
            status: 500,
            headers: { "Content-Type": "application/json" }
        });
    }

    // Move to tarballs
    const tarballPath = join(TARBALLS_DIR, filename);
    await rename(quarantinePath, tarballPath);

    // Verify hash after rename matches (detects TOCTOU race condition)
    const hashAfter = await sha256File(tarballPath);
    if (hashBefore !== hashAfter) {
        // SECURITY ALERT: File was modified during approval - revert!
        await unlink(tarballPath).catch(() => { });
        return new Response(JSON.stringify({
            error: "Security: File was modified during approval. Operation aborted.",
            code: "TOCTOU_DETECTED"
        }), {
            status: 409,
            headers: { "Content-Type": "application/json" }
        });
    }

    return new Response(JSON.stringify({ ok: true, hash: hashBefore }), {
        headers: { "Content-Type": "application/json" }
    });
}

/**
 * GET /-/admin/cache - List cached packages
 */
export async function handleAdminCacheList(ctx: AdminContext): Promise<Response> {
    const packageFiles = await readdir(PACKAGES_DIR).catch(() => []);
    const packages = [];

    for (const file of packageFiles) {
        if (!file.endsWith(".json")) continue;

        const name = file.slice(0, -5).replace("%2f", "/");
        const pkg = await ctx.loadPackage(name) as PackageMetadata & { _source?: string };
        if (!pkg) continue;

        const versions = Object.keys(pkg.versions || {});
        let totalSize = 0;

        for (const ver of versions) {
            const tarballPath = ctx.getTarballPath(name, ver);
            if (await exists(tarballPath)) {
                totalSize += await Bun.file(tarballPath).size;
            }
        }

        packages.push({
            name,
            versions,
            size: totalSize,
            source: pkg._source || "unknown",
            updatedAt: pkg.time?.modified || pkg.time?.created
        });
    }

    return new Response(JSON.stringify({ packages }), {
        headers: { "Content-Type": "application/json" }
    });
}

/**
 * DELETE /-/admin/cache/:name - Delete a cached package
 */
export async function handleAdminCacheDelete(
    name: string,
    ctx: AdminContext
): Promise<Response> {
    // Load package first to get versions for tarball cleanup
    const pkg = await ctx.loadPackage(name);

    // Delete package metadata
    const packagePath = ctx.getPackagePath(name);
    if (await exists(packagePath)) {
        await unlink(packagePath);
    }

    // Sync SQLite
    deletePackageFromDB(name);

    // Invalidate caches
    ctx.packageCache.delete(name);

    // Delete tarballs
    if (pkg) {
        for (const version of Object.keys(pkg.versions || {})) {
            const tarballPath = ctx.getTarballPath(name, version);
            await unlink(tarballPath).catch(() => { });
            deleteTarballFromCache(`${name}@${version}`);
        }
    }

    return new Response(JSON.stringify({ ok: true }), {
        headers: { "Content-Type": "application/json" }
    });
}

/**
 * POST /-/admin/cache/:name/refresh - Force refresh a package from upstream
 */
export async function handleAdminCacheRefresh(
    name: string,
    ctx: AdminContext
): Promise<Response> {
    // Delete cached metadata to force re-fetch
    const packagePath = ctx.getPackagePath(name);
    if (await exists(packagePath)) {
        await unlink(packagePath);
    }

    // Sync SQLite
    deletePackageFromDB(name);

    return new Response(JSON.stringify({ ok: true }), {
        headers: { "Content-Type": "application/json" }
    });
}

/**
 * POST /-/admin/cleanup - Clean up unused upstream packages
 */
export async function handleAdminCleanup(ctx: AdminContext): Promise<Response> {
    const packageFiles = await readdir(PACKAGES_DIR).catch(() => []);
    const localLibs: string[] = [];
    const requiredDeps = new Set<string>();
    const deleted: string[] = [];
    const kept: string[] = [];

    // Step 1: Find all local libs and their dependencies
    for (const file of packageFiles) {
        if (!file.endsWith(".json")) continue;

        const name = file.slice(0, -5).replace("%2f", "/");
        const pkg = await ctx.loadPackage(name) as PackageMetadata & { _source?: string };
        if (!pkg) continue;

        if (pkg._source === "local") {
            localLibs.push(name);

            // Collect direct dependencies from all versions
            for (const versionData of Object.values(pkg.versions)) {
                const deps = versionData.dependencies || {};
                for (const depName of Object.keys(deps)) {
                    requiredDeps.add(depName);
                }
            }
        }
    }

    // Step 2: Delete upstream packages that are not required
    for (const file of packageFiles) {
        if (!file.endsWith(".json")) continue;

        const name = file.slice(0, -5).replace("%2f", "/");
        const pkg = await ctx.loadPackage(name) as PackageMetadata & { _source?: string };
        if (!pkg) continue;

        if (pkg._source === "upstream") {
            if (!requiredDeps.has(name)) {
                // Delete package and its tarballs
                await unlink(ctx.getPackagePath(name)).catch(() => { });
                for (const version of Object.keys(pkg.versions || {})) {
                    const tarballPath = ctx.getTarballPath(name, version);
                    await unlink(tarballPath).catch(() => { });
                    deleteTarballFromCache(`${name}@${version}`);
                }
                deleted.push(name);
            } else {
                kept.push(name);
            }
        }
    }

    console.log(`🧹 Cleanup: deleted ${deleted.length} packages, kept ${kept.length} deps for ${localLibs.length} local libs`);

    return new Response(JSON.stringify({
        ok: true,
        localLibs,
        deleted,
        kept,
        requiredDeps: Array.from(requiredDeps)
    }), {
        headers: { "Content-Type": "application/json" }
    });
}
