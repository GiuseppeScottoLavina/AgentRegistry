/**
 * Server Lifecycle Management
 * 
 * Handles startup initialization, scheduled tasks, and cleanup.
 */

import { mkdir, readdir, rename } from "node:fs/promises";
import { join } from "node:path";
import {
    PACKAGES_DIR, TARBALLS_DIR, QUARANTINE_DIR, BACKUP_DIR
} from "../config";
import { scanTarball } from "../security";
import { getLogCounts, cleanupOldLogs } from "../database";

/**
 * Ensure all storage directories exist
 */
export async function ensureStorageDirs(): Promise<void> {
    await mkdir(PACKAGES_DIR, { recursive: true });
    await mkdir(TARBALLS_DIR, { recursive: true });
    await mkdir(QUARANTINE_DIR, { recursive: true });
    await mkdir(BACKUP_DIR, { recursive: true });
}

/**
 * Auto-approve safe quarantine files that passed security scan
 */
export async function autoApproveQuarantine(): Promise<number> {
    const quarantineFiles = await readdir(QUARANTINE_DIR).catch(() => []);
    let approved = 0;

    for (const file of quarantineFiles) {
        if (!file.endsWith(".tgz")) continue;

        const quarantinePath = join(QUARANTINE_DIR, file);
        const scanResult = await scanTarball(quarantinePath);

        if (scanResult.safe) {
            // Move to tarballs
            const tarballPath = join(TARBALLS_DIR, file);
            await rename(quarantinePath, tarballPath).catch(() => { });
            approved++;
            console.log(`✅ Auto-approved: ${file}`);
        }
    }

    if (approved > 0) {
        console.log(`🧹 Auto-approved ${approved} safe packages from quarantine`);
    }

    return approved;
}

/**
 * Run scheduled log cleanup
 */
export function runScheduledCleanup(): {
    requestLogs: number;
    auditLogs: number;
    scanResults: number;
    freedBytes: number;
} {
    const counts = getLogCounts();
    console.log(`🧹 Running scheduled cleanup (logs: ${counts.requestLogs} req, ${counts.auditLogs} audit, ${counts.scanResults} scans)`);

    const result = cleanupOldLogs({
        requestLogsDays: 7,   // Keep 7 days of request logs
        auditLogsDays: 30,    // Keep 30 days of audit logs (except security alerts - kept forever)
        scanResultsDays: 30   // Keep 30 days of scan results (blocked packages kept forever)
    });

    if (result.requestLogs > 0 || result.auditLogs > 0 || result.scanResults > 0) {
        console.log(`   ✅ Cleaned: ${result.requestLogs} requests, ${result.auditLogs} audits, ${result.scanResults} scans`);
        console.log(`   💾 Freed: ${(result.freedBytes / 1024).toFixed(1)}KB`);
    } else {
        console.log(`   ✅ Nothing to clean`);
    }

    return result;
}

/**
 * Cleanup interval in milliseconds (6 hours)
 */
export const CLEANUP_INTERVAL_MS = 6 * 60 * 60 * 1000;
