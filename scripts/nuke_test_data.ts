/**
 * Aggressive Database Cleanup Script
 * 
 * Removes ALL packages from SQLite database EXCEPT the whitelisted ones.
 * This ensures the Admin Panel graph only shows real packages.
 */

import { Database } from "bun:sqlite";
import { join } from "node:path";
import { rm, readdir, unlink } from "node:fs/promises";
import { existsSync } from "node:fs";

const STORAGE_DIR = process.env.STORAGE_DIR || join(process.cwd(), "storage");
const DB_PATH = join(STORAGE_DIR, "agentregistry.db");

// Only keep these packages (case-insensitive match)
const WHITELIST = ["signalbus", "microui"];

console.log(`☢️  AGGRESSIVE CLEANUP - Only keeping: ${WHITELIST.join(", ")}`);
console.log(`   Database: ${DB_PATH}`);

async function nuke() {
    if (!existsSync(DB_PATH)) {
        console.log("ℹ️  Database not found. Nothing to clean.");
        return;
    }

    const db = new Database(DB_PATH);

    // 1. Get all packages
    const allPackages = db.prepare("SELECT name FROM packages").all() as { name: string }[];
    console.log(`📦 Found ${allPackages.length} packages in database`);

    // 2. Filter to delete (anything not in whitelist)
    const toDelete = allPackages.filter(p =>
        !WHITELIST.some(w => p.name.toLowerCase() === w.toLowerCase())
    );

    console.log(`🗑️  Deleting ${toDelete.length} packages...`);

    // 3. Delete from packages table
    for (const pkg of toDelete) {
        db.prepare("DELETE FROM packages WHERE name = ?").run(pkg.name);
        console.log(`   - Deleted: ${pkg.name}`);
    }

    // 4. Clean up scan_results for deleted packages
    const scanCleanup = db.prepare(`
        DELETE FROM scan_results 
        WHERE package_name NOT IN (${WHITELIST.map(() => "?").join(", ")})
    `).run(...WHITELIST);
    console.log(`   - Cleaned ${scanCleanup.changes} scan results`);

    // 5. Vacuum
    console.log("   Running VACUUM...");
    db.exec("VACUUM");
    db.close();

    // 6. Clean filesystem (tarballs and packages directories)
    console.log("🧹 Cleaning filesystem...");
    await cleanDir(join(STORAGE_DIR, "packages"), (f) =>
        !WHITELIST.some(w => f.toLowerCase().startsWith(w.toLowerCase().replace("/", "-").replace("@", "")))
    );
    await cleanDir(join(STORAGE_DIR, "tarballs"), (f) =>
        !WHITELIST.some(w => f.toLowerCase().startsWith(w.toLowerCase().replace("/", "-").replace("@", "")))
    );
    await cleanDir(join(STORAGE_DIR, "quarantine"), () => true); // Clear all quarantine

    // 7. Clean up any leftover test-storage directories
    const cwd = process.cwd();
    const entries = await readdir(cwd);
    for (const entry of entries) {
        if (entry.startsWith("test-storage-")) {
            console.log(`   - Removing leftover test dir: ${entry}`);
            await rm(join(cwd, entry), { recursive: true, force: true }).catch(() => { });
        }
    }

    console.log("✨ Cleanup complete. Only whitelisted packages remain.");
}

async function cleanDir(path: string, shouldDelete: (name: string) => boolean) {
    if (!existsSync(path)) return;

    try {
        const files = await readdir(path);
        let deleted = 0;

        for (const file of files) {
            if (shouldDelete(file)) {
                await unlink(join(path, file)).catch(() => { });
                deleted++;
            }
        }

        if (deleted > 0) {
            console.log(`   - Deleted ${deleted} files from ${path}`);
        }
    } catch (e) {
        console.error(`   Error cleaning ${path}:`, e);
    }
}

nuke().catch(console.error);
