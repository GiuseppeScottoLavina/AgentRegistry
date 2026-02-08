import { readdir, rm } from "node:fs/promises";
import { join } from "node:path";

const STORAGE_DIR = join(process.cwd(), "storage");
const PACKAGES_DIR = join(STORAGE_DIR, "packages");
const TARBALLS_DIR = join(STORAGE_DIR, "tarballs");
const BACKUPS_DIR = join(STORAGE_DIR, "backups");

async function cleanup() {
    console.log("🧹 Starting cleanup of test packages...");

    // Test run ID pattern: t[timestamp][random] (e.g., t123abc-package)
    // Also cleaning up specific test names seen in logs
    const explicitTestNames = [
        "test-lib", "multi-version", "time-test", "desc-test",
        "rapid-test", "integrity-test", "disposition-test",
        "clean-test", "dup-test", "unpub-test", "list-test",
        "tarball-test", "prerelease-pkg", "metadata-test"
    ];

    const isTestPackage = (name) => {
        return name.startsWith("t") && name.includes("-") && /\d/.test(name.split("-")[0]) || // heuristic for t[timestamp]
            explicitTestNames.some(t => name.includes(t));
    };

    // Clean packages
    if (await exists(PACKAGES_DIR)) {
        const files = await readdir(PACKAGES_DIR);
        for (const file of files) {
            if (isTestPackage(file.replace(".json", ""))) {
                console.log(`🗑️  Deleting package manifest: ${file}`);
                await rm(join(PACKAGES_DIR, file));
            }
        }
    }

    // Clean tarballs
    if (await exists(TARBALLS_DIR)) {
        const files = await readdir(TARBALLS_DIR);
        for (const file of files) {
            if (isTestPackage(file)) {
                console.log(`🗑️  Deleting tarball: ${file}`);
                await rm(join(TARBALLS_DIR, file));
            }
        }
    }

    // Clean backups
    if (await exists(BACKUPS_DIR)) {
        const files = await readdir(BACKUPS_DIR);
        for (const file of files) {
            if (isTestPackage(file)) {
                console.log(`🗑️  Deleting backup: ${file}`);
                await rm(join(BACKUPS_DIR, file));
            }
        }
    }

    console.log("✨ Cleanup complete.");
}

async function exists(path) {
    try {
        await readdir(path);
        return true;
    } catch {
        return false;
    }
}

cleanup().catch(console.error);
