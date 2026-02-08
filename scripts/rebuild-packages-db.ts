#!/usr/bin/env bun
/**
 * Rebuild packages table from filesystem JSON files
 * 
 * Usage: bun run scripts/rebuild-packages-db.ts
 */

import { Database } from "bun:sqlite";
import { readdirSync, readFileSync } from "fs";
import { join } from "path";

const STORAGE_DIR = process.env.STORAGE_DIR || "/tmp/agentregistry-storage";
const DB_PATH = join(STORAGE_DIR, "agentregistry.db");
const PACKAGES_DIR = join(STORAGE_DIR, "packages");

console.log("🔧 AgentRegistry Database Rebuild Tool");
console.log(`   Storage: ${STORAGE_DIR}`);
console.log(`   Database: ${DB_PATH}`);
console.log("");

const db = new Database(DB_PATH);

// Get existing packages in DB
const existingPackages = new Set<string>(
    db.query("SELECT name FROM packages").all().map((row: any) => row.name)
);

console.log(`📦 Existing packages in DB: ${existingPackages.size}`);

// Read all package JSON files from filesystem
const files = readdirSync(PACKAGES_DIR).filter(f => f.endsWith('.json'));
console.log(`📁 Package files on filesystem: ${files.length}`);

let added = 0;
let skipped = 0;
let errors = 0;

// Use correct schema: metadata column, not data
const insertStmt = db.prepare(`
    INSERT OR REPLACE INTO packages (name, metadata, _source, version_count, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?)
`);

for (const file of files) {
    try {
        const filePath = join(PACKAGES_DIR, file);
        const content = readFileSync(filePath, 'utf-8');
        const pkg = JSON.parse(content);

        const name = pkg.name || decodeURIComponent(file.replace('.json', ''));

        // Skip test packages
        if (name.startsWith('broadcast-test') || name.startsWith('pkg-') || name.startsWith('test-pkg-')) {
            skipped++;
            continue;
        }

        // Determine source: local if published locally, upstream if from npmjs
        const source = pkg._agentregistry?.local ? 'local' : 'upstream';
        const versionCount = Object.keys(pkg.versions || {}).length;
        const createdAt = pkg.time?.created || new Date().toISOString();
        const updatedAt = pkg.time?.modified || createdAt;

        insertStmt.run(name, content, source, versionCount, createdAt, updatedAt);

        if (!existingPackages.has(name)) {
            added++;
            console.log(`  ✅ Added: ${name}`);
        }
    } catch (e: any) {
        errors++;
        console.log(`  ❌ Error with ${file}: ${e.message}`);
    }
}

// Final stats
const finalCount = db.query("SELECT COUNT(*) as count FROM packages").get() as { count: number };
const localCount = db.query("SELECT COUNT(*) as count FROM packages WHERE _source = 'local'").get() as { count: number };
const upstreamCount = db.query("SELECT COUNT(*) as count FROM packages WHERE _source = 'upstream'").get() as { count: number };

console.log("");
console.log("📊 Results:");
console.log(`   Previously in DB: ${existingPackages.size}`);
console.log(`   Added: ${added}`);
console.log(`   Skipped (test packages): ${skipped}`);
console.log(`   Errors: ${errors}`);
console.log(`   Total now in DB: ${finalCount.count}`);
console.log(`     - Local: ${localCount.count}`);
console.log(`     - Upstream: ${upstreamCount.count}`);
console.log("");
console.log("✅ Database rebuild complete!");

db.close();
