#!/usr/bin/env bun
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
 * AgentRegistry CLI
 * 
 * Command-line interface for daemon control.
 * 
 * Usage:
 *   agentregistry start   - Start daemon in background
 *   agentregistry stop    - Stop running daemon
 *   agentregistry status  - Show daemon status
 *   agentregistry logs    - Tail log file
 *   agentregistry restart - Restart daemon
 * 
 * @module cli
 */

import { spawn } from "bun";
import {
    isDaemonRunning,
    stopDaemon,
    getDaemonUptime,
    ensureDaemonDirs
} from "./daemon";
import { tailLogs } from "./logger";
import { PORT, PID_FILE, LOG_FILE } from "./config";
import { formatUptime } from "./utils";
import { generateTSLib } from "./templates/ts-lib";
import { stat, mkdir, rm, writeFile, readFile, copyFile, unlink, readdir } from "node:fs/promises";
import { join } from "node:path";
import { homedir, tmpdir, platform } from "node:os";
import { scanTarball } from "./security";
import { deepScanFiles, type DeepScanFinding } from "./ast-scanner";
import { TARBALLS_DIR, STORAGE_DIR } from "./config";
import * as tar from "tar";

// ============================================================================
// Helpers
// ============================================================================

function printHelp(): void {
    console.log(`
🚀 AgentRegistry CLI

Usage:
  agentregistry <command>

Commands:
  start     Start AgentRegistry daemon in background
  stop      Stop running daemon gracefully
  details   Show configuration details
  doctor    Diagnose environment issues
  publish   Publish package (resilient mode)
  create    Scaffold a new package (agentregistry create <name>)
  release   Release a new version (agentregistry release [patch|minor|major])
  backup    Create full system backup (zip)
  restore   Restore from backup (agentregistry restore <file>)
  status    Show daemon status (running/stopped, PID, uptime)
  logs      Show recent log entries
  restart   Stop and start daemon
  install   Install as macOS launchd service (auto-start on login)
  uninstall Remove launchd service
  scan      Security scan a package (agentregistry scan [--deep] <name@version>)
  help      Show this help message

Options:
  --port <port>   Specify port (default: 4873)

Examples:
  agentregistry start
  agentregistry create my-package
  agentregistry publish
  agentregistry doctor
  agentregistry release minor
  agentregistry status
  agentregistry logs
  agentregistry scan lodash@4.17.21
  agentregistry scan --deep my-package@1.0.0
`);
}

// ============================================================================
// Commands
// ============================================================================

async function dirExists(path: string): Promise<boolean> {
    try {
        await stat(path);
        return true;
    } catch {
        return false;
    }
}

async function cmdCreate(name: string): Promise<void> {
    const targetDir = join(process.cwd(), name);

    if (await dirExists(targetDir)) {
        console.log(`❌ Directory already exists: ${targetDir}`);
        process.exit(1);
    }

    console.log(`✨ Creating package "${name}" in ${targetDir}...`);

    try {
        await generateTSLib(name, targetDir, `http://localhost:${PORT}`);

        console.log(`
✅ Service created successfully!

Next steps:
  cd ${name}
  npm install
  npm run build
  npm publish
`);
    } catch (err: any) {
        console.error(`❌ Failed to create package: ${err.message || err}`);
        process.exit(1);
    }
}

async function cmdRelease(type: string = "patch"): Promise<void> {
    const pkgPath = join(process.cwd(), "package.json");
    if (!(await dirExists(process.cwd())) || !(await Bun.file(pkgPath).exists())) {
        console.log("❌ No package.json found in current directory");
        process.exit(1);
    }

    console.log(`📦 Bumping version (${type})...`);

    // Run npm version
    const versionProc = spawn({
        cmd: ["npm", "version", type],
        stdio: ["inherit", "inherit", "inherit"]
    });

    const versionExit = await versionProc.exited;
    if (versionExit !== 0) {
        console.log("❌ Failed to bump version");
        process.exit(1);
    }

    console.log("🚀 Publishing to AgentRegistry...");

    // Run npm publish
    const publishProc = spawn({
        cmd: ["npm", "publish"],
        stdio: ["inherit", "inherit", "inherit"]
    });

    const publishExit = await publishProc.exited;
    if (publishExit !== 0) {
        console.log("❌ Failed to publish");
        process.exit(1);
    }

    console.log("✅ Released successfully!");
}

async function cmdBackup(): Promise<void> {
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const backupFile = `agentregistry-backup-${timestamp}.zip`;
    const storageDir = "storage"; // Assuming current working dir is root

    console.log(`📦 Creating backup: ${backupFile}...`);

    // Check if storage exists
    if (!await Bun.file(storageDir).exists() && !await dirExists(storageDir)) {
        console.log("❌ Storage directory not found.");
        return;
    }

    // Zip storage
    const proc = spawn({
        cmd: ["zip", "-r", backupFile, storageDir],
        stdio: ["ignore", "inherit", "inherit"]
    });

    const exitCode = await proc.exited;
    if (exitCode === 0) {
        console.log(`✅ Backup created successfully: ${backupFile}`);
    } else {
        console.log("❌ Backup failed. Is 'zip' installed?");
    }
}

async function cmdRestore(archive: string): Promise<void> {
    if (!archive) {
        console.log("❌ Missing backup file. Usage: agentregistry restore <file.zip>");
        process.exit(1);
    }

    if (!await Bun.file(archive).exists()) {
        console.log(`❌ Backup file not found: ${archive}`);
        process.exit(1);
    }

    const { running } = await isDaemonRunning();
    if (running) {
        console.log("⚠️  AgentRegistry daemon is running. Stopping it first...");
        await cmdStop();
    }

    console.log(`♻️  Restoring from ${archive}...`);

    // Unzip
    const proc = spawn({
        cmd: ["unzip", "-o", archive],
        stdio: ["ignore", "inherit", "inherit"]
    });

    const exitCode = await proc.exited;
    if (exitCode === 0) {
        console.log("✅ Restore complete.");
        if (running) {
            console.log("🚀 Restarting daemon...");
            await cmdStart();
        }
    } else {
        console.log("❌ Restore failed. Is 'unzip' installed?");
    }
}

async function cmdStart(): Promise<void> {
    const { running, pid } = await isDaemonRunning();

    if (running) {
        console.log(`⚠️  AgentRegistry is already running (PID: ${pid})`);
        process.exit(1);
    }

    await ensureDaemonDirs();

    console.log("🚀 Starting AgentRegistry daemon...");

    // Get port from args if specified
    const portIdx = Bun.argv.indexOf("--port");
    const portArg = portIdx !== -1 ? ["--port", Bun.argv[portIdx + 1]] : [];

    // Use /usr/bin/env to find bun (more robust for compiled binaries)
    const proc = spawn({
        cmd: ["/usr/bin/env", "bun", "run", "server.ts", "--daemon", ...portArg],
        cwd: import.meta.dir,
        stdout: "ignore",
        stderr: "ignore",
        stdin: "ignore",
        detached: true,  // True daemon: survives shell/terminal closure
        env: process.env,  // Inherit environment (PATH, HOME, etc.)
    });

    // Detach from parent
    proc.unref();

    // Wait a bit for startup
    await Bun.sleep(1000);

    const { running: nowRunning, pid: newPid } = await isDaemonRunning();

    if (nowRunning) {
        console.log(`✅ AgentRegistry started successfully`);
        console.log(`   PID: ${newPid}`);
        console.log(`   URL: http://localhost:${PORT}`);
        console.log(`   Admin: http://localhost:${PORT}/-/admin`);
        console.log(`   Logs: ${LOG_FILE}`);
    } else {
        console.log("❌ Failed to start AgentRegistry");
        console.log(`   Check logs at: ${LOG_FILE}`);
        process.exit(1);
    }
}

async function cmdStop(): Promise<void> {
    const { running, pid } = await isDaemonRunning();

    if (!running) {
        console.log("⚠️  AgentRegistry is not running");
        process.exit(1);
    }

    console.log(`🛑 Stopping AgentRegistry (PID: ${pid})...`);

    const stopped = await stopDaemon();

    if (stopped) {
        console.log("✅ AgentRegistry stopped successfully");
    } else {
        console.log("❌ Failed to stop AgentRegistry");
        process.exit(1);
    }
}

async function cmdStatus(): Promise<void> {
    const { running, pid } = await isDaemonRunning();

    if (running && pid) {
        const uptime = await getDaemonUptime();
        console.log("🟢 AgentRegistry is running");
        console.log(`   PID: ${pid}`);
        console.log(`   PID File: ${PID_FILE}`);
        if (uptime) {
            console.log(`   Uptime: ${formatUptime(uptime)}`);
        }
        console.log(`   URL: http://localhost:${PORT}`);
        console.log(`   Admin: http://localhost:${PORT}/-/admin`);

        // Try to ping the server
        try {
            const res = await fetch(`http://localhost:${PORT}/-/ping`, {
                signal: AbortSignal.timeout(2000)
            });
            if (res.ok) {
                console.log("   Health: ✅ Responding");
            } else {
                console.log("   Health: ⚠️  Not responding properly");
            }
        } catch {
            console.log("   Health: ❌ Not responding");
        }
    } else {
        console.log("🔴 AgentRegistry is not running");
        console.log(`   PID File: ${PID_FILE} (not found)`);
    }
}

async function cmdDoctor(): Promise<void> {
    console.log("🩺 Running diagnostics...");
    let issues = 0;

    // 1. Check Server Connectivity
    try {
        const res = await fetch(`http://localhost:${PORT}/-/ping`, {
            signal: AbortSignal.timeout(2000)
        });
        if (res.ok) {
            console.log("✅ Registry server: Online");
        } else {
            console.log("❌ Registry server: Error (HTTP " + res.status + ")");
            issues++;
        }
    } catch {
        console.log("❌ Registry server: Unreachable (is it running?)");
        issues++;
    }

    // 2. Check File Permissions (~/.npm)
    const npmDir = join(homedir(), ".npm");
    try {
        const info = await stat(npmDir);
        const currentUid = process.getuid ? process.getuid() : -1;

        if (currentUid !== -1 && info.uid === 0 && currentUid !== 0) {
            console.log("❌ ~/.npm permission: Owned by ROOT (Critical)");
            console.log("   This causes EPERM errors during publish.");
            issues++;
        } else {
            // Check _cacache permissions if deeper
            const cacheDir = join(npmDir, "_cacache");
            try {
                const cacheInfo = await stat(cacheDir);
                if (currentUid !== -1 && cacheInfo.uid === 0 && currentUid !== 0) {
                    console.log("❌ ~/.npm/_cacache permission: Owned by ROOT (Critical)");
                    issues++;
                } else {
                    console.log("✅ ~/.npm permissions: OK");
                }
            } catch {
                console.log("✅ ~/.npm permissions: OK (Cache empty)");
            }
        }
    } catch {
        console.log("ℹ️  ~/.npm: Not found (Safe)");
    }

    // 3. Summary
    if (issues > 0) {
        console.log("\n⚠️  Issues detected!");
        if (issues > 0) {
            console.log("\nSuggested Fix:");
            console.log("  sudo chown -R $(whoami) ~/.npm");
        }
    } else {
        console.log("\n✨ System is healthy!");
    }
}

async function cmdPublish(npmArgs: string[]): Promise<void> {
    // Check if package.json exists
    if (!await Bun.file("package.json").exists()) {
        console.log("❌ No package.json found in current directory");
        process.exit(1);
    }

    const tempCache = join(tmpdir(), `agentregistry-publish-${Date.now()}`);
    console.log(`🛡️  Sandboxed Publish Mode`);
    console.log(`   Temp Cache: ${tempCache}`);
    console.log(`   Registry: http://localhost:${PORT}`);

    // Create temp dir
    await mkdir(tempCache, { recursive: true });

    try {
        // Run npm publish using temp cache to bypass corrupted local cache
        const cmd = ["npm", "publish",
            "--registry", `http://localhost:${PORT}`,
            "--cache", tempCache,
            ...npmArgs
        ];

        const proc = spawn({
            cmd: cmd,
            stdio: ["inherit", "inherit", "inherit"]
        });

        const exitCode = await proc.exited;

        if (exitCode === 0) {
            console.log("\n✅ Published successfully!");
        } else {
            console.log(`\n❌ Publish failed (Exit code: ${exitCode})`);
            process.exit(exitCode);
        }
    } catch (err: any) {
        console.error(`❌ Error : ${err.message}`);
    } finally {
        // Cleanup
        try {
            await rm(tempCache, { recursive: true, force: true });
        } catch { /* ignore cleanup error */ }
    }
}

async function cmdLogs(): Promise<void> {
    const lines = await tailLogs(50);

    if (lines.length === 0) {
        console.log("📝 No log entries found");
        console.log(`   Log file: ${LOG_FILE}`);
        return;
    }

    console.log(`📝 Last ${lines.length} log entries:\n`);

    for (const line of lines) {
        try {
            const entry = JSON.parse(line);
            const level = entry.level?.toUpperCase().padEnd(5) || "INFO ";
            const colorMap: Record<string, string> = {
                DEBUG: "\x1b[90m",
                INFO: "\x1b[36m",
                WARN: "\x1b[33m",
                ERROR: "\x1b[31m"
            };
            const color = colorMap[(entry.level || "INFO").toUpperCase()] || "\x1b[0m";

            console.log(`${color}[${entry.timestamp}] ${level}\x1b[0m ${entry.message}`);
        } catch {
            // Not JSON, print raw
            console.log(line);
        }
    }
}

async function cmdRestart(): Promise<void> {
    const { running } = await isDaemonRunning();

    if (running) {
        await cmdStop();
        await Bun.sleep(500);
    }

    await cmdStart();
}

// ============================================================================
// Helpers: recursive directory copy
// ============================================================================

async function copyDir(src: string, dest: string): Promise<void> {
    await mkdir(dest, { recursive: true });
    const entries = await readdir(src, { withFileTypes: true });
    for (const entry of entries) {
        const srcPath = join(src, entry.name);
        const destPath = join(dest, entry.name);
        if (entry.name === "node_modules" || entry.name === ".git") continue;
        if (entry.isDirectory()) {
            await copyDir(srcPath, destPath);
        } else {
            await copyFile(srcPath, destPath);
        }
    }
}

// ============================================================================
// Launchd Install/Uninstall (macOS only)
// ============================================================================

const LAUNCHD_LABEL = "com.agentregistry.daemon";
const LAUNCHD_PLIST = `${homedir()}/Library/LaunchAgents/${LAUNCHD_LABEL}.plist`;

async function cmdInstall(): Promise<void> {
    // OS Detection
    const os = platform();
    if (os !== "darwin") {
        console.log(`❌ This command is only available on macOS`);
        console.log(`   Current platform: ${os}`);
        console.log(``);
        console.log(`   For Linux, use systemd instead:`);
        console.log(`     sudo systemctl enable agentregistry`);
        console.log(`   For Windows, use Task Scheduler or NSSM`);
        process.exit(1);
    }

    console.log("🔧 Installing AgentRegistry as launchd service...");

    // Check if already installed
    try {
        await stat(LAUNCHD_PLIST);
        console.log(`⚠️  Already installed at ${LAUNCHD_PLIST}`);
        console.log(`   Run 'agentregistry uninstall' first to reinstall`);
        process.exit(1);
    } catch {
        // Not installed, continue
    }

    const home = homedir();
    const bunPath = Bun.which("bun") || `${home}/.bun/bin/bun`;
    const appDir = `${home}/.agentregistry/app`;
    const logDir = `${home}/.agentregistry/logs`;
    const projectRoot = join(import.meta.dir, "..");

    // Step 1: Copy app files to ~/.agentregistry/app/
    // This avoids macOS TCC restrictions (launchd can't access ~/Documents, ~/Desktop, etc.)
    console.log("📂 Copying app to ~/.agentregistry/app/ ...");
    try { await rm(appDir, { recursive: true }); } catch { /* first install */ }
    await mkdir(appDir, { recursive: true });
    await mkdir(logDir, { recursive: true });

    const filesToCopy = ["package.json", "tsconfig.json"];
    const dirsToCopy = ["src", "scripts"];

    for (const file of filesToCopy) {
        try {
            await copyFile(join(projectRoot, file), join(appDir, file));
        } catch { /* optional */ }
    }
    for (const dir of dirsToCopy) {
        try {
            await stat(join(projectRoot, dir));
            await copyDir(join(projectRoot, dir), join(appDir, dir));
        } catch { /* optional */ }
    }

    // Step 2: Install dependencies
    console.log("📦 Installing dependencies...");
    const installProc = spawn({
        cmd: [bunPath, "install", "--production"],
        cwd: appDir,
        stdio: ["inherit", "inherit", "inherit"],
        env: { ...process.env, BUN_INSTALL_CACHE_DIR: "/tmp/bun-cache", TMPDIR: "/tmp" }
    });
    const installExit = await installProc.exited;
    if (installExit !== 0) {
        console.log(`❌ Failed to install dependencies (exit code: ${installExit})`);
        process.exit(1);
    }

    // Step 3: Verify server.ts exists
    const serverPath = join(appDir, "src", "server.ts");
    try {
        await stat(serverPath);
    } catch {
        console.log(`❌ server.ts not found at ${serverPath}`);
        process.exit(1);
    }
    console.log(`✅ Server verified: ${serverPath}`);

    // Step 4: Generate plist inline (no template — avoids path bugs)
    const plistContent = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${LAUNCHD_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>-c</string>
        <string>ulimit -n 65536; exec "${bunPath}" run "${serverPath}" --daemon</string>
    </array>
    <key>WorkingDirectory</key>
    <string>${home}/.agentregistry</string>
    <key>SoftResourceLimits</key>
    <dict>
        <key>NumberOfFiles</key>
        <integer>65536</integer>
    </dict>
    <key>HardResourceLimits</key>
    <dict>
        <key>NumberOfFiles</key>
        <integer>65536</integer>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>ThrottleInterval</key>
    <integer>10</integer>
    <key>StandardOutPath</key>
    <string>${logDir}/launchd-stdout.log</string>
    <key>StandardErrorPath</key>
    <string>${logDir}/launchd-stderr.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin:${home}/.bun/bin</string>
        <key>HOME</key>
        <string>${home}</string>
        <key>AGENTREGISTRY_HOME</key>
        <string>${home}/.agentregistry</string>
    </dict>
</dict>
</plist>`;

    // Step 5: Write plist and load
    const launchAgentsDir = `${home}/Library/LaunchAgents`;
    await mkdir(launchAgentsDir, { recursive: true });
    await writeFile(LAUNCHD_PLIST, plistContent);
    console.log(`✅ Created ${LAUNCHD_PLIST}`);

    console.log("🚀 Loading service...");
    const loadProc = spawn({
        cmd: ["launchctl", "load", LAUNCHD_PLIST],
        stdio: ["inherit", "inherit", "inherit"]
    });
    const loadExit = await loadProc.exited;
    if (loadExit !== 0) {
        console.log(`❌ Failed to load service (exit code: ${loadExit})`);
        process.exit(1);
    }

    // Step 6: Health check
    console.log("⏳ Waiting for server startup...");
    let healthy = false;
    for (let i = 0; i < 6; i++) {
        await new Promise(r => setTimeout(r, 1000));
        try {
            const res = await fetch("http://localhost:4873/-/ping");
            if (res.ok) { healthy = true; break; }
        } catch { /* not ready yet */ }
    }

    if (healthy) {
        console.log(`\n✅ AgentRegistry is running!\n\n   🌐 Admin Panel: http://localhost:4873/-/admin\n   📦 Registry:    http://localhost:4873\n   🔄 Auto-start:  On login\n   🛡️  KeepAlive:   Restarts on crash\n   📝 Logs:        ${logDir}\n   📂 App:         ${appDir}\n\n   Commands:\n     agentregistry status     # Check status\n     agentregistry stop       # Stop server\n     agentregistry uninstall  # Remove service\n`);
    } else {
        console.log(`\n⚠️  Service loaded but server not responding yet.\n   Check logs: tail -f ${logDir}/launchd-stderr.log\n`);
    }
}

async function cmdUninstall(): Promise<void> {
    // OS Detection
    const os = platform();
    if (os !== "darwin") {
        console.log(`❌ This command is only available on macOS`);
        console.log(`   Current platform: ${os}`);
        process.exit(1);
    }

    console.log("🔧 Uninstalling AgentRegistry launchd service...");

    // Check if installed
    try {
        await stat(LAUNCHD_PLIST);
    } catch {
        console.log(`⚠️  Not installed (no plist at ${LAUNCHD_PLIST})`);
        process.exit(0);
    }

    // Unload from launchctl
    console.log("📦 Unloading service from launchctl...");
    const unloadProc = spawn({
        cmd: ["launchctl", "unload", LAUNCHD_PLIST],
        stdio: ["inherit", "inherit", "inherit"]
    });
    await unloadProc.exited;

    // Remove plist file
    await unlink(LAUNCHD_PLIST);
    console.log(`✅ Removed ${LAUNCHD_PLIST}`);
    console.log(`
✅ AgentRegistry launchd service uninstalled.
   The daemon will no longer auto-start on login.
   Use 'agentregistry start' for manual control.
`);
}

// ============================================================================
// Scan Command
// ============================================================================

async function cmdScan(args: string[]): Promise<void> {
    // Parse flags
    const deep = args.includes("--deep");
    const packageRef = args.find(a => !a.startsWith("--"));

    if (!packageRef || !packageRef.includes("@")) {
        console.log(`❌ Usage: agentregistry scan [--deep] <name@version>`);
        console.log(`   Example: agentregistry scan lodash@4.17.21`);
        console.log(`   Example: agentregistry scan --deep my-package@1.0.0`);
        process.exit(1);
    }

    // Parse name@version (handle scoped packages like @scope/name@1.0.0)
    const lastAt = packageRef.lastIndexOf("@");
    if (lastAt <= 0) {
        console.log(`❌ Invalid package reference: ${packageRef}`);
        console.log(`   Expected format: name@version or @scope/name@version`);
        process.exit(1);
    }

    const name = packageRef.slice(0, lastAt);
    const version = packageRef.slice(lastAt + 1);

    // Locate tarball
    const safeName = name.replace("/", "-").replace("@", "");
    const tarballPath = join(TARBALLS_DIR, `${safeName}-${version}.tgz`);

    try {
        await stat(tarballPath);
    } catch {
        console.log(`❌ Tarball not found: ${tarballPath}`);
        console.log(`   Make sure the package is published to AgentRegistry.`);
        process.exit(1);
    }

    console.log(`\n🔍 Scanning ${name}@${version}...`);
    console.log(`   Tarball: ${tarballPath}`);
    if (deep) console.log(`   Mode: Deep AST analysis (acorn)`);
    else console.log(`   Mode: Standard (regex-based)`);
    console.log();

    // Standard scan (always runs)
    const scanResult = await scanTarball(tarballPath);

    // Print standard scan results
    const severityColors: Record<string, string> = {
        critical: "\x1b[31m", // red
        high: "\x1b[33m",     // yellow
        medium: "\x1b[36m",   // cyan
        low: "\x1b[90m"       // gray
    };
    const reset = "\x1b[0m";
    const bold = "\x1b[1m";

    console.log(`${bold}━━━ Standard Scan Results ━━━${reset}`);
    console.log(`   Files scanned: ${scanResult.filesScanned}`);
    console.log(`   Time: ${scanResult.scanTimeMs}ms`);
    console.log(`   Status: ${scanResult.safe ? "\x1b[32m✅ SAFE" : "\x1b[31m⚠️  ISSUES FOUND"}${reset}`);

    if (scanResult.issues.length > 0) {
        console.log(`\n   ${bold}Security Issues (${scanResult.issues.length}):${reset}`);
        for (const issue of scanResult.issues) {
            const color = severityColors[issue.severity] || reset;
            console.log(`   ${color}[${issue.severity.toUpperCase()}]${reset} ${issue.description}`);
            if (issue.file) console.log(`            File: ${issue.file}${issue.line ? `:${issue.line}` : ""}`);
        }
    }

    if (scanResult.promptInjections && scanResult.promptInjections.length > 0) {
        console.log(`\n   ${bold}Prompt Injection Risks (${scanResult.promptInjections.length}):${reset}`);
        console.log(`   Risk Score: ${scanResult.piRiskScore ?? 0}/100`);
        for (const pi of scanResult.promptInjections) {
            const color = severityColors[pi.severity] || reset;
            console.log(`   ${color}[${pi.severity.toUpperCase()}]${reset} ${pi.pattern} — ${pi.matched}`);
            if (pi.file) console.log(`            File: ${pi.file}:${pi.line}`);
        }
    }

    // Deep scan (optional)
    if (deep) {
        console.log(`\n${bold}━━━ Deep AST Scan ━━━${reset}`);

        const tempDir = `/tmp/agentregistry-deepscan-${Date.now()}`;
        await mkdir(tempDir, { recursive: true });

        try {
            // Extract tarball
            await tar.x({ file: tarballPath, cwd: tempDir });

            // Collect JS/TS files
            const files = new Map<string, string>();
            const jsExtensions = [".js", ".mjs", ".cjs", ".ts", ".mts", ".cts"];

            async function collectFiles(dir: string, prefix: string = ""): Promise<void> {
                const entries = await readdir(dir, { withFileTypes: true }).catch(() => []);
                for (const entry of entries) {
                    const fullPath = join(dir, entry.name);
                    const relativePath = prefix ? `${prefix}/${entry.name}` : entry.name;
                    if (entry.isDirectory() && entry.name !== "node_modules") {
                        await collectFiles(fullPath, relativePath);
                    } else if (entry.isFile()) {
                        const ext = entry.name.toLowerCase();
                        if (jsExtensions.some(e => ext.endsWith(e))) {
                            try {
                                const info = await stat(fullPath);
                                if (info.size <= 100 * 1024) { // 100KB limit
                                    const content = await readFile(fullPath, "utf-8");
                                    files.set(relativePath, content);
                                }
                            } catch { /* skip */ }
                        }
                    }
                }
            }

            await collectFiles(tempDir);

            console.log(`   Files collected: ${files.size}`);

            // Run deep scan
            const deepResult = deepScanFiles(files);

            console.log(`   Files analyzed: ${deepResult.filesAnalyzed}`);
            console.log(`   Parse errors: ${deepResult.parseErrors}`);
            console.log(`   Time: ${deepResult.scanTimeMs}ms`);

            if (deepResult.findings.length === 0) {
                console.log(`   Status: \x1b[32m✅ No AST-level threats detected${reset}`);
            } else {
                console.log(`   Status: \x1b[31m⚠️  ${deepResult.findings.length} findings${reset}`);
                console.log();

                for (const finding of deepResult.findings) {
                    const color = severityColors[finding.severity] || reset;
                    console.log(`   ${color}[${finding.severity.toUpperCase()}]${reset} ${bold}${finding.pattern}${reset}`);
                    console.log(`            ${finding.description}`);
                    console.log(`            File: ${finding.file}:${finding.line}:${finding.column}`);
                    console.log(`            Code: ${finding.code}`);
                    console.log();
                }
            }
        } finally {
            await rm(tempDir, { recursive: true, force: true });
        }
    }

    // Summary
    console.log(`\n${bold}━━━ Summary ━━━${reset}`);
    const safe = scanResult.safe;
    console.log(`   Overall: ${safe ? "\x1b[32m✅ SAFE" : "\x1b[31m❌ UNSAFE"}${reset}`);
    if (!safe) {
        process.exit(2); // Non-zero exit for CI integration
    }
}

// ============================================================================
// Main
// ============================================================================

async function main(): Promise<void> {
    const args = Bun.argv.slice(2);
    const command = args[0]?.toLowerCase();

    switch (command) {
        case "start":
            await cmdStart();
            break;
        case "stop":
            await cmdStop();
            break;
        case "create":
            if (args.length < 2) {
                console.log("❌ Missing package name. Usage: agentregistry create <name>");
                process.exit(1);
            }
            await cmdCreate(args[1]);
            break;
        case "release":
            await cmdRelease(args[1]);
            break;
        case "backup":
            await cmdBackup();
            break;
        case "restore":
            await cmdRestore(args[1]);
            break;
        case "status":
            await cmdStatus();
            break;
        case "doctor":
            await cmdDoctor();
            break;
        case "publish":
            // Pass all remaining args to npm publish
            await cmdPublish(args.slice(1));
            break;
        case "logs":
        case "log":
            await cmdLogs();
            break;
        case "restart":
            await cmdRestart();
            break;
        case "install":
            await cmdInstall();
            break;
        case "uninstall":
            await cmdUninstall();
            break;
        case "scan":
            await cmdScan(args.slice(1));
            break;
        case "help":
        case "--help":
        case "-h":
        case undefined:
            printHelp();
            break;
        default:
            console.log(`❌ Unknown command: ${command}`);
            console.log("   Run 'agentregistry help' for usage");
            process.exit(1);
    }
}

main().catch(err => {
    console.error("❌ Error:", err.message);
    process.exit(1);
});
