#!/usr/bin/env bun
/**
 * Build Script for AgentRegistry Admin Panel
 * Minifies inline CSS and JS in admin.html for better performance
 */

import { readFileSync, writeFileSync } from 'fs';
import { join } from 'path';

const ADMIN_HTML_PATH = join(import.meta.dir, '../src/web/admin.html');
const OUTPUT_PATH = join(import.meta.dir, '../src/web/admin.html');

// Simple CSS minification (remove comments, whitespace)
function minifyCSS(css: string): string {
    return css
        // Remove comments
        .replace(/\/\*[\s\S]*?\*\//g, '')
        // Remove newlines and multiple spaces
        .replace(/\s*\n\s*/g, '')
        // Remove spaces around special characters
        .replace(/\s*([{};:,>~+])\s*/g, '$1')
        // Remove trailing semicolons before closing braces
        .replace(/;}/g, '}')
        // Remove leading/trailing whitespace
        .trim();
}

// Simple JS minification (removes comments and extra whitespace)
function minifyJS(js: string): string {
    try {
        let minified = js
            // Remove multi-line comments
            .replace(/\/\*[\s\S]*?\*\//g, '')
            // Remove single-line comments (but not URLs)
            .replace(/^\s*\/\/.*$/gm, '')
            // Collapse multiple newlines
            .replace(/\n\s*\n/g, '\n')
            // Remove leading whitespace on each line
            .replace(/^\s+/gm, '')
            // Collapse multiple spaces
            .replace(/\s{2,}/g, ' ')
            .trim();

        return minified;
    } catch (e) {
        console.error('JS minification warning:', e);
        return js;
    }
}

async function build() {
    console.log('🔨 Building AgentRegistry Admin Panel...\n');

    let html = readFileSync(ADMIN_HTML_PATH, 'utf-8');
    const originalSize = Buffer.byteLength(html, 'utf-8');

    // Extract and minify inline CSS
    const styleRegex = /<style>([\s\S]*?)<\/style>/g;
    let cssMatches = 0;
    let cssSaved = 0;

    html = html.replace(styleRegex, (match, cssContent) => {
        const original = cssContent.length;
        const minified = minifyCSS(cssContent);
        cssSaved += original - minified.length;
        cssMatches++;
        return `<style>${minified}</style>`;
    });

    // Extract and minify inline JS
    const scriptRegex = /<script(?!.*src=)>([\s\S]*?)<\/script>/g;
    let jsMatches = 0;
    let jsSaved = 0;

    const matches = [...html.matchAll(scriptRegex)];
    for (const match of matches) {
        const original = match[1].length;
        const minified = minifyJS(match[1]);
        jsSaved += original - minified.length;
        jsMatches++;
        html = html.replace(match[0], `<script>${minified}</script>`);
    }

    // Remove HTML comments (but keep conditional comments)
    html = html.replace(/<!--(?!\[if)[\s\S]*?-->/g, '');

    // Collapse multiple newlines
    html = html.replace(/\n\s*\n/g, '\n');

    const finalSize = Buffer.byteLength(html, 'utf-8');
    const totalSaved = originalSize - finalSize;

    writeFileSync(OUTPUT_PATH, html);

    console.log(`📊 Build Stats:`);
    console.log(`   CSS blocks minified: ${cssMatches}`);
    console.log(`   CSS bytes saved: ${cssSaved.toLocaleString()}`);
    console.log(`   JS blocks minified: ${jsMatches}`);
    console.log(`   JS bytes saved: ${jsSaved.toLocaleString()}`);
    console.log(`\n   Original size: ${originalSize.toLocaleString()} bytes`);
    console.log(`   Final size:    ${finalSize.toLocaleString()} bytes`);
    console.log(`   Total saved:   ${totalSaved.toLocaleString()} bytes (${((totalSaved / originalSize) * 100).toFixed(1)}%)`);
    console.log(`\n✅ Build complete!`);
}

build().catch(console.error);
