/**
 * AgentRegistry MCP Server
 * 
 * Model Context Protocol server that exposes AgentRegistry operations as tools
 * for AI agents like Claude, GPT, etc.
 * 
 * Usage:
 *   bun run mcp-server/index.ts
 * 
 * Then configure your MCP client (e.g., Claude Desktop) to connect to this server.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
    CallToolRequestSchema,
    ListToolsRequestSchema,
    ListResourcesRequestSchema,
    ReadResourceRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

const AGENTREGISTRY_URL = process.env.AGENTREGISTRY_URL || "http://localhost:4873";

// Create MCP server
const server = new Server(
    {
        name: "agentregistry",
        version: "0.1.0",
    },
    {
        capabilities: {
            tools: {},
            resources: {},
        },
    }
);

// ============================================================================
// TOOLS
// ============================================================================

server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
        tools: [
            {
                name: "publish_package",
                description: "Publish a package to the local AgentRegistry registry. The package will be security-scanned automatically.",
                inputSchema: {
                    type: "object",
                    properties: {
                        name: {
                            type: "string",
                            description: "Package name (e.g., 'my-package' or '@scope/name')"
                        },
                        version: {
                            type: "string",
                            description: "Semver version (e.g., '1.0.0')"
                        },
                        main: {
                            type: "string",
                            description: "Main entry point file",
                            default: "index.js"
                        },
                        code: {
                            type: "string",
                            description: "JavaScript code content for the package"
                        },
                        description: {
                            type: "string",
                            description: "Package description"
                        },
                        dependencies: {
                            type: "object",
                            description: "Package dependencies as { name: version }",
                            additionalProperties: { type: "string" }
                        }
                    },
                    required: ["name", "version", "code"]
                }
            },
            {
                name: "get_package",
                description: "Get metadata for a package from the registry, including all versions and dist-tags",
                inputSchema: {
                    type: "object",
                    properties: {
                        name: {
                            type: "string",
                            description: "Package name"
                        }
                    },
                    required: ["name"]
                }
            },
            {
                name: "search_packages",
                description: "Search for packages by name or description. Returns both local and upstream results.",
                inputSchema: {
                    type: "object",
                    properties: {
                        query: {
                            type: "string",
                            description: "Search query"
                        },
                        limit: {
                            type: "number",
                            description: "Maximum results to return",
                            default: 10
                        }
                    },
                    required: ["query"]
                }
            },
            {
                name: "list_local_packages",
                description: "List all packages published to the local registry",
                inputSchema: {
                    type: "object",
                    properties: {}
                }
            },
            {
                name: "get_server_stats",
                description: "Get AgentRegistry server statistics including memory usage, package counts, and scan results",
                inputSchema: {
                    type: "object",
                    properties: {}
                }
            },
            {
                name: "check_quarantine",
                description: "Check if there are any packages blocked in quarantine that need human review",
                inputSchema: {
                    type: "object",
                    properties: {}
                }
            }
        ]
    };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    try {
        switch (name) {
            case "publish_package": {
                const { name: pkgName, version, main = "index.js", code, description = "", dependencies = {} } = args as any;

                // Create tarball content (simplified - in production, use proper npm pack)
                const packageJson = {
                    name: pkgName,
                    version,
                    main,
                    description,
                    dependencies
                };

                // Create a minimal tarball structure
                const tarballContent = Buffer.from(JSON.stringify({ code, packageJson })).toString("base64");

                const payload = {
                    name: pkgName,
                    versions: {
                        [version]: {
                            name: pkgName,
                            version,
                            main,
                            description,
                            dependencies,
                            dist: {
                                tarball: `${AGENTREGISTRY_URL}/${pkgName}/-/${pkgName}-${version}.tgz`
                            }
                        }
                    },
                    "dist-tags": { latest: version },
                    _attachments: {
                        [`${pkgName}-${version}.tgz`]: {
                            data: tarballContent
                        }
                    }
                };

                const response = await fetch(`${AGENTREGISTRY_URL}/${pkgName}`, {
                    method: "PUT",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(payload)
                });

                const result = await response.json();

                if (!response.ok) {
                    return {
                        content: [{
                            type: "text",
                            text: `Failed to publish: ${JSON.stringify(result)}`
                        }],
                        isError: true
                    };
                }

                return {
                    content: [{
                        type: "text",
                        text: `✅ Published ${pkgName}@${version} successfully!\n\nInstall with: npm install ${pkgName} --registry ${AGENTREGISTRY_URL}`
                    }]
                };
            }

            case "get_package": {
                const { name: pkgName } = args as any;
                const response = await fetch(`${AGENTREGISTRY_URL}/${pkgName}`);

                if (!response.ok) {
                    return {
                        content: [{
                            type: "text",
                            text: `Package '${pkgName}' not found`
                        }],
                        isError: true
                    };
                }

                const pkg = await response.json();
                const versions = Object.keys(pkg.versions || {});
                const latest = pkg["dist-tags"]?.latest || versions[versions.length - 1];

                return {
                    content: [{
                        type: "text",
                        text: `📦 ${pkg.name}\n\nDescription: ${pkg.description || "No description"}\nLatest: ${latest}\nVersions: ${versions.join(", ")}\n\nDependencies:\n${JSON.stringify(pkg.versions?.[latest]?.dependencies || {}, null, 2)}`
                    }]
                };
            }

            case "search_packages": {
                const { query, limit = 10 } = args as any;
                const response = await fetch(`${AGENTREGISTRY_URL}/-/v1/search?text=${encodeURIComponent(query)}&size=${limit}`);
                const results = await response.json();

                if (!results.objects?.length) {
                    return {
                        content: [{
                            type: "text",
                            text: `No packages found for "${query}"`
                        }]
                    };
                }

                const formatted = results.objects.map((obj: any) => {
                    const p = obj.package;
                    const local = p.isLocal ? "🏠 LOCAL" : "☁️ UPSTREAM";
                    return `${local} ${p.name}@${p.version} - ${p.description || "No description"}`;
                }).join("\n");

                return {
                    content: [{
                        type: "text",
                        text: `🔍 Search results for "${query}":\n\n${formatted}`
                    }]
                };
            }

            case "list_local_packages": {
                // Use the admin API to get local packages
                const adminRes = await fetch(`${AGENTREGISTRY_URL}/-/admin`);
                const html = await adminRes.text();
                const tokenMatch = html.match(/ADMIN_SESSION_TOKEN\s*=\s*['"]([^'"]+)['"]/);

                if (!tokenMatch) {
                    return {
                        content: [{
                            type: "text",
                            text: "Could not get admin token. Is AgentRegistry running?"
                        }],
                        isError: true
                    };
                }

                // For now, just return a message about using the admin panel
                return {
                    content: [{
                        type: "text",
                        text: `To see all local packages, visit: ${AGENTREGISTRY_URL}/-/admin\n\nOr search for packages using the search_packages tool.`
                    }]
                };
            }

            case "get_server_stats": {
                const response = await fetch(`${AGENTREGISTRY_URL}/-/health`);
                const health = await response.json();

                return {
                    content: [{
                        type: "text",
                        text: `📊 AgentRegistry Server Stats\n\nStatus: ${health.status}\nUptime: ${health.uptime?.human || "Unknown"}\nPackages: ${health.packages?.local || 0} local, ${health.packages?.cached || 0} cached\nMemory: ${health.memory?.heapUsed || "Unknown"}\nScans: ${health.security?.totalScans || 0} total, ${health.security?.blocked || 0} blocked`
                    }]
                };
            }

            case "check_quarantine": {
                const statsRes = await fetch(`${AGENTREGISTRY_URL}/-/health`);
                const stats = await statsRes.json();
                const quarantineCount = stats.packages?.quarantine || 0;

                if (quarantineCount === 0) {
                    return {
                        content: [{
                            type: "text",
                            text: "✅ No packages in quarantine. All clear!"
                        }]
                    };
                }

                return {
                    content: [{
                        type: "text",
                        text: `⚠️ ${quarantineCount} package(s) in quarantine need human review!\n\nVisit: ${AGENTREGISTRY_URL}/-/admin\nGo to: Quarantine tab\n\nThese packages failed security scanning and require manual approval before they can be used.`
                    }]
                };
            }

            default:
                return {
                    content: [{
                        type: "text",
                        text: `Unknown tool: ${name}`
                    }],
                    isError: true
                };
        }
    } catch (error) {
        return {
            content: [{
                type: "text",
                text: `Error: ${error instanceof Error ? error.message : String(error)}`
            }],
            isError: true
        };
    }
});

// ============================================================================
// RESOURCES
// ============================================================================

server.setRequestHandler(ListResourcesRequestSchema, async () => {
    return {
        resources: [
            {
                uri: "agentregistry://capabilities",
                name: "AgentRegistry Capabilities",
                description: "Full list of AgentRegistry capabilities and tool definitions",
                mimeType: "application/json"
            },
            {
                uri: "agentregistry://stats",
                name: "Server Statistics",
                description: "Current server statistics and health status",
                mimeType: "application/json"
            }
        ]
    };
});

server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
    const { uri } = request.params;

    switch (uri) {
        case "agentregistry://capabilities": {
            const response = await fetch(`${AGENTREGISTRY_URL}/-/capabilities`);
            const capabilities = await response.json();
            return {
                contents: [{
                    uri,
                    mimeType: "application/json",
                    text: JSON.stringify(capabilities, null, 2)
                }]
            };
        }

        case "agentregistry://stats": {
            const response = await fetch(`${AGENTREGISTRY_URL}/-/health`);
            const stats = await response.json();
            return {
                contents: [{
                    uri,
                    mimeType: "application/json",
                    text: JSON.stringify(stats, null, 2)
                }]
            };
        }

        default:
            throw new Error(`Unknown resource: ${uri}`);
    }
});

// ============================================================================
// START SERVER
// ============================================================================

async function main() {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error("AgentRegistry MCP Server running on stdio");
}

main().catch(console.error);
