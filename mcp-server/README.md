# AgentRegistry MCP Server

Model Context Protocol (MCP) server that exposes AgentRegistry operations as tools for AI agents.

## Quick Start

1. **Install dependencies**:
```bash
cd mcp-server
bun install
```

2. **Run the server** (after starting AgentRegistry registry):
```bash
bun run start
```

## Claude Desktop Configuration

Add this to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "agentregistry": {
      "command": "bun",
      "args": ["run", "/path/to/AgentRegistry/mcp-server/index.ts"],
      "env": {
        "AGENTREGISTRY_URL": "http://localhost:4873"
      }
    }
  }
}
```

## Available Tools

| Tool | Description |
|------|-------------|
| `publish_package` | Publish a package with automatic security scanning |
| `get_package` | Get package metadata and versions |
| `search_packages` | Search local and upstream packages |
| `list_local_packages` | List all locally published packages |
| `get_server_stats` | Get server health and statistics |
| `check_quarantine` | Check for blocked packages needing review |

## Available Resources

| Resource | Description |
|----------|-------------|
| `agentregistry://capabilities` | Full server capabilities JSON |
| `agentregistry://stats` | Current server statistics |

## Example Usage (in Claude)

```
"Search for lodash-related packages"
→ Uses search_packages tool

"Publish a new utility package called 'my-utils' version 1.0.0"
→ Uses publish_package tool

"Are there any packages waiting for security review?"
→ Uses check_quarantine tool
```

## Environment Variables

- `AGENTREGISTRY_URL`: AgentRegistry server URL (default: `http://localhost:4873`)
