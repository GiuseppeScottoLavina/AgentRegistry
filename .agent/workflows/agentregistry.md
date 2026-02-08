---
description: How to use AgentRegistry to publish and install shared libraries between agents
---

# AgentRegistry - Local Registry for Agents

**Configuration is already GLOBAL** - all projects automatically use AgentRegistry.

## Prerequisites

The AgentRegistry server must be running:
```bash
cd /Users/giuseppescottolavina/Documents/PERSONAL/AgentRegistry && bun run start
```

Verify: `curl http://localhost:4873/-/ping`

---

## Publish a Library

// turbo
1. Ensure `package.json` has unique `name` and `version`

// turbo
2. Publish:
```bash
npm publish
```

3. Verify:
```bash
curl http://localhost:4873/<package-name>
```

---

## Install a Library

// turbo
1. Install from local registry:
```bash
npm install <package-name>
```

---

## Verify Available Libraries

// turbo
1. List packages:
```bash
curl -s http://localhost:4873/ | jq '.packages'
```

// turbo
2. Package info:
```bash
curl -s http://localhost:4873/<package-name> | jq
```

---

## Global Configuration (already active)

The `~/.npmrc` file contains:
```
//localhost:4873/:_authToken="local"
registry=http://localhost:4873
```

To temporarily switch back to official npm:
```bash
npm install <pkg> --registry https://registry.npmjs.org
```
