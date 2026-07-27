---
name: palsphere
description: "Check npm and Go packages for known vulnerabilities using OSV API — zero auth, single binary CLI + MCP server."
version: 0.1.0
---

# Palsphere

## When to Use

Before installing, updating, or recommending any npm or Go package, check it with palsphere.

## Usage

```bash
palsphere check <ecosystem> <package> <version>
palsphere suggest <ecosystem> <package>
palsphere compare <ecosystem> <package> <from> <to>
palsphere mcp  # start MCP server
```
