# palsphere


     __       _           
 ___/ /___   / /____  ___ 
/ _  / __ \/ / ___/ / -_)
\__,_/_/ /_/_/_/   /_/\__/ 
                          

Single-binary Rust CLI + MCP server for checking npm and Go packages against known vulnerabilities.

**Zero auth.** Uses OSV API for advisory data. No tokens, no signup, no telemetry.

## Install

```bash
cargo install --git https://github.com/faizalardhi16/palsphere
```

## CLI Usage

```bash
palsphere check npm lodash 4.17.20
palsphere check go golang.org/x/crypto latest
palsphere suggest npm lodash
palsphere compare npm lodash 4.17.20 4.17.21
```

## MCP Server

```bash
palsphere mcp
```

## Report

Reports saved to `.palsphere/reports/` in markdown format.

## License

MIT
