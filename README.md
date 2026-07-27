<p align="center">
  <img src="https://raw.githubusercontent.com/faizalardhi16/palsphere/main/.github/logo.svg" alt="palsphere" width="120" />
</p>

<h1 align="center">palsphere</h1>

<p align="center">
  <strong>Zero-auth dependency vulnerability scanner for AI agents and developers</strong><br>
  Check npm and Go packages against the OSV database — no API keys, no signup, no telemetry.
</p>

<p align="center">
  <a href="https://crates.io/crates/palsphere"><img src="https://img.shields.io/badge/rust-stable-orange?logo=rust" alt="Rust"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="License"></a>
  <a href="https://github.com/faizalardhi16/palsphere"><img src="https://img.shields.io/badge/binary-2.8MB-green" alt="Size"></a>
</p>

---

## Why palsphere?

AI coding agents like Codex and Claude Code generate dependency install commands constantly — often with outdated or vulnerable versions. **deptrust** pioneered the idea of agent-aware vulnerability checking, and palsphere brings that same protection to the Rust ecosystem: a single static binary with no runtime dependencies, no authentication, and no external service to trust.

> **The problem:** AI agents install `lodash@4.17.20` without checking if it has known CVEs. You ship a vulnerability to production.

> **The solution:** palsphere sits between the agent and the package manager. Before `npm install` or `go get` runs, palsphere checks OSV — the authoritative open-source vulnerability database. If the version is compromised, the install is blocked.

---

## Features

- 🔍 **Check any version** — exact version or `latest`, returns vulnerability count, severity, and risk score
- 🛡️ **Block unsafe installs** — critical/high severity → `BLOCK`, medium → `REVIEW`, low/clean → `ALLOW`
- 🔄 **Suggest safe versions** — walks version history to find the newest installable release
- ⚖️ **Compare two versions** — see what vulnerabilities are resolved or added when upgrading
- 🤖 **MCP server** — native Model Context Protocol support for AI agent integration (Codex, Claude Code, Hermes)
- 📄 **Markdown reports** — every check generates a detailed `.md` report for audit trails
- 🦀 **Single binary** — 2.8MB statically linked, no runtime dependencies, no Node, no Python
- 🔑 **Zero auth** — queries OSV API directly, no tokens, no API keys, no signup, no telemetry

---

## How It Works

```
┌──────────┐     ┌──────────────┐     ┌──────────┐
│ AI Agent │────▶│  palsphere   │────▶│ OSV API  │
│  (MCP)   │     │  (check)     │     │ (advisory)│
└──────────┘     └──────┬───────┘     └──────────┘
                        │
                  ┌─────▼──────┐
                  │  Decision  │
                  │ BLOCK/ALLOW│
                  └─────┬──────┘
                        │
              ┌─────────▼─────────┐
              │ npm install /     │
              │ go get (if safe)  │
              └───────────────────┘
```

1. Agent requests a package → `palsphere check npm lodash latest`
2. palsphere resolves the version and queries [OSV](https://osv.dev) for known vulnerabilities
3. Based on severity, palsphere returns a recommendation: **Block**, **Review**, or **Allow**
4. A markdown report is saved to `.palsphere/reports/` for audit trails
5. The agent (or CI pipeline) acts on the recommendation

---

## Supported Ecosystems

| Ecosystem | Registry | Advisory Source |
|-----------|----------|-----------------|
| **npm** | registry.npmjs.org | OSV (GHSA included) |
| **Go** | proxy.golang.org | OSV (GHSA included) |

> More ecosystems coming: PyPI, Cargo, RubyGems, NuGet, Maven, and more.

---

## Install

### Cargo (recommended)

```bash
cargo install --git https://github.com/faizalardhi16/palsphere
```

This gives you a single `palsphere` binary — no runtime dependencies.

### From source

```bash
git clone https://github.com/faizalardhi16/palsphere
cd palsphere
cargo build --release
./target/release/palsphere --version
```

---

## CLI Usage

### `check` — Scan a package version

```bash
# Check exact version
palsphere check npm lodash 4.17.20

# Check latest version
palsphere check go golang.org/x/crypto latest

# Output:
# 🟡 npm lodash@4.17.20: 5 vulnerabilities found
#   recommendation: Review
#   risk_score: 65/100
#   📄 Report: .palsphere/reports/20260727-092626-npm-lodash-check.md
```

**Exit codes:** `0` = safe/review, `1` = blocked (critical/high severity)

### `suggest` — Find the safest version

```bash
palsphere suggest npm express

# Output:
# express/2.4.7
#   risk_score: 40/100
#   recommendation: Allow
```

Walks versions from newest to oldest, returning the first version with no blocking vulnerabilities.

### `compare` — Audit an upgrade path

```bash
palsphere compare npm lodash 4.17.20 4.17.21

# Output:
# ✅ lodash 4.17.20 → 4.17.21: risk 65/100 → 55/100
#   recommendation: Review
#   next_action: upgrade_to_target
#   resolved: GHSA-35jh-r3h4-6jhm, GHSA-29mw-wpgm-hmr9
```

Shows exactly which vulnerabilities are resolved or introduced by the version change.

### `mcp` — Start MCP server

```bash
palsphere mcp
```

Exposes 3 MCP tools for AI agent integration:
- `check_package` — check a version for vulnerabilities
- `suggest_safe_version` — find the newest safe version
- `compare_versions` — compare two versions

---

## MCP Configuration

Add to your agent's MCP config (`claude_desktop_config.json`, `codex.yaml`, `hermes/config.yaml`):

```json
{
  "mcpServers": {
    "palsphere": {
      "command": "/absolute/path/to/palsphere",
      "args": ["mcp"]
    }
  }
}
```

The MCP server sends `instructions` telling the agent to check packages before installing, updating, or recommending them. No manual reminders needed.

---

## Impact & Use Cases

### For AI Agents

- **Prevent CVE injection** — agents can't install vulnerable packages even if they hallucinate version numbers
- **Audit trail** — every dependency decision generates a markdown report for compliance
- **Token efficient** — compact MCP responses (no full advisory bodies in context) with `full_response_command` for drill-down

### For CI/CD Pipelines

- **Pre-commit hooks** — check dependencies before they enter the codebase
- **PR gate** — block PRs that introduce vulnerable package versions
- **SBOM audit** — generate vulnerability reports as pipeline artifacts

### For Developers

- **Upgrade safely** — `compare` shows exactly what changes in a version bump
- **Find safe versions** — `suggest` eliminates manual version hunting
- **Zero setup** — no GitHub token, no API key, no registration required

---

## Report Format

Every check generates a structured markdown report:

```markdown
# 🟡 Vulnerability Check

| Field | Value |
|-------|-------|
| **Ecosystem** | npm |
| **Package** | `lodash` |
| **Version** | 4.17.20 |
| **Vulnerabilities** | 5 |
| **Highest Severity** | medium |
| **Risk Score** | 65/100 |
| **Recommendation** | **Review** |

## Vulnerabilities

### 1. Regular Expression Denial of Service (ReDoS)
- **ID:** GHSA-29mw-wpgm-hmr9
- **Severity:** medium
- **Fixed in:** 4.17.21
```

Reports are saved to `.palsphere/reports/` with timestamps for audit trails.

---

## Comparison

| | palsphere | deptrust | npm audit | govulncheck |
|---|---|---|---|---|
| **Runtime** | Rust binary (2.8MB) | Go binary | Node.js | Go toolchain |
| **No auth** | ✅ | ✅ | ❌ (npm login) | ✅ |
| **npm support** | ✅ | ✅ | ✅ | ❌ |
| **Go support** | ✅ | ✅ | ❌ | ✅ (stdlib only) |
| **MCP server** | ✅ | ✅ | ❌ | ❌ |
| **Markdown reports** | ✅ | ❌ | ❌ | ❌ |
| **Suggest safe version** | ✅ | ✅ | ❌ | ❌ |
| **Compare versions** | ✅ | ✅ | ❌ | ❌ |
| **CI integration** | Exit codes | Exit codes | Exit codes | Exit codes |

---

## Roadmap

- [ ] **More ecosystems** — PyPI, Cargo, RubyGems, NuGet, Maven
- [ ] **Lockfile scanning** — `palsphere scan package-lock.json` / `go.sum`
- [ ] **SARIF output** — GitHub Code Scanning integration
- [ ] **Pre-built binaries** — GitHub Releases with Linux/macOS/Windows
- [ ] **Homebrew tap** — `brew install faizalardhi16/tap/palsphere`

---

## License

MIT © [Faizal Ardhi Cahyanto](https://github.com/faizalardhi16)

<p align="center">
  <sub>Built with 🦀 Rust. Powered by <a href="https://osv.dev">OSV</a>. Zero auth, always.</sub>
</p>
