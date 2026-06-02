# Hermes

MCP Runtime Security Scanner & Compliance Auditor

[![CI](https://github.com/faysal-X-N/hermes/actions/workflows/ci.yml/badge.svg)](https://github.com/faysal-X-N/hermes/actions)
[![Crates.io](https://img.shields.io/crates/v/hermes.svg)](https://crates.io/crates/hermes)
[![License](https://img.shields.io/crates/l/hermes.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.88.0+-blue?logo=rust)](https://blog.rust-lang.org/)

**Hermes** is a Rust-powered CLI tool for scanning MCP (Model Context Protocol) server configurations and probing running servers for security vulnerabilities.

- **Static Audit**: Scan MCP config files for hardcoded secrets, dangerous commands, supply chain risks, and policy violations (15 rules)
- **Runtime Probe**: Connect to live MCP servers to verify TLS, authentication, SSRF, session security, confused deputy, and path traversal (12 rules)
- **Fuzz Testing**: Send malformed inputs (empty, oversized, SQL/cmd/prompt injection, path traversal) to discover crashes (7 tests)
- **Policy Engine**: JSON policy files with rule toggles, severity thresholds, whitelist exceptions, and 4 built-in presets (basic/strict/enterprise/dengbao)
- **Tamper-Proof Audit Chain**: HMAC-SHA256 chained audit records with verification and `--init-key`
- **CI-Ready**: GitHub Action available, JSON/HTML/SARIF output, exit codes, and `--output` for pipeline integration

[Installation](#installation) · [Quick Start](#quick-start) · [Commands](#commands) · [Scan Rules](#scan-rules) · [License](#license)

---

## Installation

### From crates.io

```bash
cargo install --locked hermes
```

### From source

```bash
git clone https://github.com/faysal-X-N/hermes
cd hermes
cargo build --release
./target/release/hermes --version
```

---

## Quick Start

```bash
# Scan MCP config files in a directory
hermes audit ~/.cursor/mcp_configs/

# Scan a single file
hermes audit mcp.json

# Scan with glob pattern
hermes audit "configs/**/*.json"

# Pipe config from stdin
cat mcp.json | hermes audit -

# Probe a running MCP server
hermes probe https://mcp.example.com

# Output JSON for CI pipelines
hermes audit . --format json

# Output HTML report
hermes audit . --format html > report.html

# Use policy preset for China compliance
hermes audit . --preset dengbao

# Write report to file
hermes audit . --output report.json

# Fuzz a running MCP server
hermes fuzz https://mcp.example.com

# Generate audit chain key
hermes audit --init-key

# Verify audit chain integrity
hermes verify .hermes/chain-audit-*.json --audit-key .hermes/audit.key

# Re-render a JSON result as HTML
hermes report result.json --format html
```

## GitHub Action

Add Hermes to your CI pipeline:

```yaml
- name: Hermes MCP Security Scan
  uses: faysal-X-N/hermes@v0.2
  with:
    path: "."
    severity: "high"
```

With Code Scanning integration (SARIF):

```yaml
- name: Hermes MCP Security Scan
  uses: faysal-X-N/hermes@v0.2
  with:
    path: "."
    format: "sarif"
    upload-sarif: "true"
```

Using dengbao preset for China compliance:

```yaml
- name: Hermes Dengbao Audit
  uses: faysal-X-N/hermes@v0.2
  with:
    path: "."
    preset: "dengbao"
```

## Commands

| Command | Description |
|---------|-------------|
| `hermes audit <path>` | Static security audit of MCP configuration files |
| `hermes probe <url>` | Runtime security probe of a running MCP server |
| `hermes fuzz <url>` | Fuzz-test a MCP server with malformed inputs |
| `hermes verify <file>` | Verify HMAC audit chain integrity |
| `hermes report <file>` | Re-render a JSON result as formatted report |
| `hermes policy` | Generate a default .hermes-policy.json file |

### Flags

| Flag | Description |
|------|-------------|
| `--format json` | Output as JSON |
| `--format html` | Output as technical HTML report |
| `--format html-management` | Output as management HTML report (charts + compliance) |
| `--format sarif` | Output as SARIF v2.1.0 (GitHub Code Scanning) |
| `--output <file>` | Write output to file |
| `--verbose` | Verbose output to stderr |
| `--no-color` | Disable colored output |
| `--timeout <s>` | Probe/Fuzz timeout in seconds (default: 30) |
| `--policy <file>` | Load external JSON policy file |
| `--preset <name>` | Built-in policy preset (dengbao/basic/strict/enterprise) |
| `--min-severity <level>` | Minimum severity to show (info/low/medium/high/critical) |
| `--audit-key <file>` | HMAC audit chain key file |
| `--init-key` | Generate a new audit chain key |
| `--fix` | Auto-fix fixable findings in-place |
| `--fix --dry-run` | Preview fixes without modifying files |

### Exit Codes

| Code | Meaning |
|:----:|---------|
| 0 | Pass — no issues found |
| 1 | Error — runtime or configuration error |
| 2 | Findings — security issues detected |

---

## Scan Rules

### Static Audit (15 rules)

| ID | Rule | Severity |
|----|------|----------|
| SC-01 | `hardcoded-api-key` | Critical |
| SC-02 | `hardcoded-password` | Critical |
| SC-03 | `dangerous-command` | High |
| SC-04 | `overly-permissive` | High |
| SC-05 | `no-tls` | Medium |
| SC-06 | `no-authentication` | High |
| SC-07 | `bind-public-interface` | High |
| SC-08 | `auto-approve` | High |
| SC-09 | `no-timeout` | Low |
| SC-10 | `unpinned-package` | Medium |
| SC-11 | `env-secret-leak` | High |
| SC-12 | `sensitive-file-args` | Medium |
| SC-13 | `missing-description` | Info |
| SC-14 | `unsafe-filesystem` | High |
| SC-15 | `supply-chain-risk` | Medium |

### Runtime Probe (12 rules)

| ID | Rule | Severity |
|----|------|----------|
| PR-01 | `tls-verify` | Critical |
| PR-02 | `tls-missing` | High |
| PR-03 | `auth-required` | High |
| PR-04 | `auth-weak` | Medium |
| PR-05 | `protocol-version` | Info |
| PR-06 | `tools-enumeration` | Info |
| PR-07 | `dangerous-tools` | High |
| PR-08 | `ssrf-probe` | Critical |
| PR-09 | `ssrf-redirect` | High |
| PR-10 | `session-predictability` | High |
| PR-11 | `session-replay` | High |
| PR-12 | `session-fixation` | Medium |
| PR-13 | `path-traversal` | High |
| PR-14 | `confused-deputy` | Critical |
| PR-15 | `token-passthrough` | Critical |
| PR-16 | `scope-minimization` | Medium |
| PR-17 | `health-check` | Info |

### Fuzz Tests (7 tests)

| ID | Test | Severity |
|----|------|----------|
| FZ-01 | `empty-input` | High |
| FZ-02 | `oversized-input` | Medium |
| FZ-03 | `special-chars` | Medium |
| FZ-04 | `path-injection` | High |
| FZ-05 | `sql-injection` | High |
| FZ-06 | `command-injection` | High |
| FZ-07 | `prompt-injection` | Medium |
| FZ-08 | `crash-detect` | High |

### Scoring

Score = max(0, 100 − 25×Critical − 10×High − 3×Medium)

| Grade | Range |
|:-----:|-------|
| A | 90–100 |
| B | 75–89 |
| C | 60–74 |
| D | 40–59 |
| F | 0–39 |

---

## JSON Output

```json
{
  "tool": "hermes",
  "version": "0.1.0",
  "command": "audit",
  "timestamp": "2026-06-02T12:00:00Z",
  "target": "./mcp-configs/",
  "score": {
    "grade": "C",
    "numeric": 66,
    "breakdown": {
      "secrets": 40,
      "permissions": 70,
      "network": 80,
      "authentication": 60,
      "session": 90
    }
  },
  "summary": {
    "total": 3,
    "critical": 1,
    "high": 2,
    "medium": 0,
    "low": 0,
    "info": 0,
    "files_scanned": 2,
    "auto_fixable": 1,
    "duration_ms": 15
  },
  "findings": [
    {
      "id": "hardcoded-api-key",
      "severity": "critical",
      "category": "secrets",
      "title": "Hardcoded API key in configuration",
      "file": "mcp.json",
      "line": null,
      "evidence": "sk-a...xxxx",
      "recommendation": "Replace with ${ENV_VAR} environment variable reference",
      "auto_fixable": true,
      "references": []
    }
  ]
}
```

---

## Supported Config Formats

- MCP standard JSON (`mcp.json`, `.mcp.json`)
- Claude Desktop configuration
- Generic JSON/YAML configuration files
- Directory scanning (max depth 3)
- Glob patterns (`**/*.json`)
- Stdin input (`hermes audit -`)

---

## Project Structure

```
src/
├── main.rs              # CLI entry point (clap derive) — 5 subcommands
├── audit/
│   ├── parser.rs        # MCP config file parser
│   ├── scanner.rs       # Directory/glob/stdin scanner
│   ├── rules.rs         # SC01–SC14 scan rules (11 active)
│   └── types.rs         # Finding, Severity, scoring
├── probe/
│   ├── tls.rs           # TLS certificate verification (rustls)
│   ├── auth.rs          # Authentication probing
│   ├── tools.rs         # Tool enumeration + dangerous detection
│   ├── ssrf.rs          # SSRF vulnerability probe
│   ├── session.rs       # Session ID predictability probe
│   ├── traversal.rs     # Path traversal probe
│   └── types.rs         # ProbeContext, ProbeFinding
├── fuzz/
│   ├── engine.rs        # Fuzz test engine (FZ-01/02/03/04/08)
│   ├── payloads.rs      # Malformed payload generators
│   └── types.rs         # FuzzResult, FuzzContext
├── chain/
│   ├── hmac.rs          # HMAC-SHA256 audit chain build & verify
│   ├── verify.rs        # Chain verification entry point
│   └── types.rs         # AuditRecord, AuditChain
├── policy/
│   ├── parser.rs        # JSON policy file parser
│   ├── engine.rs        # Policy filter engine
│   ├── presets.rs       # Built-in presets (dengbao)
│   └── types.rs         # PolicyConfig, BuiltinPreset
└── report/
    ├── terminal.rs      # Colored terminal output
    ├── json.rs          # JSON format output
    └── html.rs          # Self-contained HTML report output
```

---

## Requirements

- Rust 1.88.0 or later
- No external runtime dependencies

---

## License

Licensed under the Apache License, Version 2.0 ([LICENSE](LICENSE)).

Copyright 2026 Hermes Contributors.
