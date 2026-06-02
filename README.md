# Hermes

MCP Runtime Security Scanner & Compliance Auditor

[![CI](https://github.com/faysal-X-N/hermes/actions/workflows/ci.yml/badge.svg)](https://github.com/faysal-X-N/hermes/actions)
[![Crates.io](https://img.shields.io/crates/v/hermes.svg)](https://crates.io/crates/hermes)
[![License](https://img.shields.io/crates/l/hermes.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.88.0+-blue?logo=rust)](https://blog.rust-lang.org/)

**Hermes** is a Rust-powered CLI tool for scanning MCP (Model Context Protocol) server configurations and probing running servers for security vulnerabilities.

- **Static Audit**: Scan MCP config files for hardcoded secrets, dangerous commands, and policy violations
- **Runtime Probe**: Connect to live MCP servers to verify TLS, authentication, SSRF, path traversal, and session security
- **Fuzz Testing**: Send malformed inputs to discover crashes and robustness issues
- **Policy Engine**: Filter findings by severity, enable/disable rules, built-in `--preset dengbao` for China compliance
- **Tamper-Proof Audit Chain**: HMAC-SHA256 chained audit records with verification
- **Fast**: Built with Rust, single binary, no runtime dependencies
- **CI-Ready**: JSON/HTML output, exit codes, and `--output` for pipeline integration

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

---

## Commands

| Command | Description |
|---------|-------------|
| `hermes audit <path>` | Static security audit of MCP configuration files |
| `hermes probe <url>` | Runtime security probe of a running MCP server |
| `hermes fuzz <url>` | Fuzz-test a MCP server with malformed inputs |
| `hermes verify <file>` | Verify HMAC audit chain integrity |
| `hermes report <file>` | Re-render a JSON result as formatted report |

### Flags

| Flag | Description |
|------|-------------|
| `--format json` | Output as JSON |
| `--format html` | Output as self-contained HTML report |
| `--output <file>` | Write output to file |
| `--verbose` | Verbose output to stderr |
| `--no-color` | Disable colored output |
| `--timeout <s>` | Probe/Fuzz timeout in seconds (default: 30) |
| `--policy <file>` | Load external JSON policy file |
| `--preset <name>` | Built-in policy preset (`dengbao`) |
| `--min-severity <level>` | Minimum severity to show (info/low/medium/high/critical) |
| `--audit-key <file>` | HMAC audit chain key file |
| `--init-key` | Generate a new audit chain key |

### Exit Codes

| Code | Meaning |
|:----:|---------|
| 0 | Pass — no issues found |
| 1 | Error — runtime or configuration error |
| 2 | Findings — security issues detected |

---

## Scan Rules

### Static Audit (SC)

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
| SC-11 | `env-secret-leak` | High |
| SC-12 | `sensitive-file-args` | Medium |
| SC-14 | `unsafe-filesystem` | High |

### Runtime Probe (PR)

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
| PR-10 | `session-predictability` | High |
| PR-13 | `path-traversal` | High |
| PR-17 | `health-check` | Info |

### Fuzz Tests (FZ)

| ID | Test | Severity |
|----|------|----------|
| FZ-01 | `empty-input` | High |
| FZ-02 | `oversized-input` | Medium |
| FZ-03 | `special-chars` | Medium |
| FZ-04 | `path-injection` | High |
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
