# Hermes

MCP Runtime Security Scanner & Compliance Auditor

[![CI](https://github.com/faysal-X-N/hermes/actions/workflows/ci.yml/badge.svg)](https://github.com/faysal-X-N/hermes/actions)
[![Crates.io](https://img.shields.io/crates/v/hermes.svg)](https://crates.io/crates/hermes)
[![License](https://img.shields.io/crates/l/hermes.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.85.0+-blue?logo=rust)](https://blog.rust-lang.org/)

**Hermes** is a Rust-powered CLI tool for scanning MCP (Model Context Protocol) server configurations and probing running servers for security vulnerabilities.

- **Static Audit**: Scan MCP config files for hardcoded secrets, dangerous commands, and policy violations
- **Runtime Probe**: Connect to live MCP servers to verify TLS, authentication, and tool permissions
- **Fast**: Built with Rust, single binary, no runtime dependencies
- **CI-Ready**: JSON output, exit codes, and `--output` for pipeline integration

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

# Write report to file
hermes audit . --output report.json
```

---

## Commands

| Command | Description |
|---------|-------------|
| `hermes audit <path>` | Static security audit of MCP configuration files |
| `hermes probe <url>` | Runtime security probe of a running MCP server |

### Global Flags

| Flag | Description |
|------|-------------|
| `--format json` | Output as JSON |
| `--output <file>` | Write output to file |
| `--verbose` | Verbose output to stderr |
| `--no-color` | Disable colored output |
| `--timeout <s>` | Probe timeout in seconds (default: 30) |

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
| PR-17 | `health-check` | Info |

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
├── main.rs              # CLI entry point (clap derive)
├── audit/
│   ├── parser.rs        # MCP config file parser
│   ├── scanner.rs       # Directory/glob/stdin scanner
│   ├── rules.rs         # SC01–SC08 scan rules
│   └── types.rs         # Finding, Severity, scoring
├── probe/
│   ├── tls.rs           # TLS certificate verification (rustls)
│   ├── auth.rs          # Authentication probing
│   ├── tools.rs         # Tool enumeration + dangerous detection
│   └── types.rs         # ProbeContext, ProbeFinding
└── report/
    ├── terminal.rs      # Colored terminal output
    └── json.rs          # JSON format output
```

---

## Requirements

- Rust 1.85.0 or later
- No external runtime dependencies

---

## License

Licensed under the Apache License, Version 2.0 ([LICENSE](LICENSE)).

Copyright 2026 Hermes Contributors.
