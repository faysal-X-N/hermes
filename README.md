# Hermes

MCP Runtime Security Scanner & Compliance Auditor

[![CI](https://github.com/faysal-X-N/hermes/actions/workflows/ci.yml/badge.svg)](https://github.com/faysal-X-N/hermes/actions)
[![Crates.io](https://img.shields.io/crates/v/hermes.svg)](https://crates.io/crates/hermes)
[![License](https://img.shields.io/crates/l/hermes.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.88.0+-blue?logo=rust)](https://blog.rust-lang.org/)

**Hermes** is a Rust-powered CLI tool for scanning MCP (Model Context Protocol) server configurations and probing running servers for security vulnerabilities.

- **Static Audit**: Scan MCP config files for hardcoded secrets, dangerous commands, supply chain risks, and policy violations (15 rules)
- **Runtime Probe**: Connect to live MCP servers to verify TLS, authentication, SSRF, session security, confused deputy, and path traversal (17 rules)
- **Fuzz Testing**: Send malformed inputs (empty, oversized, SQL/cmd/prompt injection, path traversal) to discover crashes (8 tests)
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

# With Code Scanning (SARIF) integration:
- name: Hermes MCP Security Scan
  uses: faysal-X-N/hermes@v0.2
  with:
    path: "."
    format: "sarif"
    upload-sarif: "true"

# China compliance (dengbao):
- name: Hermes Dengbao Audit
  uses: faysal-X-N/hermes@v0.2
  with:
    path: "."
    preset: "dengbao"
```

**Inputs:**

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `.` | Path to scan |
| `format` | `sarif` | Output: json / html / html-management / sarif |
| `severity` | `high` | Min severity: info / low / medium / high / critical |
| `preset` | — | Built-in preset: basic / strict / enterprise / dengbao |
| `policy` | — | Path to JSON policy file |
| `fail-on-findings` | `true` | Fail the job if findings detected |
| `upload-sarif` | `true` | Upload SARIF to GitHub Code Scanning |

## Policy File

Hermes uses JSON policy files (`.hermes-policy.json`) for fine-grained control:

```json
{
  "version": 1,
  "name": "Enterprise MCP Security Policy",
  "min_severity": "high",
  "rules": {
    "hardcoded-api-key": { "enabled": true },
    "no-tls": { "enabled": true, "severity": "critical" },
    "auto-approve": { "enabled": false }
  },
  "exceptions": [
    {
      "rule": "dangerous-tools",
      "tool": "write_file",
      "reason": "Business requirement with secondary approval",
      "expires": "2026-12-31"
    }
  ]
}
```

**Generate from template:**

```bash
hermes policy --template enterprise   # Full rule set
hermes policy --template basic        # Critical only
hermes policy --template strict       # All rules, low threshold
hermes policy --template dengbao      # China compliance
hermes policy                         # Default (medium severity)
```

**Rule semantics:**
- Rules NOT in the `rules` map default to **enabled** (policy file) or **disabled** (preset mode)
- `enabled: false` silences a rule entirely
- `severity: "critical"` overrides a rule's default severity
- Exceptions use `rule` + optional `tool`/`path` filters with expiry dates
- `--preset` and `--policy` are mutually exclusive

## Audit Chain

Tamper-proof audit records with HMAC-SHA256:

```bash
# Generate a key (once)
hermes audit --init-key

# Scan with audit chain
hermes audit . --audit-key .hermes/audit.key
# → saves .hermes/chain-audit-20260602T120000Z.json

# Verify chain integrity
hermes verify .hermes/chain-audit-*.json --audit-key .hermes/audit.key

# Output: "Chain verified: 7 records — VALID"
# Tampered: "Chain is INVALID — records may have been tampered with"
```

**Chain structure:** Hₙ = HMAC-SHA256(Hₙ₋₁, "ts|rule|severity|target|finding|recommendation")

## Auto-Fix

Automatically fix common issues in MCP config files:

```bash
# Preview what would be fixed
hermes audit . --fix --dry-run

# Apply fixes in-place
hermes audit . --fix
```

**What `--fix` repairs:**
- Hardcoded API keys → `${ENV_VAR}` references
- Hardcoded passwords → environment variable references
- `http://` URLs → `https://`
- Exposed environment variable values → `${VAR}` references

## Fuzz Testing

Test MCP server robustness with malformed inputs:

```bash
# Run all fuzz tests
hermes fuzz https://mcp.example.com

# With custom timeout
hermes fuzz https://mcp.example.com --timeout 60
```

**Fuzz categories:**
- Empty/null/missing inputs (FZ-01)
- Oversized payloads (1MB+) (FZ-02)
- Control characters (\\x00, \\x1b) (FZ-03)
- Path traversal injection (FZ-04)
- SQL injection payloads (FZ-05)
- Command injection (`$(whoami)`, `` `id` ``) (FZ-06)
- Prompt injection ("ignore previous instructions") (FZ-07)
- Crash detection (5xx/timeout/connection errors) (FZ-08)

## Presets

| Preset | Severity | Rules | Use Case |
|--------|----------|-------|----------|
| `basic` | Critical only | 3 | Quick CI gate |
| `strict` | Low+ | 15 | Full security audit |
| `enterprise` | Medium+ | 15 | Production compliance |
| `dengbao` | High+ | 8 | China 等保 2.0 Level 2 |

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

## Common Workflows

### CI Pipeline Gate

```bash
# Fail on any critical finding
hermes audit . --preset basic --format json

# GitHub Actions: fail on high+
hermes audit . --min-severity high
```

### Full Security Audit

```bash
# Comprehensive scan with HTML management report
hermes audit . --preset strict --format html-management > audit-report.html
```

### Compliance Audit with Audit Trail

```bash
hermes audit --init-key
hermes audit . --preset enterprise --audit-key .hermes/audit.key --output result.json
hermes verify .hermes/chain-audit-*.json --audit-key .hermes/audit.key
```

### Server Security Probe

```bash
# Full probe with SARIF for Code Scanning
hermes probe https://mcp.example.com --format sarif --timeout 60
```

### Custom Policy

```bash
hermes policy --template enterprise
# Edit .hermes-policy.json with your customizations
hermes audit . --policy .hermes-policy.json
```

---

## Project Structure

```
src/
├── main.rs              # CLI entry point (clap derive) — 6 commands
├── audit/
│   ├── parser.rs        # MCP config file parser
│   ├── scanner.rs       # Directory/glob/stdin scanner
│   ├── rules.rs         # SC01–SC15 scan rules (15 active)
│   ├── fixer.rs         # --fix auto-remediation
│   └── types.rs         # Finding, Severity, scoring
├── probe/
│   ├── tls.rs           # TLS certificate verification
│   ├── auth.rs          # Authentication probing
│   ├── tools.rs         # Tool enumeration + dangerous detection
│   ├── ssrf.rs          # SSRF vulnerability probe
│   ├── redirect.rs      # SSRF redirect detection
│   ├── session.rs       # Session ID predictability
│   ├── replay.rs        # Session replay detection
│   ├── fixation.rs      # Session fixation probe
│   ├── traversal.rs     # Path traversal probe
│   ├── deputy.rs        # Confused deputy detection
│   ├── passthrough.rs   # Token passthrough + scope minimization
│   └── types.rs         # ProbeContext, ProbeFinding
├── fuzz/
│   ├── engine.rs        # Fuzz test engine (FZ-01~08)
│   ├── payloads.rs      # 6 categories of malformed payloads
│   └── types.rs         # FuzzResult, FuzzContext
├── chain/
│   ├── hmac.rs          # HMAC-SHA256 audit chain build & verify
│   ├── verify.rs        # Chain verification entry point
│   └── types.rs         # AuditRecord, AuditChain
├── policy/
│   ├── parser.rs        # JSON policy file parser
│   ├── engine.rs        # Policy filter + exception matching
│   ├── presets.rs       # 4 built-in presets (basic/strict/enterprise/dengbao)
│   └── types.rs         # PolicyConfig, Exception, BuiltinPreset
└── report/
    ├── terminal.rs      # Colored terminal output
    ├── json.rs          # JSON format output
    ├── html.rs          # Technical + management HTML reports
    └── sarif.rs         # SARIF v2.1.0 output
```

---

## Requirements

- Rust 1.88.0 or later
- No external runtime dependencies

---

## License

Licensed under the Apache License, Version 2.0 ([LICENSE](LICENSE)).

Copyright 2026 Hermes Contributors.
