# Hermes

MCP Runtime Security Scanner & Compliance Auditor

[![CI](https://github.com/faysal-X-N/hermes/actions/workflows/ci.yml/badge.svg)](https://github.com/faysal-X-N/hermes/actions)
[![Crates.io](https://img.shields.io/crates/v/hermes-mcp.svg)](https://crates.io/crates/hermes-mcp)
[![License](https://img.shields.io/crates/l/hermes-mcp.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.88.0+-blue?logo=rust)](https://blog.rust-lang.org/)

> **Hermes** is a Rust-powered CLI tool for scanning, probing, and fuzzing MCP (Model Context Protocol) server configurations. It combines static config audit, runtime TLS/auth/SSRF/session probing, fuzz testing, tamper-proof audit chains, and China compliance (等保 2.0) — all in a single binary.

[中文文档](docs/README-ZH.md)

---

## Why Hermes

Hermes is the most comprehensive MCP security scanner available.

| Feature | Hermes | agentshield | pipelock |
|---------|:--:|:--:|:--:|
| Static config audit | ✅ | ✅ | ❌ |
| Runtime probe (TLS/auth) | ✅ | ❌ | ❌ |
| Fuzz testing | ✅ | ❌ | ❌ |
| SARIF / Code Scanning | ✅ | ❌ | ❌ |
| Audit chain (HMAC) | ✅ | ❌ | ❌ |
| Policy engine + presets | ✅ | ❌ | ✅ |
| Auto-fix (`--fix`) | ✅ | ❌ | ❌ |
| GitHub Action | ✅ | ❌ | ✅ |
| 等保 compliance | ✅ | ❌ | ❌ |
| OWASP MCP Top 10 aligned | ✅ | ❌ | ❌ |

Hermes rules map directly to the [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/):

| OWASP Category | Hermes Rules |
|:--|------|
| MCP01 — Token Mismanagement | SC-01/02/11 |
| MCP02 — Privilege Escalation | SC-04/08/PR-16 |
| MCP03 — Tool Poisoning | FZ-01~08 |
| MCP04 — Supply Chain Attacks | SC-10/15 |
| MCP05 — Command Injection | SC-03/FZ-05/06 |
| MCP06 — Prompt Injection | FZ-07 |
| MCP07 — Insufficient AuthN/AuthZ | SC-06/PR-03/04/14/15 |
| MCP08 — Lack of Audit | SC-02/11/16 (audit trail via chain module) |
| MCP09 — Shadow Servers | SC-13 |
| MCP10 — Context Over-Sharing | PR-10/11/12 |

---

## Installation

```bash
cargo install hermes-mcp --locked
```

Or build from source:

```bash
git clone https://github.com/faysal-X-N/hermes
cd hermes
cargo build --release
```

## Quick Start

```bash
hermes audit ~/my-mcp-configs/
hermes probe https://mcp.example.com
hermes fuzz https://mcp.example.com
hermes audit . --preset basic --format json
```

## Supported Formats

- MCP standard JSON (`mcp.json`, `.mcp.json`)
- Claude Desktop configuration
- Directory scanning (max depth 3)
- Glob patterns (`**/*.json`)
- Stdin input (`hermes audit -`)

---

## Common Workflows

### CI Pipeline Gate

```bash
hermes audit . --preset basic --format json     # Fail on critical
hermes audit . --min-severity high               # Fail on high+
```

### Full Security Audit

```bash
hermes audit . --preset strict --format html-management > report.html
```

### Compliance Audit with Tamper-Proof Trail

```bash
hermes audit --init-key
hermes audit . --preset enterprise --audit-key .hermes/audit.key --output result.json
hermes verify .hermes/chain-audit-*.json --audit-key .hermes/audit.key
```

### GitHub Actions

```yaml
- uses: faysal-X-N/hermes@main
  with:
    path: "."
    preset: "basic"
    format: "sarif"
```

### Custom Policy

```bash
hermes policy --template enterprise
# Edit .hermes-policy.json
hermes audit . --policy .hermes-policy.json
```

### China Compliance (等保 2.0 Level 2)

```bash
hermes audit . --preset dengbao
```

---

## Commands

| Command | Description |
|---------|-------------|
| `hermes audit <path>` | Static security audit |
| `hermes probe <url>` | Runtime security probe |
| `hermes fuzz <url>` | Fuzz-test with malformed inputs |
| `hermes verify <file>` | Verify audit chain integrity |
| `hermes report <file>` | Render JSON result as report |
| `hermes policy` | Generate policy file |

### Flags

| Flag | Description |
|------|-------------|
| `--format json` | JSON output (audit/probe/fuzz/report) |
| `--format html` | Technical HTML report (audit/probe/report) |
| `--format html-management` | Management HTML — charts + compliance (audit) |
| `--format sarif` | SARIF v2.1.0 — GitHub Code Scanning (audit/probe) |
| `--output <file>` | Write to file (all commands) |
| `--verbose` | Verbose output to stderr (all commands) |
| `--no-color` | Disable colors (all commands) |
| `--dry-run` | Preview fixes without writing (requires --fix, audit only) |
| `--timeout <s>` | Timeout in seconds — probe/fuzz only (default: 30) |
| `--policy <file>` | Load JSON policy file — audit/probe/fuzz only |
| `--preset <name>` | Preset: basic / strict / enterprise / dengbao — audit/probe/fuzz only |
| `--min-severity <level>` | Min level: info / low / medium / high / critical — audit/probe/fuzz only |
| `--audit-key <file>` | HMAC audit chain key — audit/probe/fuzz/verify only. Also via `HERMES_AUDIT_KEY` env var |
| `--init-key` | Generate audit chain key — audit only |
| `--template <name>` | Policy preset name — policy command only |
| `--fix` | Auto-fix in-place — audit only |
| `--fix --dry-run` | Preview fixes without writing — audit only |

### Exit Codes

| Code | Meaning |
|:--:|------|
| 0 | Pass — no issues |
| 1 | Error |
| 2 | Findings detected |

### Presets

| Preset | Threshold | Rules | Use Case |
|--------|:--:|:--:|------|
| `basic` | Critical | 3 | CI gate |
| `strict` | Low+ | 16 | Full audit |
| `enterprise` | Medium+ | 16 | Production compliance |
| `dengbao` | High+ | 8 | China 等保 Level 2 |

---

## Scan Rules

### Static Audit (16 rules)

| ID | Rule | Severity | Description |
|----|------|:--:|------|
| SC-01 | `hardcoded-api-key` | Critical | API key in plain text |
| SC-02 | `hardcoded-password` | Critical | Password in plain text |
| SC-03 | `dangerous-command` | High | curl/wget piped to shell |
| SC-04 | `overly-permissive` | High | Wildcard `*` in tools |
| SC-05 | `no-tls` | Medium | http:// without TLS |
| SC-06 | `no-authentication` | High | No auth configured |
| SC-07 | `bind-public-interface` | High | Bound to 0.0.0.0 |
| SC-08 | `auto-approve` | High | autoApprove with `*` |
| SC-09 | `no-timeout` | Low | Missing timeout |
| SC-10 | `unpinned-package` | Medium | npx/uvx without version |
| SC-11 | `env-secret-leak` | High | env value is a secret |
| SC-12 | `sensitive-file-args` | Medium | .env/.pem/.key in args |
| SC-13 | `missing-description` | Info | No description |
| SC-14 | `unsafe-filesystem` | High | Filesystem bound to `/` |
| SC-15 | `supply-chain-risk` | Medium | Non-official registry |
| SC-16 | `world-readable-config` | Medium | Config file has overly permissive file permissions |

### Runtime Probe (17 rules)

| ID | Rule | Severity | Description |
|----|------|:--:|------|
| PR-01 | `tls-verify` | Critical | Certificate validity |
| PR-02 | `tls-missing` | High | No TLS |
| PR-03 | `auth-required` | High | Accessible without auth |
| PR-04 | `auth-weak` | Medium | Weak token |
| PR-05 | `protocol-version` | Info | MCP protocol version |
| PR-06 | `tools-enumeration` | Info | Tools enumeration |
| PR-07 | `dangerous-tools` | High | write_file/execute exposed |
| PR-08 | `ssrf-probe` | Critical | Accepts internal URLs |
| PR-09 | `ssrf-redirect` | High | Redirect to internal |
| PR-10 | `session-predictability` | High | Predictable session ID |
| PR-11 | `session-replay` | High | Session replay accepted |
| PR-12 | `session-fixation` | Medium | Session not rotated |
| PR-13 | `path-traversal` | High | `../../../` accepted |
| PR-14 | `confused-deputy` | Critical | No OAuth audience |
| PR-15 | `token-passthrough` | Critical | Token reusable elsewhere |
| PR-16 | `scope-minimization` | Medium | Wildcard OAuth scopes |
| PR-17 | `health-check` | Info | Server reachability |

### Fuzz Tests (8 tests)

| ID | Test | Severity | Payload |
|----|------|:--:|------|
| FZ-01 | `empty-input` | High | `null`, `""`, `{}` |
| FZ-02 | `oversized-input` | Medium | 1MB string |
| FZ-03 | `special-chars` | Medium | `\x00`, `\u0000` |
| FZ-04 | `path-injection` | High | `../../../etc/passwd` |
| FZ-05 | `sql-injection` | High | `' OR '1'='1` |
| FZ-06 | `command-injection` | High | `` `id` ``, `$(whoami)` |
| FZ-07 | `prompt-injection` | Medium | "ignore previous instructions" |
| FZ-08 | `crash-detect` | High | 5xx / timeout / disconnect |

### Scoring

Score = max(0, 100 − 25×Critical − 10×High − 3×Medium)

| Grade | Range |
|:--:|------|
| A | 90–100 |
| B | 75–89 |
| C | 60–74 |
| D | 40–59 |
| F | 0–39 |

---

## Policy File

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

```bash
hermes policy --template enterprise
hermes audit . --policy .hermes-policy.json
```

- Rules not listed default to **enabled** (policy file) or **disabled** (preset mode)
- `enabled: false` silences a rule
- `severity` overrides default level
- Exceptions support `rule` + `tool`/`path` + expiry
- `--preset` and `--policy` are mutually exclusive

---

## Audit Chain

```bash
hermes audit --init-key
hermes audit . --audit-key .hermes/audit.key
hermes verify .hermes/chain-audit-*.json --audit-key .hermes/audit.key
```

Chain structure: Hₙ = HMAC-SHA256(Hₙ₋₁, "ts|rule|severity|target|finding|recommendation")

---

## Auto-Fix

```bash
hermes audit . --fix --dry-run    # Preview
hermes audit . --fix              # Apply
```

Fixes: hardcoded secrets → `${VAR}`, `http://` → `https://`, exposed env values → references.

---

## Limitations

Hermes is **not** a penetration testing tool:

- **Transport:** HTTP/SSE only. No stdio/WebSocket support.
- **SSRF:** Detects if server *accepts* internal URLs; does not verify outbound request.
- **No behavioral AI analysis:** Prompt injection is pattern-based.
- **No real-time monitoring:** Manual scan, not a continuous service.
- **Windows:** TLS depends on OS certificate store. SC-16 (file permissions) applies on Unix only.

---

## Security

To report a security vulnerability, please open a [private security advisory](https://github.com/faysal-X-N/hermes/security/advisories/new).

---

## License

Apache-2.0. See [LICENSE](LICENSE).

*v0.3.1 · 2026-06-03*
