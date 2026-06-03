[English](../README.md)

---

# Hermes

MCP 运行时安全扫描器 & 合规审计工具

[![CI](https://github.com/faysal-X-N/hermes/actions/workflows/ci.yml/badge.svg)](https://github.com/faysal-X-N/hermes/actions)
[![Crates.io](https://img.shields.io/crates/v/hermes-mcp.svg)](https://crates.io/crates/hermes-mcp)
[![Rust](https://img.shields.io/badge/Rust-1.88.0+-blue?logo=rust)](https://blog.rust-lang.org/)

**Hermes** 是唯一一个将静态配置审计、运行时 TLS/认证/SSRF/会话探测、模糊测试、防篡改审计链和等保 2.0 合规集于一体的 MCP 安全工具。基于 Rust 开发，单二进制文件，零运行时依赖。

---

## 安装

### crates.io

```bash
cargo install --locked hermes-mcp
```

### 源码编译

```bash
git clone https://github.com/faysal-X-N/hermes
cd hermes
cargo build --release
```

---

## 为什么选 Hermes

| 功能 | Hermes | agentshield | pipelock |
|---------|:--:|:--:|:--:|
| 静态配置审计 | ✅ | ✅ | ❌ |
| 运行时探测 (TLS/认证) | ✅ | ❌ | ❌ |
| 模糊测试 | ✅ | ❌ | ❌ |
| SARIF / Code Scanning | ✅ | ❌ | ❌ |
| 审计链 (HMAC) | ✅ | ❌ | ❌ |
| 策略引擎 + 预设 | ✅ | ❌ | ✅ |
| 自动修复 (`--fix`) | ✅ | ❌ | ❌ |
| GitHub Action | ✅ | ❌ | ✅ |
| 等保合规 | ✅ | ❌ | ❌ |
| OWASP MCP Top 10 对齐 | ✅ | ❌ | ❌ |

Hermes 规则与 [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) 完全对齐：

| OWASP 分类 | Hermes 规则 |
|:--|------|
| MCP01 — 令牌泄露 | SC-01/02/11 |
| MCP02 — 权限提升 | SC-04/08/PR-16 |
| MCP03 — 工具投毒 | FZ-01~08 |
| MCP04 — 供应链攻击 | SC-10/15 |
| MCP05 — 命令注入 | SC-03/FZ-05/06 |
| MCP06 — 提示注入 | FZ-07 |
| MCP07 — 认证缺失 | SC-06/PR-03/04/14/15 |
| MCP08 — 审计缺失 | SC-02/11/16（chain 模块提供防篡改审计链） |
| MCP09 — 影子服务器 | SC-13 |
| MCP10 — 上下文泄露 | PR-10/11/12 |

---

## 快速开始

```bash
cargo install --locked hermes-mcp

# 扫描 MCP 配置
hermes audit ~/my-mcp-configs/

# 探测运行中的服务器
hermes probe https://mcp.example.com

# 模糊测试
hermes fuzz https://mcp.example.com

# CI 门控
hermes audit . --preset basic --format json
```

## 支持格式

- MCP 标准 JSON（`mcp.json`, `.mcp.json`）
- Claude Desktop 配置
- 目录扫描（最大深度 3 层）
- Glob 模式（`**/*.json`）
- Stdin 输入（`hermes audit -`）

---

## 常用工作流

### CI 流水线门控

```bash
hermes audit . --preset basic --format json     # 只看 critical
hermes audit . --min-severity high               # high 及以上
```

### 全面安全审计

```bash
hermes audit . --preset strict --format html-management > report.html
```

### 合规 + 防篡改审计

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

### 等保 2.0 二级

```bash
hermes audit . --preset dengbao
```

---

## 命令

| 命令 | 说明 |
|---------|-------------|
| `hermes audit <path>` | 静态安全审计 |
| `hermes probe <url>` | 运行时安全探测 |
| `hermes fuzz <url>` | 模糊测试 |
| `hermes verify <file>` | 验证审计链完整性 |
| `hermes report <file>` | 重新渲染报告 |
| `hermes policy` | 生成策略文件 |

### 主要标志

| 标志 | 说明 |
|------|-------------|
| `--format json/html/html-management/sarif` | 输出格式（json: audit/probe/fuzz/report, html: audit/probe/report, html-management: audit, sarif: audit/probe） |
| `--output <file>` | 输出到文件（所有命令） |
| `--verbose` | 详细输出到 stderr（所有命令） |
| `--no-color` | 禁用颜色（所有命令） |
| `--timeout <s>` | 超时秒数 — 仅 probe/fuzz（默认: 30） |
| `--preset <name>` | 预设: basic / strict / enterprise / dengbao — 仅 audit/probe/fuzz |
| `--min-severity <level>` | 最低级别: info / low / medium / high / critical — 仅 audit/probe/fuzz |
| `--policy <file>` | 加载 JSON 策略文件 — 仅 audit/probe/fuzz |
| `--template <name>` | 策略预设名 — 仅 policy 命令 |
| `--audit-key <file>` | 审计链 HMAC 密钥 — 仅 audit/probe/fuzz/verify（也支持 `HERMES_AUDIT_KEY` 环境变量） |
| `--init-key` | 生成审计密钥 — 仅 audit |
| `--fix` | 自动修复 — 仅 audit |
| `--fix --dry-run` | 预览修复 — 仅 audit |
| `--dry-run` | 预览修复（需配合 --fix，仅 audit） |

### 预设

| 预设 | 级别 | 规则数 | 场景 |
|--------|:--:|:--:|------|
| `basic` | Critical | 3 | CI 门控 |
| `strict` | Low+ | 16 | 全面审计 |
| `enterprise` | Medium+ | 16 | 生产合规 |
| `dengbao` | High+ | 8 | 等保二级 |
### 退出码

| 码 | 含义 |
|:--:|------|
| 0 | 通过 — 无问题 |
| 1 | 错误 |
| 2 | 发现问题 |

### 扫描规则

#### 静态审计（16 条规则）

| ID | 规则 | 严重度 | 说明 |
|----|------|:--:|------|
| SC-01 | `hardcoded-api-key` | Critical | API 密钥明文写在配置中 |
| SC-02 | `hardcoded-password` | Critical | 密码明文写在配置中 |
| SC-03 | `dangerous-command` | High | curl/wget 管道到 shell |
| SC-04 | `overly-permissive` | High | 工具有通配符 `*` |
| SC-05 | `no-tls` | Medium | http:// 未启用 TLS |
| SC-06 | `no-authentication` | High | 未配置认证 |
| SC-07 | `bind-public-interface` | High | 绑定到 0.0.0.0 |
| SC-08 | `auto-approve` | High | autoApprove 含 `*` |
| SC-09 | `no-timeout` | Low | 缺少超时设置 |
| SC-10 | `unpinned-package` | Medium | npx/uvx 未指定版本 |
| SC-11 | `env-secret-leak` | High | env 值为明文密钥 |
| SC-12 | `sensitive-file-args` | Medium | 参数含 .env/.pem/.key |
| SC-13 | `missing-description` | Info | 缺少描述 |
| SC-14 | `unsafe-filesystem` | High | 文件系统绑定到 `/` |
| SC-15 | `supply-chain-risk` | Medium | 非官方源安装 |
| SC-16 | `world-readable-config` | Medium | 配置文件权限过于宽松 |

#### 运行时探测（17 条规则）

| ID | 规则 | 严重度 | 说明 |
|----|------|:--:|------|
| PR-01 | `tls-verify` | Critical | 证书有效性 |
| PR-02 | `tls-missing` | High | 未启用 TLS |
| PR-03 | `auth-required` | High | 无需认证即可访问 |
| PR-04 | `auth-weak` | Medium | 弱认证令牌 |
| PR-05 | `protocol-version` | Info | MCP 协议版本 |
| PR-06 | `tools-enumeration` | Info | 工具枚举 |
| PR-07 | `dangerous-tools` | High | write_file/execute 等危险工具暴露 |
| PR-08 | `ssrf-probe` | Critical | 接受内网 URL 参数 |
| PR-09 | `ssrf-redirect` | High | 重定向到内网 |
| PR-10 | `session-predictability` | High | Session ID 可预测 |
| PR-11 | `session-replay` | High | Session 重放被接受 |
| PR-12 | `session-fixation` | Medium | Session 未轮换 |
| PR-13 | `path-traversal` | High | `../../../` 被接受 |
| PR-14 | `confused-deputy` | Critical | 无 OAuth audience 验证 |
| PR-15 | `token-passthrough` | Critical | Token 可被跨服务重用 |
| PR-16 | `scope-minimization` | Medium | 通配符 OAuth 权限 |
| PR-17 | `health-check` | Info | 服务可达性 |

#### 模糊测试（8 项测试）

| ID | 测试 | 严重度 | 载荷 |
|----|------|:--:|------|
| FZ-01 | `empty-input` | High | `null`、`""`、`{}` |
| FZ-02 | `oversized-input` | Medium | 1MB 字符串 |
| FZ-03 | `special-chars` | Medium | `\x00`、`\u0000` 控制字符 |
| FZ-04 | `path-injection` | High | `../../../etc/passwd` |
| FZ-05 | `sql-injection` | High | `' OR '1'='1` |
| FZ-06 | `command-injection` | High | `` `id` ``、`$(whoami)` |
| FZ-07 | `prompt-injection` | Medium | "ignore previous instructions" |
| FZ-08 | `crash-detect` | High | 5xx / 超时 / 连接断开 |

### 评分

分数 = max(0, 100 − 25×Critical − 10×High − 3×Medium)

| 等级 | 范围 |
|:--:|------|
| A | 90–100 |
| B | 75–89 |
| C | 60–74 |
| D | 40–59 |
| F | 0–39 |

---

## 策略文件

```json
{
  "version": 1,
  "name": "企业 MCP 安全策略",
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
      "reason": "业务需要，用户会二次确认",
      "expires": "2026-12-31"
    }
  ]
}
```

```bash
hermes policy --template enterprise
hermes audit . --policy .hermes-policy.json
```

---

## 审计链

```bash
hermes audit --init-key
hermes audit . --audit-key .hermes/audit.key
hermes verify .hermes/chain-audit-*.json --audit-key .hermes/audit.key
```

链结构: Hₙ = HMAC-SHA256(Hₙ₋₁, "ts|rule|severity|target|finding|recommendation")

---

## 自动修复

```bash
hermes audit . --fix --dry-run    # 预览
hermes audit . --fix              # 执行
```

可修复：明文密钥 → `${VAR}`、`http://` → `https://`、env 值泄露 → 引用。

---

## 局限性

Hermes **不是**渗透测试工具：

- **传输协议：** 仅 HTTP/SSE，不支持 stdio/WebSocket
- **SSRF 检测：** 检测服务器是否"接受"内网 URL，不验证是否真正外发请求
- **无 AI 行为分析：** Prompt 注入为模式匹配，不分析 AI 模型行为
- **无实时监控：** 手动扫描工具，非持续监控服务
- **Windows 证书：** TLS 验证依赖系统证书库。SC-16（文件权限检查）仅 Unix 上生效。

---

## 安全

如需报告安全漏洞，请在 GitHub 上提交[私有安全报告](https://github.com/faysal-X-N/hermes/security/advisories/new)。

---

## 许可证

Apache-2.0. 详见 [LICENSE](../LICENSE)。

*版本: 0.3.1 · 日期: 2026-06-03*
