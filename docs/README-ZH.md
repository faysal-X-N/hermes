[English](README.md)

---

# Hermes 赫耳墨斯

MCP 运行时安全扫描器 &amp; 合规审计工具

[![CI](https://github.com/faysal-X-N/hermes/actions/workflows/ci.yml/badge.svg)](https://github.com/faysal-X-N/hermes/actions)
[![Crates.io](https://img.shields.io/crates/v/hermes.svg)](https://crates.io/crates/hermes)
[![Rust](https://img.shields.io/badge/Rust-1.88.0+-blue?logo=rust)](https://blog.rust-lang.org/)
[![Tests](https://img.shields.io/badge/tests-108%20passed-brightgreen)]()
[![Clippy](https://img.shields.io/badge/clippy-0%20warnings-brightgreen)]()

**Hermes** 是唯一一个将静态配置审计、运行时 TLS/认证/SSRF/会话探测、模糊测试、防篡改审计链和等保 2.0 合规集于一体的 MCP 安全工具。基于 Rust 开发，单二进制文件，零运行时依赖。

---

## 为什么选 Hermes

| 功能 | Hermes | agentshield | pipelock | nono |
|---------|:--:|:--:|:--:|:--:|
| 静态配置审计 | ✅ | ✅ | ❌ | ❌ |
| 运行时探测 (TLS/认证) | ✅ | ❌ | ❌ | ✅ |
| 模糊测试 | ✅ | ❌ | ❌ | ❌ |
| SARIF / Code Scanning | ✅ | ❌ | ❌ | ❌ |
| 审计链 (HMAC) | ✅ | ❌ | ❌ | ❌ |
| 策略引擎 + 预设 | ✅ | ❌ | ✅ | ✅ |
| 自动修复 (`--fix`) | ✅ | ❌ | ❌ | ✅ |
| GitHub Action | ✅ | ❌ | ✅ | ❌ |
| 等保合规 | ✅ | ❌ | ❌ | ❌ |
| OWASP MCP Top 10 对齐 | ✅ | ❌ | ❌ | ❌ |

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
| MCP08 — 审计缺失 | AU-01~04 |
| MCP09 — 影子服务器 | SC-13 |
| MCP10 — 上下文泄露 | PR-10/11/12 |

---

## 快速开始

```bash
cargo install --locked hermes

# 扫描 MCP 配置
hermes audit ~/my-mcp-configs/

# 探测运行中的服务器
hermes probe https://mcp.example.com

# 模糊测试
hermes fuzz https://mcp.example.com

# CI 门控
hermes audit . --preset basic --format json
```

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
- uses: faysal-X-N/hermes@v0.3
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
| `--format json/html/html-management/sarif` | 输出格式 |
| `--preset <name>` | 预设: basic / strict / enterprise / dengbao |
| `--min-severity <level>` | 最低级别: info / low / medium / high / critical |
| `--policy <file>` | 加载 JSON 策略文件 |
| `--audit-key <file>` | 审计链 HMAC 密钥 |
| `--init-key` | 生成审计密钥 |
| `--fix` | 自动修复 |
| `--fix --dry-run` | 预览修复 |

### 预设

| 预设 | 级别 | 规则数 | 场景 |
|--------|:--:|:--:|------|
| `basic` | Critical | 3 | CI 门控 |
| `strict` | Low+ | 15 | 全面审计 |
| `enterprise` | Medium+ | 15 | 生产合规 |
| `dengbao` | High+ | 8 | 等保二级 |

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
- **Windows 证书：** TLS 验证依赖系统证书库

---

## 安装

### crates.io

```bash
cargo install --locked hermes
```

### 源码编译

```bash
git clone https://github.com/faysal-X-N/hermes
cd hermes
cargo build --release
```

---

## 要求

- Rust 1.88.0+
- 单二进制，无守护进程

---

## 许可证

Apache-2.0. 详见 [LICENSE](LICENSE)。
