# Hermes — 需求规格说明书

> MCP 运行时安全探测与合规审计工具  
> 版本: 0.3.1 | 日期: 2026-06-03

---

## 产品定位

**一句话:** MCP Server 的安全扫描器。静态扫配置，动态探运行时，生成合规报告。

**竞品:** agentshield (760⭐) — 只做 Claude Code 静态配置扫描。Hermes 互补：做**运行时动态探测**。

**用户:** MCP Server 开发者、企业安全团队、CI/CD 流程。

---

## 功能需求

### FR-01 CLI 命令行

| ID | 命令 | 优先级 | 输入 | 输出 | 退出码 |
|:--|------|:--:|------|------|:--:|
| CLI-01 | `hermes audit <path>` | P0 | 配置文件路径/目录 | 安全报告(终端) | 0=通过, 1=错误, 2=发现问题 |
| CLI-02 | `hermes probe <url>` | P0 | MCP Server URL | 探测报告(终端) | 同上 |
| CLI-03 | `hermes fuzz <url>` | P1 | MCP Server URL | Fuzz 报告(终端) | 同上 |
| CLI-04 | `hermes report <path>` | P1 | 扫描结果 JSON 文件 | 格式化报告(终端/HTML/SARIF) | 同上 |
| CLI-05 | `hermes policy` | P2 | — | 生成默认策略文件 | 0 |
| CLI-06 | `hermes policy check` | P2 | 策略文件 + 配置 | 策略合规报告 | （延后） |
| CLI-07 | `hermes verify <audit-file>` | P1 | 审计文件 | 验证结果 | 同上 |

**通用标志:**

| 标志 | 优先级 | 适用命令 | 说明 |
|------|:--:|------|------|
| `--format json` | P0 | all | JSON 输出。`--format` 不可重复指定，重复时最后一次生效 |
| `--format html` | P1 | audit,probe,report | HTML 报告 |
| `--format sarif` | P2 | audit,probe | SARIF(GitHub Code Scanning) |
| `--format html-management` | P2 | audit | 管理级 HTML 报告(图表+合规) |
| `--output <file>` | P0 | all | 写入文件 |
| `--policy <file>` | P1 | audit,probe,fuzz | 按外部策略文件检查。与 `--preset` 互斥，同时指定时报错 |
| `--preset <name>` | P1 | audit,probe,fuzz | 内置策略预设，编译于二进制内。与 `--policy` 互斥。可选: `dengbao`、`basic`、`strict`、`enterprise` |
| `--min-severity <level>` | P1 | audit,probe,fuzz | 最低显示级别(info/low/medium/high/critical) |
| `--fix` | P2 | audit | 自动修复安全风险。仅修复 `auto_fixable: true` 的项（替换明文 key 为 `${VAR}` 引用、设置默认 timeout）。修复前自动备份原文件为 `<file>.hermes.bak`。权限变更（如通配符缩小）**不自动修**，仅给建议 |
| `--verbose` | P1 | all | 详细输出。日志/进度走 `stderr`，结果始终走 `stdout`。与 `--format json` 同时使用时，JSON 输出不受污染（verbose 信息仅在 stderr） |
| `--no-color` | P1 | all | 禁用颜色 |
| `--timeout <seconds>` | P1 | probe,fuzz | 探测超时(默认30s) |
| `--audit-key <file>` | P1 | audit,probe,fuzz,verify | HMAC 审计链密钥文件路径(16字节以上)，也支持环境变量 `HERMES_AUDIT_KEY`。verify 时需同一密钥 |
| `--init-key` | P1 | audit | 交互式创建 HMAC 审计链密钥文件，引导用户完成首次设置 |

---

### FR-02 静态配置扫描器

**目标:** 检测 MCP 配置文件中的安全风险。

**支持的配置格式:** MCP 标准 JSON (`mcp.json` / `.claude/mcp.json`)、Claude Desktop 配置、通用 JSON/YAML 配置。

**输入行为:**
- 路径为目录时递归扫描，最大深度 3 层
- 支持 glob 模式（如 `hermes audit "configs/**/*.json"`）
- 目录无配置文件时报 `hermes: no MCP config files found in <path>` 并退出码 0
- 支持 stdin: `cat mcp.json | hermes audit -`
- 非 MCP 配置格式的 JSON/YAML 文件跳过，输出 `skipped: <file> (unrecognized format)` warning 并继续

**通用格式兼容:** 自定义 YAML/JSON 配置的字段名可能有别名。扫描器按优先级匹配: `command` > `cmd` > `run` > `exec`（启动命令字段），`apiKey` > `api_key` > `token` > `accessToken` > `secret`（凭证字段）。

| ID | 规则名 | 优先级 | 严重级别 | 检测内容 | 依据 |
|:--|------|:--:|:--:|------|------|
| SC-01 | `hardcoded-api-key` | P0 | **critical** | 检测 `apiKey`、`token`、`secret`、`api_key`、`accessToken` 字段是否包含字面值(非 `${ENV_VAR}`) | MCP 安全白皮书 §Token Passthrough |
| SC-02 | `hardcoded-password` | P0 | **critical** | 检测 `password`、`passwd`、`pwd` 字段是否包含明文密码 | MCP 安全白皮书 §Token Passthrough |
| SC-03 | `dangerous-command` | P0 | **high** | 检测启动命令(args/command)是否包含 `sudo`、`rm -rf`、`curl \| bash`、`wget -O - \| sh` | MCP 安全白皮书 §Local Server Compromise |
| SC-04 | `overly-permissive` | P0 | **high** | 检测 `allowedTools` / `allow` 是否使用 `*` 通配符或无限制 | MCP 安全白皮书 §Scope Minimization |
| SC-05 | `no-tls` | P1 | **medium** | 检测 `url` 字段是否为 `http://`(非 `https://`) | 最佳实践 |
| SC-06 | `no-authentication` | P1 | **high** | 检测是否缺少 `Authorization` 头、OAuth 配置、`auth` 字段 | MCP 安全白皮书 §Authorization |
| SC-07 | `bind-public-interface` | P1 | **high** | 检测 `host` / `bind` 是否为 `0.0.0.0` | MCP 安全白皮书 §SSRF |
| SC-08 | `auto-approve` | P1 | **high** | 检测 `autoApprove` 配置跳过了用户确认 | MCP 安全白皮书 §Local Server Compromise |
| SC-09 | `no-timeout` | P2 | **low** | 检测高风险 Server 是否缺少 `timeout` 设置 | 最佳实践 |
| SC-10 | `unpinned-package` | P2 | **medium** | 检测 `npx -y` 是否未指定具体版本，存在供应链风险 | agentshield 验证 |
| SC-11 | `env-secret-leak` | P1 | **high** | 检测 `env` 字段是否暴露敏感值(非 `${VAR}` 引用) | MCP 安全白皮书 §Local Server Compromise |
| SC-12 | `sensitive-file-args` | P1 | **medium** | 检测启动参数是否传递 `.env`、`*.pem`、`*.key`、`credentials.*` | agentshield 验证 |
| SC-13 | `missing-description` | P2 | **info** | 检测 Server 是否缺少 `description` 字段 | 最佳实践 |
| SC-14 | `unsafe-filesystem` | P1 | **high** | 检测文件系统 Server 是否允许访问根目录 `/` 或用户目录 `~` | MCP 安全白皮书 §Local Server Compromise |
| SC-15 | `supply-chain-risk` | P2 | **medium** | 检测是否从非 npm/PyPI 官方源安装 | agentshield 验证 |
| SC-16 | `world-readable-config` | P2 | **medium** | 检测 MCP 配置文件权限是否过于宽松（world/group 可读） | 最佳实践 |

---

### FR-03 运行时探测器

**目标:** 连接运行中的 MCP Server，执行主动安全测试。

| ID | 规则名 | 优先级 | 严重级别 | 检测内容 | 依据 |
|:--|------|:--:|:--:|------|------|
| PR-01 | `tls-verify` | P0 | **critical** | 连接 MCP Server，验证 TLS 证书有效性、过期时间、加密套件强度。直接用 `rustls` 建连(非 `reqwest`，因 reqwest 不暴露对等证书) | 安全最佳实践 |
| PR-02 | `tls-missing` | P0 | **high** | 检测是否完全未启用 TLS | 安全最佳实践 |
| PR-03 | `auth-required` | P0 | **high** | 尝试无认证连接，检测 Server 是否正确拒绝 | MCP 安全白皮书 §Authorization |
| PR-04 | `auth-weak` | P1 | **medium** | 尝试弱认证(空 token/假 token)，检测错误信息是否泄露细节 | MCP 安全白皮书 §Authorization |
| PR-05 | `protocol-version` | P1 | **info** | 检测 MCP 协议版本是否过旧 | MCP 规范 |
| PR-06 | `tools-enumeration` | P0 | **info** | 获取并列出 `tools/list` 返回的所有工具(不计分，仅供参考) | 基础探测 |
| PR-07 | `dangerous-tools` | P0 | **high** | 标记危险工具——**基于模式匹配而非硬编码表**: 匹配 `delete`、`remove`、`execute`、`shell`、`exec`、`bash`、`run`、`write`、`patch`、`apply`、`create` 等危险操作前缀 | MCP 安全白皮书 §Scope Minimization |
| PR-08 | `ssrf-probe` | P1 | **critical** | 检测 Server 是否接受内网 URL 作为 tool 参数(参数注入检测)。无法做完整回连验证(需内网监听器) | MCP 安全白皮书 §SSRF |
| PR-09 | `ssrf-redirect` | P2 | **high** | 检测 Server 是否跟随 HTTP 重定向到内网地址 | MCP 安全白皮书 §SSRF |
| PR-10 | `session-predictability` | P1 | **high** | 获取 N 个 Session ID(默认10)，检测 UUID格式/hex格式/长度/是否自增。不做统计随机性检验(需>100样本) | MCP 安全白皮书 §Session Hijacking |
| PR-11 | `session-replay` | P2 | **high** | 重放过期/无效 Session ID，检测 Server 是否拒绝 | MCP 安全白皮书 §Session Hijacking |
| PR-12 | `session-fixation` | P2 | **medium** | 尝试在认证前设置 Session ID，检测认证后是否轮换 | MCP 安全白皮书 §Session Hijacking |
| PR-13 | `path-traversal` | P1 | **high** | 对文件工具发送 `../../../etc/passwd`、`..\..\windows\system32` 等，检测是否被正确拒绝 | MCP 安全白皮书 §Local Server Compromise |
| PR-14 | `confused-deputy` | P2 | **critical** | 检测代理 Server 的 OAuth 配置: audience 验证、per-client consent。**仅适用于 2025-11-25+ 协议版本的 Server** | MCP 安全白皮书 §Confused Deputy |
| PR-15 | `token-passthrough` | P2 | **critical** | 检测 Server 是否做了 token audience 验证。**仅适用于 2025-11-25+ 协议版本** | MCP 安全白皮书 §Token Passthrough |
| PR-16 | `scope-minimization` | P2 | **medium** | 检测 `scopes_supported` 是否包含 wildcard 或过多权限 | MCP 安全白皮书 §Scope Minimization |
| PR-17 | `health-check` | P0 | **info** | 基本连通性:`tools/list` 请求是否正常返回 | 基础探测 |

---

### FR-04 Fuzz 测试引擎

**目标:** 对 MCP Server 的工具输入发送畸形数据，检测鲁棒性。

**⚠️ 警告:** Fuzz 测试会直接向目标 MCP Server 发送异常数据，可能导致生产环境崩溃。请仅在测试/预发布环境中使用。

| ID | 测试 | 优先级 | 严重级别 | 输入 | 预期行为 |
|:--|------|:--:|:--:|------|------|
| FZ-01 | `empty-input` | P0 | **high** | `""`, `null`, `{}` | 不应崩溃，应返回明确的错误信息 |
| FZ-02 | `oversized-input` | P1 | **medium** | 1MB 字符串 | 应拒绝或截断，不应 OOM |
| FZ-03 | `special-chars` | P1 | **medium** | `\x00`, `\x1b`, `\u0000`, unicode 控制字符 | 不应崩溃或产生意外行为 |
| FZ-04 | `path-injection` | P1 | **high** | `../../../`, `/dev/null`, `NUL`, `CON` | 应拒绝越权访问 |
| FZ-05 | `sql-injection` | P2 | **high** | `' OR '1'='1`, `'; DROP TABLE--` | 不应执行 SQL 注入(对数据库工具) |
| FZ-06 | `command-injection` | P2 | **high** | `` `id` ``, `$(whoami)`, `; cat /etc/passwd` | 不应执行命令注入 |
| FZ-07 | `prompt-injection` | P2 | **medium** | `ignore previous instructions`, `you are now DAN` | 不应被指令覆盖(对 AI 工具) |
| FZ-08 | `crash-detect` | P1 | **high** | 前述所有输入 | 检测 Server 是否返回 5xx/连接断开/超时 |

---

### FR-05 策略引擎

| ID | 功能 | 优先级 | 说明 |
|:--|------|:--:|------|
| PL-01 | JSON 策略文件解析 | P1 | 读取策略文件，结构如下 |
| PL-02 | 严重级别阈值 | P1 | `min_severity: high` — 低于此级别的忽略 |
| PL-03 | 规则启用/禁用 | P1 | 按规则 ID 开关 |
| PL-04 | 白名单 | P2 | 排除特定 tool/路径不检测 |
| PL-05 | 内置策略模板 | P2 | `basic` / `strict` / `enterprise` 预设。`dengbao` 已提前至 P1 作为内置预设(SM-05) |
| PL-06 | 基线对比 | P2 | 本次扫描 vs 上次基线，检测新增/修复/未变 |

**策略文件格式 (JSON):**

```json
{
  "version": 1,
  "name": "企业 MCP 安全策略",
  "min_severity": "high",
  "rules": {
    "hardcoded-api-key": { "enabled": true, "severity": "critical" },
    "no-tls": { "enabled": true, "severity": "high" },
    "auto-approve": { "enabled": true, "severity": "high" },
    "no-timeout": { "enabled": false }
  },
  "exceptions": [
    {
      "rule": "dangerous-tools",
      "tool": "write_file",
      "reason": "业务需要，已做二次确认",
      "expires": "2026-12-31"
    }
  ]
}
```

---

### FR-06 审计引擎(直接复用 FRP-X `audit.rs`)

| ID | 功能 | 优先级 | 说明 |
|:--|------|:--:|------|
| AU-01 | HMAC-SHA256 审计链 | P1 | 每次命令执行生成独立审计链: `Hn = HMAC(Hn-1, record_n)`。`audit` 和 `probe` 产生独立的链，不合并。链文件命名: `.hermes/chain-{command}-{timestamp}.json` |
| AU-02 | 审计链文件 | P1 | 输出 `chain-{command}-{iso_timestamp}.json`，包含该次会话的全部检测记录 |
| AU-03 | 审计链验证 | P1 | `hermes verify` 重算 HMAC 链，检测是否被篡改 |
| AU-04 | 审计记录结构 | P1 | 每条记录: 时间戳、规则ID、严重级别、文件/目标、检测值、修复建议 |

**审计记录格式:**

```json
{
  "chain_version": 1,
  "algorithm": "HMAC-SHA256",
  "secret_hash": "sha256:abc123...",
  "records": [
    {
      "index": 1,
      "timestamp": "2026-06-02T12:00:00Z",
      "rule_id": "hardcoded-api-key",
      "severity": "critical",
      "target": "mcp.json:15",
      "finding": "apiKey 字段包含硬编码值 'sk-ant-...'",
      "recommendation": "替换为 ${ANTHROPIC_API_KEY}",
      "hmac": "a1b2c3..."
    }
  ]
}
```

---

### FR-07 合规报告

| ID | 功能 | 优先级 | 说明 |
|:--|------|:--:|------|
| RP-01 | 终端彩色报告 | P0 | 默认 human-readable 输出，颜色标识 CRITICAL(红)/HIGH(黄)/MEDIUM(蓝)/LOW(灰)/INFO(绿) |
| RP-02 | JSON 报告 | P0 | `{"score": 65, "grade": "C", "findings": [...]}` |
| RP-03 | 综合评分 | P1 | **公式:** `score = max(0, 100 - 25×critical - 10×high - 3×medium)`。下限为 0。`low`/`info` 不计分但出现在 summary 中。A=90-100, B=75-89, C=60-74, D=40-59, F=0-39 |
| RP-04 | 修复建议 | P1 | 每条 finding 附带 `recommendation` 字段 |
| RP-05 | HTML 报告 | P2 | 自包含 HTML，给管理层 |
| RP-06 | SARIF 报告 | P2 | GitHub Code Scanning 兼容 `.sarif` |
| RP-07 | 等保 2.0 合规报告 | P2 | 中国网络安全等级保护合规检查项 |
| RP-08 | 统计摘要 | P1 | 总发现数、各级别数量、扫描文件数、耗时 |

**JSON 报告格式:**

```json
{
  "tool": "hermes",
    "version": "0.3.1",
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
    "total": 29,
    "critical": 1,
    "high": 7,
    "medium": 8,
    "low": 10,
    "info": 3,
    "files_scanned": 17,
    "auto_fixable": 2,
    "duration_ms": 1234
  },
  "findings": [
    {
      "id": "hardcoded-api-key",
      "severity": "critical",
      "category": "secrets",
      "title": "API key 明文写在配置中",
      "file": "mcp.json",
      "line": 15,
      "evidence": "sk-ant-api03-xxxx...xxxx",
      "recommendation": "替换为 ${ANTHROPIC_API_KEY} 环境变量引用",
      "auto_fixable": true,
      "references": ["MCP Security §Token Passthrough"]
    }
  ]
}
```

---

### FR-08 CI/CD 集成

| ID | 功能 | 优先级 | 说明 |
|:--|------|:--:|------|
| CI-01 | 退出码约定 | P0 | 0=通过, 1=运行时错误, 2=发现问题 |
| CI-02 | `--format json` | P0 | JSON 输出供 CI 解析 |
| CI-03 | `--min-severity high` | P1 | CI 中只关注 high+ 的问题 |
| CI-04 | GitHub Action | P2 | 预构建 Action，一行配置即可集成 |
| CI-05 | SARIF 上传 | P2 | `hermes --format sarif > results.sarif` → `github/codeql-action/upload-sarif` |
| CI-06 | PR 评论 | P2 | 将扫描结果作为 PR Comment |

**GitHub Action 示例:**

```yaml
- name: Hermes Security Scan
  uses: faysal-X-N/hermes-action@v1
  with:
    path: "."
    min-severity: "high"
    fail-on-findings: "true"
```

---

### FR-09 SM-05 等保策略预设

| ID | 功能 | 优先级 | 说明 |
|:--|------|:--:|------|
| SM-05 | 等保策略预设 | P1 | `--preset dengbao` 在 audit/probe/fuzz 命令中启用内置等保 2.0 二级合规规则集，编译为 `BuiltinPreset` 嵌入二进制，零文件依赖。`hermes policy --template dengbao` 可序列化为 JSON 写盘 |

**Dengbao 预设规则映射（等保 2.0 二级）:**

| 等保要求 | 启用规则 |
|----------|---------|
| 访问控制 | SC-01(hardcoded-api-key), SC-04(overly-permissive), SC-06(no-authentication), SC-08(auto-approve), PR-03(auth-required), PR-07(dangerous-tools), PR-13(path-traversal) |
| 安全审计 | SC-02(hardcoded-password), SC-11(env-secret-leak) |
| 通信完整性 | SC-05(no-tls), PR-01(tls-verify), PR-02(tls-missing) |
| 通信保密性 | SC-05(no-tls), PR-01(tls-verify) |
| 软件容错 | FZ-01(empty-input), FZ-08(crash-detect) |
| 网络安全 | SC-07(bind-public-interface), PR-08(ssrf-probe) |

---

### FR-10 依赖管理
| `rustls` 显式使用 `ring` | `aws-lc-rs`(默认)需要 C 编译器。用 `ring` 纯 Rust 实现 |

---

## 非功能需求

| ID | 需求 | 说明 |
|:--|------|------|
| NF-01 | 性能 | 静态扫描 100 个配置文件 < 5 秒 |
| NF-02 | 性能 | 运行时探测单个 Server < 60 秒 |
| NF-03 | 二进制大小 | 单二进制 < 15MB |
| NF-04 | 跨平台 | Windows / Linux / macOS |
| NF-05 | 无外部依赖 | 纯 Rust 二进制，无需 Node/Python |
| NF-06 | 离线可用 | 静态扫描无需网络 |
| NF-07 | 安全 | 不收集任何遥测数据，不联网 |
| NF-08 | 安全 | Fuzz 测试在沙箱隔离的网络环境执行 |
| NF-09 | 语言 | 全部英文(README + 帮助文本 + 报告)。中文 README 作为补充 |
| NF-10 | 兼容性 | 兼容 MCP 协议 **2025-11-25 (DRAFT) 及以后版本**。PR-14/PR-15 等安全特性在 2024-11-05 协议中不存在，仅对 2025-11-25+ Server 生效 |

---

## 不做的功能

| 功能 | 原因 |
|------|------|
| 实时防护/在线阻断 | agentshield 已有 MiniClaw 沙箱。P2 后再评估 |
| Web Dashboard | CLI 工具为主。P2 后可加简单的本地 Dashboard |
| 插件系统 | 过度设计。v1.0 只做核心 |
| 多租户 SaaS | v1.0 是开源 CLI 工具，不是 SaaS |
| AI 自动修复 | agentshield 已有 Opus 4.6 分析。可以后续集成 LLM |
| Claude Code 专属扫描 | agentshield 已经做得很好。聚焦 MCP 协议层 |

---

## 开发里程碑

| 阶段 | 版本 | 时间 | 内容 | 状态 |
|:--:|------|:--:|------|:--:|
| **P0** | v0.1.0 | 2026-06-02 | CLI + 静态扫描(SC01-08) + 运行时基本探测(PR01-07) + JSON/终端输出 + CI(3平台+MSRV+双lint) | ✅ 已完成 |
| **P1** | v0.2.0 | 2026-06-02 | Fuzz 引擎(FZ-01/02/03/04/08) + 策略引擎(PL-01~03) + 审计链(AU-01~04) + 等保预设(SM-05) + SC-11/12/14 + PR-08/10/13 + HTML报告 + `hermes fuzz`/`verify`/`report` 命令 | ✅ 已完成 |
| **P2** | v0.3.0 | 2026-06-02 | SARIF + --fix + GitHub Action + 全部P2规则(SC-09/10/13/15/PR-09~16/FZ-05~07) + 白名单(PL-04) + 预设(PL-05) + 管理HTML(RP-05) + policy命令 | ✅ 已完成 |
| **P3** | v0.3.1 | — | wiremock集成测试 + cargo-dist预编译二进制 + 代码清洁 | — |
| **v1.0** | v1.0.0 | +2 周 | 文档完善 + 发布到 crates.io | — |

### P0 已交付清单

| 模块 | 内容 | 测试 | CI |
|------|------|:--:|:--:|
| CLI | `audit <path>` + `probe <url>` + 6 个通用标志 | 33 单元测试 | 3 平台 ✅ |
| 扫描器 | 目录递归(3层) + glob + stdin + JSON/YAML + 字段别名 | 5 扫描器测试 | — |
| SC01-08 | 8 条扫描规则全覆盖 | 每个规则 ≥1 测试 | — |
| PR01-07+17 | 8 条探测规则(TLS直连rustls + 认证 + 工具枚举) | — | — |
| 报告 | 终端彩色 + JSON 完整格式 + `--output` | — | — |
| CI | 3 平台测试 + MSRV 1.88.0 + 双 lint job | — | 6/6 ✅ |

---

## 技术决策

| 决策 | 选择 | 原因 |
|------|------|------|
| 语言 | Rust 1.88.0+ (MSRV) | 70% 代码参考 FRP-X，单二进制，无运行时依赖 |
| 异步运行时 | tokio 1.38 | 与 FRP-X 一致 |
| HTTP 客户端 | reqwest 0.12 | Rust 社区标准，支持 TLS |
| TLS 检测 | rustls 0.23 (ring) | 直接建连获取对等证书(非 reqwest)。显式使用 `ring` 加密后端 |
| TLS 连接 | tokio-rustls 0.26 + rustls-native-certs 0.8 | 系统根证书库 |
| CLI 框架 | clap 4 | derive 宏，简洁 |
| 序列化 | serde + serde_json | Rust 社区标准 |
| 日志 | tracing + tracing-subscriber | 结构化日志，verbose → stderr |
| 错误处理 | color-eyre | 彩色错误输出 |
| 终端输出 | console + tracing | 彩色报告 |
| 时间 | chrono | 证书过期检测 |
| 审计链 | HMAC-SHA256 (复用 FRP-X) | 金融级审计 |

---

## CI/CD 架构

| Job | 工具链 | 阻断? | 说明 |
|-----|--------|:--:|------|
| Test (3 平台) | stable | ✅ | 编译 + 33 单元测试 |
| MSRV | 1.88.0 | ✅ | 最低版本编译 |
| Lint (1.88.0) | 1.88.0 | ❌ | 固定版本 clippy 报告 |
| Lint (stable) | stable | ❌ | 最新版 lint 前瞻 |

---

## 依赖清单

> 实际依赖（21 个直接依赖）

| Crate | 用途 | 许可证 |
|------|------|------|
| clap 4 | CLI 解析 | MIT/Apache2 |
| tokio 1.38 | 异步运行时 | MIT |
| serde/serde_json | 序列化 | MIT/Apache2 |
| reqwest 0.12 | HTTP 探测 | MIT/Apache2 |
| rustls 0.23 | TLS 检测(直连) | MIT/Apache2 |
| tokio-rustls 0.26 | TLS 异步连接器 | MIT/Apache2 |
| rustls-native-certs 0.8 | 系统根证书 | MIT/Apache2 |
| x509-parser 0.16 | X509 证书解析 | MIT/Apache2 |
| ring 0.17 | 加密后端(显式声明) | ISC |
| tracing/tracing-subscriber | 日志 | MIT |
| chrono | 时间戳/证书过期 | MIT/Apache2 |
| uuid | Session ID 检测 | MIT/Apache2 |
| sha2/hmac/hex | 审计链哈希 | MIT/Apache2 |
| color-eyre | 错误报告 | MIT/Apache2 |
| console | 终端样式 | MIT |
| serde_yaml_ng 0.10 | MCP 配置文件 YAML 解析 | MIT |
| glob 0.3.3 | 配置文件 glob 路径匹配 | MIT/Apache2 |


### 维护风险提示

| Crate | 风险 | 缓解 |
|------|------|------|
| `serde_yaml_ng 0.10` | 自 2024-05 零更新，仓库无活动。仅用于 MCP 配置文件 YAML 回退解析 | 策略文件使用 JSON 格式（`.hermes-policy.json`）。关注替代品 `serde_yml` |
| `reqwest 0.12` | 0.13 已发布（2026-04），0.12 可能停止维护 | 当前使用 0.12，后续评估升级 |

---

## 已知技术限制

| 限制 | 影响 | 缓解 |
|------|------|------|
| **SSRF 无法做完整回连验证** — 无法在用户内网开监听器确认请求已发出 | PR-08 精度局限为参数注入检测。P2 考虑内网监听模式 | P1 检测 Server 是否接受内网 URL；P2 增加可选本地监听器 |
| **Session 随机性无法做统计检验** — 10 个样本不够算统计显著性 | PR-10 精度局限为格式和自增检测 | 检测 UUID/hex 格式、固定长度、是否单调自增 |
| **OAuth 攻击无法模拟** — 无有效 token 无法重放完整 OAuth 流程 | PR-14/PR-15 精度局限为静态合规检查 | 做配置合规检查 + 基础协议版本检测 |
| **stdio Server 不支持** — 当前架构只支持 HTTP/SSE MCP Server | P0 只能探测 HTTP/SSE Server | P2 增加 stdio 子进程启动支持 |
| **TLS 对等证书不通过 reqwest** — reqwest 不暴露 `PeerCertificate` | PR-01 需单独用 `rustls` + `tokio-rustls` 建连 | 在 prober 模块单独实现 TLS 握手代码 |
| **审计链持久化** — CLI 无状态，审计链文件需显式存储 | 需 `.hermes/` 目录 + `--audit-key` 参数 | 自动创建 `.hermes/`，找不到密钥时提示 |
| **Fuzz 测试无沙箱** — Hermes 直接在用户环境发 fuzz 请求 | 可能击溃生产环境 | CLI 和文档开头显式警告：仅用于测试/预发布环境 |
| **`--fix` 自动修改用户文件** | 修改配置有出错风险 | 修复前自动备份为 `<file>.hermes.bak`。仅修 `auto_fixable` 项。权限变更不自动修 |
| **scopes_supported 仅 OAuth Server** — PR-16 对无 OAuth 的本地 Server 无意义 | 误报 | 运行时探测先检测 Server 是否启用 OAuth，无则跳过 PR-16 |
| `--preset` 预设规则不可局部覆盖 | 灵活性受限 | P1 预设为全量启用，需覆盖时用 `--policy` |

---

## 已验证的依赖兼容性

所有依赖经 crates.io 和 RUSTSEC 验证：

- ✅ 零 RUSTSEC 安全公告
- ✅ 全部 MIT / Apache 2.0（除 `ring` 为 ISC 许可）
- ✅ 全部与 tokio 1.38 运行时兼容
- ✅ `rustls 0.23` + `ring` 与 FRP-X 一致，未来 workspace 合并无冲突
- ✅ `reqwest 0.12` + `rustls 0.23` 兼容 (hyper-rustls ^0.27)
- ✅ 无 Windows/Linux/macOS 特定限制

---

*文档版本: 3.0 | 最后更新: 2026-06-03*
*变更: P0/P1/P2 里程碑已完成交付。依赖清单同步至 Cargo.toml。MSRV 1.88.0。策略格式确认 JSON。移除未实现功能引用。*
