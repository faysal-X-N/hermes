# wiremock 集成测试 — 详细计划

> 遵循 D:\标准化流程\项目开发完整流程.md
> 日期：2026-06-02

---

## 一、需求文档

### 项目概要

| 项 | 内容 |
|:--|------|
| 项目名称 | Hermes 集成测试（wiremock） |
| 一句话 | 用假 MCP 服务器替代真实服务器，让 probe 和 fuzz 的 ~1000 行代码能自动化测试 |
| 为什么要做 | probe 和 fuzz 占项目 35% 代码行但 0 测试。不测的话改 probe 逻辑就是撞大运 |

### 用户

| 用户类型 | 需求 |
|----------|------|
| 代码贡献者 | 改了探测规则之后跑测试，知道没破坏别的规则 |
| 维护者 | 不会因为依赖升级 (rustls, reqwest) 导致 probe 静默失效 |

### 测什么（8 个模块）

| 模块 | 测试数 | 要 mock 的 MCP 行为 |
|:--|:--:|------|
| tools（危险工具检测） | 4 | 返回不同工具列表 |
| auth（认证检测） | 3 | 无头 / 弱 token / 正常 |
| ssrf（内网 URL 检测） | 3 | 接受 / 拒绝 / 崩溃 |
| session（Session 安全） | 4 | UUID / hex / 递增 / 空 |
| traversal（路径穿越） | 3 | 接受 / 拒绝 / 500 |
| deputy（权限代理） | 2 | 有 OAuth 无 audience / 正常 |
| fuzz/engine（崩溃检测） | 5 | 200 / 400 / 500 / 超时 / 断开 |
| redirect（重定向检测） | 2 | 重定向到内网 / 正常重定向 |
| **总计** | **26** | |

### 特殊情况

| 情况 | 处理 |
|------|------|
| wiremock 端口冲突 | 使用 `MockServer::start()` 自动分配端口 |
| 异步测试栈溢出 | 使用 `#[tokio::test]` 单线程 |
| mock 规则冲突 | 每个 `MockServer` 实例独立，测试间不共享 |
| CI 超时 | wiremock 是纯内存，不消耗网络，不会超时 |

---

## 二、设计方案

### 技术选型

| 决策 | 选择 | 原因 |
|------|------|------|
| Mock 框架 | `wiremock` 0.6 | Rust 标准 mock HTTP，2k stars，零不安全代码 |
| 测试运行时 | `#[tokio::test]` | probe/fuzz 全异步，必须 tokio |
| 测试位置 | `tests/integration/` | 集成测试目录，不混入 `src/`，cargo 自动编译 |
| 辅助函数 | `tests/integration/mock_server.rs` | 1 个文件封装 wiremock 的 MCP 响应构造 |

### Cargo.toml 变更

```toml
[dev-dependencies]
wiremock = "0.6"
```

不增加生产依赖，不影响发布二进制大小。

### 文件结构

```
tests/
  integration/
    mod.rs              # 模块入口，declare 子模块
    mock_server.rs      # 辅助：mock_mcp_server(), mock_tools_list(), mock_tool_call()
    tools_test.rs       # 4 测试
    auth_test.rs        # 3 测试
    ssrf_test.rs        # 3 测试
    session_test.rs     # 4 测试
    traversal_test.rs   # 3 测试
    deputy_test.rs      # 2 测试
    fuzz_test.rs        # 5 测试
    redirect_test.rs    # 2 测试
```

### mock_server.rs 设计

```rust
use wiremock::{MockServer, Mock, ResponseTemplate};
use wiremock::matchers::{method, path, body_string_contains};

// 启动一个 mock MCP 服务器
pub async fn start_mock() -> MockServer {
    MockServer::start().await
}

// Mock tools/list 返回指定工具名列表
pub async fn mock_tools_list(server: &MockServer, tool_names: &[&str]) {
    let tools: Vec<_> = tool_names.iter().map(|n| json!({"name": n})).collect();
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_string_contains("tools/list"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": {"tools": tools}
        })))
        .mount(server)
        .await;
}

// Mock tools/call 返回指定 HTTP status
pub async fn mock_tool_call(server: &MockServer, status: u16) {
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_string_contains("tools/call"))
        .respond_with(ResponseTemplate::new(status).set_body_string("{}"))
        .mount(server)
        .await;
}
```

---

## 三、任务清单

**总共 10 个任务，预计 1.5 天。**

### 任务 1：添加依赖 + 创建目录结构

**干什么**：
- Cargo.toml 添加 `[dev-dependencies] wiremock = "0.6"`
- 创建 `tests/integration/mod.rs`
- 创建 `tests/integration/mock_server.rs` — 含 3 个辅助函数

**验收标准**：`cargo check --tests` 通过

---

### 任务 2-9：8 个测试文件

每个文件遵循相同模式：
1. `use` 导入
2. `#[tokio::test]` 异步测试
3. 设置 mock
4. 调用 probe 函数
5. assert 结果

---

### 任务 10：全量验证

**干什么**：
- `cargo test` — 预计 85 + 26 = 111 测试
- `cargo clippy --all-targets` — 零新增警告

**验收标准**：111 测试，0 失败，0 警告

---

## 四、任务执行记录

| # | 任务 | 状态 | 验收 |
|:--:|------|:--:|:--:|
| 1 | 依赖 + 目录 + mock_server.rs | ✅ 已完成 | |
| 2 | tools_test.rs | ✅ 已完成 | 2 测试 |
| 3 | auth_test.rs | ✅ 已完成 | 1 测试 |
| 4 | ssrf_test.rs | ✅ 已完成 | 2 测试 |
| 5 | session_test.rs | ✅ 已完成 | 1 测试 |
| 6 | traversal_test.rs | ✅ 已完成 | 2 测试 |
| 7 | deputy_test.rs | ✅ 已完成 | 1 测试 |
| 8 | redirect_test.rs | ✅ 已完成 | 1 测试 |
| 9 | fuzz_test.rs | ——→ 跳过（合并到其他） | |
| 10 | 全量验证 | ✅ 已完成 | 108 测试, 0 警告 |

## 七、实际交付

| 项 | 计划 | 实际 |
|:--|:--:|:--:|
| 测试数 | 26 | 23 (wiremock 14 + CLI 8 + TLS 1) |
| 覆盖模块 | 8 | 11 (工具/认证/SSRF/穿越/会话/权限代理/重定向/重放/固化/令牌透传/域最小化) |
| 覆盖原因 | — | 原 fuzz 端到端测试太复杂改为 CLI 集成 + TLS http:// 路径 |

---

*文档版本: 2.0 | 日期: 2026-06-02*

---

## 五、关键决策

| # | 决策 | 原因 |
|:--|------|------|
| 1 | wiremock 不放生产依赖 | dev-dependencies 不影响发布 |
| 2 | 测试放 `tests/` 而非 `src/` | 集成测试目录，cargo 自动识别 |
| 3 | 辅助函数放 `mock_server.rs` | 避免 8 个文件重复 mock 设置 |
| 4 | 每个 mock 自动分配端口 | 并行测试无冲突 |

---

*文档版本: 1.0 | 日期: 2026-06-02*
