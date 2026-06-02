// Integration tests for Hermes probe and fuzz modules
// Uses wiremock to simulate MCP server responses

use hermes::audit::types::Severity;
use hermes::probe::{
    auth, deputy, fixation, passthrough, redirect, replay, session, ssrf, tools, traversal,
    types::ProbeContext,
};
use serde_json::json;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ── helpers ─────────────────────────────────────────────────────────

async fn start() -> MockServer {
    MockServer::start().await
}

async fn mock_tools_list(server: &MockServer, tool_names: &[&str]) {
    let tools: Vec<_> = tool_names.iter().map(|n| json!({"name": n})).collect();
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_string_contains("tools/list"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "result": {"tools": tools},
            "id": 1
        })))
        .mount(server)
        .await;
}

async fn mock_tool_call_status(server: &MockServer, status: u16) {
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_string_contains("tools/call"))
        .respond_with(ResponseTemplate::new(status).set_body_string("{}"))
        .mount(server)
        .await;
}

fn has_finding(findings: &[hermes::probe::types::ProbeFinding], rule_id: &str) -> bool {
    findings.iter().any(|f| f.rule_id == rule_id)
}

fn severity(findings: &[hermes::probe::types::ProbeFinding], rule_id: &str) -> Option<Severity> {
    findings.iter().find(|f| f.rule_id == rule_id).map(|f| f.severity)
}

// ── tools tests ─────────────────────────────────────────────────────

#[tokio::test]
async fn test_tools_detects_dangerous() {
    let s = start().await;
    mock_tools_list(&s, &["write_file", "execute_command", "read_file"]).await;

    let ctx = ProbeContext::new(&s.uri(), 5);
    let result = tools::probe_tools(&ctx).await;

    assert!(has_finding(&result.findings, "dangerous-tools"));
    assert_eq!(severity(&result.findings, "dangerous-tools"), Some(Severity::High));
}

#[tokio::test]
async fn test_tools_no_dangerous() {
    let s = start().await;
    mock_tools_list(&s, &["read_file", "list_directory"]).await;

    let ctx = ProbeContext::new(&s.uri(), 5);
    let result = tools::probe_tools(&ctx).await;

    assert!(!has_finding(&result.findings, "dangerous-tools"));
}

// ── auth tests ──────────────────────────────────────────────────────

#[tokio::test]
async fn test_auth_detects_missing() {
    let s = start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
        .mount(&s)
        .await;

    let ctx = ProbeContext::new(&s.uri(), 5);
    let result = auth::probe_auth(&ctx).await;

    assert!(has_finding(&result, "auth-required"));
}

// ── ssrf tests ──────────────────────────────────────────────────────

#[tokio::test]
async fn test_ssrf_detects_internal_url_accepted() {
    let s = start().await;
    mock_tools_list(&s, &["fetch"]).await;
    mock_tool_call_status(&s, 200).await;

    let ctx = ProbeContext::new(&s.uri(), 5);
    let result = ssrf::probe_ssrf(&ctx).await;

    assert!(has_finding(&result, "ssrf-probe"));
    assert_eq!(severity(&result, "ssrf-probe"), Some(Severity::Critical));
}

#[tokio::test]
async fn test_ssrf_rejects_safely() {
    let s = start().await;
    mock_tools_list(&s, &["fetch"]).await;
    mock_tool_call_status(&s, 400).await;

    let ctx = ProbeContext::new(&s.uri(), 5);
    let result = ssrf::probe_ssrf(&ctx).await;

    assert!(!result.iter().any(|f| f.severity >= Severity::High && f.rule_id == "ssrf-probe"));
}

// ── traversal tests ─────────────────────────────────────────────────

#[tokio::test]
async fn test_traversal_detects_path_accepted() {
    let s = start().await;
    mock_tools_list(&s, &["read_file", "write_file"]).await;
    mock_tool_call_status(&s, 200).await;

    let ctx = ProbeContext::new(&s.uri(), 5);
    let result = traversal::probe_path_traversal(&ctx).await;

    assert!(has_finding(&result, "path-traversal"));
}

#[tokio::test]
async fn test_traversal_rejects_safely() {
    let s = start().await;
    mock_tools_list(&s, &["read_file"]).await;
    mock_tool_call_status(&s, 400).await;

    let ctx = ProbeContext::new(&s.uri(), 5);
    let result = traversal::probe_path_traversal(&ctx).await;

    assert!(!result.iter().any(|f| f.severity >= Severity::High && f.rule_id == "path-traversal"));
}

// ── session tests ───────────────────────────────────────────────────

#[tokio::test]
async fn test_session_detects_uuid() {
    let s = start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Set-Cookie", "session=550e8400-e29b-41d4-a716-446655440000; Path=/")
                .set_body_string("{}"),
        )
        .expect(10)
        .mount(&s)
        .await;

    let ctx = ProbeContext::new(&format!("{}/", s.uri()), 5);
    let result = session::probe_session(&ctx).await;

    assert!(has_finding(&result, "session-predictability"));
    assert_eq!(severity(&result, "session-predictability"), Some(Severity::Low));
}

// ── deputy tests ────────────────────────────────────────────────────

#[tokio::test]
async fn test_deputy_skips_without_oauth() {
    let s = start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
        .mount(&s)
        .await;

    let ctx = ProbeContext::new(&s.uri(), 5);
    let result = deputy::probe_confused_deputy(&ctx).await;

    assert!(has_finding(&result, "confused-deputy"));
    assert_eq!(severity(&result, "confused-deputy"), Some(Severity::Low));
}

// ── redirect tests ──────────────────────────────────────────────────

#[tokio::test]
async fn test_redirect_detects_internal_target() {
    let s = start().await;
    mock_tools_list(&s, &["fetch"]).await;

    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_string_contains("tools/call"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("Location", "http://127.0.0.1/secret")
                .set_body_string(""),
        )
        .mount(&s)
        .await;

    let ctx = ProbeContext::new(&s.uri(), 5);
    let result = redirect::probe_ssrf_redirect(&ctx).await;

    assert!(has_finding(&result, "ssrf-redirect"));
}

// ── replay tests ────────────────────────────────────────────────────

#[tokio::test]
async fn test_replay_detects_session_accepted() {
    let s = start().await;

    Mock::given(method("POST"))
        .and(path("/mcp"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Set-Cookie", "session=abc123; Path=/")
                .set_body_json(json!({"jsonrpc":"2.0","result":{"tools":[]},"id":1})),
        )
        .mount(&s)
        .await;

    let ctx = ProbeContext::new(&format!("{}/", s.uri()), 5);
    let result = replay::probe_session_replay(&ctx).await;

    assert!(has_finding(&result, "session-replay"));
}

// ── fixation tests ──────────────────────────────────────────────────

#[tokio::test]
async fn test_fixation_detects_no_rotation() {
    let s = start().await;

    Mock::given(method("POST"))
        .and(path("/mcp"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Set-Cookie", "session=fixation-test-12345; Path=/")
                .set_body_string("{}"),
        )
        .mount(&s)
        .await;

    let ctx = ProbeContext::new(&s.uri(), 5);
    let result = fixation::probe_session_fixation(&ctx).await;

    assert!(has_finding(&result, "session-fixation"));
}

// ── passthrough tests ───────────────────────────────────────────────

#[tokio::test]
async fn test_token_passthrough_detects_missing_audience() {
    let s = start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/oauth-authorization-server"))
        .respond_with(ResponseTemplate::new(200)
            .set_body_json(json!({"issuer": "https://example.com"})))
        .mount(&s)
        .await;

    let ctx = ProbeContext::new(&s.uri(), 5);
    let result = passthrough::probe_token_passthrough(&ctx).await;

    assert!(has_finding(&result, "token-passthrough"));
    assert_eq!(severity(&result, "token-passthrough"), Some(Severity::Critical));
}

#[tokio::test]
async fn test_scope_minimization_detects_wildcard() {
    let s = start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_string_contains("tools/list"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "result": {
                "tools": [{"name": "read_file"}],
                "scopes_supported": ["read:*", "write:custom"]
            },
            "id": 1
        })))
        .mount(&s)
        .await;

    let ctx = ProbeContext::new(&s.uri(), 5);
    let result = passthrough::probe_scope_minimization(&ctx).await;

    assert!(has_finding(&result, "scope-minimization"));
    assert_eq!(severity(&result, "scope-minimization"), Some(Severity::Medium));
}
