use reqwest::Client;
use serde_json::Value;

pub async fn discover_tools(client: &Client, base: &str) -> Option<Vec<String>> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "tools/list",
        "params": {},
        "id": 1
    });

    let resp = client
        .post(format!("{base}/mcp"))
        .json(&body)
        .header("Content-Type", "application/json")
        .send()
        .await
        .ok()?;

    let json: Value = resp.json().await.ok()?;
    let tools: Vec<String> = json
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(|t| t.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|t| t.get("name").and_then(|n| n.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default();

    if tools.is_empty() { None } else { Some(tools) }
}

pub async fn discover_fs_tools(client: &Client, base: &str) -> Option<Vec<String>> {
    let mut tools = discover_tools(client, base).await?;
    tools.retain(|name| {
        let lower = name.to_lowercase();
        lower.contains("file") || lower.contains("read") || lower.contains("write") || lower.contains("fs")
    });
    if tools.is_empty() { None } else { Some(tools) }
}
