use hermes::probe::{tls, types::ProbeContext};

#[tokio::test]
async fn test_tls_missing_http() {
    let ctx = ProbeContext::new("http://localhost", 5);
    let findings = tls::probe_tls(&ctx).await;
    assert!(findings.iter().any(|f| f.rule_id == "tls-missing"));
    assert_eq!(findings.len(), 1);
}
