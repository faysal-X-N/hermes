use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub index: u64,
    pub timestamp: String,
    pub rule_id: String,
    pub severity: String,
    pub target: String,
    pub finding: String,
    pub recommendation: String,
    pub hmac: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditChain {
    pub chain_version: u32,
    pub algorithm: String,
    pub secret_hash: String,
    pub records: Vec<AuditRecord>,
}

impl AuditChain {
    pub fn new(secret_hash: String) -> Self {
        Self {
            chain_version: 1,
            algorithm: "HMAC-SHA256".into(),
            secret_hash,
            records: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_chain_new() {
        let chain = AuditChain::new("sha256:abc123".into());
        assert_eq!(chain.chain_version, 1);
        assert_eq!(chain.algorithm, "HMAC-SHA256");
        assert_eq!(chain.secret_hash, "sha256:abc123");
        assert!(chain.records.is_empty());
    }
}
