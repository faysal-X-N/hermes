#![allow(dead_code)]
use super::hmac;
use super::types::AuditChain;
use std::fs;

pub fn verify_chain_file(path: &str, key: Option<&str>) -> Result<(AuditChain, bool), String> {
    let content = fs::read_to_string(path).map_err(|e| format!("Cannot read file: {e}"))?;
    let chain: AuditChain =
        serde_json::from_str(&content).map_err(|e| format!("Invalid chain JSON: {e}"))?;
    let key_bytes = hmac::load_key(key)?;
    let valid = hmac::verify_chain(&chain, &key_bytes)?;
    Ok((chain, valid))
}
