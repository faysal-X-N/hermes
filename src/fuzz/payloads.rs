#![allow(dead_code)]
use serde_json::Value;

pub fn empty_payloads() -> Vec<Value> {
    vec![
        Value::Null,
        Value::String(String::new()),
        serde_json::json!({}),
    ]
}

pub fn oversized_payloads() -> Vec<Value> {
    let big = "A".repeat(1024 * 1024);
    vec![Value::String(big)]
}

pub fn special_char_payloads() -> Vec<Value> {
    vec![
        Value::String("\x00".into()),
        Value::String("\x1b".into()),
        Value::String("\u{0000}".into()),
        Value::String("\\x00\\x1b\\u0000".into()),
    ]
}

pub fn path_injection_payloads() -> Vec<Value> {
    vec![
        Value::String("../../../etc/passwd".into()),
        Value::String("..\\..\\windows\\system32".into()),
        Value::String("/dev/null".into()),
        Value::String("NUL".into()),
        Value::String("CON".into()),
    ]
}
