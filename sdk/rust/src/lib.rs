//! Lightweight Rust SDK payload and endpoint helper for NextGen-Anything (`nga`).

/// Escape a string safely for embedding inside a JSON string literal.
pub fn escape_json_string(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 8);
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// Build a full REST endpoint URL from a base URL and API route.
pub fn build_endpoint_url(base_url: &str, route: &str) -> String {
    let base = base_url.trim_end_matches('/');
    let path = if route.starts_with('/') {
        route.to_string()
    } else {
        format!("/{route}")
    };
    format!("{base}{path}")
}

/// Build a JSON payload for `/api/simulate`.
pub fn build_simulate_payload(code: &str, label: &str, smoke_code: &str) -> String {
    format!(
        "{{\"code\":\"{}\",\"label\":\"{}\",\"smoke_code\":\"{}\"}}",
        escape_json_string(code),
        escape_json_string(label),
        escape_json_string(smoke_code)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sdk_helpers() {
        assert_eq!(
            build_endpoint_url("http://127.0.0.1:8765/", "api/doctor"),
            "http://127.0.0.1:8765/api/doctor"
        );
        let payload = build_simulate_payload("print(\"hi\")", "rust_sdk", "");
        assert!(payload.contains("\\\"hi\\\""));
        assert!(payload.contains("rust_sdk"));
    }
          }
