//! Zero-dependency Rust SDK payload, URL, and HTTP/1.1 client for NextGen-Anything (`nga`).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

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

/// Build a full REST endpoint URL from a base URL and API route safely.
pub fn build_endpoint_url(base_url: &str, route: &str) -> String {
    let base = base_url.trim().trim_end_matches('/');
    let clean_route = route.trim().trim_start_matches('/');
    format!("{base}/{clean_route}")
}

/// Build a JSON payload for `/api/simulate` using canonical `"smoke"` field.
pub fn build_simulate_payload(code: &str, label: &str, smoke_code: &str) -> String {
    format!(
        "{{\"code\":\"{}\",\"label\":\"{}\",\"smoke\":\"{}\"}}",
        escape_json_string(code),
        escape_json_string(label),
        escape_json_string(smoke_code)
    )
}

/// Build a JSON payload for `/api/inspect` or `/api/rebuild`.
pub fn build_target_action_payload(kind: &str, target: &str, output_dir: &str) -> String {
    format!(
        "{{\"kind\":\"{}\",\"target\":\"{}\",\"output_dir\":\"{}\"}}",
        escape_json_string(kind),
        escape_json_string(target),
        escape_json_string(output_dir)
    )
}

/// Build a JSON payload for `/api/agent`.
pub fn build_agent_payload(prompt: &str, candidate_code: &str, target_label: &str) -> String {
    format!(
        "{{\"prompt\":\"{}\",\"candidate_code\":\"{}\",\"target_label\":\"{}\"}}",
        escape_json_string(prompt),
        escape_json_string(candidate_code),
        escape_json_string(target_label)
    )
}

/// Build a JSON payload for `/api/memory` (`POST`).
pub fn build_memory_store_payload(title: &str, body: &str, namespace: &str) -> String {
    format!(
        "{{\"title\":\"{}\",\"body\":\"{}\",\"namespace\":\"{}\"}}",
        escape_json_string(title),
        escape_json_string(body),
        escape_json_string(namespace)
    )
}

/// Build a JSON payload for `/api/brief` (`POST`).
pub fn build_brief_payload(label: &str, kind: &str) -> String {
    format!(
        "{{\"label\":\"{}\",\"kind\":\"{}\"}}",
        escape_json_string(label),
        escape_json_string(kind)
    )
}

/// Lightweight zero-dependency HTTP/1.1 client for `http://` loopback/LAN endpoints with optional token auth.
pub struct NgaRustClient {
    pub base_url: String,
    pub api_token: String,
    pub timeout: Duration,
}

impl NgaRustClient {
    pub fn new(base_url: &str, api_token: &str, timeout_secs: u64) -> Self {
        Self {
            base_url: base_url.trim().trim_end_matches('/').to_string(),
            api_token: api_token.trim().to_string(),
            timeout: Duration::from_secs(timeout_secs.max(1)),
        }
    }

    pub fn endpoint_url(&self, route: &str) -> String {
        build_endpoint_url(&self.base_url, route)
    }

    fn parse_http_target(&self, route: &str) -> Result<(String, u16, String), String> {
        let without_scheme = self
            .base_url
            .strip_prefix("http://")
            .ok_or_else(|| "NgaRustClient stdlib TCP transport supports http:// endpoints.".to_string())?;
        let authority = without_scheme.split('/').next().unwrap_or("").trim();
        if authority.is_empty() {
            return Err("Missing host in base_url.".to_string());
        }
        let (host, port) = if let Some((h, p)) = authority.rsplit_once(':') {
            let parsed_port = p.parse::<u16>().unwrap_or(80);
            (h.trim_matches(|c| c == '[' || c == ']').to_string(), parsed_port)
        } else {
            (authority.trim_matches(|c| c == '[' || c == ']').to_string(), 80)
        };
        let clean_route = route.trim().trim_start_matches('/');
        let path = format!("/{clean_route}");
        Ok((host, port, path))
    }

    /// Perform an HTTP/1.1 GET or POST request and return raw HTTP response text.
    pub fn send_request(&self, method: &str, route: &str, json_body: Option<&str>) -> Result<String, String> {
        let (host, port, path) = self.parse_http_target(route)?;
        let addr_iter = format!("{host}:{port}")
            .to_socket_addrs()
            .map_err(|e| format!("DNS/address resolution failed: {e}"))?;
        let addr: SocketAddr = addr_iter
            .into_iter()
            .next()
            .ok_or_else(|| "No socket address resolved.".to_string())?;

        let mut stream = TcpStream::connect_timeout(&addr, self.timeout)
            .map_err(|e| format!("TCP connection failed: {e}"))?;
        let _ = stream.set_read_timeout(Some(self.timeout));
        let _ = stream.set_write_timeout(Some(self.timeout));

        let upper_method = method.trim().to_uppercase();
        let body_str = json_body.unwrap_or("{}");
        let is_post = upper_method != "GET" && upper_method != "HEAD";
        let body_bytes = if is_post { body_str.as_bytes() } else { &[][..] };

        let mut req = format!(
            "{upper_method} {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\nAccept: application/json\r\n"
        );
        if !self.api_token.is_empty() {
            req.push_str(&format!(
                "X-NGA-Token: {}\r\nAuthorization: Bearer {}\r\n",
                self.api_token, self.api_token
            ));
        }
        if is_post {
            req.push_str(&format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                body_bytes.len()
            ));
        }
        req.push_str("\r\n");

        stream
            .write_all(req.as_bytes())
            .map_err(|e| format!("Failed writing HTTP request headers: {e}"))?;
        if is_post && !body_bytes.is_empty() {
            stream
                .write_all(body_bytes)
                .map_err(|e| format!("Failed writing HTTP request body: {e}"))?;
        }
        let _ = stream.flush();

        let mut raw_resp = Vec::with_capacity(4096);
        let mut buf = [0u8; 2048];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    raw_resp.extend_from_slice(&buf[..n]);
                    if raw_resp.len() > 2 * 1024 * 1024 {
                        break;
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                    break;
                }
                Err(e) => return Err(format!("Failed reading HTTP response: {e}")),
            }
        }
        Ok(String::from_utf8_lossy(&raw_resp).into_owned())
    }

    pub fn doctor(&self) -> Result<String, String> {
        self.send_request("GET", "/api/doctor", None)
    }

    pub fn simulate(&self, code: &str, label: &str, smoke_code: &str) -> Result<String, String> {
        let payload = build_simulate_payload(code, label, smoke_code);
        self.send_request("POST", "/api/simulate", Some(&payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sdk_helpers() {
        assert_eq!(
            build_endpoint_url("http://127.0.0.1:8765/", "/api/doctor"),
            "http://127.0.0.1:8765/api/doctor"
        );
        let payload = build_simulate_payload("print(\"hi\")", "rust_sdk", "assert True");
        assert!(payload.contains("\\\"hi\\\""));
        assert!(payload.contains("rust_sdk"));
        assert!(payload.contains("\"smoke\":\"assert True\""));

        let client = NgaRustClient::new("http://127.0.0.1:8765", "tok_123", 5);
        assert_eq!(client.endpoint_url("api/ledger"), "http://127.0.0.1:8765/api/ledger");
    }
}
