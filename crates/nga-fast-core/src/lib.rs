//! Zero-dependency Rust utility library for NextGen-Anything (`nga-fast-core`).
//! Provides fast byte hashing, printable string extraction, and strict relative path checks.

/// Compute a deterministic 64-bit FNV-1a digest over raw bytes.
pub fn fnv1a_64(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// Extract printable ASCII runs of at least `min_len` bytes (capped at `max_str_len`) from a binary buffer.
pub fn extract_printable_ascii(
    data: &[u8],
    min_len: usize,
    max_items: usize,
    max_str_len: usize = 512,
) -> Vec<String> {
    let threshold = min_len.max(1);
    let limit = max_items.max(1);
    let cap_len = max_str_len.max(threshold);
    let mut results: Vec<String> = Vec::new();
    let mut current: Vec<u8> = Vec::new();

    for &b in data {
        if (0x20..=0x7e).contains(&b) {
            if current.len() < cap_len {
                current.push(b);
            }
        } else {
            if current.len() >= threshold {
                if let Ok(s) = String::from_utf8(std::mem::take(&mut current)) {
                    results.push(s);
                    if results.len() >= limit {
                        return results;
                    }
                }
            }
            current.clear();
        }
    }

    if current.len() >= threshold && results.len() < limit {
        if let Ok(s) = String::from_utf8(current) {
            results.push(s);
        }
    }

    results
}

/// Strictly verify that a relative archive/entry path does not escape or use unsafe characters.
pub fn is_safe_relative_entry(entry: &str) -> bool {
    if entry.bytes().any(|b| b == 0 || b < 0x20) {
        return false;
    }
    let trimmed = entry.trim();
    if trimmed.is_empty() || trimmed.starts_with('/') || trimmed.starts_with('\\') || trimmed.starts_with('~') {
        return false;
    }
    let normalized = trimmed.replace('\\', "/");
    if normalized.starts_with('/') {
        return false;
    }

    let mut non_empty_segments = 0usize;
    for seg in normalized.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." || seg.contains(':') || seg.starts_with('~') {
            return false;
        }
        let stripped_trailing = seg.trim_end_matches(|c| c == '.' || c == ' ');
        if stripped_trailing.is_empty() {
            return false;
        }
        non_empty_segments += 1;
    }

    non_empty_segments > 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fnv1a_and_strings() {
        let h1 = fnv1a_64(b"nextgen-anything");
        let h2 = fnv1a_64(b"nextgen-anything");
        assert_eq!(h1, h2);

        let sample = b"\x00\x01Hello_NGA_World\x00test";
        let found = extract_printable_ascii(sample, 4, 10, 64);
        assert!(found.contains(&"Hello_NGA_World".to_string()));
        assert!(found.contains(&"test".to_string()));
    }

    #[test]
    fn test_safe_relative_entry() {
        assert!(is_safe_relative_entry("assets/app.js"));
        assert!(!is_safe_relative_entry("../etc/passwd"));
        assert!(!is_safe_relative_entry(" /etc/passwd"));
        assert!(!is_safe_relative_entry("/abs/path.bin"));
        assert!(!is_safe_relative_entry("dir/file:stream"));
        assert!(!is_safe_relative_entry("..."));
    }
}
