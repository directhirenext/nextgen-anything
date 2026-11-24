# Rust Developer Guide — NextGen-Anything (`nga`)

## Overview

While the core `NextGen-Anything` (`nga`) engine runs on Python 3.10+ with zero external runtime dependencies, Rust developers can explore and extend two clean, zero-dependency Rust components:

1. **`crates/nga-fast-core/`**: High-speed utility functions for deterministic FNV-1a byte hashing (`fnv1a_64`), printable ASCII string scanning (`extract_printable_ascii`), and safe relative archive path validation (`is_safe_relative_entry`).
2. **`sdk/rust/`**: Endpoint URL builder (`build_endpoint_url`), JSON string escaping (`escape_json_string`), and simulation payload builder (`build_simulate_payload`) for talking to `nga` HTTP endpoints.

---

## Running Rust Tests

From the `crates/nga-fast-core` directory:

```bash
cargo test
```
