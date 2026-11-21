# NextGen-Anything (`nga`)

**Cross-OS Software Analysis, Pre-Execution Sandbox Simulation, Mock Runtime & Autonomous Reconstruction Engine**

`NextGen-Anything` (`nga`) is an open-source, clean-room developer toolkit for learning, inspecting web/JS/HAR/archive/binary targets, running offline mock stand-in servers, validating crafted code in an isolated sandbox simulation gate, and tracking reconstruction coverage via an obligation ledger and SHA-256 Merkle audit chain.

---

## 1. Core Capabilities & Architecture

- **Layer 1 — Foundation (`nga/core/`):**
  - `contracts.py`: `NgaError`, `ToolResponse`, `SimulationReport`, `LedgerObligation`, and compact integer handles (`#1`, `#2`...).
  - `security.py`: Secret/token redaction, HTTP header sanitization, Zip-Slip path guards, Python AST safety checks, and output character budgets.
  - `cache.py`: SQLite WAL SHA-256 cache (`NgaCache`) with TTL expiration.
  - `doctor.py`: Cross-OS detection (`linux`, `windows`, `macos`, `android-termux`) and optional external tool detection (`jadx`, `apktool`, `rizin`, `radare2`, `node`, `cargo`, `curl`).
  - `workspace.py`: Lockfile-guarded workspace state, journal, and tamper-evident `MerkleAuditChain`.
  - `ledger.py`: Reconstruction coverage tracker (`ObligationLedger`).
  - `plugins.py`: External plugin runner using JSON over `stdin`/`stdout`.
- **Layer 2 — Analyzers (`nga/analyzers/`):**
  - `web_js.py`: HTML structure and JS routes, API calls, storage keys, imports, and sourcemaps.
  - `network_har.py`: HAR parsing, JSON schema inference, and secret-redacted mock routes.
  - `archive_pkg.py`: Safe `.zip`, `.apk`, `.jar`, and `.asar` inspection with Zip-Slip and decompression bomb limits.
  - `binary_meta.py`: ELF, PE, Mach-O, and WASM header/string inspection + optional `rizin`/`radare2` bridge.
- **Layer 3 — Runtime (`nga/runtime/`):**
  - `sandbox.py`: Isolated temporary folder execution with AST check, restricted environment, timeout, and process cleanup.
  - `simulator.py`: Pre-output dry-run simulation and smoke-test gate (`SimulationGate`).
  - `standin_server.py`: Thread-safe local HTTP mock/replay server (`127.0.0.1`).
- **Layer 4 — Builder (`nga/builder/`):**
  - `orchestrator.py`: DAG task planner with topological sorting and cycle detection (`WorkflowOrchestrator`).
  - `brief_gen.py`: Clean-room architecture brief and stack selector.
  - `parity_loop.py`: Iterative simulation verification with 3-strike stall detection (`ParityVerificationLoop`).
- **Layer 5 — Quad-Interface (`nga/interfaces/`):**
  - **CLI (`cli.py`)**: `nga doctor`, `nga inspect`, `nga simulate`, `nga ledger`, `nga brief`, `nga ui`, `nga mcp`.
  - **MCP Server (`mcp_server.py`)**: Line-delimited JSON-RPC `stdio` server (`nga mcp`).
  - **Local Web UI & REST API (`web_ui.py`)**: Zero-build HTML5/CSS3/Vanilla JS dashboard + CORS JSON API (`nga ui --port 8765`).
  - **Website Embed Widget (`web_embed/`)**: `nga-widget.js`, `nga-widget.css`, and `demo.html`.
- **Layer 6 — Polyglot & Docs (`crates/`, `sdk/`, `docs/`, `tests/`):**
  - Optional Rust crate (`crates/nga-fast-core`) and SDKs in Python (`sdk/python/nga_client.py`), Rust (`sdk/rust/src/lib.rs`), JS (`sdk/js/nga-client.mjs`), and Web (`sdk/web/nga-embed-example.html`).

---

## 2. How to Create & Edit Files via GitHub Web UI (Mobile Chrome)

1. Open your repository on GitHub in Chrome.
2. Tap **Add file -> Create new file** (or open an existing file and tap the **Edit / pencil** icon).
3. Enter the exact file path (for example, `tests/test_core_security.py` or `docs/GUIDE_WEB.md`).
4. Paste the complete file content with no placeholders or `TODO` stubs.
5. Tap **Commit changes...** and confirm.

---

## 3. Setup & Usage Commands

```bash
pip install -e .
nga doctor
nga inspect web index.html
nga simulate 'x = 2 + 2; assert x == 4; print("OK")' --label check
nga ledger add --id api_health --category endpoint --title "Health endpoint"
nga ledger list
nga brief --label my_project --kind web
nga ui --host 127.0.0.1 --port 8765
nga mcp
