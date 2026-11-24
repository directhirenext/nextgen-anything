# Python Developer Guide — NextGen-Anything (`nga`)

## Architecture Overview

`NextGen-Anything` (`nga`) is organized into clean, decoupled Python 3.10+ packages using the Python standard library:

- **`nga.core`**:
  - `contracts.py`: `NgaError`, `ToolResponse`, `SimulationReport`, `LedgerObligation`, and `HandleRegistry` (`#1`, `#2`...).
  - `security.py`: Secret/token redaction, HTTP header sanitization, Zip-Slip path containment, Python AST safety checks, and output character budgets.
  - `cache.py`: SQLite WAL content-addressed cache (`NgaCache`) with SHA-256 keys and TTL expiration.
  - `doctor.py`: Cross-OS detection (`linux`, `windows`, `macos`, `android-termux`) and optional CLI toolchain discovery.
  - `workspace.py`: Lockfile-guarded workspace state, journal, and tamper-evident `MerkleAuditChain`.
  - `ledger.py`: Reconstruction coverage tracker (`ObligationLedger`).
  - `plugins.py`: External plugin runner speaking JSON over `stdin`/`stdout`.
- **`nga.analyzers`**:
  - `web_js.py`: HTML structure and JS route/API/storage/sourcemap inspection.
  - `network_har.py`: HAR capture parsing, schema inference, and secret-redacted mock route extraction.
  - `archive_pkg.py`: Safe `.zip`, `.apk`, `.jar`, and `.asar` inspection with Zip-Slip and decompression bomb guards.
  - `binary_meta.py`: ELF, PE, Mach-O, and WASM header/string inspection with optional `rizin`/`radare2` support.
- **`nga.runtime`**:
  - `sandbox.py`: Isolated temporary directory execution with AST safety checks, timeouts, and process cleanup.
  - `simulator.py`: Pre-output simulation and smoke-test gate (`SimulationGate`).
  - `standin_server.py`: Thread-safe local HTTP mock/replay server (`StandInMockServer`).
- **`nga.builder`**:
  - `orchestrator.py`: Topological DAG task planner and runner (`WorkflowOrchestrator`).
  - `brief_gen.py`: Clean-room architectural blueprint and target stack generator.
  - `parity_loop.py`: Iterative simulation verification with 3-strike stall detection (`ParityVerificationLoop`).
  - `synthesizer.py`: SQLite CRUD project synthesizer (`AutonomousProjectSynthesizer`).
- **`nga.aaire`**:
  - `intent_agent.py`: Autonomous intent classifier, planner, and sandbox-verified runner (`AutonomousIntentAgent`).
  - `llm_engine.py`: Zero-dependency multi-provider LLM client (`UniversalLlmEngine`).
  - `memory_vault.py`: SQLite FTS5 RAG memory vault (`AaireMemoryVault`).
  - `telegram_bridge.py`: Telegram Bot API connector (`TelegramBotBridge`).
- **`nga.interfaces`**:
  - `cli.py`: Command-line entrypoint (`nga`).
  - `mcp_server.py`: Line-delimited JSON-RPC MCP `stdio` server (`nga mcp`).
  - `web_ui.py`: Local HTML5/Vanilla-JS dashboard and token-protected JSON REST API (`nga ui`).
  - `web_embed/`: Drop-in embeddable widget assets (`nga-widget.js`, `nga-widget.css`, `console.html`).
  - 
