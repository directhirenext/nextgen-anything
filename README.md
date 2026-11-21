# NextGen-Anything (`nga`)

**Cross-OS Software Analysis, Pre-Execution Sandbox Simulation, Mock Runtime & Autonomous Reconstruction Engine**

`NextGen-Anything` (`nga`) is an open-source, clean-room developer toolkit designed for learning, inspecting software structures and network captures, running offline mock stand-in servers, validating generated code inside an isolated sandbox simulation gate, and tracking reconstruction coverage via an obligation ledger and SHA-256 Merkle audit chain.

---

## Key Capabilities

- **Four-Way Accessibility:**
  - **CLI (`nga`)**: `nga doctor`, `nga inspect`, `nga simulate`, `nga ledger`, `nga brief`, `nga ui`, `nga mcp`.
  - **Local Web UI (`nga ui`)**: Zero-build HTML5 + CSS3 + Vanilla JS dashboard and CORS-enabled JSON REST API (`/api/doctor`, `/api/inspect`, `/api/simulate`, `/api/ledger`, `/api/brief`).
  - **Website Embed Widget (`nga/interfaces/web_embed/`)**: Drop-in `<script src="nga-widget.js">` + `nga-widget.css` for embedding `nga` into websites.
  - **MCP Server (`nga mcp`)**: Line-delimited JSON-RPC `stdio` server exposing `nga_*` tools to AI agents.
- **Pre-Output Sandbox & Simulation Gate:** Validates Python syntax/AST safety and executes candidates in an isolated directory with timeouts and process-tree cleanup before reporting success.
- **Built-In Security & Budgets:** Automatic secret/token redaction, HTTP header sanitization, Zip-Slip path containment guards, SHA-256 SQLite caching, integer handles (`#1`, `#2`), and output character budgets.
- **Cross-OS Compatibility:** Built on Python 3.10+ standard library so it runs across Linux, macOS, Windows, and mobile terminal environments.

---

## Quickstart

```bash
pip install -e .
nga doctor
nga simulate 'print("hello from nga sandbox")' --label quickstart
nga ui --port 8765
