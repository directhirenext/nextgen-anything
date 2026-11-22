"""Zero-build local Web UI dashboard and JSON REST API server for NextGen-Anything (`nga`)."""

from __future__ import annotations

import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from nga.analyzers.archive_pkg import inspect_archive_package
from nga.analyzers.binary_meta import inspect_binary_target
from nga.analyzers.network_har import inspect_local_har
from nga.analyzers.web_js import inspect_local_web_target
from nga.builder.brief_gen import generate_architecture_brief
from nga.core.cache import NgaCache
from nga.core.contracts import ErrorCode, NgaError, ObligationStatus, ToolResponse
from nga.core.doctor import run_environment_doctor
from nga.core.ledger import ObligationLedger
from nga.core.workspace import NgaWorkspace
from nga.runtime.simulator import SimulationGate

_DASHBOARD_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>NextGen-Anything (nga) — Workbench</title>
  <style>
    :root {
      --bg: #0d1117;
      --panel: #161b22;
      --border: #30363d;
      --text: #e6edf3;
      --muted: #8b949e;
      --accent: #2f81f7;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
    }
    header {
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      padding: 16px 20px;
      border-bottom: 1px solid var(--border);
      background: var(--panel);
    }
    h1 { margin: 0; font-size: 1.15rem; }
    .badge {
      font-size: 0.78rem;
      padding: 3px 8px;
      border-radius: 999px;
      border: 1px solid var(--border);
      color: var(--muted);
    }
    main {
      max-width: 1100px;
      margin: 20px auto;
      padding: 0 16px;
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(310px, 1fr));
      gap: 16px;
    }
    .card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 16px;
    }
    .card h2 { margin: 0 0 10px 0; font-size: 1rem; }
    label { display: block; font-size: 0.85rem; color: var(--muted); margin-top: 8px; }
    input, select, textarea {
      width: 100%;
      margin-top: 4px;
      padding: 8px 10px;
      border-radius: 6px;
      border: 1px solid var(--border);
      background: var(--bg);
      color: var(--text);
      font-family: inherit;
    }
    textarea { min-height: 84px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.82rem; }
    button {
      margin-top: 12px;
      padding: 8px 14px;
      border-radius: 6px;
      border: 1px solid transparent;
      background: var(--accent);
      color: #fff;
      font-weight: 600;
      cursor: pointer;
    }
    .output-card { grid-column: 1 / -1; }
    pre {
      margin: 0;
      padding: 12px;
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow-x: auto;
      max-height: 360px;
      font-size: 0.8rem;
    }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>NextGen-Anything (<code>nga</code>)</h1>
      <span class="badge">Cross-OS Analysis • Sandbox Simulation • Ledger • Briefs</span>
    </div>
    <button type="button" onclick="runDoctor()">Run Doctor</button>
  </header>
  <main>
    <section class="card">
      <h2>1. Inspect Target</h2>
      <label for="ins-kind">Target Kind</label>
      <select id="ins-kind">
        <option value="web">web (HTML / JS)</option>
        <option value="har">har (Network Capture)</option>
        <option value="archive">archive (ZIP / APK / ASAR)</option>
        <option value="binary">binary (ELF / PE / Mach-O / WASM)</option>
      </select>
      <label for="ins-path">Relative Path (inside --root)</label>
      <input id="ins-path" type="text" placeholder="sample.html" />
      <button type="button" onclick="runInspect()">Inspect</button>
    </section>

    <section class="card">
      <h2>2. Sandbox Simulation Gate</h2>
      <label for="sim-label">Label</label>
      <input id="sim-label" type="text" value="ui_check" />
      <label for="sim-code">Python Code</label>
      <textarea id="sim-code">x = 6 * 7
assert x == 42
print("SIM_OK:", x)</textarea>
      <button type="button" onclick="runSimulate()">Simulate in Sandbox</button>
    </section>

    <section class="card">
      <h2>3. Ledger &amp; Clean-Room Brief</h2>
      <label for="brief-label">Project / Target Label</label>
      <input id="brief-label" type="text" value="nextgen_target" />
      <label for="brief-kind">Stack Kind</label>
      <select id="brief-kind">
        <option value="web">web</option>
        <option value="archive">archive</option>
        <option value="binary">binary</option>
      </select>
      <div style="display:flex;gap:8px;flex-wrap:wrap;">
        <button type="button" onclick="runBrief()">Generate Brief</button>
        <button type="button" onclick="loadLedger()">View Ledger</button>
      </div>
    </section>

    <section class="card output-card">
      <h2>Live Output</h2>
      <pre id="out-box">Ready. Click Run Doctor or any action above.</pre>
    </section>
  </main>
  <script>
    const outBox = document.getElementById("out-box");
    function showJson(obj) { outBox.textContent = JSON.stringify(obj, null, 2); }
    async function postJson(url, body) {
      const resp = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body || {})
      });
      return await resp.json();
    }
    async function runDoctor() { showJson(await (await fetch("/api/doctor")).json()); }
    async function runInspect() {
      const kind = document.getElementById("ins-kind").value;
      const target = document.getElementById("ins-path").value.trim();
      showJson(await postJson("/api/inspect", { kind, target }));
    }
    async function runSimulate() {
      const label = document.getElementById("sim-label").value.trim() || "ui_check";
      const code = document.getElementById("sim-code").value;
      showJson(await postJson("/api/simulate", { label, code }));
    }
    async function runBrief() {
      const label = document.getElementById("brief-label").value.trim() || "nextgen_target";
      const kind = document.getElementById("brief-kind").value;
      showJson(await postJson("/api/brief", { label, kind }));
    }
    async function loadLedger() { showJson(await (await fetch("/api/ledger")).json()); }
  </script>
</body>
</html>
"""


def _resolve_allowed_origin(origin_header: str, extra_origins: set[str]) -> str | None:
    """Allow local loopback origins, file:// embeds, or explicitly configured trusted origins."""
    clean = (origin_header or "").strip()
    if not clean:
        return "http://127.0.0.1"
    if clean == "null":
        return "null"
    if clean in extra_origins:
        return clean
    parsed = urlparse(clean)
    if parsed.scheme in {"http", "https"} and parsed.hostname in {"127.0.0.1", "localhost", "::1"}:
        return clean
    return None


class NgaWebState:
    """Shared state container for local Web UI and JSON REST endpoints."""

    def __init__(self, project_name: str = "default", base_root: Path | None = None) -> None:
        self.base_root = Path(base_root).resolve() if base_root else Path.cwd().resolve()
        self.ws = NgaWorkspace(project_name=project_name)
        self.cache = NgaCache(self.ws.root / "cache.sqlite")
        self.handles = self.ws.get_handles()
        self.ledger = ObligationLedger(self.ws.root / "ledger.json", handles=self.handles)
        self.simulator = SimulationGate()


def run_web_ui_server(
    host: str = "127.0.0.1",
    port: int = 8765,
    project_name: str = "default",
    base_root: Path | None = None,
    max_requests: int | None = None,
    api_token: str | None = None,
    allowed_origins: list[str] | None = None,
) -> int:
    """Start the local HTML5/Vanilla-JS dashboard and hardened CORS JSON REST API."""
    bind_host = "127.0.0.1" if host in {"", "0.0.0.0", "localhost"} else str(host)
    bind_port = max(0, min(65535, int(port)))
    configured_token = (api_token if api_token is not None else os.environ.get("NGA_API_TOKEN", "")).strip()
    extra_origins = {o.strip() for o in (allowed_origins or []) if o and o.strip()}
    state = NgaWebState(project_name=project_name, base_root=base_root)
    counter = {"served": 0}

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return

        def _set_cors(self) -> None:
            origin = self.headers.get("Origin", "")
            matched_origin = _resolve_allowed_origin(origin, extra_origins)
            if matched_origin:
                self.send_header("Access-Control-Allow-Origin", matched_origin)
                self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-NGA-Token")

        def _is_authorized(self) -> bool:
            if not configured_token:
                return True
            header_tok = self.headers.get("X-NGA-Token", "").strip()
            auth_hdr = self.headers.get("Authorization", "").strip()
            bearer_tok = auth_hdr[7:].strip() if auth_hdr.lower().startswith("bearer ") else ""
            candidate = header_tok or bearer_tok
            return bool(candidate) and hmac.compare_digest(candidate, configured_token)

        def _send_json(self, status_code: int, payload: dict[str, Any], count_request: bool = True) -> None:
            raw = json.dumps(payload, indent=2, default=str).encode("utf-8")
            self.send_response(status_code)
            self._set_cors()
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            if count_request:
                counter["served"] += 1

        def _send_html(self, html_str: str) -> None:
            raw = html_str.encode("utf-8")
            self.send_response(200)
            self._set_cors()
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            counter["served"] += 1

        def _read_json_body(self) -> dict[str, Any] | NgaError:
            length_raw = self.headers.get("Content-Length", "0")
            try:
                length = int(length_raw)
            except ValueError:
                length = 0
            if length < 0 or length > 2_000_000:
                return NgaError(
                    error_code=ErrorCode.BUDGET_EXCEEDED.value,
                    module="nga.interfaces.web_ui",
                    message="Request body size out of allowed bounds.",
                    recoverable=True,
                )
            raw_bytes = self.rfile.read(length) if length > 0 else b"{}"
            try:
                parsed = json.loads(raw_bytes.decode("utf-8", errors="replace"))
                return parsed if isinstance(parsed, dict) else {}
            except json.JSONDecodeError as exc:
                return NgaError(
                    error_code=ErrorCode.INVALID_INPUT.value,
                    module="nga.interfaces.web_ui",
                    message=f"Invalid JSON request body: {exc}",
                    recoverable=True,
                )

        def do_OPTIONS(self) -> None:
            self.send_response(204)
            self._set_cors()
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_GET(self) -> None:
            path = urlparse(self.path).path or "/"
            if path == "/favicon.ico":
                self.send_response(204)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if path in {"/", "/index.html"}:
                self._send_html(_DASHBOARD_HTML)
                return
            if not self._is_authorized():
                err = NgaError(
                    error_code=ErrorCode.INVALID_INPUT.value,
                    module="nga.interfaces.web_ui",
                    message="Unauthorized API request. Provide valid X-NGA-Token or Bearer token.",
                    recoverable=True,
                )
                self._send_json(401, err.to_dict())
                return
            if path == "/api/doctor":
                res = run_environment_doctor(workspace_root=state.ws.root)
                self._send_json(200, res.to_dict())
                return
            if path == "/api/ledger":
                listing = state.ledger.list_obligations()
                res = ToolResponse(
                    module="nga.core.ledger",
                    summary=f"Ledger verified: {listing['coverage']['verified_percent']}%.",
                    data=listing,
                )
                self._send_json(200, res.to_dict())
                return

            err = NgaError(
                error_code=ErrorCode.NOT_FOUND.value,
                module="nga.interfaces.web_ui",
                message=f"Route not found: {path}",
                recoverable=True,
            )
            self._send_json(404, err.to_dict())

        def do_POST(self) -> None:
            path = urlparse(self.path).path or "/"
            if not self._is_authorized():
                err = NgaError(
                    error_code=ErrorCode.INVALID_INPUT.value,
                    module="nga.interfaces.web_ui",
                    message="Unauthorized API request. Provide valid X-NGA-Token or Bearer token.",
                    recoverable=True,
                )
                self._send_json(401, err.to_dict())
                return
            body = self._read_json_body()
            if isinstance(body, NgaError):
                self._send_json(400, body.to_dict())
                return

            if path == "/api/inspect":
                kind = str(body.get("kind", "web")).strip().lower()
                target = str(body.get("target", "")).strip()
                if kind == "web":
                    res: ToolResponse | NgaError = inspect_local_web_target(
                        target, base_root=state.base_root, cache=state.cache, handles=state.handles
                    )
                elif kind == "har":
                    res = inspect_local_har(
                        target, base_root=state.base_root, cache=state.cache, handles=state.handles
                    )
                elif kind == "archive":
                    res = inspect_archive_package(
                        target, base_root=state.base_root, cache=state.cache, handles=state.handles
                    )
                elif kind == "binary":
                    res = inspect_binary_target(
                        target, base_root=state.base_root, cache=state.cache, handles=state.handles
                    )
                else:
                    res = NgaError(
                        error_code=ErrorCode.INVALID_INPUT.value,
                        module="nga.interfaces.web_ui",
                        message=f"Unsupported inspection kind '{kind}'.",
                        recoverable=True,
                    )
                self._send_json(200 if not isinstance(res, NgaError) else 400, res.to_dict())
                return

            if path == "/api/simulate":
                code = str(body.get("code", ""))
                label = str(body.get("label", "web_snippet"))
                smoke = str(body.get("smoke_code", ""))
                rep = state.simulator.simulate_crafted_python(code=code, smoke_assertions_code=smoke, target_label=label)
                if isinstance(rep, NgaError):
                    self._send_json(400, rep.to_dict())
                    return
                out = ToolResponse(
                    module="nga.runtime.simulator",
                    summary=f"Simulation {rep.status.value} ({rep.duration_ms}ms).",
                    simulation_status=rep.status.value,
                    data={"simulation": rep.to_dict()},
                )
                self._send_json(200, out.to_dict())
                return

            if path == "/api/brief":
                label = str(body.get("label", "target_app"))
                kind = str(body.get("kind", "web"))
                out = generate_architecture_brief(target_label=label, target_kind=kind)
                self._send_json(200, out.to_dict())
                return

            if path == "/api/ledger":
                obl_id = str(body.get("obligation_id", "")).strip()
                title = str(body.get("title", obl_id)).strip()
                cat = str(body.get("category", "endpoint")).strip() or "endpoint"
                st = str(body.get("status", ObligationStatus.PENDING.value)).strip()
                added = state.ledger.add_obligation(obligation_id=obl_id, category=cat, title=title, status=st)
                if isinstance(added, NgaError):
                    self._send_json(400, added.to_dict())
                    return
                out = ToolResponse(
                    module="nga.core.ledger",
                    summary=f"Saved obligation #{added.handle} ({added.obligation_id}).",
                    data={"obligation": added.to_dict()},
                )
                self._send_json(200, out.to_dict())
                return

            err = NgaError(
                error_code=ErrorCode.NOT_FOUND.value,
                module="nga.interfaces.web_ui",
                message=f"Endpoint not found: {path}",
                recoverable=True,
            )
            self._send_json(404, err.to_dict())

    httpd = ThreadingHTTPServer((bind_host, bind_port), _Handler)
    httpd.daemon_threads = True
    try:
        if max_requests is not None and max_requests > 0:
            while counter["served"] < max_requests:
                httpd.handle_request()
        else:
            httpd.serve_forever()
    finally:
        httpd.server_close()
    return 0
  
