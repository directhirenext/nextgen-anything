"""Local HTML5/Vanilla-JS dashboard and token-protected REST API server for NextGen-Anything (`nga`)."""

from __future__ import annotations

import base64
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import sys
import threading
from typing import Any
from urllib.parse import parse_qs, urlparse

from nga.aaire.intent_agent import AutonomousIntentAgent
from nga.aaire.llm_engine import UniversalLlmEngine
from nga.aaire.memory_vault import AaireMemoryVault
from nga.analyzers.archive_pkg import inspect_archive_package
from nga.analyzers.binary_meta import inspect_binary_target
from nga.analyzers.network_har import inspect_local_har
from nga.analyzers.web_js import inspect_live_web_url, inspect_local_web_target
from nga.builder.brief_gen import generate_architecture_brief
from nga.builder.synthesizer import AutonomousProjectSynthesizer
from nga.core.cache import NgaCache
from nga.core.contracts import ErrorCode, NgaError, ObligationStatus, ToolResponse
from nga.core.doctor import run_environment_doctor
from nga.core.ledger import ObligationLedger
from nga.core.security import redact_secrets, safe_resolve_path, sanitize_archive_member_name
from nga.core.workspace import NgaWorkspace
from nga.runtime.simulator import SimulationGate

_LOCAL_ORIGIN_RE = re.compile(r"^https?://(localhost|127\.0\.0\.1)(:\d{1,5})?$", re.IGNORECASE)
_MAX_BODY_BYTES = 25_000_000
_MAX_UPLOAD_RAW_BYTES = 18_000_000


def is_allowed_cors_origin(origin: str | None) -> bool:
    """Allow browser CORS strictly for local loopback origins."""
    if not origin:
        return False
    return bool(_LOCAL_ORIGIN_RE.match(origin.strip()))


def _run_target_inspection(
    kind: str,
    target: str,
    base_root: Path,
    cache: NgaCache,
    handles: Any,
) -> ToolResponse | NgaError:
    if kind == "web":
        return inspect_local_web_target(target, base_root=base_root, cache=cache, handles=handles)
    if kind == "har":
        return inspect_local_har(target, base_root=base_root, cache=cache, handles=handles)
    if kind == "archive":
        return inspect_archive_package(target, base_root=base_root, cache=cache, handles=handles)
    return inspect_binary_target(target, base_root=base_root, cache=cache, handles=handles)


def _flatten_inspection_data(inspected: ToolResponse) -> dict[str, Any]:
    base = dict(inspected.data) if isinstance(inspected.data, dict) else {}
    for nested_key in ("analysis", "package", "metadata"):
        nested = base.get(nested_key)
        if isinstance(nested, dict):
            for k, v in nested.items():
                if k not in base or not base[k]:
                    base[k] = v
    return base


class NgaWebRuntime:
    """Stateful API controller backing all REST routes in the local web server."""

    def __init__(
        self,
        project_name: str = "default",
        base_root: Path | str | None = None,
        api_token: str | None = None,
        workspace_base_dir: Path | str | None = None,
        llm_engine: UniversalLlmEngine | None = None,
    ) -> None:
        self.project_name = project_name
        self.base_root = Path(base_root).resolve() if base_root is not None else Path.cwd().resolve()
        resolved_token = api_token if api_token is not None else os.environ.get("NGA_API_TOKEN", "")
        self.api_token = str(resolved_token or "").strip()
        self._state_lock = threading.Lock()

        self.workspace = NgaWorkspace(project_name=project_name, base_dir=workspace_base_dir)
        self.cache = NgaCache(self.workspace.root / "cache.sqlite")
        self.handles = self.workspace.get_handles()
        self.ledger = ObligationLedger(self.workspace.root / "ledger.json", handles=self.handles)
        self.vault = AaireMemoryVault(self.workspace.root / "memory_vault.sqlite")
        self.simulator = SimulationGate()
        self.llm = llm_engine if llm_engine is not None else UniversalLlmEngine()
        self.synthesizer = AutonomousProjectSynthesizer(
            simulator=self.simulator,
            workspace=self.workspace,
            ledger=self.ledger,
            llm_engine=self.llm,
        )
        self.agent = AutonomousIntentAgent(
            vault=self.vault,
            simulator=self.simulator,
            ledger=self.ledger,
            workspace=self.workspace,
            llm_engine=self.llm,
        )

    def is_authorized(self, headers: Any) -> bool:
        """Verify X-NGA-Token or Bearer token when API authentication is enabled."""
        if not self.api_token:
            return True
        direct = str(headers.get("X-NGA-Token", "") or "").strip()
        if direct and hmac.compare_digest(direct, self.api_token):
            return True
        auth_header = str(headers.get("Authorization", "") or "").strip()
        if auth_header.lower().startswith("bearer "):
            bearer = auth_header[7:].strip()
            if bearer and hmac.compare_digest(bearer, self.api_token):
                return True
        return False

    def _handle_upload(self, body: dict[str, Any]) -> ToolResponse | NgaError:
        """Safely save uploaded file content (text or base64 for APK/ZIP/HAR/HTML/JS) inside base_root."""
        raw_name = str(body.get("filename", "") or "").strip()
        ok_name, safe_name_or_err = sanitize_archive_member_name(raw_name)
        if not ok_name or not isinstance(safe_name_or_err, str):
            return NgaError(
                error_code=ErrorCode.INVALID_INPUT.value,
                module="nga.interfaces.web_ui",
                message="Invalid or unsafe upload filename.",
                recoverable=True,
                suggested_fix="Provide a safe filename such as sample.apk, capture.har, or page.html.",
            )

        sub_dir = str(body.get("upload_dir", "uploads") or "uploads").strip() or "uploads"
        ok_dir, dest_dir = safe_resolve_path(self.base_root, sub_dir)
        if not ok_dir or not isinstance(dest_dir, Path):
            return NgaError(
                error_code=ErrorCode.PATH_TRAVERSAL.value,
                module="nga.interfaces.web_ui",
                message="Upload directory escapes base_root.",
                recoverable=False,
            )

        is_b64 = bool(body.get("is_base64", False))
        content_raw = body.get("content_base64" if is_b64 else "content", "")
        if not isinstance(content_raw, str) or not content_raw:
            return NgaError(
                error_code=ErrorCode.INVALID_INPUT.value,
                module="nga.interfaces.web_ui",
                message="Upload payload missing non-empty content.",
                recoverable=True,
            )

        if is_b64:
            b64_clean = content_raw.split(",", 1)[-1].strip()
            try:
                file_bytes = base64.b64decode(b64_clean, validate=True)
            except Exception as exc:
                return NgaError(
                    error_code=ErrorCode.INVALID_INPUT.value,
                    module="nga.interfaces.web_ui",
                    message=f"Invalid base64 upload content: {exc}",
                    recoverable=True,
                )
        else:
            file_bytes = content_raw.encode("utf-8", errors="replace")

        if len(file_bytes) > _MAX_UPLOAD_RAW_BYTES:
            return NgaError(
                error_code=ErrorCode.BUDGET_EXCEEDED.value,
                module="nga.interfaces.web_ui",
                message=f"Uploaded file ({len(file_bytes)} bytes) exceeds {_MAX_UPLOAD_RAW_BYTES} byte limit.",
                recoverable=True,
            )

        clean_leaf = Path(safe_name_or_err).name
        ok_file, dest_file = safe_resolve_path(dest_dir, clean_leaf)
        if not ok_file or not isinstance(dest_file, Path):
            return NgaError(
                error_code=ErrorCode.PATH_TRAVERSAL.value,
                module="nga.interfaces.web_ui",
                message="Resolved upload path escapes upload directory.",
                recoverable=False,
            )

        with self._state_lock:
            dest_file.parent.mkdir(parents=True, exist_ok=True)
            dest_file.write_bytes(file_bytes)

        rel_target = str(dest_file.relative_to(self.base_root))
        return ToolResponse(
            module="nga.interfaces.web_ui",
            summary=f"Uploaded '{rel_target}' ({len(file_bytes)} bytes).",
            data={
                "filename": clean_leaf,
                "relative_path": rel_target,
                "size_bytes": len(file_bytes),
            },
        )

    def handle_api(
        self,
        method: str,
        path: str,
        query: dict[str, list[str]],
        body: dict[str, Any],
    ) -> tuple[int, dict[str, Any]]:
        """Dispatch REST API call and return (http_status, json_payload)."""
        outcome: ToolResponse | NgaError | dict[str, Any]

        if method == "GET" and path == "/api/doctor":
            outcome = run_environment_doctor(workspace_root=self.workspace.root)
        elif method == "GET" and path == "/api/ledger":
            with self._state_lock:
                listing = self.ledger.list_obligations()
            outcome = ToolResponse(
                module="nga.core.ledger",
                summary=f"Ledger coverage: {listing['coverage']['verified_percent']}%.",
                data=listing,
            )
        elif method == "POST" and path == "/api/ledger":
            action = str(body.get("action", "add")).strip().lower()
            oid = str(body.get("obligation_id") or body.get("id") or body.get("handle") or "").strip()
            status = str(body.get("status", ObligationStatus.PENDING.value)).strip()
            with self._state_lock:
                if action == "update":
                    upd = self.ledger.update_status(oid, status)
                    outcome = (
                        upd
                        if isinstance(upd, NgaError)
                        else ToolResponse(
                            module="nga.core.ledger",
                            summary=f"Updated obligation #{upd.handle} to {upd.status.value}.",
                            data={"obligation": upd.to_dict()},
                        )
                    )
                else:
                    added = self.ledger.add_obligation(
                        obligation_id=oid,
                        category=str(body.get("category", "endpoint")).strip() or "endpoint",
                        title=str(body.get("title", "")).strip() or oid,
                        status=status,
                    )
                    outcome = (
                        added
                        if isinstance(added, NgaError)
                        else ToolResponse(
                            module="nga.core.ledger",
                            summary=f"Added obligation #{added.handle} ({added.obligation_id}).",
                            data={"obligation": added.to_dict()},
                        )
                    )
        elif method == "POST" and path == "/api/upload":
            outcome = self._handle_upload(body)
        elif method == "POST" and path == "/api/live_inspect":
            url = str(body.get("url", "")).strip()
            if not url:
                outcome = NgaError(
                    error_code=ErrorCode.INVALID_INPUT.value,
                    module="nga.interfaces.web_ui",
                    message="/api/live_inspect requires non-empty 'url'.",
                    recoverable=True,
                )
            else:
                with self._state_lock:
                    outcome = inspect_live_web_url(url=url, cache=self.cache, handles=self.handles)
        elif method == "POST" and path == "/api/inspect":
            kind = str(body.get("kind", "")).strip()
            target = str(body.get("target", "")).strip()
            if kind not in {"web", "har", "archive", "binary"} or not target:
                outcome = NgaError(
                    error_code=ErrorCode.INVALID_INPUT.value,
                    module="nga.interfaces.web_ui",
                    message="/api/inspect requires valid 'kind' and non-empty 'target'.",
                    recoverable=True,
                )
            else:
                with self._state_lock:
                    outcome = _run_target_inspection(kind, target, self.base_root, self.cache, self.handles)
        elif method == "POST" and path == "/api/simulate":
            smoke_val = str(body.get("smoke", "") or body.get("smoke_code", "") or "")
            rep = self.simulator.simulate_crafted_python(
                code=str(body.get("code", "")),
                smoke_assertions_code=smoke_val,
                target_label=str(body.get("label", "web_ui_snippet")),
            )
            outcome = (
                rep
                if isinstance(rep, NgaError)
                else ToolResponse(
                    module="nga.runtime.simulator",
                    ok=rep.passed,
                    summary=f"Simulation {rep.status.value} ({rep.duration_ms}ms).",
                    simulation_status=rep.status.value,
                    data={"simulation": rep.to_dict()},
                )
            )
        elif method == "POST" and path == "/api/synthesize":
            findings = body.get("findings")
            if not isinstance(findings, dict):
                outcome = NgaError(
                    error_code=ErrorCode.INVALID_INPUT.value,
                    module="nga.interfaces.web_ui",
                    message="/api/synthesize requires a 'findings' JSON object.",
                    recoverable=True,
                )
            else:
                with self._state_lock:
                    outcome = self.synthesizer.synthesize_project(
                        app_name=str(body.get("app_name", "reconstructed_app")),
                        findings=findings,
                        output_dir=str(body.get("output_dir", "synthesized_out")),
                        base_root=self.base_root,
                        custom_prompt=str(body.get("custom_prompt", "")),
                        include_android_scaffold=bool(body.get("include_android_scaffold", False)),
                    )
        elif method == "POST" and path == "/api/rebuild":
            kind = str(body.get("kind", "")).strip()
            target = str(body.get("target", "")).strip()
            if kind not in {"web", "har", "archive", "binary"} or not target:
                outcome = NgaError(
                    error_code=ErrorCode.INVALID_INPUT.value,
                    module="nga.interfaces.web_ui",
                    message="/api/rebuild requires valid 'kind' and non-empty 'target'.",
                    recoverable=True,
                )
            else:
                with self._state_lock:
                    inspected = _run_target_inspection(kind, target, self.base_root, self.cache, self.handles)
                if isinstance(inspected, NgaError):
                    outcome = inspected
                else:
                    findings = _flatten_inspection_data(inspected)
                    app_name = str(body.get("app_name", "")).strip() or Path(target).stem or "reconstructed_app"
                    with self._state_lock:
                        synth_res = self.synthesizer.synthesize_project(
                            app_name=app_name,
                            findings=findings,
                            output_dir=str(body.get("output_dir", "rebuilt_app")),
                            base_root=self.base_root,
                            custom_prompt=str(body.get("custom_prompt", "")),
                            include_android_scaffold=(kind == "archive"),
                        )
                    if isinstance(synth_res, NgaError):
                        outcome = synth_res
                    else:
                        outcome = ToolResponse(
                            module="nga.interfaces.web_ui",
                            summary=f"Rebuild complete: {inspected.summary} -> {synth_res.summary}",
                            simulation_status=synth_res.simulation_status,
                            data={"inspection_summary": inspected.summary, "synthesis": synth_res.data},
                        )
        elif method == "POST" and path == "/api/agent":
            with self._state_lock:
                outcome = self.agent.run_turn(
                    prompt=str(body.get("prompt", "")),
                    candidate_code=str(body.get("candidate_code", "")),
                    target_label=str(body.get("target_label", "web_ui_agent")),
                    target_kind=str(body.get("target_kind", "web")),
                )
        elif method == "GET" and path == "/api/memory":
            q_val = (query.get("q") or [""])[0].strip()
            ns_raw = (query.get("namespace") or [""])[0].strip()
            limit_raw = (query.get("limit") or ["5"])[0]
            try:
                limit = max(1, min(50, int(limit_raw)))
            except ValueError:
                limit = 5
            hits = self.vault.retrieve(q_val, namespace=ns_raw or None, limit=limit)
            outcome = ToolResponse(
                module="nga.aaire.memory_vault",
                summary=f"Retrieved {len(hits)} memory record(s).",
                data={"hits": hits, "count": len(hits)},
            )
        elif method == "POST" and path == "/api/memory":
            raw_tags = body.get("tags")
            tags = [str(t) for t in raw_tags] if isinstance(raw_tags, list) else []
            stored = self.vault.store(
                title=str(body.get("title", "")),
                body=str(body.get("body", "")),
                namespace=str(body.get("namespace", self.agent.namespace)),
                tags=tags,
                source="web_ui",
            )
            outcome = (
                stored
                if isinstance(stored, NgaError)
                else ToolResponse(
                    module="nga.aaire.memory_vault",
                    summary=f"Stored memory #{stored.get('id')} in '{stored.get('namespace')}'.",
                    data={"memory": stored},
                )
            )
        elif method == "POST" and path == "/api/brief":
            label = str(body.get("label", "")).strip()
            if not label:
                outcome = NgaError(
                    error_code=ErrorCode.INVALID_INPUT.value,
                    module="nga.interfaces.web_ui",
                    message="/api/brief requires non-empty 'label'.",
                    recoverable=True,
                )
            else:
                outcome = generate_architecture_brief(
                    target_label=label,
                    target_kind=str(body.get("kind", "web")),
                    custom_requirements=str(body.get("custom_requirements", "")),
                )
        else:
            return 404, {
                "ok": False,
                "error_code": ErrorCode.NOT_FOUND.value,
                "module": "nga.interfaces.web_ui",
                "message": f"Unknown endpoint: {method} {path}",
            }

        if isinstance(outcome, NgaError):
            http_status = 403 if outcome.error_code in {
                ErrorCode.PATH_TRAVERSAL.value,
                ErrorCode.SANDBOX_VIOLATION.value,
            } else 400
            return http_status, outcome.to_dict()
        if isinstance(outcome, ToolResponse):
            return (200 if bool(outcome.ok) else 400), outcome.to_dict()
        return 200, outcome


_DASHBOARD_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>NextGen-Anything (nga) — Control Console</title>
  <style>
    :root { --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #e6edf3; --muted: #8b949e; --accent: #2f81f7; --ok: #238636; }
    * { box-sizing: border-box; }
    body { margin: 0; padding: 16px; background: var(--bg); color: var(--text); font-family: system-ui, sans-serif; }
    .wrap { max-width: 1080px; margin: 0 auto; }
    header { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 16px; }
    h1 { margin: 0; font-size: 1.35rem; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 14px; }
    .card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 14px; }
    .card h2 { margin: 0 0 10px; font-size: 1rem; color: #79c0ff; }
    label { display: block; font-size: 0.8rem; color: var(--muted); margin-top: 8px; }
    input, select, textarea { width: 100%; margin-top: 4px; padding: 8px 10px; border-radius: 6px; border: 1px solid var(--border); background: var(--bg); color: var(--text); font-family: inherit; font-size: 0.9rem; }
    textarea { min-height: 78px; font-family: ui-monospace, monospace; font-size: 0.82rem; }
    .row { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }
    button { padding: 7px 13px; border: 0; border-radius: 6px; background: var(--accent); color: #fff; font-weight: 600; cursor: pointer; }
    button.green { background: var(--ok); }
    button.gray { background: #30363d; }
    pre { margin: 0; background: #010409; border: 1px solid var(--border); border-radius: 8px; padding: 12px; max-height: 360px; overflow: auto; font-size: 0.82rem; }
  </style>
</head>
<body>
  <div class="wrap">
    <header>
      <h1>NextGen-Anything (nga) — Control Console</h1>
      <div class="row" style="margin-top:0; align-items:center;">
        <input id="api-token" type="password" placeholder="Optional API Token" style="width:200px; margin-top:0;" />
        <button class="green" onclick="callApi('GET', '/api/doctor')">Doctor</button>
        <button class="gray" onclick="callApi('GET', '/api/ledger')">Ledger</button>
      </div>
    </header>
    <div class="grid">
              <div class="card">
        <h2>1. Upload, Inspect & Rebuild (APK / Web / HAR)</h2>
        <label>Upload Local File (.apk, .zip, .har, .html, .js)</label>
        <input id="up-file" type="file" />
        <div class="row"><button class="gray" onclick="uploadSelectedFile()">Upload File</button></div>
        <label>Target Kind</label>
        <select id="ins-kind">
          <option value="web">web</option><option value="har">har</option>
          <option value="archive">archive</option><option value="binary">binary</option>
        </select>
        <label>Target Path</label>
        <input id="ins-target" placeholder="e.g. uploads/app.apk or sample.html" />
        <label>Custom Build Prompt / Features</label>
        <input id="reb-prompt" placeholder="e.g. Add search & export features" />
        <label>Rebuild Output Folder</label>
        <input id="reb-out" value="rebuilt_app" />
        <div class="row">
          <button onclick="runInspect()">Inspect</button>
          <button class="green" onclick="runRebuild()">Rebuild App</button>
        </div>
      </div>
      <div class="card">
        <h2>2. Sandbox Simulation Gate</h2>
        <label>Target Label</label><input id="sim-label" value="console_check" />
        <label>Python Code</label>
        <textarea id="sim-code">result = sum(range(1, 11))
assert result == 55
print("SANDBOX_OK:", result)</textarea>
        <div class="row"><button onclick="runSimulate()">Run Sandbox</button></div>
      </div>
      <div class="card">
        <h2>3. AAIRE Autonomous Agent & Memory Vault</h2>
        <label>Agent Goal / Prompt</label><input id="ag-prompt" placeholder="Enter task or architecture goal" />
        <label>Optional Candidate Python Code</label><textarea id="ag-code"></textarea>
        <div class="row"><button class="green" onclick="runAgent()">Run Agent Turn</button></div>
        <label>Memory Search Query</label><input id="mem-query" placeholder="Search stored memory vault" />
        <div class="row"><button class="gray" onclick="searchMemory()">Retrieve Memory</button></div>
      </div>
      <div class="card">
        <h2>4. Architecture Blueprint & Live URL</h2>
        <label>Project / Target Label</label><input id="br-label" placeholder="e.g. payments_service" />
        <label>Kind</label>
        <select id="br-kind"><option value="web">web</option><option value="archive">archive</option><option value="binary">binary</option></select>
        <div class="row"><button onclick="runBrief()">Generate Blueprint</button></div>
        <label>Live URL Inspection</label><input id="live-url" placeholder="https://example.com" />
        <div class="row"><button class="gray" onclick="runLiveInspect()">Inspect Live URL</button></div>
      </div>
    </div>
    <div class="card" style="margin-top:14px;">
      <h2>Live API Response</h2>
      <pre id="out">Ready. Click Doctor or run any operation above.</pre>
    </div>
  </div>
  <script>
    const outEl = document.getElementById("out");
    function buildHeaders(hasBody) {
      const h = {};
      if (hasBody) h["Content-Type"] = "application/json";
      const t = document.getElementById("api-token").value.trim();
      if (t) h["X-NGA-Token"] = t;
      return h;
    }
    async function callApi(method, path, payload) {
      outEl.textContent = "Running " + method + " " + path + " ...";
      try {
        const opts = { method, headers: buildHeaders(payload !== undefined) };
        if (payload !== undefined) opts.body = JSON.stringify(payload);
        const res = await fetch(path, opts);
        const txt = await res.text();
        try { const d = JSON.parse(txt); outEl.textContent = JSON.stringify(d, null, 2); return d; }
        catch { const fb = { ok: res.ok, status: res.status, raw: txt }; outEl.textContent = JSON.stringify(fb, null, 2); return fb; }
      } catch (err) { outEl.textContent = "Request failed: " + err.message; return null; }
    }
    async function uploadSelectedFile() {
      const inp = document.getElementById("up-file");
      if (!inp.files || !inp.files[0]) { outEl.textContent = "Please choose a file first."; return; }
      const f = inp.files[0], bytes = new Uint8Array(await f.arrayBuffer());
      let bin = "";
      for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
      const data = await callApi("POST", "/api/upload", { filename: f.name, is_base64: true, content_base64: btoa(bin) });
      if (data && data.ok && data.data && data.data.relative_path) document.getElementById("ins-target").value = data.data.relative_path;
    }
    function runInspect() { callApi("POST", "/api/inspect", { kind: document.getElementById("ins-kind").value, target: document.getElementById("ins-target").value.trim() }); }
    function runRebuild() { callApi("POST", "/api/rebuild", { kind: document.getElementById("ins-kind").value, target: document.getElementById("ins-target").value.trim(), custom_prompt: document.getElementById("reb-prompt").value.trim(), output_dir: document.getElementById("reb-out").value.trim() || "rebuilt_app" }); }
    function runSimulate() { callApi("POST", "/api/simulate", { label: document.getElementById("sim-label").value.trim() || "console_check", code: document.getElementById("sim-code").value }); }
    function runAgent() { callApi("POST", "/api/agent", { prompt: document.getElementById("ag-prompt").value.trim(), candidate_code: document.getElementById("ag-code").value }); }
    function searchMemory() { callApi("GET", "/api/memory?q=" + encodeURIComponent(document.getElementById("mem-query").value.trim()) + "&limit=5"); }
    function runBrief() { callApi("POST", "/api/brief", { label: document.getElementById("br-label").value.trim(), kind: document.getElementById("br-kind").value }); }
    function runLiveInspect() { callApi("POST", "/api/live_inspect", { url: document.getElementById("live-url").value.trim() }); }
  </script>
</body>
</html>
"""


def create_web_ui_server(
    host: str = "127.0.0.1",
    port: int = 8765,
    project_name: str = "default",
    base_root: Path | str | None = None,
    api_token: str | None = None,
    workspace_base_dir: Path | str | None = None,
    llm_engine: UniversalLlmEngine | None = None,
) -> ThreadingHTTPServer:
    """Create a configured ThreadingHTTPServer instance ready to serve or test."""
    effective_token = api_token if api_token is not None else os.environ.get("NGA_API_TOKEN", "")
    clean_host = str(host or "127.0.0.1").strip()
    if clean_host in {"0.0.0.0", "::"} and not str(effective_token or "").strip():
        effective_token = secrets.token_urlsafe(24)

    runtime = NgaWebRuntime(
        project_name=project_name,
        base_root=base_root,
        api_token=effective_token,
        workspace_base_dir=workspace_base_dir,
        llm_engine=llm_engine,
    )

    class NgaWebHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return

        def _apply_common_headers(self, content_type: str, length: int, is_no_content: bool = False) -> None:
            self.send_header("Content-Type", content_type)
            if not is_no_content:
                self.send_header("Content-Length", str(length))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            origin = self.headers.get("Origin")
            if is_allowed_cors_origin(origin):
                self.send_header("Access-Control-Allow-Origin", str(origin))
                self.send_header("Vary", "Origin")
                self.send_header("Access-Control-Allow-Headers", "Content-Type, X-NGA-Token, Authorization")
                self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

        def _send_json(self, status: int, payload: dict[str, Any]) -> None:
            raw = redact_secrets(json.dumps(payload, indent=2, default=str)).encode("utf-8")
            self.send_response(status)
            self._apply_common_headers("application/json; charset=utf-8", len(raw))
            self.end_headers()
            try:
                self.wfile.write(raw)
            except OSError:
                pass

        def _send_html(self, status: int, html_text: str) -> None:
            raw = html_text.encode("utf-8")
            self.send_response(status)
            self._apply_common_headers("text/html; charset=utf-8", len(raw))
            self.end_headers()
            try:
                self.wfile.write(raw)
            except OSError:
                pass

        def do_OPTIONS(self) -> None:
            self.send_response(204)
            self._apply_common_headers("text/plain; charset=utf-8", 0, is_no_content=True)
            self.end_headers()

        def do_GET(self) -> None:
            try:
                parsed = urlparse(self.path)
                req_path = parsed.path or "/"
                if req_path in {"/", "/index.html"}:
                    self._send_html(200, _DASHBOARD_HTML)
                    return
                if not runtime.is_authorized(self.headers):
                    self._send_json(
                        401,
                        {
                            "ok": False,
                            "error_code": ErrorCode.AUTH_ERROR.value,
                            "module": "nga.interfaces.web_ui",
                            "message": "Unauthorized: valid X-NGA-Token or Bearer token required.",
                        },
                    )
                    return
                query = parse_qs(parsed.query)
                status, payload = runtime.handle_api("GET", req_path, query, {})
                self._send_json(status, payload)
            except Exception as exc:
                self._send_json(
                    500,
                    {
                        "ok": False,
                        "error_code": ErrorCode.INTERNAL_ERROR.value,
                        "module": "nga.interfaces.web_ui",
                        "message": redact_secrets(f"Internal GET error: {exc}"),
                    },
                )

        def do_POST(self) -> None:
            try:
                parsed = urlparse(self.path)
                req_path = parsed.path or "/"
                if not runtime.is_authorized(self.headers):
                    self._send_json(
                        401,
                        {
                            "ok": False,
                            "error_code": ErrorCode.AUTH_ERROR.value,
                            "module": "nga.interfaces.web_ui",
                            "message": "Unauthorized: valid X-NGA-Token or Bearer token required.",
                        },
                    )
                    return

                length_raw = self.headers.get("Content-Length", "0")
                try:
                    length = int(length_raw)
                except ValueError:
                    length = 0
                if length < 0 or length > _MAX_BODY_BYTES:
                    self._send_json(
                        413,
                        {
                            "ok": False,
                            "error_code": ErrorCode.BUDGET_EXCEEDED.value,
                            "module": "nga.interfaces.web_ui",
                            "message": f"Request body exceeds limit ({_MAX_BODY_BYTES} bytes).",
                        },
                    )
                    return

                body_obj: dict[str, Any] = {}
                if length > 0:
                    raw_text = self.rfile.read(length).decode("utf-8", errors="replace")
                    try:
                        decoded = json.loads(raw_text)
                        if not isinstance(decoded, dict):
                            self._send_json(
                                400,
                                {
                                    "ok": False,
                                    "error_code": ErrorCode.INVALID_INPUT.value,
                                    "module": "nga.interfaces.web_ui",
                                    "message": "Request JSON body must be an object.",
                                },
                            )
                            return
                        body_obj = decoded
                    except json.JSONDecodeError as exc:
                        self._send_json(
                            400,
                            {
                                "ok": False,
                                "error_code": ErrorCode.INVALID_INPUT.value,
                                "module": "nga.interfaces.web_ui",
                                "message": f"Invalid JSON payload: {exc}",
                            },
                        )
                        return

                query = parse_qs(parsed.query)
                status, payload = runtime.handle_api("POST", req_path, query, body_obj)
                self._send_json(status, payload)
            except Exception as exc:
                self._send_json(
                    500,
                    {
                        "ok": False,
                        "error_code": ErrorCode.INTERNAL_ERROR.value,
                        "module": "nga.interfaces.web_ui",
                        "message": redact_secrets(f"Internal POST error: {exc}"),
                    },
                )

    srv = ThreadingHTTPServer((clean_host, int(port)), NgaWebHandler)
    srv.daemon_threads = True
    return srv


def run_web_ui_server(
    host: str = "127.0.0.1",
    port: int = 8765,
    project_name: str = "default",
    base_root: Path | str | None = None,
    api_token: str | None = None,
    workspace_base_dir: Path | str | None = None,
) -> int:
    """Start the local Web UI & REST API server until interrupted."""
    try:
        httpd = create_web_ui_server(
            host=host,
            port=port,
            project_name=project_name,
            base_root=base_root,
            api_token=api_token,
            workspace_base_dir=workspace_base_dir,
        )
    except OSError as exc:
        err = NgaError(
            error_code=ErrorCode.STORAGE_ERROR.value,
            module="nga.interfaces.web_ui",
            message=redact_secrets(f"Failed binding Web UI server on {host}:{port}: {exc}"),
            recoverable=True,
        )
        sys.stdout.write(err.to_json(indent=2) + "\n")
        sys.stdout.flush()
        return 1

    actual_port = httpd.server_address[1]
    sys.stdout.write(
        json.dumps(
            {
                "ok": True,
                "listening": f"http://{host}:{actual_port}",
                "port": actual_port,
                "auth_enabled": bool(api_token or os.environ.get("NGA_API_TOKEN", "").strip() or str(host) in {"0.0.0.0", "::"}),
            }
        )
        + "\n"
    )
    sys.stdout.flush()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(run_web_ui_server())
    
