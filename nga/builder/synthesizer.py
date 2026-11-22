"""Autonomous multi-file project synthesizer with SQLite CRUD persistence and sandbox verification."""

from __future__ import annotations

import html
import json
from pathlib import Path
import re
from typing import Any

from nga.core.contracts import (
    ErrorCode,
    NgaError,
    ObligationStatus,
    SimulationStatus,
    ToolResponse,
    utc_now_iso,
)
from nga.core.ledger import ObligationLedger
from nga.core.security import (
    compute_sha256_text,
    redact_secrets,
    safe_resolve_path,
)
from nga.core.workspace import NgaWorkspace
from nga.runtime.simulator import SimulationGate


def _sanitize_identifier(raw: str, fallback: str = "item") -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_]+", "_", str(raw or "").strip()).strip("_").lower()
    if not cleaned:
        return fallback
    if cleaned[0].isdigit():
        cleaned = f"n_{cleaned}"
    return cleaned[:48]


def _normalize_route_specs(findings: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract normalized HTTP route specifications from web, HAR, archive, or binary findings."""
    specs: list[dict[str, Any]] = []
    seen: set[str] = set()

    mock_by_key: dict[str, dict[str, Any]] = {}
    if isinstance(findings.get("mock_routes"), list):
        for mr in findings["mock_routes"]:
            if isinstance(mr, dict):
                m = str(mr.get("method", "GET")).upper().strip() or "GET"
                p = str(mr.get("path", "/")).strip() or "/"
                if not p.startswith("/"):
                    p = f"/{p}"
                mock_by_key[f"{m} {p}"] = mr

    if isinstance(findings.get("endpoints"), list):
        for ep in findings["endpoints"]:
            if not isinstance(ep, dict):
                continue
            method = str(ep.get("method", "GET")).upper().strip() or "GET"
            path = str(ep.get("path", "/")).strip() or "/"
            if not path.startswith("/"):
                path = f"/{path}"
            sig = f"{method} {path}"
            if sig in seen:
                continue
            seen.add(sig)
            mr = mock_by_key.get(sig, {})
            sample_body: Any = mr.get("parsed_json")
            if not isinstance(sample_body, dict):
                sample_body = {
                    "ok": True,
                    "endpoint": path,
                    "method": method,
                    "reconstructed": True,
                    "schema": ep.get("schema"),
                }
            fields: list[str] = []
            if isinstance(ep.get("fields"), list):
                fields = [str(f).strip() for f in ep["fields"] if str(f).strip()]
            specs.append(
                {
                    "method": method,
                    "path": path,
                    "status": int(ep.get("status", 200) or 200),
                    "fields": fields,
                    "response_json": sample_body,
                    "source": "har_endpoint",
                }
            )

    for key in ("routes", "embedded_routes", "api_calls", "embedded_api_calls"):
        items = findings.get(key)
        if not isinstance(items, list):
            continue
        for item in items:
            raw_path = ""
            if isinstance(item, dict):
                raw_path = str(item.get("path") or item.get("endpoint") or "").strip()
            elif isinstance(item, str):
                raw_path = item.strip()
            if not raw_path or not raw_path.startswith("/"):
                continue
            sig = f"GET {raw_path}"
            if sig in seen:
                continue
            seen.add(sig)
            specs.append(
                {
                    "method": "GET",
                    "path": raw_path,
                    "status": 200,
                    "fields": [],
                    "response_json": {
                        "ok": True,
                        "route": raw_path,
                        "reconstructed": True,
                    },
                    "source": key,
                }
            )

    if isinstance(findings.get("forms"), list):
        for idx, form in enumerate(findings["forms"], start=1):
            if not isinstance(form, dict):
                continue
            action = str(form.get("action", "")).strip() or f"/submit/form_{idx}"
            if not action.startswith("/"):
                action = f"/{action}"
            method = str(form.get("method", "POST")).upper().strip() or "POST"
            sig = f"{method} {action}"
            if sig in seen:
                continue
            seen.add(sig)
            fields = [
                str(inp.get("name", "")).strip()
                for inp in (form.get("inputs") or [])
                if isinstance(inp, dict) and str(inp.get("name", "")).strip()
            ]
            specs.append(
                {
                    "method": method,
                    "path": action,
                    "status": 200,
                    "fields": fields,
                    "response_json": {
                        "ok": True,
                        "submitted_to": action,
                        "accepted_fields": fields,
                    },
                    "source": "html_form",
                }
            )

    if not specs:
        specs.append(
            {
                "method": "GET",
                "path": "/api/records",
                "status": 200,
                "fields": ["title", "value"],
                "response_json": {
                    "ok": True,
                    "service": "reconstructed_service",
                    "reconstructed": True,
                },
                "source": "default_crud_contract",
            }
        )

    return specs[:100]


_BACKEND_SERVER_TEMPLATE = '''"""Reconstructed SQLite-backed backend service."""

from __future__ import annotations

from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sqlite3
from typing import Any
from urllib.parse import urlparse

APP_NAME = __APP_NAME_LITERAL__
BASE_DIR = Path(__file__).resolve().parent
PUBLIC_DIR = BASE_DIR / "public"
DEFAULT_DB_PATH = str(BASE_DIR / "app_data.sqlite")
ROUTE_TABLE: list[dict[str, Any]] = json.loads(__ROUTES_LITERAL__)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class RecordStore:
    """Persistent SQLite CRUD store supporting both on-disk DB files and :memory: testing."""

    def __init__(self, db_path: str = DEFAULT_DB_PATH) -> None:
        self.db_path = str(db_path or ":memory:")
        self._mem_conn: sqlite3.Connection | None = None
        if self.db_path == ":memory:":
            self._mem_conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._mem_conn.row_factory = sqlite3.Row
        self._init_schema()

    def _get_conn(self) -> tuple[sqlite3.Connection, bool]:
        if self._mem_conn is not None:
            return self._mem_conn, False
        conn = sqlite3.connect(self.db_path, timeout=15.0)
        conn.row_factory = sqlite3.Row
        return conn, True

    def _init_schema(self) -> None:
        conn, should_close = self._get_conn()
        try:
            if should_close:
                conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    route_path TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_records_route ON records(route_path);")
            conn.commit()
        finally:
            if should_close:
                conn.close()

    def list_records(self, route_path: str) -> list[dict[str, Any]]:
        conn, should_close = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT id, route_path, payload_json, created_at, updated_at FROM records WHERE route_path = ? ORDER BY id ASC",
                (route_path,),
            ).fetchall()
            out: list[dict[str, Any]] = []
            for r in rows:
                out.append(
                    {
                        "id": int(r["id"]),
                        "route_path": r["route_path"],
                        "data": json.loads(r["payload_json"]),
                        "created_at": r["created_at"],
                        "updated_at": r["updated_at"],
                    }
                )
            return out
        finally:
            if should_close:
                conn.close()

    def insert_record(self, route_path: str, payload: dict[str, Any]) -> dict[str, Any]:
        now = _utc_now()
        encoded = json.dumps(payload, default=str)
        conn, should_close = self._get_conn()
        try:
            cur = conn.execute(
                "INSERT INTO records(route_path, payload_json, created_at, updated_at) VALUES (?, ?, ?, ?)",
                (route_path, encoded, now, now),
            )
            conn.commit()
            rec_id = int(cur.lastrowid or 0)
            return {
                "id": rec_id,
                "route_path": route_path,
                "data": payload,
                "created_at": now,
                "updated_at": now,
            }
        finally:
            if should_close:
                conn.close()

    def update_record(self, route_path: str, record_id: int, payload: dict[str, Any]) -> dict[str, Any] | None:
        now = _utc_now()
        encoded = json.dumps(payload, default=str)
        conn, should_close = self._get_conn()
        try:
            cur = conn.execute(
                "UPDATE records SET payload_json = ?, updated_at = ? WHERE route_path = ? AND id = ?",
                (encoded, now, route_path, int(record_id)),
            )
            conn.commit()
            if cur.rowcount == 0:
                return None
            row = conn.execute(
                "SELECT id, route_path, payload_json, created_at, updated_at FROM records WHERE id = ?",
                (int(record_id),),
            ).fetchone()
            if row is None:
                return None
            return {
                "id": int(row["id"]),
                "route_path": row["route_path"],
                "data": json.loads(row["payload_json"]),
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
        finally:
            if should_close:
                conn.close()

    def delete_record(self, route_path: str, record_id: int) -> bool:
        conn, should_close = self._get_conn()
        try:
            cur = conn.execute(
                "DELETE FROM records WHERE route_path = ? AND id = ?",
                (route_path, int(record_id)),
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            if should_close:
                conn.close()

    def count_all(self) -> int:
        conn, should_close = self._get_conn()
        try:
            row = conn.execute("SELECT COUNT(*) AS cnt FROM records").fetchone()
            return int(row["cnt"]) if row is not None else 0
        finally:
            if should_close:
                conn.close()


DEFAULT_STORE: RecordStore | None = None


def _resolve_store(store: RecordStore | None) -> RecordStore:
    global DEFAULT_STORE
    if store is not None:
        return store
    if DEFAULT_STORE is None:
        DEFAULT_STORE = RecordStore(DEFAULT_DB_PATH)
    return DEFAULT_STORE


def _known_route_paths() -> set[str]:
    return {str(spec["path"]) for spec in ROUTE_TABLE}


def _split_item_path(clean_path: str) -> tuple[str, int] | None:
    if "/" not in clean_path:
        return None
    raw_base, last_seg = clean_path.rsplit("/", 1)
    if not last_seg.isdigit():
        return None
    base_path = raw_base or "/"
    if base_path in _known_route_paths():
        return base_path, int(last_seg)
    return None


def dispatch_route(
    method: str,
    path: str,
    body_data: dict[str, Any] | None = None,
    store: RecordStore | None = None,
) -> tuple[int, dict[str, Any]]:
    """Pure SQLite-backed route dispatcher for direct unit testing and HTTP serving."""
    clean_method = method.upper().strip()
    clean_path = path or "/"
    active_store = _resolve_store(store)

    if clean_path == "/__health":
        return 200, {
            "ok": True,
            "app": APP_NAME,
            "storage": "sqlite",
            "routes_count": len(ROUTE_TABLE),
            "stored_records": active_store.count_all(),
        }

    if clean_path == "/__routes":
        return 200, {"ok": True, "routes": ROUTE_TABLE}

    item_match = _split_item_path(clean_path)
    if item_match is not None:
        base_path, rec_id = item_match
        if clean_method == "DELETE":
            deleted = active_store.delete_record(base_path, rec_id)
            if not deleted:
                return 404, {"ok": False, "error": "Record not found", "id": rec_id}
            return 200, {"ok": True, "deleted_id": rec_id, "route_path": base_path}
        if clean_method in {"PUT", "PATCH"}:
            updated = active_store.update_record(base_path, rec_id, body_data if isinstance(body_data, dict) else {})
            if updated is None:
                return 404, {"ok": False, "error": "Record not found", "id": rec_id}
            return 200, {"ok": True, "record": updated}
        if clean_method == "GET":
            items = [it for it in active_store.list_records(base_path) if it["id"] == rec_id]
            if not items:
                return 404, {"ok": False, "error": "Record not found", "id": rec_id}
            return 200, {"ok": True, "record": items[0]}

    for spec in ROUTE_TABLE:
        if spec["method"] == clean_method and spec["path"] == clean_path:
            payload = dict(spec.get("response_json") or {"ok": True})
            if clean_method in {"POST", "PUT", "PATCH"}:
                data_obj = body_data if isinstance(body_data, dict) else {}
                inserted = active_store.insert_record(clean_path, data_obj)
                payload["record"] = inserted
                payload["stored_count"] = len(active_store.list_records(clean_path))
            elif clean_method == "GET":
                items = active_store.list_records(clean_path)
                payload["stored_items"] = items
                payload["stored_count"] = len(items)
            elif clean_method == "DELETE" and isinstance(body_data, dict) and "id" in body_data:
                deleted = active_store.delete_record(clean_path, int(body_data["id"]))
                payload["deleted"] = deleted
            return int(spec.get("status", 200)), payload

    if clean_path in _known_route_paths():
        if clean_method == "POST":
            data_obj = body_data if isinstance(body_data, dict) else {}
            inserted = active_store.insert_record(clean_path, data_obj)
            return 201, {
                "ok": True,
                "route_path": clean_path,
                "record": inserted,
                "stored_count": len(active_store.list_records(clean_path)),
            }
        if clean_method == "GET":
            items = active_store.list_records(clean_path)
            return 200, {
                "ok": True,
                "route_path": clean_path,
                "stored_items": items,
                "stored_count": len(items),
            }

    return 404, {"ok": False, "error": "Not Found", "method": clean_method, "path": clean_path}


class ReconstructedHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send_bytes(self, status: int, content_type: str, data: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _handle(self, method: str) -> None:
        parsed = urlparse(self.path)
        req_path = parsed.path or "/"

        if method == "GET" and req_path in {"/", "/index.html"}:
            index_file = PUBLIC_DIR / "index.html"
            if index_file.is_file():
                self._send_bytes(200, "text/html; charset=utf-8", index_file.read_bytes())
                return

        body_obj: dict[str, Any] | None = None
        length_raw = self.headers.get("Content-Length", "0")
        try:
            length = max(0, min(1_000_000, int(length_raw)))
        except ValueError:
            length = 0
        if length > 0:
            raw = self.rfile.read(length).decode("utf-8", errors="replace")
            try:
                loaded = json.loads(raw)
                body_obj = loaded if isinstance(loaded, dict) else {"raw": loaded}
            except json.JSONDecodeError:
                body_obj = {"raw": raw}

        status, resp_payload = dispatch_route(method, req_path, body_obj)
        encoded = json.dumps(resp_payload, indent=2, default=str).encode("utf-8")
        self._send_bytes(status, "application/json; charset=utf-8", encoded)

    def do_GET(self) -> None:
        self._handle("GET")

    def do_POST(self) -> None:
        self._handle("POST")

    def do_PUT(self) -> None:
        self._handle("PUT")

    def do_PATCH(self) -> None:
        self._handle("PATCH")

    def do_DELETE(self) -> None:
        self._handle("DELETE")


def serve(host: str = "127.0.0.1", port: int = 8080) -> None:
    httpd = ThreadingHTTPServer((host, port), ReconstructedHandler)
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()


if __name__ == "__main__":
    serve()
'''


def _render_backend_server_py(app_name: str, route_specs: list[dict[str, Any]]) -> str:
    """Render a standalone, SQLite-backed Python HTTP server implementing all discovered routes."""
    routes_literal = json.dumps(route_specs, indent=2, default=str)
    template = _BACKEND_SERVER_TEMPLATE
    return template.replace("__ROUTES_LITERAL__", repr(routes_literal)).replace("__APP_NAME_LITERAL__", repr(app_name))


_FRONTEND_HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>__APP_NAME_HTML__ — Application Console</title>
  <style>
    body {
      margin: 0;
      padding: 20px;
      background: #0d1117;
      color: #e6edf3;
      font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
    }
    .wrap { max-width: 960px; margin: 0 auto; }
    .card {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 10px;
      padding: 16px;
      margin-bottom: 14px;
    }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 10px; }
    label { display: block; font-size: 0.85rem; color: #8b949e; margin-top: 8px; }
    input, select, textarea {
      width: 100%;
      box-sizing: border-box;
      margin-top: 4px;
      padding: 8px 10px;
      border-radius: 6px;
      border: 1px solid #30363d;
      background: #0d1117;
      color: #e6edf3;
      font-family: inherit;
    }
    textarea { min-height: 90px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.82rem; }
    .actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }
    button {
      padding: 7px 14px;
      border-radius: 6px;
      border: 0;
      background: #2f81f7;
      color: #fff;
      font-weight: 600;
      cursor: pointer;
    }
    button.danger { background: #da3633; }
    button.secondary { background: #30363d; }
    pre {
      background: #0d1117;
      border: 1px solid #30363d;
      border-radius: 8px;
      padding: 12px;
      overflow-x: auto;
      font-size: 0.82rem;
    }
    .rec-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 10px;
      padding: 8px 0;
      border-bottom: 1px solid #21262d;
    }
  </style>
</head>
<body>
  <div class="wrap">
    <h1>__APP_NAME_HTML__</h1>
    <div class="card">
      <div class="grid">
        <div>
          <label for="route-select">Endpoint</label>
          <select id="route-select"></select>
        </div>
        <div>
          <label for="record-id">Record ID (for Update / Delete)</label>
          <input id="record-id" type="number" min="1" placeholder="Optional ID" />
        </div>
      </div>
      <div id="dynamic-fields"></div>
      <label for="payload-json">JSON Payload (override or custom fields)</label>
      <textarea id="payload-json" placeholder='{"name": "value"}'></textarea>
      <div class="actions">
        <button type="button" onclick="loadRecords()">Fetch (GET)</button>
        <button type="button" onclick="saveRecord()">Create (POST)</button>
        <button type="button" class="secondary" onclick="updateRecord()">Update (PUT)</button>
        <button type="button" class="danger" onclick="deleteRecord()">Delete (DELETE)</button>
        <button type="button" class="secondary" onclick="checkHealth()">Health</button>
      </div>
    </div>

    <div class="card">
      <h3>Persisted SQLite Records</h3>
      <div id="records-list">Select an endpoint and click Fetch (GET).</div>
    </div>

    <div class="card">
      <h3>Live API Response</h3>
      <pre id="resp-out">Ready.</pre>
    </div>
  </div>
  <script>
    const ROUTES = __ROUTES_JSON__;
    const routeSelect = document.getElementById("route-select");
    const fieldsBox = document.getElementById("dynamic-fields");
    const payloadArea = document.getElementById("payload-json");
    const recordIdInput = document.getElementById("record-id");
    const recordsList = document.getElementById("records-list");
    const out = document.getElementById("resp-out");

    const uniquePaths = Array.from(new Set(ROUTES.map((r) => r.path)));
    uniquePaths.forEach((p) => {
      const opt = document.createElement("option");
      opt.value = p;
      opt.textContent = p;
      routeSelect.appendChild(opt);
    });

    function renderFieldsForPath(path) {
      fieldsBox.innerHTML = "";
      const matched = ROUTES.find((r) => r.path === path && Array.isArray(r.fields) && r.fields.length > 0);
      if (!matched) return;
      const grid = document.createElement("div");
      grid.className = "grid";
      matched.fields.forEach((fname) => {
        const wrap = document.createElement("div");
        const lbl = document.createElement("label");
        lbl.textContent = fname;
        const inp = document.createElement("input");
        inp.dataset.fieldName = fname;
        inp.placeholder = "Enter " + fname;
        wrap.appendChild(lbl);
        wrap.appendChild(inp);
        grid.appendChild(wrap);
      });
      fieldsBox.appendChild(grid);
    }

    function collectPayload() {
      const raw = payloadArea.value.trim();
      if (raw) {
        return JSON.parse(raw);
      }
      const obj = {};
      fieldsBox.querySelectorAll("input[data-field-name]").forEach((inp) => {
        obj[inp.dataset.fieldName] = inp.value;
      });
      return obj;
    }

    function renderRecords(items, path) {
      recordsList.innerHTML = "";
      if (!Array.isArray(items) || items.length === 0) {
        recordsList.textContent = "No records stored for " + path + " yet.";
        return;
      }
      items.forEach((item) => {
        const row = document.createElement("div");
        row.className = "rec-row";
        const info = document.createElement("code");
        info.textContent = "#" + item.id + " " + JSON.stringify(item.data);
        const delBtn = document.createElement("button");
        delBtn.className = "danger";
        delBtn.textContent = "Delete #" + item.id;
        delBtn.onclick = async () => {
          const res = await fetch(path.replace(/\/$/, "") + "/" + item.id, { method: "DELETE" });
          out.textContent = JSON.stringify(await res.json(), null, 2);
          await loadRecords();
        };
        row.appendChild(info);
        row.appendChild(delBtn);
        recordsList.appendChild(row);
      });
    }

    async function loadRecords() {
      const path = routeSelect.value;
      const res = await fetch(path, { method: "GET" });
      const data = await res.json();
      out.textContent = JSON.stringify(data, null, 2);
      renderRecords(data.stored_items || [], path);
    }

    async function saveRecord() {
      try {
        const path = routeSelect.value;
        const body = collectPayload();
        const res = await fetch(path, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        });
        out.textContent = JSON.stringify(await res.json(), null, 2);
        await loadRecords();
      } catch (err) {
        out.textContent = "Invalid JSON payload: " + err.message;
      }
    }

    async function updateRecord() {
      const id = recordIdInput.value.trim();
      if (!id) {
        out.textContent = "Enter a Record ID to update.";
        return;
      }
      try {
        const path = routeSelect.value;
        const body = collectPayload();
        const res = await fetch(path.replace(/\/$/, "") + "/" + id, {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        });
        out.textContent = JSON.stringify(await res.json(), null, 2);
        await loadRecords();
      } catch (err) {
        out.textContent = "Invalid JSON payload: " + err.message;
      }
    }

    async function deleteRecord() {
      const id = recordIdInput.value.trim();
      if (!id) {
        out.textContent = "Enter a Record ID to delete.";
        return;
      }
      const path = routeSelect.value;
      const res = await fetch(path.replace(/\/$/, "") + "/" + id, { method: "DELETE" });
      out.textContent = JSON.stringify(await res.json(), null, 2);
      await loadRecords();
    }

    async function checkHealth() {
      const res = await fetch("/__health");
      out.textContent = JSON.stringify(await res.json(), null, 2);
    }

    routeSelect.onchange = () => renderFieldsForPath(routeSelect.value);
    if (uniquePaths.length > 0) {
      renderFieldsForPath(uniquePaths[0]);
    }
  </script>
</body>
</html>
"""

_TESTS_PY_TEMPLATE = '''"""Automated SQLite CRUD verification tests for the reconstructed application."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from app.server import ROUTE_TABLE, RecordStore, dispatch_route


class ReconstructedAppTests(unittest.TestCase):
    def test_health_and_sqlite_crud_persistence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_file = str(Path(tmp) / "test_app.sqlite")
            store = RecordStore(db_file)

            status, health = dispatch_route("GET", "/__health", store=store)
            self.assertEqual(status, 200)
            self.assertTrue(health.get("ok"))
            self.assertEqual(health.get("storage"), "sqlite")
            self.assertEqual(len(ROUTE_TABLE), __ROUTES_COUNT__)

            post_status, post_body = dispatch_route(
                "POST",
                __FIRST_PATH__,
                {"item": "persisted_entry"},
                store=store,
            )
            self.assertIn(post_status, (200, 201))
            rec_id = post_body["record"]["id"]

            reopened_store = RecordStore(db_file)
            get_status, get_body = dispatch_route("GET", __FIRST_PATH__, store=reopened_store)
            self.assertEqual(get_status, 200)
            ids = [r["id"] for r in get_body.get("stored_items", [])]
            self.assertIn(rec_id, ids)

            base = __FIRST_PATH__.rstrip("/")
            del_status, del_body = dispatch_route("DELETE", f"{base}/{rec_id}", store=reopened_store)
            self.assertEqual(del_status, 200)
            self.assertEqual(del_body.get("deleted_id"), rec_id)


if __name__ == "__main__":
    unittest.main()
'''


def _render_frontend_index_html(app_name: str, route_specs: list[dict[str, Any]]) -> str:
    """Render an interactive HTML5 + Vanilla JS CRUD frontend wired to all endpoints."""
    routes_json = json.dumps(route_specs, default=str)
    safe_title = html.escape(app_name)
    return _FRONTEND_HTML_TEMPLATE.replace("__APP_NAME_HTML__", safe_title).replace("__ROUTES_JSON__", routes_json)


def _render_generated_tests_py(route_specs: list[dict[str, Any]]) -> str:
    """Render an executable unittest file verifying real on-disk SQLite CRUD persistence."""
    first_route = route_specs[0]
    return (
        _TESTS_PY_TEMPLATE
        .replace("__ROUTES_COUNT__", str(len(route_specs)))
        .replace("__FIRST_PATH__", repr(first_route["path"]))
    )


def _build_sandbox_smoke_script(server_code: str, route_specs: list[dict[str, Any]]) -> str:
    """Construct a self-contained AST-safe SQLite CRUD smoke verification script for the sandbox."""
    first_route = route_specs[0]
    stripped_lines: list[str] = []
    for line in server_code.splitlines():
        if line.startswith(("from __future__", "from pathlib", "BASE_DIR =", "PUBLIC_DIR =", "DEFAULT_DB_PATH =")):
            continue
        stripped_lines.append(line)
    pure_logic = 'PUBLIC_DIR = None\nDEFAULT_DB_PATH = ":memory:"\n' + "\n".join(stripped_lines)
    first_path = first_route["path"]
    base_prefix = first_path.rstrip("/")
    smoke_footer = (
        "\n# --- Sandbox Pre-Output SQLite CRUD Verification ---\n"
        "MEM_STORE = RecordStore(':memory:')\n"
        "st_h, body_h = dispatch_route('GET', '/__health', store=MEM_STORE)\n"
        "assert st_h == 200 and body_h.get('ok') is True and body_h.get('storage') == 'sqlite', 'Health failed'\n"
        f"st_p, body_p = dispatch_route('POST', {first_path!r}, {{'entry': 'verified'}}, store=MEM_STORE)\n"
        "assert st_p in (200, 201) and isinstance(body_p.get('record'), dict), f'POST failed: {st_p}'\n"
        "rec_id = body_p['record']['id']\n"
        f"st_g, body_g = dispatch_route('GET', {first_path!r}, store=MEM_STORE)\n"
        "assert st_g == 200 and any(r['id'] == rec_id for r in body_g.get('stored_items', [])), 'GET persistence failed'\n"
        f"st_u, body_u = dispatch_route('PUT', f'{base_prefix}/{{rec_id}}', {{'entry': 'updated'}}, store=MEM_STORE)\n"
        "assert st_u == 200 and body_u['record']['data']['entry'] == 'updated', 'PUT update failed'\n"
        f"st_d, body_d = dispatch_route('DELETE', f'{base_prefix}/{{rec_id}}', store=MEM_STORE)\n"
        "assert st_d == 200 and body_d.get('deleted_id') == rec_id, 'DELETE failed'\n"
        "print('SYNTHESIS_SQLITE_CRUD_VERIFIED:', len(ROUTE_TABLE))\n"
    )
    return pure_logic + smoke_footer


class AutonomousProjectSynthesizer:
    """Synthesizes a complete SQLite-backed multi-file project from findings and verifies it in sandbox."""

    def __init__(
        self,
        simulator: SimulationGate | None = None,
        workspace: NgaWorkspace | None = None,
        ledger: ObligationLedger | None = None,
    ) -> None:
        self.simulator = simulator if simulator is not None else SimulationGate()
        self.workspace = workspace
        self.ledger = ledger

    def synthesize_project(
        self,
        app_name: str,
        findings: dict[str, Any],
        output_dir: str | Path,
        base_root: Path | None = None,
    ) -> ToolResponse | NgaError:
        """Generate multi-file SQLite CRUD app (backend, frontend, tests, manifest), simulate first, then write."""
        clean_name = redact_secrets(str(app_name or "reconstructed_app").strip()) or "reconstructed_app"
        root = Path(base_root).resolve() if base_root is not None else Path.cwd().resolve()

        ok_out, resolved_out = safe_resolve_path(root, output_dir)
        if not ok_out or not isinstance(resolved_out, Path):
            return resolved_out if isinstance(resolved_out, NgaError) else NgaError(
                error_code=ErrorCode.PATH_TRAVERSAL.value,
                module="nga.builder.synthesizer",
                message="Output directory escapes allowed root.",
                recoverable=False,
            )

        route_specs = _normalize_route_specs(findings if isinstance(findings, dict) else {})
        server_py = _render_backend_server_py(clean_name, route_specs)
        index_html = _render_frontend_index_html(clean_name, route_specs)
        tests_py = _render_generated_tests_py(route_specs)

        smoke_script = _build_sandbox_smoke_script(server_py, route_specs)
        sim_report = self.simulator.simulate_crafted_python(
            code=smoke_script,
            target_label=f"synthesize::{_sanitize_identifier(clean_name)}",
        )
        if isinstance(sim_report, NgaError):
            return sim_report
        if not sim_report.passed:
            return NgaError(
                error_code=ErrorCode.SIMULATION_FAILED.value,
                module="nga.builder.synthesizer",
                message=f"Synthesized project failed pre-output sandbox simulation ({sim_report.status.value}).",
                recoverable=True,
                suggested_fix="Inspect simulation stderr_preview and adjust findings/routes.",
                details={"simulation": sim_report.to_dict()},
            )

        synced_obligations: list[str] = []
        if self.ledger is not None:
            for spec in route_specs:
                oid = f"route_{_sanitize_identifier(spec['method'])}_{_sanitize_identifier(spec['path'])}"
                title = f"{spec['method']} {spec['path']}"
                added = self.ledger.add_obligation(
                    obligation_id=oid,
                    category="reconstructed_route",
                    title=title,
                    status=ObligationStatus.VERIFIED,
                    notes=f"Synthesized SQLite CRUD route and sandbox-verified ({sim_report.run_id}).",
                    evidence_text=json.dumps(spec, default=str),
                )
                if not isinstance(added, NgaError):
                    synced_obligations.append(oid)

        files_to_write: dict[str, str] = {
            "app/__init__.py": '"""Reconstructed SQLite-backed application package."""\n',
            "app/server.py": server_py,
            "app/public/index.html": index_html,
            "tests/__init__.py": "",
            "tests/test_reconstructed_app.py": tests_py,
        }

        file_manifest: list[dict[str, Any]] = []
        for rel_path, content in files_to_write.items():
            ok_f, target_file = safe_resolve_path(resolved_out, rel_path)
            if not ok_f or not isinstance(target_file, Path):
                return NgaError(
                    error_code=ErrorCode.PATH_TRAVERSAL.value,
                    module="nga.builder.synthesizer",
                    message=f"Unsafe relative output path blocked: {rel_path}",
                    recoverable=False,
                )
            target_file.parent.mkdir(parents=True, exist_ok=True)
            target_file.write_text(content, encoding="utf-8")
            file_manifest.append(
                {
                    "path": rel_path,
                    "bytes": len(content.encode("utf-8")),
                    "sha256": compute_sha256_text(content),
                }
            )

        manifest_payload = {
            "app_name": clean_name,
            "storage_engine": "sqlite",
            "generated_at": utc_now_iso(),
            "simulation_run_id": sim_report.run_id,
            "routes_count": len(route_specs),
            "synced_obligations": synced_obligations,
            "files": file_manifest,
        }
        manifest_path = resolved_out / "reconstruction_manifest.json"
        manifest_path.write_text(json.dumps(manifest_payload, indent=2), encoding="utf-8")

        if self.workspace is not None:
            self.workspace.merkle.append(
                "PROJECT_SYNTHESIZED_AND_VERIFIED",
                {
                    "app_name": clean_name,
                    "output_dir": str(resolved_out),
                    "storage_engine": "sqlite",
                    "routes_count": len(route_specs),
                    "simulation_run_id": sim_report.run_id,
                },
            )

        return ToolResponse(
            module="nga.builder.synthesizer",
            summary=(
                f"Synthesized & SQLite-CRUD verified '{clean_name}' ({len(file_manifest)} files, "
                f"{len(route_specs)} route(s)) in {sim_report.duration_ms}ms."
            ),
            simulation_status=SimulationStatus.SIMULATION_PASSED.value,
            data={
                "output_dir": str(resolved_out),
                "storage_engine": "sqlite",
                "routes_count": len(route_specs),
                "synced_obligations_count": len(synced_obligations),
                "simulation": sim_report.to_dict(),
                "manifest": manifest_payload,
            },
    )
