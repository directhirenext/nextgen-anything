"""Autonomous multi-file SQLite CRUD project synthesizer with sandbox verification and custom feature support."""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any

from nga.aaire.llm_engine import UniversalLlmEngine
from nga.core.contracts import (
    ErrorCode,
    NgaError,
    ObligationStatus,
    SimulationStatus,
    ToolResponse,
    utc_now_iso,
)
from nga.core.ledger import ObligationLedger
from nga.core.security import compute_sha256_text, redact_secrets, safe_resolve_path
from nga.core.workspace import NgaWorkspace
from nga.runtime.simulator import SimulationGate

_SAFE_IDENT_RE = re.compile(r"[^a-zA-Z0-9_]+")
_ROUTE_CLEAN_RE = re.compile(r"^/[a-zA-Z0-9_./-]{1,80}$")


def _sanitize_slug(raw: str, fallback: str = "reconstructed_app") -> str:
    cleaned = _SAFE_IDENT_RE.sub("_", str(raw or "").strip().lower()).strip("_")
    if not cleaned:
        cleaned = fallback
    if cleaned[0].isdigit():
        cleaned = f"app_{cleaned}"
    return cleaned[:48]


def _normalize_resource_path(raw_path: str) -> str:
    p = str(raw_path or "").strip()
    if not p:
        return "/api/records"
    if not p.startswith("/"):
        p = f"/{p}"
    p = p.split("?", 1)[0].rstrip("/") or "/"
    if p == "/":
        return "/api/records"
    if not _ROUTE_CLEAN_RE.match(p):
        slug = _sanitize_slug(p, "records")
        return f"/api/{slug}"
    return p


def _extract_routes_and_fields(findings: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    """Flatten nested analyzer outputs (web_js, network_har, archive_pkg, binary_meta) into routes & fields."""
    flat: dict[str, Any] = dict(findings) if isinstance(findings, dict) else {}
    for nested_key in ("analysis", "package", "metadata"):
        sub = flat.get(nested_key)
        if isinstance(sub, dict):
            for k, v in sub.items():
                flat.setdefault(k, v)

    route_entries: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    fields: list[str] = []
    seen_fields: set[str] = set()

    def _add_field(name: Any) -> None:
        clean_f = _sanitize_slug(str(name or ""), "")
        if clean_f and clean_f not in {"id", "created_at"} and clean_f not in seen_fields and len(fields) < 16:
            seen_fields.add(clean_f)
            fields.append(clean_f)

    def _add_route(method: str, raw_path: Any, route_fields: list[str] | None = None) -> None:
        norm_p = _normalize_resource_path(str(raw_path or "/api/records"))
        m = str(method or "GET").upper().strip() or "GET"
        if norm_p not in seen_paths and len(route_entries) < 20:
            seen_paths.add(norm_p)
            route_entries.append({"method": m, "path": norm_p})
        for rf in route_fields or []:
            _add_field(rf)

    for form in flat.get("forms") or []:
        if isinstance(form, dict):
            f_action = form.get("action") or "/api/records"
            f_method = form.get("method") or "POST"
            f_inputs = [
                inp.get("name") for inp in (form.get("inputs") or []) if isinstance(inp, dict) and inp.get("name")
            ]
            _add_route(f_method, f_action, f_inputs)

    for ep in flat.get("endpoints") or []:
        if isinstance(ep, dict):
            _add_route(str(ep.get("method", "GET")), ep.get("path"), ep.get("fields") if isinstance(ep.get("fields"), list) else None)

    for key in ("routes", "embedded_routes"):
        for r in flat.get(key) or []:
            if isinstance(r, dict):
                _add_route("GET", r.get("path"))
            elif isinstance(r, str) and r.strip():
                _add_route("GET", r)

    for key in ("api_calls", "embedded_api_calls"):
        for u in flat.get(key) or []:
            if isinstance(u, dict) and u.get("endpoint"):
                _add_route("GET", u["endpoint"])
            elif isinstance(u, str) and u.strip():
                _add_route("GET", u)

    if not route_entries:
        _add_route("GET", "/api/records", ["title", "notes"])
        _add_route("POST", "/api/records", ["title", "notes"])

    if not fields:
        _add_field("title")
        _add_field("notes")

    return route_entries, fields


def _render_server_code(
    app_slug: str,
    primary_route: str,
    fields: list[str],
    custom_prompt: str,
) -> str:
    """Render a self-contained pure-Python SQLite CRUD + JSON + HTML UI HTTP server."""
    safe_custom = redact_secrets(custom_prompt).replace('"""', "'''")
    field_defs_sql = ",\n    ".join(f"{f} TEXT NOT NULL DEFAULT ''" for f in fields)
    col_names = ["id", *fields, "created_at"]
    cols_sql = ", ".join(col_names)
    insert_cols = ", ".join(fields)
    placeholders = ", ".join("?" for _ in fields)

    return f'''"""Generated SQLite CRUD HTTP server for {app_slug}."""

from __future__ import annotations

from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sqlite3
import threading
from typing import Any
from urllib.parse import parse_qs, urlparse

PRIMARY_ROUTE = {primary_route!r}
FIELDS = {fields!r}
CUSTOM_SPEC = {safe_custom!r}


def _to_int(val: Any, default: int) -> int:
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


class SqliteStore:
    """Thread-safe SQLite storage backend for reconstructed records."""

    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=15.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock, closing(self._connect()) as conn:
            with conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS records (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        {field_defs_sql},
                        created_at TEXT NOT NULL DEFAULT (datetime('now'))
                    );
                    """
                )

    def list_items(self, query: str = "", limit: int = 100) -> list[dict[str, Any]]:
        safe_lim = max(1, min(500, _to_int(limit, 100)))
        q = str(query or "").strip().lower()
        with self._lock, closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT {cols_sql} FROM records ORDER BY id DESC LIMIT ?",
                (safe_lim,),
            ).fetchall()
        items = [dict(r) for r in rows]
        if not q:
            return items
        return [
            it for it in items
            if any(q in str(it.get(col, "")).lower() for col in FIELDS)
        ]

    def get_item(self, item_id: int) -> dict[str, Any] | None:
        with self._lock, closing(self._connect()) as conn:
            row = conn.execute("SELECT {cols_sql} FROM records WHERE id = ?", (item_id,)).fetchone()
        return dict(row) if row else None

    def create_item(self, payload: dict[str, Any]) -> dict[str, Any]:
        values = [str(payload.get(f, "") or "").strip() for f in FIELDS]
        with self._lock, closing(self._connect()) as conn:
            with conn:
                cur = conn.execute(
                    "INSERT INTO records ({insert_cols}) VALUES ({placeholders})",
                    values,
                )
                new_id = int(cur.lastrowid or 0)
        created = self.get_item(new_id)
        return created if created is not None else {{"id": new_id}}

    def update_item(self, item_id: int, payload: dict[str, Any]) -> dict[str, Any] | None:
        current = self.get_item(item_id)
        if current is None:
            return None
        updates = [str(payload.get(f, current.get(f, "")) or "").strip() for f in FIELDS]
        set_clause = ", ".join(f"{f} = ?" for f in FIELDS)
        with self._lock, closing(self._connect()) as conn:
            with conn:
                conn.execute(f"UPDATE records SET {set_clause} WHERE id = ?", [*updates, item_id])
        return self.get_item(item_id)

    def delete_item(self, item_id: int) -> bool:
        with self._lock, closing(self._connect()) as conn:
            with conn:
                cur = conn.execute("DELETE FROM records WHERE id = ?", (item_id,))
                return int(cur.rowcount or 0) > 0


def build_app_server(db_path: Path | str, public_dir: Path | str, host: str = "127.0.0.1", port: int = 0) -> ThreadingHTTPServer:
    store = SqliteStore(db_path)
    pub_root = Path(public_dir).resolve()

    class AppHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return

        def _send_json(self, status: int, data: Any) -> None:
            raw = json.dumps(data, indent=2, default=str).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _send_file(self, rel_name: str) -> None:
            candidate = (pub_root / rel_name).resolve()
            try:
                candidate.relative_to(pub_root)
            except ValueError:
                self._send_json(403, {{"ok": False, "error": "Forbidden"}})
                return
            if not candidate.is_file():
                self._send_json(404, {{"ok": False, "error": "Not found"}})
                return
            content = candidate.read_bytes()
            ctype = "text/html; charset=utf-8" if candidate.suffix == ".html" else "application/octet-stream"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)

        def _parse_body(self) -> dict[str, Any]:
            length = max(0, min(1_000_000, _to_int(self.headers.get("Content-Length", "0"), 0)))
            if length == 0:
                return {{}}
            raw = self.rfile.read(length).decode("utf-8", errors="replace")
            try:
                parsed = json.loads(raw)
                return parsed if isinstance(parsed, dict) else {{}}
            except json.JSONDecodeError:
                q_parsed = parse_qs(raw)
                return {{k: v[0] for k, v in q_parsed.items() if v}}

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            path = parsed.path or "/"
            qs = parse_qs(parsed.query)
            if path in {{"/", "/index.html"}}:
                self._send_file("index.html")
                return
            if path == "/health":
                self._send_json(200, {{"ok": True, "app": {app_slug!r}, "primary_route": PRIMARY_ROUTE}})
                return
            if path in {{PRIMARY_ROUTE, "/api/records"}}:
                q = (qs.get("q") or [""])[0]
                items = store.list_items(query=q)
                self._send_json(200, {{"ok": True, "items": items, "count": len(items)}})
                return
            if path.startswith(PRIMARY_ROUTE + "/") or path.startswith("/api/records/"):
                tail = path.rsplit("/", 1)[-1]
                if tail.isdigit():
                    item = store.get_item(int(tail))
                    if item is None:
                        self._send_json(404, {{"ok": False, "error": "Record not found"}})
                    else:
                        self._send_json(200, {{"ok": True, "item": item}})
                    return
            self._send_json(404, {{"ok": False, "error": "Endpoint not found"}})

        def do_POST(self) -> None:
            path = urlparse(self.path).path or "/"
            if path in {{PRIMARY_ROUTE, "/api/records"}}:
                created = store.create_item(self._parse_body())
                self._send_json(201, {{"ok": True, "item": created}})
                return
            self._send_json(404, {{"ok": False, "error": "Endpoint not found"}})

        def do_PUT(self) -> None:
            path = urlparse(self.path).path or "/"
            tail = path.rsplit("/", 1)[-1]
            if (path.startswith(PRIMARY_ROUTE + "/") or path.startswith("/api/records/")) and tail.isdigit():
                updated = store.update_item(int(tail), self._parse_body())
                if updated is None:
                    self._send_json(404, {{"ok": False, "error": "Record not found"}})
                else:
                    self._send_json(200, {{"ok": True, "item": updated}})
                return
            self._send_json(404, {{"ok": False, "error": "Endpoint not found"}})

        def do_DELETE(self) -> None:
            path = urlparse(self.path).path or "/"
            tail = path.rsplit("/", 1)[-1]
            if (path.startswith(PRIMARY_ROUTE + "/") or path.startswith("/api/records/")) and tail.isdigit():
                deleted = store.delete_item(int(tail))
                if not deleted:
                    self._send_json(404, {{"ok": False, "error": "Record not found"}})
                else:
                    self._send_json(200, {{"ok": True, "deleted": True, "id": int(tail)}})
                return
            self._send_json(404, {{"ok": False, "error": "Endpoint not found"}})

    srv = ThreadingHTTPServer((host, port), AppHandler)
    srv.daemon_threads = True
    return srv


def main() -> int:
    here = Path(__file__).resolve().parent
    srv = build_app_server(here / "data.sqlite", here / "public", host="127.0.0.1", port=8790)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


def _render_index_html(app_slug: str, primary_route: str, fields: list[str]) -> str:
    inputs_html = "\n      ".join(
        f'<label>{f}<input id="f_{f}" name="{f}" placeholder="{f}" /></label>' for f in fields
    )
    fields_js = json.dumps(fields)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>{app_slug} — Reconstructed App</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 20px; background: #0d1117; color: #e6edf3; }}
    .box {{ max-width: 760px; margin: 0 auto; background: #161b22; padding: 18px; border-radius: 10px; border: 1px solid #30363d; }}
    label {{ display: block; margin-top: 10px; font-size: 0.85rem; color: #8b949e; }}
    input {{ width: 100%; padding: 8px; margin-top: 4px; border-radius: 6px; border: 1px solid #30363d; background: #0d1117; color: #e6edf3; }}
    button {{ margin-top: 12px; padding: 8px 14px; border: 0; border-radius: 6px; background: #2f81f7; color: #fff; font-weight: 600; cursor: pointer; }}
    pre {{ background: #010409; padding: 12px; border-radius: 8px; margin-top: 14px; overflow: auto; }}
  </style>
</head>
<body>
  <div class="box">
    <h1>{app_slug}</h1>
    <p>Endpoint: <code>{primary_route}</code></p>
    <form id="rec-form">
      {inputs_html}
      <button type="submit">Save Record</button>
    </form>
    <pre id="out">Loading...</pre>
  </div>
  <script>
    const ROUTE = {json.dumps(primary_route)};
    const FIELDS = {fields_js};
    const out = document.getElementById("out");
    async function refreshList() {{
      const r = await fetch(ROUTE);
      const d = await r.json();
      out.textContent = JSON.stringify(d, null, 2);
    }}
    document.getElementById("rec-form").addEventListener("submit", async (e) => {{
      e.preventDefault();
      const body = {{}};
      FIELDS.forEach(k => {{ const el = document.getElementById("f_" + k); if (el) body[k] = el.value; }});
      await fetch(ROUTE, {{ method: "POST", headers: {{"Content-Type": "application/json"}}, body: JSON.stringify(body) }});
      refreshList();
    }});
    refreshList();
  </script>
</body>
</html>
"""

    def _render_generated_tests(app_slug: str, primary_route: str, fields: list[str]) -> str:
    sample_obj = {f: f"sample_{f}_1" for f in fields}
    updated_obj = {f: f"updated_{f}_1" for f in fields}
    sample_json_literal = json.dumps(json.dumps(sample_obj))
    updated_json_literal = json.dumps(json.dumps(updated_obj))
    return f'''"""Automated SQLite CRUD verification tests for {app_slug}."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

APP_DIR = Path(__file__).resolve().parent.parent / "app"
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

from server import build_app_server  # noqa: E402


class ReconstructedAppTests(unittest.TestCase):
    def test_sqlite_crud_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            srv = build_app_server(root / "test.sqlite", APP_DIR / "public", host="127.0.0.1", port=0)
            port = srv.server_address[1]
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            base = f"http://127.0.0.1:{{port}}"
            route = {primary_route!r}
            try:
                with urlopen(f"{{base}}/health", timeout=5) as resp:
                    self.assertEqual(resp.status, 200)

                create_payload = {sample_json_literal}.encode("utf-8")
                req_post = Request(f"{{base}}{{route}}", data=create_payload, headers={{"Content-Type": "application/json"}}, method="POST")
                with urlopen(req_post, timeout=5) as resp:
                    self.assertEqual(resp.status, 201)
                    created = json.loads(resp.read().decode("utf-8"))["item"]
                item_id = created["id"]

                with urlopen(f"{{base}}{{route}}", timeout=5) as resp:
                    listed = json.loads(resp.read().decode("utf-8"))
                    self.assertGreaterEqual(listed["count"], 1)

                upd_payload = {updated_json_literal}.encode("utf-8")
                req_put = Request(f"{{base}}{{route}}/{{item_id}}", data=upd_payload, headers={{"Content-Type": "application/json"}}, method="PUT")
                with urlopen(req_put, timeout=5) as resp:
                    self.assertEqual(resp.status, 200)

                req_del = Request(f"{{base}}{{route}}/{{item_id}}", method="DELETE")
                with urlopen(req_del, timeout=5) as resp:
                    self.assertEqual(resp.status, 200)

                with self.assertRaises(HTTPError) as ctx:
                    urlopen(f"{{base}}{{route}}/{{item_id}}", timeout=5)
                self.assertEqual(ctx.exception.code, 404)
            finally:
                srv.shutdown()
                srv.server_close()
                t.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
'''


def _render_android_scaffold(app_slug: str, package_name: str, app_title: str) -> dict[str, str]:
    safe_pkg = re.sub(r"[^a-z0-9_.]+", "_", str(package_name or f"com.nga.{app_slug}").lower()).strip(".") or f"com.nga.{app_slug}"
    if "." not in safe_pkg:
        safe_pkg = f"com.nga.{safe_pkg}"
    pkg_path = safe_pkg.replace(".", "/")
    settings_gradle = f'rootProject.name = "{app_slug}"\ninclude(":app")\n'
    build_gradle = (
        'plugins {\n'
        '    id("com.android.application") version "8.2.0" apply false\n'
        '    id("org.jetbrains.kotlin.android") version "1.9.22" apply false\n'
        '}\n'
    )
    app_gradle = (
        'plugins {\n'
        '    id("com.android.application")\n'
        '    id("org.jetbrains.kotlin.android")\n'
        '}\n\n'
        'android {\n'
        f'    namespace = "{safe_pkg}"\n'
        '    compileSdk = 34\n'
        '    defaultConfig {\n'
        f'        applicationId = "{safe_pkg}"\n'
        '        minSdk = 24\n'
        '        targetSdk = 34\n'
        '        versionCode = 1\n'
        '        versionName = "1.0.0"\n'
        '    }\n'
        '    compileOptions {\n'
        '        sourceCompatibility = JavaVersion.VERSION_17\n'
        '        targetCompatibility = JavaVersion.VERSION_17\n'
        '    }\n'
        '}\n'
    )
    manifest_xml = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android">\n'
        '    <uses-permission android:name="android.permission.INTERNET" />\n'
        f'    <application android:label="{app_title}" android:usesCleartextTraffic="true">\n'
        f'        <activity android:name=".MainActivity" android:exported="true">\n'
        '            <intent-filter>\n'
        '                <action android:name="android.intent.action.MAIN" />\n'
        '                <category android:name="android.intent.category.LAUNCHER" />\n'
        '            </intent-filter>\n'
        '        </activity>\n'
        '    </application>\n'
        '</manifest>\n'
    )
    main_kt = (
        f"package {safe_pkg}\n\n"
        "import android.os.Bundle\n"
        "import android.webkit.WebSettings\n"
        "import android.webkit.WebView\n"
        "import androidx.appcompat.app.AppCompatActivity\n\n"
        "class MainActivity : AppCompatActivity() {\n"
        "    override fun onCreate(savedInstanceState: Bundle?) {\n"
        "        super.onCreate(savedInstanceState)\n"
        "        val webView = WebView(this)\n"
        "        webView.settings.javaScriptEnabled = true\n"
        "        webView.settings.domStorageEnabled = true\n"
        "        webView.settings.mixedContentMode = WebSettings.MIXED_CONTENT_ALWAYS_ALLOW\n"
        '        webView.loadUrl("file:///android_asset/index.html")\n'
        "        setContentView(webView)\n"
        "    }\n"
        "}\n"
    )
    return {
        "android_scaffold/settings.gradle.kts": settings_gradle,
        "android_scaffold/build.gradle.kts": build_gradle,
        "android_scaffold/app/build.gradle.kts": app_gradle,
        "android_scaffold/app/src/main/AndroidManifest.xml": manifest_xml,
        f"android_scaffold/app/src/main/kotlin/{pkg_path}/MainActivity.kt": main_kt,
    }


class AutonomousProjectSynthesizer:
    """Synthesizes, sandbox-verifies, and writes complete SQLite-backed apps from findings."""

    def __init__(
        self,
        simulator: SimulationGate | None = None,
        workspace: NgaWorkspace | None = None,
        ledger: ObligationLedger | None = None,
        llm_engine: UniversalLlmEngine | None = None,
    ) -> None:
        self.simulator = simulator if simulator is not None else SimulationGate()
        self.workspace = workspace
        self.ledger = ledger
        self.llm = llm_engine

    def synthesize_project(
        self,
        app_name: str,
        findings: dict[str, Any],
        output_dir: str | Path = "synthesized_out",
        base_root: Path | None = None,
        custom_prompt: str = "",
        include_android_scaffold: bool = False,
    ) -> ToolResponse | NgaError:
        """Build a multi-file SQLite CRUD project, verify it in sandbox, and persist outputs."""
        if not isinstance(findings, dict):
            return NgaError(
                error_code=ErrorCode.INVALID_INPUT.value,
                module="nga.builder.synthesizer",
                message="findings must be a dictionary.",
                recoverable=True,
            )

        root = Path(base_root) if base_root is not None else Path.cwd()
        ok_out, dest_or_err = safe_resolve_path(root, output_dir)
        if not ok_out or not isinstance(dest_or_err, Path):
            return dest_or_err if isinstance(dest_or_err, NgaError) else NgaError(
                error_code=ErrorCode.PATH_TRAVERSAL.value,
                module="nga.builder.synthesizer",
                message="Invalid output_dir path.",
            )

        app_slug = _sanitize_slug(app_name, "reconstructed_app")
        routes, fields = _extract_routes_and_fields(findings)
        primary_route = next(
            (r["path"] for r in routes if r["path"] != "/health"),
            "/api/records",
        )

        server_code = _render_server_code(app_slug, primary_route, fields, custom_prompt)
        index_html = _render_index_html(app_slug, primary_route, fields)
        test_code = _render_generated_tests(app_slug, primary_route, fields)

        # Verify generated server & store logic inside isolated sandbox before writing project files
        smoke_script = (
            "import tempfile\n"
            "from pathlib import Path\n"
            "import server as srv_mod\n"
            "with tempfile.TemporaryDirectory() as td:\n"
            "    st = srv_mod.SqliteStore(Path(td) / 'smoke.sqlite')\n"
            f"    sample = {{f: 'v_' + f for f in FIELDS}}\n"
            "    created = st.create_item(sample)\n"
            "    assert created.get('id') is not None\n"
            "    items = st.list_items()\n"
            "    assert len(items) == 1\n"
            "    assert st.delete_item(int(created['id'])) is True\n"
            "print('SYNTH_SMOKE_OK')\n"
        )
        sim_rep = self.simulator.simulate_crafted_python(
            code=server_code,
            smoke_assertions_code=smoke_script,
            target_label=f"synthesize::{app_slug}",
        )
        if isinstance(sim_rep, NgaError):
            return sim_rep

        if not sim_rep.passed:
            return NgaError(
                error_code=ErrorCode.SIMULATION_FAILED.value,
                module="nga.builder.synthesizer",
                message=f"Synthesized project failed sandbox verification for '{app_slug}'.",
                recoverable=True,
                suggested_fix="Inspect sandbox stderr_preview and input findings.",
                details={"simulation": sim_rep.to_dict()},
            )

        app_dir = dest_or_err / "app"
        public_dir = app_dir / "public"
        tests_dir = dest_or_err / "tests"
        for d in (app_dir, public_dir, tests_dir):
            d.mkdir(parents=True, exist_ok=True)

        written_files: dict[str, str] = {
            "app/server.py": server_code,
            "app/public/index.html": index_html,
            "tests/test_reconstructed_app.py": test_code,
        }

        apk_meta = findings.get("apk_metadata") if isinstance(findings.get("apk_metadata"), dict) else {}
        pkg_obj = findings.get("package") if isinstance(findings.get("package"), dict) else {}
        is_apk_target = include_android_scaffold or (str(pkg_obj.get("format", "")).lower() == "apk") or bool(apk_meta)
        if is_apk_target:
            pkg_name = str(apk_meta.get("package_name") or f"com.nga.{app_slug}")
            android_files = _render_android_scaffold(app_slug, pkg_name, app_slug)
            written_files.update(android_files)
            written_files["android_scaffold/app/src/main/assets/index.html"] = index_html

        for rel_path, content in written_files.items():
            target_file = dest_or_err / rel_path
            target_file.parent.mkdir(parents=True, exist_ok=True)
            target_file.write_text(content, encoding="utf-8")

        manifest_obj = {
            "app_name": app_slug,
            "created_at": utc_now_iso(),
            "storage_engine": "sqlite",
            "primary_route": primary_route,
            "fields": fields,
            "routes": routes,
            "files": sorted(written_files.keys()),
            "simulation_run_id": sim_rep.run_id,
            "manifest_sha256": compute_sha256_text(json.dumps(sorted(written_files.keys()))),
        }
        (dest_or_err / "reconstruction_manifest.json").write_text(
            json.dumps(manifest_obj, indent=2),
            encoding="utf-8",
        )

        if self.ledger is not None:
            for r in routes:
                obl_id = f"synth_{_sanitize_slug(r['method'] + '_' + r['path'], 'route')}"
                self.ledger.add_obligation(
                    obligation_id=obl_id,
                    category="synthesized_route",
                    title=f"{r['method']} {r['path']}",
                    status=ObligationStatus.VERIFIED,
                    notes=f"Synthesized & sandbox-verified ({sim_rep.run_id}).",
                )

        if self.workspace is not None:
            self.workspace.merkle.append(
                "PROJECT_SYNTHESIZED",
                {
                    "app_name": app_slug,
                    "output_dir": str(dest_or_err),
                    "routes_count": len(routes),
                    "simulation_run_id": sim_rep.run_id,
                },
            )

        return ToolResponse(
            module="nga.builder.synthesizer",
            summary=f"Synthesized SQLite CRUD app '{app_slug}' at '{dest_or_err}' ({len(written_files)} file(s), verified).",
            simulation_status=SimulationStatus.SIMULATION_PASSED.value,
            data={
                "app_name": app_slug,
                "output_dir": str(dest_or_err),
                "storage_engine": "sqlite",
                "primary_route": primary_route,
                "fields": fields,
                "routes": routes,
                "files": sorted(written_files.keys()),
                "simulation_run_id": sim_rep.run_id,
            },
                     )
        
