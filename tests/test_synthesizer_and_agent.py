"""End-to-end tests for SQLite synthesizer, CLI rebuild/mock, MCP server, Web UI auth, SDK & agent."""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from nga.aaire.intent_agent import AutonomousIntentAgent
from nga.aaire.memory_vault import AaireMemoryVault
from nga.aaire.telegram_bridge import TelegramBotBridge
from nga.builder.synthesizer import AutonomousProjectSynthesizer
from nga.core.contracts import ErrorCode, NgaError, SimulationStatus
from nga.core.ledger import ObligationLedger
from nga.core.workspace import NgaWorkspace
from nga.interfaces.cli import main as cli_main
from nga.interfaces.mcp_server import NgaMcpServer
from nga.interfaces.web_ui import create_web_ui_server, is_allowed_cors_origin
from nga.runtime.sandbox import ExecutionSandbox
from nga.runtime.simulator import SimulationGate
from sdk.python.nga_client import NgaHttpClient


class SynthesizerAndAgentTests(unittest.TestCase):
    def test_synthesizer_generates_and_runs_sqlite_crud_project_with_custom_prompt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = NgaWorkspace(project_name="synth_sqlite_proj", base_dir=root / "ws")
            ledger = ObligationLedger(root / "ledger.json", handles=ws.get_handles())
            sbx = ExecutionSandbox(base_sandbox_dir=root / "sbx", timeout_seconds=15.0)
            sim = SimulationGate(sandbox=sbx)

            synth = AutonomousProjectSynthesizer(simulator=sim, workspace=ws, ledger=ledger)
            findings = {
                "endpoints": [
                    {"method": "GET", "path": "/api/items", "status": 200, "fields": ["name", "qty"]},
                    {"method": "POST", "path": "/api/items", "status": 200, "fields": ["name", "qty"]},
                ]
            }
            res = synth.synthesize_project(
                app_name="InventoryService",
                findings=findings,
                output_dir="out_app",
                base_root=root,
                custom_prompt="Add search query support and clean CRUD lifecycle",
            )
            self.assertNotIsInstance(res, NgaError)
            assert not isinstance(res, NgaError)
            self.assertEqual(res.simulation_status, SimulationStatus.SIMULATION_PASSED.value)
            self.assertEqual(res.data.get("storage_engine"), "sqlite")
            self.assertEqual(res.data.get("primary_route"), "/api/items")

            out_app = root / "out_app"
            self.assertTrue((out_app / "app" / "server.py").is_file())
            self.assertTrue((out_app / "app" / "public" / "index.html").is_file())
            self.assertTrue((out_app / "tests" / "test_reconstructed_app.py").is_file())
            self.assertTrue((out_app / "reconstruction_manifest.json").is_file())

            proc = subprocess.run(
                [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"],
                cwd=str(out_app),
                capture_output=True,
                text=True,
                timeout=25,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, msg=f"Generated tests failed:\n{proc.stdout}\n{proc.stderr}")

    def test_memory_vault_intent_agent_and_telegram_bridge(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            vault = AaireMemoryVault(root / "vault.sqlite")
            stored = vault.store(
                title="Sandbox Policy",
                body="Always verify generated Python code in an isolated sandbox before output.",
                namespace="agent_ns",
                tags=["policy", "sandbox"],
            )
            self.assertNotIsInstance(stored, NgaError)
            hits = vault.retrieve("isolated sandbox verification", namespace="agent_ns", limit=3)
            self.assertGreaterEqual(len(hits), 1)

            sbx = ExecutionSandbox(base_sandbox_dir=root / "sbx", timeout_seconds=10.0)
            sim = SimulationGate(sandbox=sbx)
            agent = AutonomousIntentAgent(vault=vault, simulator=sim, namespace="agent_ns")
            turn = agent.run_turn(
                prompt="Run sandbox check on math helper",
                candidate_code="def double(n):\n    return n * 2\nassert double(4) == 8\nprint('DOUBLE_OK')\n",
                target_label="double_helper",
            )
            self.assertNotIsInstance(turn, NgaError)
            assert not isinstance(turn, NgaError)
            self.assertEqual(turn.simulation_status, SimulationStatus.SIMULATION_PASSED.value)

            bridge = TelegramBotBridge(allowed_chat_ids=[1001], agent=agent, simulator=sim)
            blocked = bridge.process_update(
                {"update_id": 1, "message": {"chat": {"id": 9999}, "text": "/doctor"}}
            )
            self.assertIsInstance(blocked, NgaError)
            assert isinstance(blocked, NgaError)
            self.assertEqual(blocked.error_code, ErrorCode.SANDBOX_VIOLATION.value)

            allowed = bridge.process_update(
                {"update_id": 2, "message": {"chat": {"id": 1001}, "text": "/sim print('TG_OK')"}}
            )
            self.assertNotIsInstance(allowed, NgaError)
            assert not isinstance(allowed, NgaError)
            self.assertIn("TG_OK", allowed.data.get("reply_text", ""))

            doc_cmd = bridge.process_update(
                {"update_id": 3, "message": {"chat": {"id": 1001}, "text": "/doctor"}}
            )
            self.assertNotIsInstance(doc_cmd, NgaError)
            assert not isinstance(doc_cmd, NgaError)
            self.assertNotIn("OS: None", doc_cmd.data.get("reply_text", ""))

    def test_cli_rebuild_and_har_mock_dry_run_isolated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws_dir = root / "ws"
            html_file = root / "sample.html"
            html_file.write_text(
                '<html><body><form action="/api/tasks" method="POST">'
                '<input name="title" /><input name="owner" /></form></body></html>',
                encoding="utf-8",
            )

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli_main(
                    [
                        "--project",
                        "cli_rebuild_test",
                        "--root",
                        str(root),
                        "--workspace-dir",
                        str(ws_dir),
                        "rebuild",
                        "web",
                        "sample.html",
                        "--out",
                        "rebuilt_web",
                    ]
                )
            self.assertEqual(rc, 0, msg=buf.getvalue())
            server_path = root / "rebuilt_web" / "app" / "server.py"
            manifest_path = root / "rebuilt_web" / "reconstruction_manifest.json"
            self.assertTrue(server_path.is_file())
            self.assertTrue(manifest_path.is_file())
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(manifest.get("primary_route"), "/api/tasks")
            self.assertIn("title", manifest.get("fields", []))

            har_payload = {
                "log": {
                    "version": "1.2",
                    "entries": [
                        {
                            "request": {"method": "GET", "url": "https://api.example.test/v1/orders"},
                            "response": {
                                "status": 200,
                                "content": {
                                    "mimeType": "application/json",
                                    "text": '{"orders": [{"id": 1}]}',
                                },
                            },
                        }
                    ],
                }
            }
            (root / "sample.har").write_text(json.dumps(har_payload), encoding="utf-8")

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc_mock = cli_main(
                    [
                        "--project",
                        "cli_mock_test",
                        "--root",
                        str(root),
                        "--workspace-dir",
                        str(ws_dir),
                        "mock",
                        "sample.har",
                        "--dry-run",
                    ]
                )
            self.assertEqual(rc_mock, 0, msg=buf.getvalue())
            parsed_mock = json.loads(buf.getvalue())
            self.assertEqual(parsed_mock["data"]["routes_count"], 1)
            self.assertEqual(parsed_mock["data"]["routes"][0]["body"], '{"orders": [{"id": 1}]}')

    def test_mcp_server_tools_and_rebuild_isolated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.html").write_text(
                '<html><body><form action="/api/notes" method="POST"><input name="body" /></form></body></html>',
                encoding="utf-8",
            )
            server = NgaMcpServer(
                project_name="mcp_e2e_test",
                base_root=root,
                workspace_base_dir=root / "ws",
            )

            init_resp = server.handle_message({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
            assert init_resp is not None
            self.assertIn("protocolVersion", init_resp["result"])

            list_resp = server.handle_message({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
            assert list_resp is not None
            tool_names = {t["name"] for t in list_resp["result"]["tools"]}
            self.assertIn("nga_rebuild", tool_names)
            self.assertIn("nga_agent_turn", tool_names)
            self.assertIn("nga_memory_store", tool_names)

            store_resp = server.handle_message(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "nga_memory_store",
                        "arguments": {"title": "MCP Check", "body": "SQLite CRUD verified via MCP"},
                    },
                }
            )
            assert store_resp is not None
            self.assertFalse(store_resp["result"]["isError"])

            reb_resp = server.handle_message(
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {
                        "name": "nga_rebuild",
                        "arguments": {"kind": "web", "target": "app.html", "output_dir": "mcp_out"},
                    },
                }
            )
            assert reb_resp is not None
            self.assertFalse(reb_resp["result"]["isError"])
            self.assertTrue((root / "mcp_out" / "app" / "server.py").is_file())
            manifest = json.loads((root / "mcp_out" / "reconstruction_manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest.get("primary_route"), "/api/notes")

    def test_web_ui_auth_cors_upload_and_python_sdk_isolated(self) -> None:
        self.assertTrue(is_allowed_cors_origin("http://127.0.0.1:8765"))
        self.assertTrue(is_allowed_cors_origin("http://localhost:3000"))
        self.assertFalse(is_allowed_cors_origin("https://untrusted.example.com"))

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "page.html").write_text(
                '<html><body><form action="/api/ping" method="POST"><input name="msg" /></form></body></html>',
                encoding="utf-8",
            )
            token = "test-secret-token-99"
            httpd = create_web_ui_server(
                host="127.0.0.1",
                port=0,
                project_name="webui_e2e_test",
                base_root=root,
                api_token=token,
                workspace_base_dir=root / "ws",
            )
            port = httpd.server_address[1]
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()
            base_url = f"http://127.0.0.1:{port}"
            try:
                with self.assertRaises(HTTPError) as ctx:
                    urlopen(f"{base_url}/api/doctor", timeout=5)
                self.assertEqual(ctx.exception.code, 401)

                req_doc = Request(
                    f"{base_url}/api/doctor",
                    headers={"X-NGA-Token": token, "Origin": "http://localhost:3000"},
                )
                with urlopen(req_doc, timeout=5) as resp:
                    self.assertEqual(resp.status, 200)
                    self.assertEqual(resp.headers.get("Access-Control-Allow-Origin"), "http://localhost:3000")
                    doc_data = json.loads(resp.read().decode("utf-8"))
                    self.assertTrue(doc_data.get("ok"))

                # Test Python SDK client with token auth + simulate smoke assertion
                sdk = NgaHttpClient(base_url=base_url, timeout=10.0, api_token=token)
                sim_via_sdk = sdk.simulate_python(
                    code="def add_one(x):\n    return x + 1\n",
                    label="sdk_smoke_test",
                    smoke_code="assert add_one(9) == 10\nprint('SDK_SMOKE_OK')\n",
                )
                self.assertTrue(sim_via_sdk.get("ok"), msg=str(sim_via_sdk))
                self.assertIn("SDK_SMOKE_OK", sim_via_sdk["data"]["simulation"]["stdout_preview"])

                req_reb = Request(
                    f"{base_url}/api/rebuild",
                    data=json.dumps({"kind": "web", "target": "page.html", "output_dir": "web_out"}).encode("utf-8"),
                    headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
                    method="POST",
                )
                with urlopen(req_reb, timeout=20) as resp:
                    self.assertEqual(resp.status, 200)
                    reb_data = json.loads(resp.read().decode("utf-8"))
                    self.assertTrue(reb_data.get("ok"))
                self.assertTrue((root / "web_out" / "app" / "server.py").is_file())
            finally:
                httpd.shutdown()
                httpd.server_close()
                thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
            
