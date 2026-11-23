"""Tests for web/JS, HAR, archive Zip-Slip & ASAR, binary inspection, mock server, DAG & MCP."""

from __future__ import annotations

import json
from pathlib import Path
import struct
import tempfile
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import zipfile

from nga.analyzers.archive_pkg import inspect_archive_package
from nga.analyzers.binary_meta import inspect_binary_target
from nga.analyzers.network_har import inspect_local_har
from nga.analyzers.web_js import inspect_local_web_target
from nga.builder.orchestrator import DagNode, WorkflowOrchestrator
from nga.core.contracts import ErrorCode, NgaError, ToolResponse
from nga.interfaces.mcp_server import NgaMcpDispatcher
from nga.runtime.standin_server import StandInMockServer, build_routes_from_har_analysis


def _make_sample_asar(asar_path: Path) -> None:
    """Create a valid minimal Electron ASAR archive with a safe file entry."""
    header_json = json.dumps({"files": {"index.js": {"size": 18, "offset": "0"}}}).encode("utf-8")
    pad = (4 - (len(header_json) % 4)) % 4
    padded_json = header_json + (b"\x00" * pad)
    header_payload_size = len(padded_json) + 8
    header_pickle_size = header_payload_size + 4
    prefix = struct.pack("<IIII", 4, header_pickle_size, header_payload_size, len(padded_json))
    asar_path.write_bytes(prefix + padded_json + b"console.log('asar');")


class AnalyzersAndMockTests(unittest.TestCase):
    def test_web_har_archive_asar_and_binary_analyzers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            # 1. HTML + JS + Form
            html_file = root / "app.html"
            html_file.write_text(
                '<html><head><title>Test</title></head><body>'
                '<form action="/api/v1/jobs" method="POST"><input name="role" /></form>'
                '<script>fetch("/api/v1/jobs"); localStorage.setItem("theme", "dark");</script>'
                "</body></html>",
                encoding="utf-8",
            )
            web_res = inspect_local_web_target("app.html", base_root=root)
            self.assertNotIsInstance(web_res, NgaError)
            assert not isinstance(web_res, NgaError)
            self.assertGreaterEqual(len(web_res.data.get("forms", [])), 1)
            route_paths = [r.get("path") for r in web_res.data.get("routes", []) if isinstance(r, dict)]
            self.assertIn("/api/v1/jobs", route_paths)

            # 2. HAR with mock_routes & response JSON
            har_file = root / "capture.har"
            har_payload = {
                "log": {
                    "entries": [
                        {
                            "request": {"method": "GET", "url": "https://example.test/api/status", "headers": []},
                            "response": {
                                "status": 200,
                                "headers": [{"name": "Content-Type", "value": "application/json"}],
                                "content": {"mimeType": "application/json", "text": '{"status":"healthy"}'},
                            },
                        }
                    ]
                }
            }
            har_file.write_text(json.dumps(har_payload), encoding="utf-8")
            har_res = inspect_local_har("capture.har", base_root=root)
            self.assertNotIsInstance(har_res, NgaError)
            assert not isinstance(har_res, NgaError)
            self.assertEqual(har_res.data["unique_endpoints"], 1)
            self.assertEqual(len(har_res.data.get("mock_routes", [])), 1)

            # 3. Archive with Zip-Slip entry blocked
            zip_file = root / "sample.zip"
            with zipfile.ZipFile(zip_file, "w") as zf:
                zf.writestr("safe/readme.txt", "hello")
                zf.writestr("../escape.txt", "evil")
            pkg_res = inspect_archive_package("sample.zip", base_root=root)
            self.assertNotIsInstance(pkg_res, NgaError)
            assert not isinstance(pkg_res, NgaError)
            self.assertGreaterEqual(pkg_res.data["package"]["unsafe_entries_blocked"], 1)

            # 4. ASAR archive inspection
            asar_file = root / "sample.asar"
            _make_sample_asar(asar_file)
            asar_res = inspect_archive_package("sample.asar", base_root=root)
            self.assertNotIsInstance(asar_res, NgaError)
            assert not isinstance(asar_res, NgaError)
            self.assertEqual(asar_res.data["package"]["format"], "asar")
            self.assertEqual(asar_res.data["package"]["safe_entries_indexed"], 1)

            # 5. ELF header binary
            elf_file = root / "sample.elf"
            elf_file.write_bytes(
                b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 12 + b"\xb7\x00" + b"\x00" * 20 + b"NGA_TEST_STRING"
            )
            bin_res = inspect_binary_target("sample.elf", base_root=root)
            self.assertNotIsInstance(bin_res, NgaError)
            assert not isinstance(bin_res, NgaError)
            self.assertEqual(bin_res.data["metadata"]["format_info"]["format"], "elf")

    def test_standin_server_dag_and_mcp_isolated(self) -> None:
        routes = build_routes_from_har_analysis(
            {
                "mock_routes": [
                    {
                        "method": "GET",
                        "path": "/api/ping",
                        "status": 200,
                        "content_type": "application/json",
                        "headers": {},
                        "body_preview": '{"pong":true}',
                        "parsed_json": {"pong": True},
                    }
                ]
            }
        )
        server = StandInMockServer(routes=routes, host="127.0.0.1", port=0)
        started = server.start()
        self.assertNotIsInstance(started, NgaError)
        assert not isinstance(started, NgaError)
        try:
            url = f"{started.data['url']}/api/ping"
            with urlopen(url, timeout=3) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                self.assertTrue(body.get("pong"))

            # Wrong HTTP method on existing route returns 405
            req_del = Request(url, method="DELETE")
            with self.assertRaises(HTTPError) as ctx_405:
                urlopen(req_del, timeout=3)
            self.assertEqual(ctx_405.exception.code, 405)

            # Unknown path returns 404
            with self.assertRaises(HTTPError) as ctx_404:
                urlopen(f"{started.data['url']}/api/missing", timeout=3)
            self.assertEqual(ctx_404.exception.code, 404)
        finally:
            server.stop()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            orch = WorkflowOrchestrator(base_dir=root / "ws")

            # Missing handler must fail explicitly (no fake completed_dry)
            dry_plan = orch.build_default_plan("sample.html", "web")
            self.assertNotIsInstance(dry_plan, NgaError)
            assert isinstance(dry_plan, list)
            missing_res = orch.run_plan(dry_plan)
            self.assertIsInstance(missing_res, NgaError)
            assert isinstance(missing_res, NgaError)
            self.assertEqual(missing_res.error_code, ErrorCode.TOOL_UNAVAILABLE.value)

            # Real data passing between dependent DAG nodes
            chain_nodes = [
                DagNode(node_id="step1", title="Produce value", action="produce", depends_on=[]),
                DagNode(node_id="step2", title="Consume value", action="consume", depends_on=["step1"]),
            ]
            chain_res = orch.run_plan(
                chain_nodes,
                runner_map={
                    "produce": lambda _p: ToolResponse(module="test", summary="ok", data={"val": 42}),
                    "consume": lambda p: ToolResponse(
                        module="test",
                        summary="consumed",
                        data={"received_val": p.get("previous_output", {}).get("data", {}).get("val")},
                    ),
                },
            )
            self.assertNotIsInstance(chain_res, NgaError)
            assert not isinstance(chain_res, NgaError)
            self.assertEqual(chain_res.data["node_outputs"]["step2"]["data"]["received_val"], 42)

            mcp = NgaMcpDispatcher(
                project_name="mcp_test",
                base_root=root,
                workspace_base_dir=root / "ws",
            )
            tools_rpc = mcp.handle_rpc({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
            self.assertIsNotNone(tools_rpc)
            assert tools_rpc is not None
            self.assertGreater(len(tools_rpc["result"]["tools"]), 0)


if __name__ == "__main__":
    unittest.main()
    
