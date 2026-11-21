"""Tests for web/JS, HAR, archive Zip-Slip safety, binary inspection, mock server, DAG & MCP."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from urllib.request import urlopen
import zipfile

from nga.analyzers.archive_pkg import inspect_archive_package
from nga.analyzers.binary_meta import inspect_binary_target
from nga.analyzers.network_har import inspect_local_har
from nga.analyzers.web_js import inspect_local_web_target
from nga.builder.orchestrator import WorkflowOrchestrator
from nga.core.contracts import NgaError
from nga.interfaces.mcp_server import NgaMcpDispatcher
from nga.runtime.standin_server import StandInMockServer, build_routes_from_har_analysis


class AnalyzersAndMockTests(unittest.TestCase):
    def test_web_har_archive_and_binary_analyzers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            # 1. HTML + JS
            html_file = root / "app.html"
            html_file.write_text(
                '<html><head><title>Test</title></head><body>'
                '<script>fetch("/api/v1/jobs"); localStorage.setItem("theme", "dark");</script>'
                "</body></html>",
                encoding="utf-8",
            )
            web_res = inspect_local_web_target("app.html", base_root=root)
            self.assertNotIsInstance(web_res, NgaError)

            # 2. HAR
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

            # 3. Archive with Zip-Slip entry blocked
            zip_file = root / "sample.zip"
            with zipfile.ZipFile(zip_file, "w") as zf:
                zf.writestr("safe/readme.txt", "hello")
                zf.writestr("../escape.txt", "evil")
            pkg_res = inspect_archive_package("sample.zip", base_root=root)
            self.assertNotIsInstance(pkg_res, NgaError)
            assert not isinstance(pkg_res, NgaError)
            self.assertGreaterEqual(pkg_res.data["package"]["unsafe_entries_blocked"], 1)

            # 4. ELF header binary
            elf_file = root / "sample.elf"
            elf_file.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 12 + b"\xb7\x00" + b"\x00" * 20 + b"NGA_TEST_STRING")
            bin_res = inspect_binary_target("sample.elf", base_root=root)
            self.assertNotIsInstance(bin_res, NgaError)
            assert not isinstance(bin_res, NgaError)
            self.assertEqual(bin_res.data["metadata"]["format_info"]["format"], "elf")

    def test_standin_server_dag_and_mcp(self) -> None:
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
        finally:
            server.stop()

        with tempfile.TemporaryDirectory() as tmp:
            orch = WorkflowOrchestrator()
            plan = orch.build_default_plan("sample.html", "web")
            dag_res = orch.run_plan(plan)
            self.assertNotIsInstance(dag_res, NgaError)

            mcp = NgaMcpDispatcher(project_name="mcp_test", base_root=Path(tmp))
            tools_rpc = mcp.handle_rpc({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
            self.assertIsNotNone(tools_rpc)
            assert tools_rpc is not None
            self.assertGreater(len(tools_rpc["result"]["tools"]), 0)


if __name__ == "__main__":
    unittest.main()
  
