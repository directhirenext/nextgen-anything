"""Model Context Protocol (MCP) stdio JSON-RPC server exposing `nga` tools to AI agents."""

from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any

from nga.analyzers.archive_pkg import inspect_archive_package
from nga.analyzers.binary_meta import inspect_binary_target
from nga.analyzers.network_har import inspect_local_har
from nga.analyzers.web_js import inspect_local_web_target
from nga.builder.brief_gen import generate_architecture_brief
from nga.core.cache import NgaCache
from nga.core.contracts import ErrorCode, NgaError, ToolResponse
from nga.core.doctor import run_environment_doctor
from nga.core.ledger import ObligationLedger
from nga.core.workspace import NgaWorkspace
from nga.runtime.simulator import SimulationGate

MCP_TOOLS: list[dict[str, Any]] = [
    {
        "name": "nga_doctor",
        "description": "Check host OS, Python version, workspace health, and optional toolchains.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "nga_inspect_web",
        "description": "Inspect a local HTML/JS file for routes, API calls, forms, and sourcemaps.",
        "inputSchema": {
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
        },
    },
    {
        "name": "nga_inspect_har",
        "description": "Inspect a local HAR network capture and extract sanitized endpoints & schemas.",
        "inputSchema": {
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
        },
    },
    {
        "name": "nga_inspect_archive",
        "description": "Safely inspect a local .zip, .apk, .jar, or .asar package with Zip-Slip guards.",
        "inputSchema": {
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
        },
    },
    {
        "name": "nga_inspect_binary",
        "description": "Inspect ELF/PE/Mach-O/WASM binary headers and redacted printable strings.",
        "inputSchema": {
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
        },
    },
    {
        "name": "nga_simulate_python",
        "description": "Simulate candidate Python code inside an isolated sandbox before outputting.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "code": {"type": "string"},
                "smoke_code": {"type": "string"},
                "label": {"type": "string"},
            },
            "required": ["code"],
        },
    },
    {
        "name": "nga_ledger_list",
        "description": "List obligations and reconstruction coverage metrics.",
        "inputSchema": {
            "type": "object",
            "properties": {"status": {"type": "string"}},
        },
    },
    {
        "name": "nga_brief",
        "description": "Generate a clean-room architectural brief for a target application.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "label": {"type": "string"},
                "kind": {"type": "string"},
            },
            "required": ["label"],
        },
    },
]


class NgaMcpDispatcher:
    """Handles MCP JSON-RPC requests cleanly with deterministic error payloads."""

    def __init__(self, project_name: str = "default", base_root: Path | None = None) -> None:
        self.base_root = Path(base_root).resolve() if base_root else Path.cwd().resolve()
        self.ws = NgaWorkspace(project_name=project_name)
        self.cache = NgaCache(self.ws.root / "cache.sqlite")
        self.handles = self.ws.get_handles()
        self.ledger = ObligationLedger(self.ws.root / "ledger.json", handles=self.handles)
        self.simulator = SimulationGate()

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        """Execute a named MCP tool and return a dict payload."""
        args = arguments if isinstance(arguments, dict) else {}
        res: ToolResponse | NgaError

        if name == "nga_doctor":
            res = run_environment_doctor(workspace_root=self.ws.root)
        elif name == "nga_inspect_web":
            res = inspect_local_web_target(str(args.get("target", "")), base_root=self.base_root, cache=self.cache, handles=self.handles)
        elif name == "nga_inspect_har":
            res = inspect_local_har(str(args.get("target", "")), base_root=self.base_root, cache=self.cache, handles=self.handles)
        elif name == "nga_inspect_archive":
            res = inspect_archive_package(str(args.get("target", "")), base_root=self.base_root, cache=self.cache, handles=self.handles)
        elif name == "nga_inspect_binary":
            res = inspect_binary_target(str(args.get("target", "")), base_root=self.base_root, cache=self.cache, handles=self.handles)
        elif name == "nga_simulate_python":
            rep = self.simulator.simulate_crafted_python(
                code=str(args.get("code", "")),
                smoke_assertions_code=str(args.get("smoke_code", "")),
                target_label=str(args.get("label", "mcp_snippet")),
            )
            if isinstance(rep, NgaError):
                res = rep
            else:
                res = ToolResponse(
                    module="nga.runtime.simulator",
                    summary=f"Sandbox simulation {rep.status.value} ({rep.duration_ms}ms).",
                    simulation_status=rep.status.value,
                    data={"simulation": rep.to_dict()},
                )
        elif name == "nga_ledger_list":
            listing = self.ledger.list_obligations(status_filter=str(args.get("status", "") or "") or None)
            res = ToolResponse(
                module="nga.core.ledger",
                summary=f"Obligations verified: {listing['coverage']['verified_percent']}%.",
                data=listing,
            )
        elif name == "nga_brief":
            res = generate_architecture_brief(
                target_label=str(args.get("label", "target_app")),
                target_kind=str(args.get("kind", "web")),
            )
        else:
            res = NgaError(
                error_code=ErrorCode.NOT_FOUND.value,
                module="nga.interfaces.mcp_server",
                message=f"Unknown MCP tool: {name}",
                recoverable=True,
                suggested_fix="Call tools/list to inspect supported `nga_*` tool names.",
            )

        return res.to_dict()

    def handle_rpc(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """Process a single JSON-RPC 2.0 request dictionary."""
        req_id = message.get("id")
        method = str(message.get("method", "")).strip()
        params = message.get("params") if isinstance(message.get("params"), dict) else {}

        # Notifications without id do not require a JSON-RPC response
        if req_id is None and method.startswith("notifications/"):
            return None

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {"name": "nextgen-anything-mcp", "version": "0.1.0"},
                    "capabilities": {"tools": {}},
                },
            }

        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": MCP_TOOLS},
            }

        if method == "tools/call":
            tool_name = str(params.get("name", "")).strip()
            tool_args = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
            payload = self.call_tool(tool_name, tool_args)
            is_err = not bool(payload.get("ok", False))
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "isError": is_err,
                    "content": [{"type": "text", "text": json.dumps(payload, indent=2, default=str)}],
                },
            }

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }


def serve_mcp_stdio(project_name: str = "default", base_root: Path | None = None) -> None:
    """Run line-delimited JSON-RPC loop over stdin/stdout."""
    dispatcher = NgaMcpDispatcher(project_name=project_name, base_root=base_root)
    for line in sys.stdin:
        raw = line.strip()
        if not raw:
            continue
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError as exc:
            err_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {exc}"},
            }
            sys.stdout.write(json.dumps(err_resp) + "\n")
            sys.stdout.flush()
            continue

        if not isinstance(msg, dict):
            continue
        resp = dispatcher.handle_rpc(msg)
        if resp is not None:
            sys.stdout.write(json.dumps(resp, default=str) + "\n")
            sys.stdout.flush()
