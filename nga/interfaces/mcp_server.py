"""Model Context Protocol (MCP) JSON-RPC 2.0 stdio server for NextGen-Anything (`nga`)."""

from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any

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
from nga.core.security import DEFAULT_MAX_OUTPUT_CHARS, apply_output_budget, redact_secrets
from nga.core.workspace import NgaWorkspace
from nga.runtime.simulator import SimulationGate

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "nextgen-anything", "version": "0.2.0"}

TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "name": "nga_doctor",
        "description": "Inspect host OS, Python runtime, SQLite/FTS5, workspace health, and available CLI tools.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "nga_inspect",
        "description": "Inspect a local web/JS, HAR, archive/APK, or binary target safely inside base_root.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "kind": {"type": "string", "enum": ["web", "har", "archive", "binary"]},
                "target": {"type": "string"},
            },
            "required": ["kind", "target"],
        },
    },
    {
        "name": "nga_live_inspect",
        "description": "Fetch and inspect a live HTTP/HTTPS web URL safely with size and output budgets.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "nga_simulate",
        "description": "Execute Python code inside the isolated sandbox simulation gate with AST guards.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "code": {"type": "string"},
                "smoke": {"type": "string", "default": ""},
                "label": {"type": "string", "default": "mcp_snippet"},
            },
            "required": ["code"],
        },
    },
    {
        "name": "nga_synthesize",
        "description": "Synthesize and sandbox-verify a multi-file SQLite CRUD project from findings and custom features.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "app_name": {"type": "string", "default": "reconstructed_app"},
                "findings": {"type": "object"},
                "output_dir": {"type": "string", "default": "synthesized_out"},
                "custom_prompt": {"type": "string", "default": ""},
                "include_android_scaffold": {"type": "boolean", "default": False},
            },
            "required": ["findings"],
        },
    },
    {
        "name": "nga_rebuild",
        "description": "One-command pipeline: inspect target -> synthesize SQLite CRUD app (+ Android scaffold for APK) -> sandbox verify -> sync ledger.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "kind": {"type": "string", "enum": ["web", "har", "archive", "binary"]},
                "target": {"type": "string"},
                "app_name": {"type": "string", "default": ""},
                "output_dir": {"type": "string", "default": "rebuilt_app"},
                "custom_prompt": {"type": "string", "default": ""},
            },
            "required": ["kind", "target"],
        },
    },
    {
        "name": "nga_agent_turn",
        "description": "Run an autonomous AAIRE intent turn with memory vault recall, universal LLM (optional), and sandbox gate.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "prompt": {"type": "string"},
                "candidate_code": {"type": "string", "default": ""},
                "target_label": {"type": "string", "default": "mcp_agent"},
                "target_kind": {"type": "string", "default": "web"},
            },
            "required": ["prompt"],
        },
    },
    {
        "name": "nga_memory_store",
        "description": "Store a deduplicated, secret-redacted note inside the SQLite FTS5 memory vault.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "body": {"type": "string"},
                "namespace": {"type": "string", "default": "agent_core"},
                "tags": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["title", "body"],
        },
    },
    {
        "name": "nga_memory_retrieve",
        "description": "Retrieve ranked memories from the SQLite FTS5 memory vault.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "namespace": {"type": "string"},
                "limit": {"type": "integer", "default": 5},
            },
            "required": ["query"],
        },
    },
    {
        "name": "nga_ledger_list",
        "description": "List tracked obligations and current verification coverage percentage.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "nga_ledger_add",
        "description": "Add a new obligation record to the coverage ledger.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "obligation_id": {"type": "string"},
                "category": {"type": "string", "default": "endpoint"},
                "title": {"type": "string"},
                "status": {
                    "type": "string",
                    "enum": [s.value for s in ObligationStatus],
                    "default": ObligationStatus.PENDING.value,
                },
            },
            "required": ["obligation_id"],
        },
    },
    {
        "name": "nga_ledger_update",
        "description": "Update the verification status of an existing obligation by ID or handle.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "obligation_id": {"type": "string"},
                "status": {"type": "string", "enum": [s.value for s in ObligationStatus]},
            },
            "required": ["obligation_id", "status"],
        },
    },
    {
        "name": "nga_brief",
        "description": "Generate a deterministic clean-room architecture and technology blueprint for a target.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "label": {"type": "string"},
                "kind": {"type": "string", "default": "web"},
                "custom_requirements": {"type": "string", "default": ""},
            },
            "required": ["label"],
        },
    },
]


def _jsonrpc_result(req_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _jsonrpc_error(req_id: Any, code: int, message: str, data: Any = None) -> dict[str, Any]:
    err: dict[str, Any] = {"code": code, "message": redact_secrets(message)}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": req_id, "error": err}


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


def _flatten_inspection_findings(inspected: ToolResponse) -> dict[str, Any]:
    """Merge top-level and nested analyzer payloads so synthesizer sees routes, forms, endpoints & APK metadata."""
    base = dict(inspected.data) if isinstance(inspected.data, dict) else {}
    for nested_key in ("analysis", "package", "metadata"):
        nested = base.get(nested_key)
        if isinstance(nested, dict):
            for k, v in nested.items():
                if k not in base or not base[k]:
                    base[k] = v
    return base


class NgaMcpServer:
    """Stateful MCP JSON-RPC 2.0 dispatcher wired to all nga subsystems."""

    def __init__(
        self,
        project_name: str = "default",
        base_root: Path | str | None = None,
        max_output_chars: int = DEFAULT_MAX_OUTPUT_CHARS,
        workspace_base_dir: Path | str | None = None,
        llm_engine: UniversalLlmEngine | None = None,
    ) -> None:
        self.base_root = Path(base_root).resolve() if base_root is not None else Path.cwd().resolve()
        self.max_output_chars = max(512, int(max_output_chars))
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

    def call_tool(self, tool_name: str, arguments: dict[str, Any] | None = None) -> tuple[dict[str, Any], bool]:
        """Invoke a registered MCP tool and return (payload_dict, is_error)."""
        args = arguments if isinstance(arguments, dict) else {}
        outcome: ToolResponse | NgaError | dict[str, Any]

        try:
            if tool_name == "nga_doctor":
                outcome = run_environment_doctor(workspace_root=self.workspace.root)
            elif tool_name == "nga_inspect":
                kind = str(args.get("kind", "")).strip()
                target = str(args.get("target", "")).strip()
                if kind not in {"web", "har", "archive", "binary"} or not target:
                    outcome = NgaError(
                        error_code=ErrorCode.INVALID_INPUT.value,
                        module="nga.interfaces.mcp_server",
                        message="nga_inspect requires valid 'kind' and non-empty 'target'.",
                        recoverable=True,
                    )
                else:
                    outcome = _run_target_inspection(kind, target, self.base_root, self.cache, self.handles)
            elif tool_name == "nga_live_inspect":
                url = str(args.get("url", "")).strip()
                if not url:
                    outcome = NgaError(
                        error_code=ErrorCode.INVALID_INPUT.value,
                        module="nga.interfaces.mcp_server",
                        message="nga_live_inspect requires non-empty 'url'.",
                        recoverable=True,
                    )
                else:
                    outcome = inspect_live_web_url(url=url, cache=self.cache, handles=self.handles)
            elif tool_name == "nga_simulate":
                rep = self.simulator.simulate_crafted_python(
                    code=str(args.get("code", "")),
                    smoke_assertions_code=str(args.get("smoke", "")),
                    target_label=str(args.get("label", "mcp_snippet")),
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
            elif tool_name == "nga_synthesize":
                findings = args.get("findings")
                if not isinstance(findings, dict):
                    outcome = NgaError(
                        error_code=ErrorCode.INVALID_INPUT.value,
                        module="nga.interfaces.mcp_server",
                        message="nga_synthesize requires 'findings' JSON object.",
                        recoverable=True,
                    )
                else:
                    outcome = self.synthesizer.synthesize_project(
                        app_name=str(args.get("app_name", "reconstructed_app")),
                        findings=findings,
                        output_dir=str(args.get("output_dir", "synthesized_out")),
                        base_root=self.base_root,
                        custom_prompt=str(args.get("custom_prompt", "")),
                        include_android_scaffold=bool(args.get("include_android_scaffold", False)),
                    )
            elif tool_name == "nga_rebuild":
                kind = str(args.get("kind", "")).strip()
                target = str(args.get("target", "")).strip()
                if kind not in {"web", "har", "archive", "binary"} or not target:
                    outcome = NgaError(
                        error_code=ErrorCode.INVALID_INPUT.value,
                        module="nga.interfaces.mcp_server",
                        message="nga_rebuild requires valid 'kind' and non-empty 'target'.",
                        recoverable=True,
                    )
                else:
                    inspected = _run_target_inspection(kind, target, self.base_root, self.cache, self.handles)
                    if isinstance(inspected, NgaError):
                        outcome = inspected
                    else:
                        findings = _flatten_inspection_findings(inspected)
                        app_name = str(args.get("app_name", "")).strip() or Path(target).stem or "reconstructed_app"
                        synth_res = self.synthesizer.synthesize_project(
                            app_name=app_name,
                            findings=findings,
                            output_dir=str(args.get("output_dir", "rebuilt_app")),
                            base_root=self.base_root,
                            custom_prompt=str(args.get("custom_prompt", "")),
                            include_android_scaffold=(kind == "archive"),
                        )
                        if isinstance(synth_res, NgaError):
                            outcome = synth_res
                        else:
                            outcome = ToolResponse(
                                module="nga.interfaces.mcp_server",
                                summary=f"Rebuild complete: {inspected.summary} -> {synth_res.summary}",
                                simulation_status=synth_res.simulation_status,
                                data={"inspection_summary": inspected.summary, "synthesis": synth_res.data},
                            )
            elif tool_name == "nga_agent_turn":
                outcome = self.agent.run_turn(
                    prompt=str(args.get("prompt", "")),
                    candidate_code=str(args.get("candidate_code", "")),
                    target_label=str(args.get("target_label", "mcp_agent")),
                    target_kind=str(args.get("target_kind", "web")),
                )
            elif tool_name == "nga_memory_store":
                raw_tags = args.get("tags")
                tags = [str(t) for t in raw_tags] if isinstance(raw_tags, list) else []
                stored = self.vault.store(
                    title=str(args.get("title", "")),
                    body=str(args.get("body", "")),
                    namespace=str(args.get("namespace", self.agent.namespace)),
                    tags=tags,
                    source="mcp",
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
            elif tool_name == "nga_memory_retrieve":
                ns_val = args.get("namespace")
                ns = str(ns_val).strip() if isinstance(ns_val, str) and ns_val.strip() else None
                try:
                    limit = max(1, min(50, int(args.get("limit", 5) or 5)))
                except (TypeError, ValueError):
                    limit = 5
                hits = self.vault.retrieve(str(args.get("query", "")), namespace=ns, limit=limit)
                outcome = ToolResponse(
                    module="nga.aaire.memory_vault",
                    summary=f"Retrieved {len(hits)} memory record(s).",
                    data={"hits": hits, "count": len(hits)},
                )
            elif tool_name == "nga_ledger_list":
                listing = self.ledger.list_obligations()
                outcome = ToolResponse(
                    module="nga.core.ledger",
                    summary=f"Ledger coverage: {listing['coverage']['verified_percent']}%.",
                    data=listing,
                )
            elif tool_name == "nga_ledger_add":
                oid = str(args.get("obligation_id", "")).strip()
                added = self.ledger.add_obligation(
                    obligation_id=oid,
                    category=str(args.get("category", "endpoint")),
                    title=str(args.get("title", "")).strip() or oid,
                    status=str(args.get("status", ObligationStatus.PENDING.value)),
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
            elif tool_name == "nga_ledger_update":
                upd = self.ledger.update_status(
                    str(args.get("obligation_id", "")),
                    str(args.get("status", ObligationStatus.PENDING.value)),
                )
                outcome = (
                    upd
                    if isinstance(upd, NgaError)
                    else ToolResponse(
                        module="nga.core.ledger",
                        summary=f"Updated obligation #{upd.handle} to {upd.status.value}.",
                        data={"obligation": upd.to_dict()},
                    )
                )
            elif tool_name == "nga_brief":
                label = str(args.get("label", "")).strip()
                if not label:
                    outcome = NgaError(
                        error_code=ErrorCode.INVALID_INPUT.value,
                        module="nga.interfaces.mcp_server",
                        message="nga_brief requires non-empty 'label'.",
                        recoverable=True,
                    )
                else:
                    outcome = generate_architecture_brief(
                        target_label=label,
                        target_kind=str(args.get("kind", "web")),
                        custom_requirements=str(args.get("custom_requirements", "")),
                    )
            else:
                outcome = NgaError(
                    error_code=ErrorCode.INVALID_INPUT.value,
                    module="nga.interfaces.mcp_server",
                    message=f"Unknown MCP tool: {tool_name}",
                    recoverable=True,
                )
        except Exception as exc:
            err = NgaError(
                error_code=ErrorCode.INTERNAL_ERROR.value,
                module="nga.interfaces.mcp_server",
                message=redact_secrets(f"Unhandled error in MCP tool '{tool_name}': {exc}"),
                recoverable=True,
            )
            return err.to_dict(), True

        if isinstance(outcome, NgaError):
            return outcome.to_dict(), True
        if isinstance(outcome, ToolResponse):
            return outcome.to_dict(), (not bool(outcome.ok))
        return outcome, False

    def handle_message(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """Process a single decoded JSON-RPC 2.0 request object."""
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            return _jsonrpc_error(None, -32600, "Invalid JSON-RPC 2.0 request.")

        has_id = "id" in message and message.get("id") is not None
        req_id = message.get("id")
        method = str(message.get("method", "")).strip()
        params = message.get("params") if isinstance(message.get("params"), dict) else {}

        if not method:
            return _jsonrpc_error(req_id if has_id else None, -32600, "Request missing method name.")

        if not has_id and method.startswith("notifications/"):
            return None

        if method == "ping":
            return _jsonrpc_result(req_id, {"ok": True})

        if method == "initialize":
            return _jsonrpc_result(
                req_id,
                {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": SERVER_INFO,
                },
            )

        if method == "tools/list":
            return _jsonrpc_result(req_id, {"tools": TOOL_DEFINITIONS})

        if method == "tools/call":
            tool_name = str(params.get("name", "")).strip()
            tool_args = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
            if not tool_name:
                return _jsonrpc_error(req_id, -32602, "tools/call requires 'name'.")
            payload, is_err = self.call_tool(tool_name, tool_args)
            serialized = redact_secrets(json.dumps(payload, indent=2, default=str))
            budgeted = apply_output_budget(serialized, max_chars=self.max_output_chars, offset=0)
            return _jsonrpc_result(
                req_id,
                {
                    "content": [{"type": "text", "text": budgeted["content"]}],
                    "isError": is_err,
                },
            )

        return _jsonrpc_error(req_id if has_id else None, -32601, f"Method not found: {method}")

    def handle_rpc(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """Compatibility alias for JSON-RPC callers invoking `handle_rpc`."""
        return self.handle_message(message)


NgaMcpDispatcher = NgaMcpServer


def run_mcp_stdio_server(
    project_name: str = "default",
    base_root: Path | str | None = None,
    workspace_base_dir: Path | str | None = None,
) -> int:
    """Run newline-delimited JSON-RPC 2.0 MCP server over stdin/stdout."""
    server = NgaMcpServer(
        project_name=project_name,
        base_root=base_root,
        workspace_base_dir=workspace_base_dir,
    )
    try:
        for raw_line in sys.stdin:
            line = raw_line.strip()
            if not line:
                continue
            try:
                decoded = json.loads(line)
            except json.JSONDecodeError as exc:
                err_resp = _jsonrpc_error(None, -32700, f"Parse error: {exc}")
                sys.stdout.write(json.dumps(err_resp) + "\n")
                sys.stdout.flush()
                continue

            reply = server.handle_message(decoded)
            if reply is not None:
                sys.stdout.write(json.dumps(reply, default=str) + "\n")
                sys.stdout.flush()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(run_mcp_stdio_server())
                    
