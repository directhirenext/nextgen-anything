"""Command-line interface entrypoint for NextGen-Anything (`nga`)."""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import time
from typing import Any
from urllib.parse import urlparse

from nga.aaire.intent_agent import AutonomousIntentAgent
from nga.aaire.memory_vault import AaireMemoryVault
from nga.aaire.telegram_bridge import TelegramBotBridge
from nga.analyzers.archive_pkg import inspect_archive_package
from nga.analyzers.binary_meta import inspect_binary_target
from nga.analyzers.network_har import inspect_local_har
from nga.analyzers.web_js import inspect_local_web_target
from nga.builder.brief_gen import generate_architecture_brief
from nga.builder.synthesizer import AutonomousProjectSynthesizer
from nga.core.cache import NgaCache
from nga.core.contracts import ErrorCode, NgaError, ObligationStatus, ToolResponse
from nga.core.doctor import run_environment_doctor
from nga.core.ledger import ObligationLedger
from nga.core.security import DEFAULT_MAX_OUTPUT_CHARS, apply_output_budget, redact_secrets
from nga.core.workspace import NgaWorkspace
from nga.interfaces.mcp_server import run_mcp_stdio_server
from nga.interfaces.web_ui import run_web_ui_server
from nga.runtime.simulator import SimulationGate


def _emit_payload(payload: dict[str, Any], max_chars: int = DEFAULT_MAX_OUTPUT_CHARS, offset: int = 0) -> None:
    """Serialize output cleanly while enforcing output budgets and redacting secrets."""
    raw = redact_secrets(json.dumps(payload, indent=2, default=str))
    budgeted = apply_output_budget(raw, max_chars=max_chars, offset=offset)
    if budgeted["truncated"]:
        wrapper = {
            "ok": payload.get("ok", True),
            "truncated": True,
            "total_chars": budgeted["total_chars"],
            "offset": budgeted["offset"],
            "next_offset": budgeted["next_offset"],
            "content_slice": budgeted["content"],
        }
        sys.stdout.write(json.dumps(wrapper, indent=2) + "\n")
    else:
        sys.stdout.write(raw + "\n")


def _run_inspection(
    kind: str,
    target: str,
    base_root: Path,
    cache: NgaCache,
    handles: Any,
) -> ToolResponse | NgaError:
    """Dispatch inspection to the matching analyzer module."""
    if kind == "web":
        return inspect_local_web_target(target, base_root=base_root, cache=cache, handles=handles)
    if kind == "har":
        return inspect_local_har(target, base_root=base_root, cache=cache, handles=handles)
    if kind == "archive":
        return inspect_archive_package(target, base_root=base_root, cache=cache, handles=handles)
    return inspect_binary_target(target, base_root=base_root, cache=cache, handles=handles)


def _extract_mock_routes(findings: dict[str, Any]) -> list[dict[str, Any]]:
    """Build normalized mock route entries from HAR inspection data."""
    routes: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for raw in findings.get("mock_routes") or []:
        if not isinstance(raw, dict):
            continue
        method = str(raw.get("method", "GET")).upper().strip() or "GET"
        path = str(raw.get("path", "/")).strip() or "/"
        if not path.startswith("/"):
            path = f"/{path}"
        key = (method, path)
        if key in seen:
            continue
        seen.add(key)
        body = raw.get("parsed_json")
        if body is None:
            body = {"ok": True, "method": method, "path": path, "mock": True}
        routes.append({"method": method, "path": path, "status": int(raw.get("status", 200) or 200), "body": body})

    for ep in findings.get("endpoints") or []:
        if not isinstance(ep, dict):
            continue
        method = str(ep.get("method", "GET")).upper().strip() or "GET"
        path = str(ep.get("path", "/")).strip() or "/"
        if not path.startswith("/"):
            path = f"/{path}"
        key = (method, path)
        if key in seen:
            continue
        seen.add(key)
        routes.append(
            {
                "method": method,
                "path": path,
                "status": int(ep.get("status", 200) or 200),
                "body": {"ok": True, "method": method, "path": path, "schema": ep.get("schema")},
            }
        )

    return routes


def _serve_mock_http(host: str, port: int, routes: list[dict[str, Any]]) -> int:
    """Serve discovered HAR routes over a local threaded HTTP server."""
    route_map: dict[tuple[str, str], tuple[int, Any]] = {
        (r["method"], r["path"]): (int(r["status"]), r["body"]) for r in routes
    }

    class _MockHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return

        def _send_json(self, status: int, payload: Any) -> None:
            encoded = json.dumps(payload, indent=2, default=str).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def _handle(self, method: str) -> None:
            req_path = urlparse(self.path).path or "/"
            if method == "GET" and req_path == "/__health":
                self._send_json(200, {"ok": True, "mode": "har_mock", "routes_count": len(route_map)})
                return
            hit = route_map.get((method, req_path))
            if hit is not None:
                self._send_json(hit[0], hit[1])
                return
            self._send_json(404, {"ok": False, "error": "Not Found", "method": method, "path": req_path})

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

    httpd = ThreadingHTTPServer((host, port), _MockHandler)
    sys.stdout.write(
        json.dumps({"ok": True, "listening": f"http://{host}:{port}", "routes_count": len(route_map)}) + "\n"
    )
    sys.stdout.flush()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Create the argument parser for `nga` CLI commands."""
    parser = argparse.ArgumentParser(
        prog="nga",
        description="NextGen-Anything: Cross-OS inspection, sandbox simulation, synthesis, agent & mock runtime.",
    )
    parser.add_argument("--project", default="default", help="Workspace project name.")
    parser.add_argument("--root", default=".", help="Base root directory for target files.")
    parser.add_argument("--max-chars", type=int, default=DEFAULT_MAX_OUTPUT_CHARS, help="Max output characters.")
    parser.add_argument("--offset", type=int, default=0, help="Character offset for paginated output.")

    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("doctor", help="Inspect host OS, Python version, and optional CLI tools.")

    p_inspect = sub.add_parser("inspect", help="Inspect a local web/JS, HAR, archive, or binary target.")
    p_inspect.add_argument("kind", choices=["web", "har", "archive", "binary"], help="Target category.")
    p_inspect.add_argument("target", help="Target path relative to --root.")

    p_rebuild = sub.add_parser(
        "rebuild",
        help="One-command inspect + SQLite CRUD synthesis + sandbox verification + ledger sync.",
    )
    p_rebuild.add_argument("kind", choices=["web", "har", "archive", "binary"], help="Target category.")
    p_rebuild.add_argument("target", help="Target path relative to --root.")
    p_rebuild.add_argument("--name", default="", help="Optional application name.")
    p_rebuild.add_argument("--out", default="rebuilt_app", help="Output directory relative to --root.")

    p_mock = sub.add_parser("mock", help="Start a local HTTP mock server from a captured HAR file.")
    p_mock.add_argument("target", help="HAR file path relative to --root.")
    p_mock.add_argument("--host", default="127.0.0.1", help="Bind host.")
    p_mock.add_argument("--port", type=int, default=8090, help="Bind port.")
    p_mock.add_argument("--dry-run", action="store_true", help="Parse and print mock routes without binding a port.")

    p_sim = sub.add_parser("simulate", help="Run Python code inside the isolated sandbox simulation gate.")
    p_sim.add_argument("code", help="Python code snippet to simulate.")
    p_sim.add_argument("--smoke", default="", help="Optional smoke-test assertions code.")
    p_sim.add_argument("--label", default="cli_snippet", help="Target label.")

    p_synth = sub.add_parser("synthesize", help="Synthesize and sandbox-verify a multi-file app from JSON findings.")
    p_synth.add_argument("--name", default="reconstructed_app", help="Application name.")
    p_synth.add_argument("--findings-json", default="{}", help="JSON object of inspection findings.")
    p_synth.add_argument("--out", default="synthesized_out", help="Output directory relative to --root.")

    p_agent = sub.add_parser("agent", help="Run an autonomous agent turn with memory vault and sandbox gate.")
    p_agent.add_argument("prompt", help="Goal or instruction for the agent.")
    p_agent.add_argument("--code", default="", help="Optional Python candidate code.")
    p_agent.add_argument("--label", default="agent_cli", help="Target label.")

    p_tg = sub.add_parser("telegram", help="Poll Telegram updates once or run continuously with --loop.")
    p_tg.add_argument("--limit", type=int, default=10, help="Maximum updates per poll.")
    p_tg.add_argument("--loop", action="store_true", help="Run continuous polling loop until interrupted.")
    p_tg.add_argument("--interval", type=float, default=3.0, help="Seconds between poll cycles in --loop mode.")
    p_tg.add_argument("--max-cycles", type=int, default=0, help="Stop after N cycles in --loop mode (0 = unlimited).")
    p_tg.add_argument("--allowed-chat-id", action="append", default=[], help="Allowed Telegram chat ID (repeatable).")

    p_ledger = sub.add_parser("ledger", help="Manage reconstruction obligations.")
    p_ledger.add_argument("action", choices=["list", "add", "update"], help="Ledger action.")
    p_ledger.add_argument("--id", default="", help="Obligation ID.")
    p_ledger.add_argument("--category", default="endpoint", help="Obligation category.")
    p_ledger.add_argument("--title", default="", help="Obligation title.")
    p_ledger.add_argument(
        "--status",
        choices=[s.value for s in ObligationStatus],
        default=ObligationStatus.PENDING.value,
        help="Obligation status.",
    )

    p_brief = sub.add_parser("brief", help="Generate a clean-room architecture and stack blueprint.")
    p_brief.add_argument("--label", required=True, help="Target/project label.")
    p_brief.add_argument("--kind", default="web", help="Target kind (web, archive, binary).")

    p_ui = sub.add_parser("ui", help="Start local HTML5/Vanilla-JS dashboard and REST API server.")
    p_ui.add_argument("--host", default="127.0.0.1", help="Bind host.")
    p_ui.add_argument("--port", type=int, default=8765, help="Bind port.")
    p_ui.add_argument("--token", default="", help="Optional API token (or set NGA_API_TOKEN).")

    sub.add_parser("mcp", help="Run JSON-RPC Model Context Protocol server over stdio.")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Execute CLI command and return process exit code (0 on success, 1 on error)."""
    parser = build_parser()
    args = parser.parse_args(argv)

    base_root = Path(args.root).resolve()
    ws = NgaWorkspace(project_name=args.project)
    cache = NgaCache(ws.root / "cache.sqlite")
    handles = ws.get_handles()
    ledger = ObligationLedger(ws.root / "ledger.json", handles=handles)
    vault = AaireMemoryVault(ws.root / "memory_vault.sqlite")
    simulator = SimulationGate()

    if args.command == "mcp":
        return run_mcp_stdio_server(project_name=args.project, base_root=base_root)

    if args.command == "ui":
        return run_web_ui_server(
            host=args.host,
            port=args.port,
            project_name=args.project,
            base_root=base_root,
            api_token=args.token or None,
        )

    result: ToolResponse | NgaError | dict[str, Any]

    if args.command == "doctor":
        result = run_environment_doctor(workspace_root=ws.root)
    elif args.command == "inspect":
        result = _run_inspection(args.kind, args.target, base_root, cache, handles)
    elif args.command == "rebuild":
        inspected = _run_inspection(args.kind, args.target, base_root, cache, handles)
        if isinstance(inspected, NgaError):
            result = inspected
        else:
            findings = inspected.data if isinstance(inspected.data, dict) else {}
            app_name = args.name.strip() or Path(args.target).stem or "reconstructed_app"
            synth = AutonomousProjectSynthesizer(simulator=simulator, workspace=ws, ledger=ledger)
            synth_res = synth.synthesize_project(
                app_name=app_name,
                findings=findings,
                output_dir=args.out,
                base_root=base_root,
            )
            if isinstance(synth_res, NgaError):
                result = synth_res
            else:
                result = ToolResponse(
                    module="nga.interfaces.cli",
                    summary=f"Rebuild complete: {inspected.summary} -> {synth_res.summary}",
                    simulation_status=synth_res.simulation_status,
                    data={
                        "inspection_summary": inspected.summary,
                        "synthesis": synth_res.data,
                    },
                )
    elif args.command == "mock":
        inspected = inspect_local_har(args.target, base_root=base_root, cache=cache, handles=handles)
        if isinstance(inspected, NgaError):
            result = inspected
        else:
            findings = inspected.data if isinstance(inspected.data, dict) else {}
            routes = _extract_mock_routes(findings)
            if args.dry_run:
                result = ToolResponse(
                    module="nga.interfaces.cli",
                    summary=f"Loaded {len(routes)} mock route(s) from HAR (dry-run).",
                    data={"routes_count": len(routes), "routes": routes},
                )
            else:
                return _serve_mock_http(args.host, args.port, routes)
    elif args.command == "simulate":
        rep = simulator.simulate_crafted_python(
            code=args.code,
            smoke_assertions_code=args.smoke,
            target_label=args.label,
        )
        if isinstance(rep, NgaError):
            result = rep
        else:
            result = ToolResponse(
                module="nga.runtime.simulator",
                summary=f"Simulation {rep.status.value} ({rep.duration_ms}ms).",
                simulation_status=rep.status.value,
                data={"simulation": rep.to_dict()},
            )
    elif args.command == "synthesize":
        try:
            parsed_findings = json.loads(args.findings_json)
            if not isinstance(parsed_findings, dict):
                parsed_findings = {}
        except json.JSONDecodeError as exc:
            result = NgaError(
                error_code=ErrorCode.INVALID_INPUT.value,
                module="nga.interfaces.cli",
                message=f"Invalid --findings-json: {exc}",
                recoverable=True,
            )
            _emit_payload(result.to_dict(), max_chars=args.max_chars, offset=args.offset)
            return 1

        synth = AutonomousProjectSynthesizer(simulator=simulator, workspace=ws, ledger=ledger)
        result = synth.synthesize_project(
            app_name=args.name,
            findings=parsed_findings,
            output_dir=args.out,
            base_root=base_root,
        )
    elif args.command == "agent":
        agent = AutonomousIntentAgent(
            vault=vault,
            simulator=simulator,
            ledger=ledger,
            workspace=ws,
        )
        result = agent.run_turn(
            prompt=args.prompt,
            candidate_code=args.code,
            target_label=args.label,
        )
    elif args.command == "telegram":
        bridge = TelegramBotBridge(
            allowed_chat_ids=args.allowed_chat_id or None,
            agent=AutonomousIntentAgent(vault=vault, simulator=simulator, ledger=ledger, workspace=ws),
            simulator=simulator,
        )
        if args.loop:
            cycles = 0
            total_updates = 0
            sleep_sec = max(0.5, float(args.interval))
            try:
                while args.max_cycles <= 0 or cycles < args.max_cycles:
                    cycles += 1
                    polled = bridge.poll_once(limit=args.limit)
                    if isinstance(polled, NgaError):
                        _emit_payload(polled.to_dict(), max_chars=args.max_chars, offset=args.offset)
                        return 1
                    total_updates += len(polled)
                    if polled:
                        _emit_payload({"ok": True, "cycle": cycles, "updates": polled}, max_chars=args.max_chars)
                    if args.max_cycles <= 0 or cycles < args.max_cycles:
                        time.sleep(sleep_sec)
            except KeyboardInterrupt:
                pass
            result = ToolResponse(
                module="nga.aaire.telegram_bridge",
                summary=f"Telegram polling stopped after {cycles} cycle(s), {total_updates} update(s).",
                data={"cycles": cycles, "total_updates": total_updates},
            )
        else:
            polled = bridge.poll_once(limit=args.limit)
            if isinstance(polled, NgaError):
                result = polled
            else:
                result = ToolResponse(
                    module="nga.aaire.telegram_bridge",
                    summary=f"Processed {len(polled)} Telegram update(s).",
                    data={"updates": polled},
                )
    elif args.command == "ledger":
        if args.action == "list":
            listing = ledger.list_obligations()
            result = ToolResponse(
                module="nga.core.ledger",
                summary=f"Ledger coverage: {listing['coverage']['verified_percent']}%.",
                data=listing,
            )
        elif args.action == "add":
            added = ledger.add_obligation(
                obligation_id=args.id,
                category=args.category,
                title=args.title or args.id,
                status=args.status,
            )
            result = (
                added
                if isinstance(added, NgaError)
                else ToolResponse(
                    module="nga.core.ledger",
                    summary=f"Added obligation #{added.handle} ({added.obligation_id}).",
                    data={"obligation": added.to_dict()},
                )
            )
        else:
            upd = ledger.update_status(args.id, args.status)
            result = (
                upd
                if isinstance(upd, NgaError)
                else ToolResponse(
                    module="nga.core.ledger",
                    summary=f"Updated obligation #{upd.handle} to {upd.status.value}.",
                    data={"obligation": upd.to_dict()},
                )
            )
    elif args.command == "brief":
        result = generate_architecture_brief(target_label=args.label, target_kind=args.kind)
    else:
        result = NgaError(
            error_code=ErrorCode.INVALID_INPUT.value,
            module="nga.interfaces.cli",
            message=f"Unknown CLI command: {args.command}",
            recoverable=True,
        )

    if isinstance(result, NgaError):
        _emit_payload(result.to_dict(), max_chars=args.max_chars, offset=args.offset)
        return 1
    if isinstance(result, ToolResponse):
        _emit_payload(result.to_dict(), max_chars=args.max_chars, offset=args.offset)
        return 0 if result.ok else 1

    _emit_payload(result, max_chars=args.max_chars, offset=args.offset)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
