"""Cross-OS Command Line Interface (`nga`) for NextGen-Anything."""

from __future__ import annotations

import argparse
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
from nga.core.contracts import ErrorCode, NgaError, ObligationStatus, ToolResponse
from nga.core.doctor import run_environment_doctor
from nga.core.ledger import ObligationLedger
from nga.core.workspace import NgaWorkspace
from nga.runtime.simulator import SimulationGate


def _emit_result(result: ToolResponse | NgaError, as_json: bool) -> int:
    """Print ToolResponse or NgaError cleanly and return process exit code."""
    if as_json:
        print(result.to_json(indent=2))
    else:
        if isinstance(result, NgaError):
            print(f"[ERROR {result.error_code}] ({result.module}) {result.message}")
            print(f"Suggested Fix: {result.suggested_fix}")
        else:
            print(f"[OK] ({result.module}) {result.summary}")
            if result.truncated and result.next_offset is not None:
                print(f"[TRUNCATED] Pass --offset {result.next_offset} for next slice.")
            print(json.dumps(result.data, indent=2, default=str))
    return 0 if not isinstance(result, NgaError) else 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nga",
        description="NextGen-Anything (`nga`) — Analysis, Sandbox Simulation & Reconstruction CLI",
    )
    parser.add_argument("--project", default="default", help="Workspace project name (default: 'default').")
    parser.add_argument("--root", default=".", help="Base directory allowed for local file inspection (default: '.').")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON output.")
    parser.add_argument("--max-chars", type=int, default=12000, help="Output character budget cap.")
    parser.add_argument("--offset", type=int, default=0, help="Pagination offset for sliced output.")

    sub = parser.add_subparsers(dest="command", required=True)

    # nga doctor
    sub.add_parser("doctor", help="Inspect OS, Python version, and optional external toolchains.")

    # nga inspect <kind> <path>
    p_inspect = sub.add_parser("inspect", help="Inspect web/js, har, archive, or binary target.")
    p_inspect.add_argument("kind", choices=["web", "har", "archive", "binary"], help="Target inspection category.")
    p_inspect.add_argument("target", help="Relative or local path to target file.")

    # nga simulate <code>
    p_sim = sub.add_parser("simulate", help="Run Python code inside the isolated sandbox simulation gate.")
    p_sim.add_argument("code", help="Python code snippet to simulate.")
    p_sim.add_argument("--label", default="cli_snippet", help="Simulation target label.")
    p_sim.add_argument("--smoke", default="", help="Optional smoke-test assertion code.")

    # nga ledger <subcmd>
    p_ledger = sub.add_parser("ledger", help="Manage and inspect the Reconstruction Obligation Ledger.")
    p_ledger.add_argument("subcmd", choices=["list", "add", "verify"], help="Ledger operation.")
    p_ledger.add_argument("--id", dest="obl_id", default="", help="Obligation ID.")
    p_ledger.add_argument("--category", default="endpoint", help="Obligation category.")
    p_ledger.add_argument("--title", default="", help="Obligation title.")
    p_ledger.add_argument("--handle", default="", help="Obligation integer handle or ID for verify.")
    p_ledger.add_argument("--status", default="", help="Optional status filter for list.")

    # nga brief
    p_brief = sub.add_parser("brief", help="Generate clean-room architectural blueprint.")
    p_brief.add_argument("--label", default="target_app", help="Target name/label.")
    p_brief.add_argument("--kind", default="web", help="Target kind (web, archive, binary).")

    # nga mcp
    sub.add_parser("mcp", help="Run stdio JSON-RPC Model Context Protocol server.")

    # nga ui
    p_ui = sub.add_parser("ui", help="Launch local Web UI dashboard server.")
    p_ui.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1).")
    p_ui.add_argument("--port", type=int, default=8765, help="Bind port (default: 8765).")

    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    base_root = Path(args.root).resolve()
    ws = NgaWorkspace(project_name=args.project)
    cache = NgaCache(ws.root / "cache.sqlite")
    handles = ws.get_handles()
    ledger = ObligationLedger(ws.root / "ledger.json", handles=handles)

    if args.command == "doctor":
        res: ToolResponse | NgaError = run_environment_doctor(workspace_root=ws.root)
        return _emit_result(res, args.json)

    if args.command == "inspect":
        if args.kind == "web":
            res = inspect_local_web_target(
                args.target,
                base_root=base_root,
                cache=cache,
                handles=handles,
                max_output_chars=args.max_chars,
                offset=args.offset,
            )
        elif args.kind == "har":
            res = inspect_local_har(
                args.target,
                base_root=base_root,
                cache=cache,
                handles=handles,
                max_output_chars=args.max_chars,
                offset=args.offset,
            )
        elif args.kind == "archive":
            res = inspect_archive_package(
                args.target,
                base_root=base_root,
                cache=cache,
                handles=handles,
                max_output_chars=args.max_chars,
                offset=args.offset,
            )
        else:
            res = inspect_binary_target(
                args.target,
                base_root=base_root,
                cache=cache,
                handles=handles,
                max_output_chars=args.max_chars,
                offset=args.offset,
            )

        if not isinstance(res, NgaError):
            ws.register_handle(f"inspect::{args.kind}::{args.target}", {"kind": args.kind})
        return _emit_result(res, args.json)

    if args.command == "simulate":
        gate = SimulationGate()
        report = gate.simulate_crafted_python(
            code=args.code,
            smoke_assertions_code=args.smoke,
            target_label=args.label,
        )
        if isinstance(report, NgaError):
            return _emit_result(report, args.json)
        res = ToolResponse(
            module="nga.runtime.simulator",
            summary=f"Simulation {report.status.value} for '{args.label}' ({report.duration_ms}ms).",
            simulation_status=report.status.value,
            data={"simulation": report.to_dict()},
        )
        return _emit_result(res, args.json)

    if args.command == "ledger":
        if args.subcmd == "list":
            listing = ledger.list_obligations(status_filter=args.status or None, offset=args.offset)
            res = ToolResponse(
                module="nga.core.ledger",
                summary=f"Ledger coverage: {listing['coverage']['verified_percent']}% verified.",
                truncated=listing["next_offset"] is not None,
                next_offset=listing["next_offset"],
                data=listing,
            )
            return _emit_result(res, args.json)

        if args.subcmd == "add":
            added = ledger.add_obligation(
                obligation_id=args.obl_id,
                category=args.category,
                title=args.title or args.obl_id,
            )
            if isinstance(added, NgaError):
                return _emit_result(added, args.json)
            res = ToolResponse(
                module="nga.core.ledger",
                summary=f"Added obligation #{added.handle} ({added.obligation_id}).",
                data={"obligation": added.to_dict()},
            )
            return _emit_result(res, args.json)

        # verify
        ident: int | str = int(args.handle) if str(args.handle).isdigit() else str(args.handle)
        updated = ledger.update_status(ident, ObligationStatus.VERIFIED, notes="Verified via CLI.")
        if isinstance(updated, NgaError):
            return _emit_result(updated, args.json)
        res = ToolResponse(
            module="nga.core.ledger",
            summary=f"Marked obligation #{updated.handle} as VERIFIED.",
            data={"obligation": updated.to_dict()},
        )
        return _emit_result(res, args.json)

    if args.command == "brief":
        res = generate_architecture_brief(target_label=args.label, target_kind=args.kind)
        return _emit_result(res, args.json)

    if args.command == "mcp":
        from nga.interfaces.mcp_server import serve_mcp_stdio

        serve_mcp_stdio(project_name=args.project, base_root=base_root)
        return 0

    if args.command == "ui":
        from nga.interfaces.web_ui import run_web_ui_server

        return run_web_ui_server(host=args.host, port=args.port, project_name=args.project, base_root=base_root)

    err = NgaError(
        error_code=ErrorCode.INVALID_INPUT.value,
        module="nga.interfaces.cli",
        message=f"Unsupported CLI command: {args.command}",
    )
    return _emit_result(err, args.json)


if __name__ == "__main__":
    sys.exit(main())
                            
