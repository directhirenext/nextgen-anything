"""Command-line interface entrypoint for NextGen-Anything (`nga`)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

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

    p_tg = sub.add_parser("telegram", help="Run a single non-blocking Telegram getUpdates poll cycle.")
    p_tg.add_argument("--limit", type=int, default=10, help="Maximum updates to fetch.")

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
        if args.kind == "web":
            result = inspect_local_web_target(args.target, base_root=base_root, cache=cache, handles=handles)
        elif args.kind == "har":
            result = inspect_local_har(args.target, base_root=base_root, cache=cache, handles=handles)
        elif args.kind == "archive":
            result = inspect_archive_package(args.target, base_root=base_root, cache=cache, handles=handles)
        else:
            result = inspect_binary_target(args.target, base_root=base_root, cache=cache, handles=handles)
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
            parsed_findings = {}
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
            agent=AutonomousIntentAgent(vault=vault, simulator=simulator, ledger=ledger, workspace=ws),
            simulator=simulator,
        )
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
    
