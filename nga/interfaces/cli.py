"""Command-line interface (CLI) for NextGen-Anything (`nga`)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time
from typing import Any

from nga.aaire.intent_agent import AutonomousIntentAgent
from nga.aaire.llm_engine import UniversalLlmEngine
from nga.aaire.memory_vault import AaireMemoryVault
from nga.aaire.telegram_bridge import TelegramBotBridge
from nga.analyzers.archive_pkg import inspect_archive_package
from nga.analyzers.binary_meta import inspect_binary_target
from nga.analyzers.network_har import inspect_local_har
from nga.analyzers.web_js import inspect_live_web_url, inspect_local_web_target
from nga.builder.brief_gen import generate_architecture_brief
from nga.builder.orchestrator import WorkflowOrchestrator
from nga.builder.parity_loop import ParityLoopConfig, ParityVerificationLoop
from nga.builder.synthesizer import AutonomousProjectSynthesizer
from nga.core.cache import NgaCache
from nga.core.contracts import ErrorCode, NgaError, ObligationStatus, ToolResponse
from nga.core.doctor import run_environment_doctor
from nga.core.ledger import ObligationLedger
from nga.core.plugins import PluginRegistry
from nga.core.security import DEFAULT_MAX_OUTPUT_CHARS, redact_secrets
from nga.core.workspace import NgaWorkspace
from nga.interfaces.mcp_server import run_mcp_stdio_server
from nga.interfaces.web_ui import run_web_ui_server
from nga.runtime.simulator import SimulationGate
from nga.runtime.standin_server import StandInMockServer, build_routes_from_har_analysis


def _emit(payload: ToolResponse | NgaError | dict[str, Any], as_json: bool = True) -> int:
    """Print deterministic JSON or concise text and return standard exit code."""
    if isinstance(payload, NgaError):
        sys.stdout.write(payload.to_json(indent=2) + "\n")
        sys.stdout.flush()
        return 1
    if isinstance(payload, ToolResponse):
        if as_json:
            sys.stdout.write(payload.to_json(indent=2) + "\n")
        else:
            sys.stdout.write(redact_secrets(payload.summary) + "\n")
        sys.stdout.flush()
        return 0 if bool(payload.ok) else 1

    sys.stdout.write(redact_secrets(json.dumps(payload, indent=2, default=str)) + "\n")
    sys.stdout.flush()
    return 0


class _CliSession:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.base_root = Path(args.root).resolve() if args.root else Path.cwd().resolve()
        ws_base = Path(args.workspace_dir).resolve() if getattr(args, "workspace_dir", None) else None
        self.workspace = NgaWorkspace(project_name=args.project, base_dir=ws_base)
        self.cache = NgaCache(self.workspace.root / "cache.sqlite")
        self.handles = self.workspace.get_handles()
        self.ledger = ObligationLedger(self.workspace.root / "ledger.json", handles=self.handles)
        self.vault = AaireMemoryVault(self.workspace.root / "memory_vault.sqlite")
        self.plugins = PluginRegistry()
        self.simulator = SimulationGate()
        self.llm = UniversalLlmEngine(plugin_registry=self.plugins)
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

    def inspect_target(self, kind: str, target: str) -> ToolResponse | NgaError:
        max_chars = int(getattr(self.args, "max_chars", DEFAULT_MAX_OUTPUT_CHARS))
        offset = int(getattr(self.args, "offset", 0))
        if kind == "web":
            return inspect_local_web_target(
                target, base_root=self.base_root, cache=self.cache, handles=self.handles,
                max_output_chars=max_chars, offset=offset,
            )
        if kind == "har":
            return inspect_local_har(
                target, base_root=self.base_root, cache=self.cache, handles=self.handles,
                max_output_chars=max_chars, offset=offset,
            )
        if kind == "archive":
            return inspect_archive_package(
                target, base_root=self.base_root, cache=self.cache, handles=self.handles,
                max_output_chars=max_chars, offset=offset,
            )
        if kind == "binary":
            return inspect_binary_target(
                target, base_root=self.base_root, cache=self.cache, handles=self.handles,
                max_output_chars=max_chars, offset=offset,
            )
        return NgaError(
            error_code=ErrorCode.INVALID_INPUT.value,
            module="nga.interfaces.cli",
            message=f"Unsupported inspection kind: {kind}",
            recoverable=True,
        )

    @staticmethod
    def flatten_findings(inspected: ToolResponse) -> dict[str, Any]:
        base = dict(inspected.data) if isinstance(inspected.data, dict) else {}
        for nested_key in ("analysis", "package", "metadata"):
            nested = base.get(nested_key)
            if isinstance(nested, dict):
                for k, v in nested.items():
                    if k not in base or not base[k]:
                        base[k] = v
        return base


def _cmd_doctor(session: _CliSession, _args: argparse.Namespace) -> int:
    doc = run_environment_doctor(workspace_root=session.workspace.root)
    return _emit(doc, as_json=True)


def _cmd_inspect(session: _CliSession, args: argparse.Namespace) -> int:
    session.workspace.set_target(args.target, args.kind)
    res = session.inspect_target(args.kind, args.target)
    return _emit(res, as_json=True)


def _cmd_live_inspect(session: _CliSession, args: argparse.Namespace) -> int:
    res = inspect_live_web_url(url=args.url, cache=session.cache, handles=session.handles)
    return _emit(res, as_json=True)


def _cmd_simulate(session: _CliSession, args: argparse.Namespace) -> int:
    code_text = args.code
    if args.file:
        p = Path(args.file)
        if not p.is_file():
            return _emit(
                NgaError(
                    error_code=ErrorCode.NOT_FOUND.value,
                    module="nga.interfaces.cli",
                    message=f"Snippet file not found: {args.file}",
                    recoverable=True,
                )
            )
        code_text = p.read_text(encoding="utf-8", errors="replace")

    smoke_text = args.smoke or ""
    if args.smoke_file:
        sp = Path(args.smoke_file)
        if not sp.is_file():
            return _emit(
                NgaError(
                    error_code=ErrorCode.NOT_FOUND.value,
                    module="nga.interfaces.cli",
                    message=f"Smoke file not found: {args.smoke_file}",
                    recoverable=True,
                )
            )
        smoke_text = sp.read_text(encoding="utf-8", errors="replace")

    rep = session.simulator.simulate_crafted_python(
        code=code_text or "",
        smoke_assertions_code=smoke_text,
        target_label=args.label,
    )
    if isinstance(rep, NgaError):
        return _emit(rep)
    return _emit(
        ToolResponse(
            module="nga.runtime.simulator",
            ok=rep.passed,
            summary=f"Simulation {rep.status.value} ({rep.duration_ms}ms).",
            simulation_status=rep.status.value,
            data={"simulation": rep.to_dict()},
        ),
        as_json=True,
    )


def _cmd_synthesize(session: _CliSession, args: argparse.Namespace) -> int:
    fpath = Path(args.findings_file)
    if not fpath.is_file():
        return _emit(
            NgaError(
                error_code=ErrorCode.NOT_FOUND.value,
                module="nga.interfaces.cli",
                message=f"Findings JSON file not found: {args.findings_file}",
                recoverable=True,
            )
        )
    try:
        findings_obj = json.loads(fpath.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return _emit(
            NgaError(
                error_code=ErrorCode.INVALID_INPUT.value,
                module="nga.interfaces.cli",
                message=f"Invalid findings JSON: {exc}",
                recoverable=True,
            )
        )
    if not isinstance(findings_obj, dict):
        return _emit(
            NgaError(
                error_code=ErrorCode.INVALID_INPUT.value,
                module="nga.interfaces.cli",
                message="Findings JSON root must be an object.",
                recoverable=True,
            )
        )
    res = session.synthesizer.synthesize_project(
        app_name=args.app_name,
        findings=findings_obj,
        output_dir=args.out,
        base_root=session.base_root,
        custom_prompt=getattr(args, "prompt", "") or "",
        include_android_scaffold=bool(getattr(args, "android", False)),
    )
    return _emit(res, as_json=True)


def _cmd_rebuild(session: _CliSession, args: argparse.Namespace) -> int:
    session.workspace.set_target(args.target, args.kind)
    inspected = session.inspect_target(args.kind, args.target)
    if isinstance(inspected, NgaError):
        return _emit(inspected)

    findings = session.flatten_findings(inspected)
    app_name = (args.app_name or "").strip() or Path(args.target).stem or "reconstructed_app"
    synth = session.synthesizer.synthesize_project(
        app_name=app_name,
        findings=findings,
        output_dir=args.out,
        base_root=session.base_root,
        custom_prompt=getattr(args, "prompt", "") or "",
        include_android_scaffold=(args.kind == "archive"),
    )
    if isinstance(synth, NgaError):
        return _emit(synth)

    return _emit(
        ToolResponse(
            module="nga.interfaces.cli",
            summary=f"Rebuild complete: {inspected.summary} -> {synth.summary}",
            simulation_status=synth.simulation_status,
            data={"inspection_summary": inspected.summary, "synthesis": synth.data},
        ),
        as_json=True,
    )


def _cmd_mock(session: _CliSession, args: argparse.Namespace) -> int:
    inspected = inspect_local_har(args.har_file, base_root=session.base_root, cache=session.cache, handles=session.handles)
    if isinstance(inspected, NgaError):
        return _emit(inspected)

    routes = build_routes_from_har_analysis(inspected.data)
    if args.dry_run:
        return _emit(
            ToolResponse(
                module="nga.runtime.standin_server",
                summary=f"Dry-run built {len(routes)} mock route(s) from '{args.har_file}'.",
                data={"dry_run": True, "routes_count": len(routes), "routes": routes},
            ),
            as_json=True,
        )

    srv = StandInMockServer(routes=routes, host=args.host, port=args.port)
    started = srv.start()
    if isinstance(started, NgaError):
        return _emit(started)

    sys.stdout.write(started.to_json(indent=2) + "\n")
    sys.stdout.flush()
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass
    finally:
        srv.stop()
    return 0
def _cmd_orchestrate(session: _CliSession, args: argparse.Namespace) -> int:
    orch = WorkflowOrchestrator(workspace=session.workspace)
    plan = orch.build_default_plan(args.target, target_type=args.kind)
    if isinstance(plan, NgaError):
        return _emit(plan)

    shared_ctx: dict[str, Any] = {}

    def _step_inspect(p: dict[str, Any]) -> ToolResponse | NgaError:
        out = session.inspect_target(str(p.get("target_type", args.kind)), str(p.get("target", args.target)))
        if not isinstance(out, NgaError):
            shared_ctx["findings"] = session.flatten_findings(out)
        return out

    def _step_ledger(p: dict[str, Any]) -> ToolResponse | NgaError:
        tgt = str(p.get("target", args.target))
        obl = session.ledger.add_obligation(
            obligation_id=f"dag_{Path(tgt).name or 'target'}",
            category="dag_target",
            title=f"Inspect & verify {tgt}",
            status=ObligationStatus.IN_PROGRESS,
        )
        if isinstance(obl, NgaError):
            return obl
        return ToolResponse(module="nga.core.ledger", summary=f"Synced obligation #{obl.handle}.", data=obl.to_dict())

    def _step_brief(p: dict[str, Any]) -> ToolResponse | NgaError:
        return generate_architecture_brief(
            target_label=str(p.get("target", args.target)),
            target_kind=str(p.get("target_type", args.kind)),
            findings=shared_ctx.get("findings"),
        )

    def _step_verify(p: dict[str, Any]) -> ToolResponse | NgaError:
        rep = session.simulator.simulate_crafted_python(
            code="assert 1 + 1 == 2\nprint('DAG_VERIFY_OK')\n",
            target_label=f"dag::{p.get('target', args.target)}",
        )
        if isinstance(rep, NgaError):
            return rep
        return ToolResponse(
            module="nga.runtime.simulator",
            ok=rep.passed,
            summary=f"DAG verification {rep.status.value}.",
            simulation_status=rep.status.value,
            data={"simulation": rep.to_dict()},
        )

    res = orch.run_plan(
        plan,
        runner_map={
            "inspect": _step_inspect,
            "ledger_sync": _step_ledger,
            "brief": _step_brief,
            "simulate_check": _step_verify,
        },
    )
    return _emit(res, as_json=True)


def _cmd_parity(session: _CliSession, args: argparse.Namespace) -> int:
    cpath = Path(args.candidates_file)
    if not cpath.is_file():
        return _emit(
            NgaError(
                error_code=ErrorCode.NOT_FOUND.value,
                module="nga.interfaces.cli",
                message=f"Candidates JSON file not found: {args.candidates_file}",
                recoverable=True,
            )
        )
    try:
        cands = json.loads(cpath.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return _emit(
            NgaError(
                error_code=ErrorCode.INVALID_INPUT.value,
                module="nga.interfaces.cli",
                message=f"Invalid candidates JSON: {exc}",
                recoverable=True,
            )
        )
    if not isinstance(cands, list):
        return _emit(
            NgaError(
                error_code=ErrorCode.INVALID_INPUT.value,
                module="nga.interfaces.cli",
                message="Candidates JSON must be a list of candidate objects.",
                recoverable=True,
            )
        )
    loop = ParityVerificationLoop(simulator=session.simulator, workspace=session.workspace, ledger=session.ledger)
    res = loop.run_candidates(
        cands,
        config=ParityLoopConfig(max_iterations=args.max_iterations, stall_threshold=args.stall_threshold),
    )
    return _emit(res, as_json=True)


def _cmd_agent(session: _CliSession, args: argparse.Namespace) -> int:
    code_txt = ""
    if args.code_file:
        cp = Path(args.code_file)
        if not cp.is_file():
            return _emit(
                NgaError(
                    error_code=ErrorCode.NOT_FOUND.value,
                    module="nga.interfaces.cli",
                    message=f"Code file not found: {args.code_file}",
                    recoverable=True,
                )
            )
        code_txt = cp.read_text(encoding="utf-8", errors="replace")

    res = session.agent.run_turn(
        prompt=args.prompt,
        candidate_code=code_txt,
        target_label=args.label,
        target_kind=args.kind,
    )
    return _emit(res, as_json=True)


def _cmd_memory(session: _CliSession, args: argparse.Namespace) -> int:
    if args.mem_cmd == "store":
        tags = [t.strip() for t in (args.tags or "").split(",") if t.strip()]
        stored = session.vault.store(
            title=args.title,
            body=args.body,
            namespace=args.namespace or session.agent.namespace,
            tags=tags,
            source="cli",
        )
        if isinstance(stored, NgaError):
            return _emit(stored)
        return _emit(
            ToolResponse(
                module="nga.aaire.memory_vault",
                summary=f"Stored memory #{stored.get('id')} in '{stored.get('namespace')}'.",
                data={"memory": stored},
            ),
            as_json=True,
        )

    hits = session.vault.retrieve(args.query, namespace=args.namespace or None, limit=args.limit)
    return _emit(
        ToolResponse(
            module="nga.aaire.memory_vault",
            summary=f"Retrieved {len(hits)} memory record(s).",
            data={"hits": hits, "count": len(hits)},
        ),
        as_json=True,
    )


def _cmd_ledger(session: _CliSession, args: argparse.Namespace) -> int:
    if args.ledger_cmd == "add":
        added = session.ledger.add_obligation(
            obligation_id=args.obligation_id,
            category=args.category,
            title=args.title or args.obligation_id,
            status=args.status,
        )
        if isinstance(added, NgaError):
            return _emit(added)
        return _emit(
            ToolResponse(
                module="nga.core.ledger",
                summary=f"Added obligation #{added.handle} ({added.obligation_id}).",
                data={"obligation": added.to_dict()},
            ),
            as_json=True,
        )

    if args.ledger_cmd == "update":
        upd = session.ledger.update_status(args.obligation_id, args.status, notes=args.notes)
        if isinstance(upd, NgaError):
            return _emit(upd)
        return _emit(
            ToolResponse(
                module="nga.core.ledger",
                summary=f"Updated obligation #{upd.handle} to {upd.status.value}.",
                data={"obligation": upd.to_dict()},
            ),
            as_json=True,
        )

    listing = session.ledger.list_obligations(status_filter=getattr(args, "status_filter", None))
    return _emit(
        ToolResponse(
            module="nga.core.ledger",
            summary=f"Ledger coverage: {listing['coverage']['verified_percent']}%.",
            data=listing,
        ),
        as_json=True,
    )


def _cmd_brief(session: _CliSession, args: argparse.Namespace) -> int:
    findings_data: dict[str, Any] | None = None
    if args.target_file:
        inspected = session.inspect_target(args.kind, args.target_file)
        if isinstance(inspected, NgaError):
            return _emit(inspected)
        findings_data = session.flatten_findings(inspected)

    res = generate_architecture_brief(
        target_label=args.label,
        target_kind=args.kind,
        findings=findings_data,
        custom_requirements=getattr(args, "prompt", "") or "",
    )
    return _emit(res, as_json=True)


def _cmd_plugins(session: _CliSession, args: argparse.Namespace) -> int:
    if args.plugin_cmd == "invoke":
        payload_obj: dict[str, Any] = {}
        if args.payload_json:
            try:
                loaded = json.loads(args.payload_json)
                if isinstance(loaded, dict):
                    payload_obj = loaded
            except json.JSONDecodeError as exc:
                return _emit(
                    NgaError(
                        error_code=ErrorCode.INVALID_INPUT.value,
                        module="nga.interfaces.cli",
                        message=f"Invalid plugin payload JSON: {exc}",
                        recoverable=True,
                    )
                )
        res = session.plugins.invoke(args.name, action=args.action, payload=payload_obj)
        return _emit(res, as_json=True)

    found = session.plugins.discover()
    return _emit(
        ToolResponse(
            module="nga.core.plugins",
            summary=f"Discovered {len(found)} plugin(s) in {session.plugins.plugins_dir}.",
            data={"plugins": found, "count": len(found)},
        ),
        as_json=True,
    )


def _cmd_telegram(session: _CliSession, args: argparse.Namespace) -> int:
    allowed = [c.strip() for c in (args.allowed_chats or "").split(",") if c.strip()]
    bridge = TelegramBotBridge(
        bot_token=args.token,
        allowed_chat_ids=allowed or None,
        agent=session.agent,
        simulator=session.simulator,
        state_path=session.workspace.root / "telegram_offset.json",
    )
    if args.once:
        out = bridge.poll_once(limit=args.limit)
        if isinstance(out, NgaError):
            return _emit(out)
        return _emit({"ok": True, "processed_count": len(out), "updates": out}, as_json=True)

    while True:
        out = bridge.poll_once(limit=args.limit)
        if isinstance(out, NgaError):
            sys.stderr.write(redact_secrets(out.message) + "\n")
            sys.stderr.flush()
            time.sleep(max(2.0, float(args.interval)))
            continue
        if out:
            sys.stdout.write(json.dumps({"ok": True, "processed": out}, default=str) + "\n")
            sys.stdout.flush()
        time.sleep(max(0.5, float(args.interval)))


def _cmd_mcp(session: _CliSession, args: argparse.Namespace) -> int:
    return run_mcp_stdio_server(
        project_name=session.workspace.project_name,
        base_root=session.base_root,
        workspace_base_dir=session.workspace.root.parent,
    )


def _cmd_ui(session: _CliSession, args: argparse.Namespace) -> int:
    return run_web_ui_server(
        host=args.host,
        port=args.port,
        project_name=session.workspace.project_name,
        base_root=session.base_root,
        api_token=args.token,
        workspace_base_dir=session.workspace.root.parent,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="nga", description="NextGen-Anything CLI")
    parser.add_argument("--project", default="default", help="Workspace project name")
    parser.add_argument("--root", default=".", help="Base root directory for target files")
    parser.add_argument("--workspace-dir", default=None, help="Optional custom base directory for workspaces")
    parser.add_argument("--max-chars", type=int, default=DEFAULT_MAX_OUTPUT_CHARS, help="Max output characters")
    parser.add_argument("--offset", type=int, default=0, help="Output slice start offset")

    sub = parser.add_subparsers(dest="command", required=True)

    p_doc = sub.add_parser("doctor", help="Check runtime environment and optional tools")
    p_doc.set_defaults(func=_cmd_doctor)

    p_ins = sub.add_parser("inspect", help="Inspect a local web/JS, HAR, archive/APK, or binary file")
    p_ins.add_argument("kind", choices=["web", "har", "archive", "binary"])
    p_ins.add_argument("target")
    p_ins.set_defaults(func=_cmd_inspect)

    p_live = sub.add_parser("live-inspect", help="Inspect a live HTTP/HTTPS URL safely")
    p_live.add_argument("url")
    p_live.set_defaults(func=_cmd_live_inspect)

    p_sim = sub.add_parser("simulate", help="Run Python code in isolated sandbox")
    p_sim.add_argument("code", nargs="?", default="")
    p_sim.add_argument("--file", default=None)
    p_sim.add_argument("--smoke", default="")
    p_sim.add_argument("--smoke-file", default=None)
    p_sim.add_argument("--label", default="cli_snippet")
    p_sim.set_defaults(func=_cmd_simulate)

    p_syn = sub.add_parser("synthesize", help="Synthesize SQLite CRUD app from findings JSON")
    p_syn.add_argument("findings_file")
    p_syn.add_argument("--app-name", default="reconstructed_app")
    p_syn.add_argument("--out", default="synthesized_out")
    p_syn.add_argument("--prompt", default="")
    p_syn.add_argument("--android", action="store_true")
    p_syn.set_defaults(func=_cmd_synthesize)

    p_reb = sub.add_parser("rebuild", help="Inspect target and synthesize verified SQLite CRUD app")
    p_reb.add_argument("kind", choices=["web", "har", "archive", "binary"])
    p_reb.add_argument("target")
    p_reb.add_argument("--app-name", default="")
    p_reb.add_argument("--out", default="rebuilt_app")
    p_reb.add_argument("--prompt", default="")
    p_reb.set_defaults(func=_cmd_rebuild)

    p_mock = sub.add_parser("mock", help="Serve or dry-run mock routes from a HAR file")
    p_mock.add_argument("har_file")
    p_mock.add_argument("--host", default="127.0.0.1")
    p_mock.add_argument("--port", type=int, default=8090)
    p_mock.add_argument("--dry-run", action="store_true")
    p_mock.set_defaults(func=_cmd_mock)

    p_orch = sub.add_parser("orchestrate", help="Run default DAG workflow on a target")
    p_orch.add_argument("target")
    p_orch.add_argument("--kind", default="web")
    p_orch.set_defaults(func=_cmd_orchestrate)

    p_par = sub.add_parser("parity", help="Run parity verification loop over candidate JSON list")
    p_par.add_argument("candidates_file")
    p_par.add_argument("--max-iterations", type=int, default=5)
    p_par.add_argument("--stall-threshold", type=int, default=3)
    p_par.set_defaults(func=_cmd_parity)

    p_ag = sub.add_parser("agent", help="Run an autonomous AAIRE agent turn")
    p_ag.add_argument("prompt")
    p_ag.add_argument("--code-file", default=None)
    p_ag.add_argument("--label", default="cli_agent")
    p_ag.add_argument("--kind", default="web")
    p_ag.set_defaults(func=_cmd_agent)

    p_mem = sub.add_parser("memory", help="Store or query AAIRE memory vault")
    mem_sub = p_mem.add_subparsers(dest="mem_cmd", required=True)
    p_ms = mem_sub.add_parser("store")
    p_ms.add_argument("title")
    p_ms.add_argument("body")
    p_ms.add_argument("--namespace", default=None)
    p_ms.add_argument("--tags", default="")
    p_ms.set_defaults(func=_cmd_memory)
    p_mr = mem_sub.add_parser("retrieve")
    p_mr.add_argument("query")
    p_mr.add_argument("--namespace", default=None)
    p_mr.add_argument("--limit", type=int, default=5)
    p_mr.set_defaults(func=_cmd_memory)

    p_led = sub.add_parser("ledger", help="Manage reconstruction obligation ledger")
    led_sub = p_led.add_subparsers(dest="ledger_cmd", required=True)
    p_ll = led_sub.add_parser("list")
    p_ll.add_argument("--status", dest="status_filter", default=None)
    p_ll.set_defaults(func=_cmd_ledger)
    p_la = led_sub.add_parser("add")
    p_la.add_argument("obligation_id")
    p_la.add_argument("--category", default="endpoint")
    p_la.add_argument("--title", default="")
    p_la.add_argument("--status", default="pending")
    p_la.set_defaults(func=_cmd_ledger)
    p_lu = led_sub.add_parser("update")
    p_lu.add_argument("obligation_id")
    p_lu.add_argument("status")
    p_lu.add_argument("--notes", default=None)
    p_lu.set_defaults(func=_cmd_ledger)

    p_br = sub.add_parser("brief", help="Generate clean-room architecture blueprint")
    p_br.add_argument("label")
    p_br.add_argument("--kind", default="web")
    p_br.add_argument("--target-file", default=None)
    p_br.add_argument("--prompt", default="")
    p_br.set_defaults(func=_cmd_brief)

    p_plg = sub.add_parser("plugins", help="Discover or invoke polyglot plugins")
    plg_sub = p_plg.add_subparsers(dest="plugin_cmd", required=True)
    p_pd = plg_sub.add_parser("discover")
    p_pd.set_defaults(func=_cmd_plugins)
    p_pi = plg_sub.add_parser("invoke")
    p_pi.add_argument("name")
    p_pi.add_argument("--action", default="run")
    p_pi.add_argument("--payload-json", default="{}")
    p_pi.set_defaults(func=_cmd_plugins)

    p_tg = sub.add_parser("telegram", help="Run Telegram bot bridge polling loop")
    p_tg.add_argument("--token", default=None)
    p_tg.add_argument("--allowed-chats", default="")
    p_tg.add_argument("--once", action="store_true")
    p_tg.add_argument("--limit", type=int, default=10)
    p_tg.add_argument("--interval", type=float, default=2.0)
    p_tg.set_defaults(func=_cmd_telegram)

    p_mcp = sub.add_parser("mcp", help="Run MCP JSON-RPC 2.0 stdio server")
    p_mcp.set_defaults(func=_cmd_mcp)

    p_ui = sub.add_parser("ui", help="Run local Web UI and REST API server")
    p_ui.add_argument("--host", default="127.0.0.1")
    p_ui.add_argument("--port", type=int, default=8765)
    p_ui.add_argument("--token", default=None)
    p_ui.set_defaults(func=_cmd_ui)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    parsed = parser.parse_args(argv)
    session = _CliSession(parsed)
    handler = getattr(parsed, "func", None)
    if not callable(handler):
        return 1
    try:
        return int(handler(session, parsed))
    except Exception as exc:
        err = NgaError(
            error_code=ErrorCode.INTERNAL_ERROR.value,
            module="nga.interfaces.cli",
            message=redact_secrets(f"Unhandled CLI error: {exc}"),
            recoverable=True,
        )
        return _emit(err)


if __name__ == "__main__":
    raise SystemExit(main())
                         
