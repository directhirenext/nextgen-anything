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
        
