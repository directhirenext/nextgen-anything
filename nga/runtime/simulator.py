"""Pre-output simulation and smoke-test gate ensuring tools and crafted outputs run safely first."""

from __future__ import annotations

import json
import time
from typing import Any
import uuid

from nga.core.contracts import (
    ErrorCode,
    NgaError,
    SimulationReport,
    SimulationStatus,
    ToolResponse,
)
from nga.core.security import redact_secrets
from nga.runtime.sandbox import ExecutionSandbox

_MAX_TOOL_PAYLOAD_CHARS = 250_000


def _combine_code_and_smoke(code: str, smoke_code: str) -> str:
    """Merge candidate code and smoke assertions while keeping `from __future__` imports at top."""
    future_lines: list[str] = []
    main_lines: list[str] = []
    smoke_lines: list[str] = []

    for line in str(code or "").splitlines():
        if line.strip().startswith("from __future__ import "):
            if line.strip() not in future_lines:
                future_lines.append(line.strip())
        else:
            main_lines.append(line)

    for line in str(smoke_code or "").splitlines():
        if line.strip().startswith("from __future__ import "):
            if line.strip() not in future_lines:
                future_lines.append(line.strip())
        else:
            smoke_lines.append(line)

    parts: list[str] = []
    if future_lines:
        parts.append("\n".join(future_lines))
    main_body = "\n".join(main_lines).strip()
    if main_body:
        parts.append(main_body)
    smoke_body = "\n".join(smoke_lines).strip()
    if smoke_body:
        parts.append("# --- Automated Pre-Output Smoke Assertions ---\n" + smoke_body)
    return "\n\n".join(parts) + "\n"


def _redact_payload_tree(value: Any, depth: int = 0) -> Any:
    if depth >= 8:
        return value
    if isinstance(value, str):
        return redact_secrets(value)
    if isinstance(value, list):
        return [_redact_payload_tree(item, depth + 1) for item in value]
    if isinstance(value, dict):
        return {str(k): _redact_payload_tree(v, depth + 1) for k, v in value.items()}
    return value


class SimulationGate:
    """Runs dry-run simulations and smoke checks before releasing outputs to UI, CLI, or MCP."""

    def __init__(self, sandbox: ExecutionSandbox | None = None) -> None:
        self.sandbox = sandbox if sandbox is not None else ExecutionSandbox()

    def simulate_crafted_python(
        self,
        code: str,
        smoke_assertions_code: str = "",
        target_label: str = "crafted_module",
        files: dict[str, str] | None = None,
    ) -> SimulationReport | NgaError:
        """Simulate candidate Python code + optional smoke test assertions inside the sandbox."""
        combined_script = _combine_code_and_smoke(code, smoke_assertions_code)
        report = self.sandbox.run_python_snippet(
            code=combined_script,
            target_label=target_label,
            files=files,
        )
        if isinstance(report, NgaError):
            return report

        if report.passed:
            report.checks_passed.append("pre_output_simulation_gate_passed")
        return report

    def simulate_tool_payload(
        self,
        tool_name: str,
        payload: dict[str, Any],
    ) -> ToolResponse | NgaError:
        """Validate, redact, and size-check a tool's structured payload without leaking secrets to disk."""
        if not isinstance(payload, dict):
            return NgaError(
                error_code=ErrorCode.INVALID_INPUT.value,
                module="nga.runtime.simulator",
                message="Simulation payload must be a dictionary.",
                recoverable=True,
                suggested_fix="Pass a valid JSON object/dictionary as payload.",
            )

        start_perf = time.monotonic()
        run_id = f"sim_{uuid.uuid4().hex[:12]}"
        sanitized_payload = _redact_payload_tree(payload)

        try:
            encoded = json.dumps(sanitized_payload, default=str)
            parsed = json.loads(encoded)
        except (TypeError, ValueError) as exc:
            return NgaError(
                error_code=ErrorCode.SIMULATION_FAILED.value,
                module="nga.runtime.simulator",
                message=f"Pre-output payload serialization failed for '{tool_name}': {exc}",
                recoverable=True,
                suggested_fix="Ensure payload values are JSON-serializable.",
            )

        if not isinstance(parsed, dict) or len(encoded) > _MAX_TOOL_PAYLOAD_CHARS:
            return NgaError(
                error_code=ErrorCode.BUDGET_EXCEEDED.value,
                module="nga.runtime.simulator",
                message=(
                    f"Pre-output simulation failed for tool '{tool_name}': "
                    f"payload size ({len(encoded)} chars) exceeds {_MAX_TOOL_PAYLOAD_CHARS} char cap."
                ),
                recoverable=True,
                suggested_fix="Reduce payload size or apply output pagination before emitting.",
            )

        duration_ms = int((time.monotonic() - start_perf) * 1000)
        checks = [
            "payload_dict_root_valid",
            "payload_json_roundtrip_valid",
            "payload_size_within_cap",
            "payload_secrets_redacted",
        ]

        return ToolResponse(
            module="nga.runtime.simulator",
            summary=f"Tool '{tool_name}' passed pre-output payload gate ({duration_ms}ms).",
            simulation_status=SimulationStatus.SIMULATION_PASSED.value,
            data={
                "tool_name": tool_name,
                "simulation_run_id": run_id,
                "duration_ms": duration_ms,
                "checks_passed": checks,
                "validated_payload": parsed,
            },
    )
        
