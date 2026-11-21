"""Pre-output simulation and smoke-test gate ensuring tools and crafted outputs run safely first."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from nga.core.contracts import (
    ErrorCode,
    NgaError,
    SimulationReport,
    SimulationStatus,
    ToolResponse,
)
from nga.runtime.sandbox import ExecutionSandbox


class SimulationGate:
    """Runs dry-run simulations and smoke checks before releasing outputs to UI, CLI, or MCP."""

    def __init__(self, sandbox: ExecutionSandbox | None = None) -> None:
        self.sandbox = sandbox if sandbox is not None else ExecutionSandbox()

    def simulate_crafted_python(
        self,
        code: str,
        smoke_assertions_code: str = "",
        target_label: str = "crafted_module",
    ) -> SimulationReport | NgaError:
        """Simulate candidate Python code + optional smoke test assertions inside the sandbox."""
        combined_parts: list[str] = [code.strip()]
        if smoke_assertions_code.strip():
            combined_parts.append("\n# --- Automated Pre-Output Smoke Assertions ---\n")
            combined_parts.append(smoke_assertions_code.strip())
        combined_script = "\n".join(combined_parts)

        report = self.sandbox.run_python_snippet(
            code=combined_script,
            target_label=target_label,
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
        """Dry-run validate a tool's structured payload inside the sandbox before returning to caller."""
        if not isinstance(payload, dict):
            return NgaError(
                error_code=ErrorCode.INVALID_INPUT.value,
                module="nga.runtime.simulator",
                message="Simulation payload must be a dictionary.",
                recoverable=True,
                suggested_fix="Pass a valid JSON object/dictionary as payload.",
            )

        encoded_payload = json.dumps(payload, default=str)
        verification_script = (
            "import json\n"
            f"raw = {encoded_payload!r}\n"
            "parsed = json.loads(raw)\n"
            "assert isinstance(parsed, dict), 'Payload root must be a dict'\n"
            "assert len(raw) <= 250000, 'Payload exceeds simulation size cap'\n"
            "print(json.dumps({'simulated': True, 'keys_count': len(parsed)}))\n"
        )

        sim_report = self.sandbox.run_python_snippet(
            code=verification_script,
            target_label=f"tool_dry_run::{tool_name}",
        )
        if isinstance(sim_report, NgaError):
            return sim_report

        if not sim_report.passed:
            return NgaError(
                error_code=ErrorCode.SIMULATION_FAILED.value,
                module="nga.runtime.simulator",
                message=f"Pre-output simulation failed for tool '{tool_name}'.",
                recoverable=True,
                suggested_fix="Reduce payload size or fix invalid fields before emitting output.",
                details={"simulation": sim_report.to_dict()},
            )

        return ToolResponse(
            module="nga.runtime.simulator",
            summary=f"Tool '{tool_name}' passed sandbox simulation ({sim_report.duration_ms}ms).",
            simulation_status=SimulationStatus.SIMULATION_PASSED.value,
            data={
                "tool_name": tool_name,
                "simulation_run_id": sim_report.run_id,
                "duration_ms": sim_report.duration_ms,
                "checks_passed": sim_report.checks_passed,
                "validated_payload": payload,
            },
      )
              
