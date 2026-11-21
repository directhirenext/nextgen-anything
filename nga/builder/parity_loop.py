"""Iterative build-and-verify loop with pre-output sandbox simulation and 3-strike stall detection."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from nga.core.contracts import (
    ErrorCode,
    NgaError,
    ObligationStatus,
    SimulationReport,
    SimulationStatus,
    ToolResponse,
)
from nga.core.ledger import ObligationLedger
from nga.core.workspace import NgaWorkspace
from nga.runtime.simulator import SimulationGate


@dataclass
class ParityLoopConfig:
    """Configuration parameters for iterative code candidate verification."""

    max_iterations: int = 5
    stall_threshold: int = 3
    obligation_handle_or_id: int | str | None = None


class ParityVerificationLoop:
    """Runs candidate implementations through sandbox simulation and halts on repeated stalls."""

    def __init__(
        self,
        simulator: SimulationGate | None = None,
        workspace: NgaWorkspace | None = None,
        ledger: ObligationLedger | None = None,
    ) -> None:
        self.simulator = simulator if simulator is not None else SimulationGate()
        self.workspace = workspace
        self.ledger = ledger

    def run_candidates(
        self,
        candidates: list[dict[str, str]],
        config: ParityLoopConfig | None = None,
        repair_fn: Callable[[str, SimulationReport, int], str | None] | None = None,
    ) -> ToolResponse | NgaError:
        """Evaluate candidate code snippets via sandbox simulation with stall detection and optional repair."""
        cfg = config if config is not None else ParityLoopConfig()
        max_iter = max(1, min(20, int(cfg.max_iterations)))
        stall_limit = max(2, min(10, int(cfg.stall_threshold)))

        if not isinstance(candidates, list) or not candidates:
            return NgaError(
                error_code=ErrorCode.INVALID_INPUT.value,
                module="nga.builder.parity_loop",
                message="At least one candidate code item is required to run parity verification.",
                recoverable=True,
                suggested_fix="Provide a non-empty list of {'label': ..., 'code': ..., 'smoke_code': ...} dicts.",
            )

        history: list[dict[str, Any]] = []
        last_error_sig: str = ""
        consecutive_same_errors: int = 0

        for idx, cand in enumerate(candidates[:max_iter], start=1):
            label = str(cand.get("label", f"candidate_{idx}")).strip() or f"candidate_{idx}"
            code = str(cand.get("code", "") or "")
            smoke_code = str(cand.get("smoke_code", "") or "")

            attempt = 0
            current_code = code

            while True:
                attempt += 1
                report = self.simulator.simulate_crafted_python(
                    code=current_code,
                    smoke_assertions_code=smoke_code,
                    target_label=f"{label}#attempt{attempt}",
                )
                if isinstance(report, NgaError):
                    return report

                record = {
                    "iteration": idx,
                    "attempt": attempt,
                    "label": label,
                    "status": report.status.value,
                    "passed": report.passed,
                    "error_signature": report.error_signature,
                    "duration_ms": report.duration_ms,
                    "checks_passed": report.checks_passed,
                    "checks_failed": report.checks_failed,
                }
                history.append(record)

                if report.passed:
                    if self.ledger is not None and cfg.obligation_handle_or_id is not None:
                        self.ledger.update_status(
                            cfg.obligation_handle_or_id,
                            ObligationStatus.VERIFIED,
                            notes=f"Verified in sandbox ({report.run_id}, {report.duration_ms}ms).",
                        )
                    if self.workspace is not None:
                        self.workspace.merkle.append(
                            "PARITY_SIMULATION_PASSED",
                            {
                                "label": label,
                                "run_id": report.run_id,
                                "duration_ms": report.duration_ms,
                            },
                        )

                    return ToolResponse(
                        module="nga.builder.parity_loop",
                        summary=(
                            f"Parity simulation PASSED on '{label}' (iteration {idx}, attempt {attempt}) "
                            f"in {report.duration_ms}ms."
                        ),
                        simulation_status=SimulationStatus.SIMULATION_PASSED.value,
                        data={
                            "passed": True,
                            "winning_label": label,
                            "verified_code": current_code,
                            "simulation": report.to_dict(),
                            "history": history,
                        },
                    )

                # Handle failure & stall tracking
                sig = report.error_signature or f"FAIL:{label}:{attempt}"
                if sig == last_error_sig:
                    consecutive_same_errors += 1
                else:
                    last_error_sig = sig
                    consecutive_same_errors = 1

                if consecutive_same_errors >= stall_limit:
                    if self.workspace is not None:
                        self.workspace.merkle.append(
                            "PARITY_STALL_DETECTED",
                            {
                                "label": label,
                                "error_signature": sig,
                                "consecutive_failures": consecutive_same_errors,
                            },
                        )
                    return NgaError(
                        error_code=ErrorCode.STALL_DETECTED.value,
                        module="nga.builder.parity_loop",
                        message=(
                            f"Stall detected after {consecutive_same_errors} identical failures "
                            f"(signature={sig}) on '{label}'."
                        ),
                        recoverable=True,
                        suggested_fix=(
                            "Change implementation approach, inspect sandbox stderr_preview, "
                            "and supply a revised candidate."
                        ),
                        details={
                            "error_signature": sig,
                            "consecutive_same_errors": consecutive_same_errors,
                            "last_simulation": report.to_dict(),
                            "history": history,
                        },
                    )

                if callable(repair_fn) and attempt < 3:
                    repaired = repair_fn(current_code, report, attempt)
                    if isinstance(repaired, str) and repaired.strip():
                        current_code = repaired
                        continue
                break

        last_sim = history[-1] if history else {}
        return NgaError(
            error_code=ErrorCode.SIMULATION_FAILED.value,
            module="nga.builder.parity_loop",
            message=f"All {len(history)} simulation attempt(s) did not reach SIMULATION_PASSED.",
            recoverable=True,
            suggested_fix="Review failed checks and stderr_preview in details before retrying.",
            details={
                "last_attempt": last_sim,
                "history": history,
            },
      )
                  
