"""Autonomous intent classifier, tool planner, and sandbox-verified agent runner for nga."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any

from nga.aaire.memory_vault import AaireMemoryVault
from nga.builder.brief_gen import generate_architecture_brief
from nga.builder.parity_loop import ParityLoopConfig, ParityVerificationLoop
from nga.core.contracts import (
    ErrorCode,
    NgaError,
    ObligationStatus,
    SimulationReport,
    SimulationStatus,
    ToolResponse,
    utc_now_iso,
)
from nga.core.ledger import ObligationLedger
from nga.core.security import redact_secrets
from nga.core.workspace import NgaWorkspace
from nga.runtime.simulator import SimulationGate

_CODE_BLOCK_RE = re.compile(r"```(?:python)?\s*\n([\s\S]*?)```", re.IGNORECASE)


@dataclass
class AgentTurnResult:
    """Structured output produced after executing a single autonomous agent turn."""

    intent: str
    goal: str
    recalled_memories: list[dict[str, Any]]
    actions_taken: list[dict[str, Any]]
    simulation_passed: bool
    summary: str
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "intent": self.intent,
            "goal": self.goal,
            "recalled_memories": self.recalled_memories,
            "actions_taken": self.actions_taken,
            "simulation_passed": self.simulation_passed,
            "summary": self.summary,
            "created_at": self.created_at,
        }


def classify_user_intent(prompt: str) -> str:
    """Classify a user request into a deterministic action intent."""
    text = str(prompt or "").lower()
    if any(k in text for k in ("simulate", "sandbox", "verify code", "test snippet", "run code")):
        return "simulate_code"
    if any(k in text for k in ("blueprint", "architecture", "brief", "design")):
        return "generate_brief"
    if any(k in text for k in ("remember", "store note", "save memory", "vault")):
        return "store_memory"
    if any(k in text for k in ("inspect", "analyze", "scan", "endpoint", "route")):
        return "inspect_and_plan"
    return "autonomous_task"


def extract_python_candidate(prompt: str) -> str:
    """Extract embedded Python code block or inline code expression if present."""
    match = _CODE_BLOCK_RE.search(prompt or "")
    if match:
        return match.group(1).strip()
    return ""


def _parse_verification_result(outcome: Any) -> tuple[bool, int, str]:
    """Normalize return values from ParityVerificationLoop or SimulationGate."""
    if isinstance(outcome, NgaError):
        return False, 0, outcome.message
    if isinstance(outcome, SimulationReport):
        return bool(outcome.passed), 1, outcome.status.value
    if isinstance(outcome, ToolResponse):
        payload = outcome.data if isinstance(outcome.data, dict) else {}
        passed = bool(
            payload.get(
                "passed",
                outcome.ok and outcome.simulation_status == SimulationStatus.SIMULATION_PASSED.value,
            )
        )
        iters = int(payload.get("iterations_used", payload.get("attempts", 1)) or 0)
        return passed, iters, outcome.summary
    if isinstance(outcome, dict):
        passed = bool(outcome.get("passed", outcome.get("ok", False)))
        iters = int(outcome.get("iterations_used", outcome.get("attempts", 1)) or 0)
        return passed, iters, str(outcome.get("summary", ""))
    return False, 0, "Unknown verification output"


class AutonomousIntentAgent:
    """Executes goal-driven turns using memory vault recall, sandbox simulation, and ledger sync."""

    def __init__(
        self,
        vault: AaireMemoryVault | None = None,
        simulator: SimulationGate | None = None,
        ledger: ObligationLedger | None = None,
        workspace: NgaWorkspace | None = None,
        namespace: str = "agent_core",
    ) -> None:
        self.namespace = re.sub(r"[^a-zA-Z0-9_.-]+", "_", str(namespace or "agent_core")).strip("_") or "agent_core"
        self.vault = vault if vault is not None else AaireMemoryVault()
        self.simulator = simulator if simulator is not None else SimulationGate()
        self.ledger = ledger
        self.workspace = workspace
        self.parity_loop = ParityVerificationLoop(simulator=self.simulator)

    def _verify_candidate_code(self, code: str, target_label: str) -> tuple[bool, dict[str, Any]]:
        """Run code through parity verification loop with direct sandbox gate fallback."""
        candidates = [{"label": target_label, "code": code}]
        try:
            loop_res = self.parity_loop.run_candidates(
                candidates,
                config=ParityLoopConfig(max_iterations=2, stall_threshold=2),
            )
            passed, iters, detail = _parse_verification_result(loop_res)
            return passed, {
                "tool": "parity_loop",
                "status": "passed" if passed else "failed",
                "iterations_used": iters,
                "detail": detail,
            }
        except (TypeError, AttributeError):
            rep = self.simulator.simulate_crafted_python(code=code, target_label=target_label)
            passed, iters, detail = _parse_verification_result(rep)
            return passed, {
                "tool": "simulation_gate",
                "status": "passed" if passed else "failed",
                "iterations_used": iters,
                "detail": detail,
            }

    def run_turn(
        self,
        prompt: str,
        candidate_code: str = "",
        target_label: str = "agent_goal",
        target_kind: str = "web",
        persist_memory: bool = True,
    ) -> ToolResponse | NgaError:
        """Execute a complete autonomous turn with memory recall and sandbox gate."""
        clean_prompt = redact_secrets(str(prompt or "")).strip()
        if not clean_prompt:
            return NgaError(
                error_code=ErrorCode.INVALID_INPUT.value,
                module="nga.aaire.intent_agent",
                message="Agent prompt cannot be empty.",
                recoverable=True,
                suggested_fix="Provide a clear goal or instruction in prompt.",
            )

        intent = classify_user_intent(clean_prompt)
        recalled = self.vault.retrieve(clean_prompt, namespace=self.namespace, limit=4)
        actions_taken: list[dict[str, Any]] = []
        sim_passed = True

        code_to_test = (candidate_code or "").strip() or extract_python_candidate(clean_prompt)
        if code_to_test:
            sim_passed, action_meta = self._verify_candidate_code(code_to_test, target_label)
            actions_taken.append(action_meta)

        if intent == "generate_brief" or (intent == "inspect_and_plan" and not code_to_test):
            brief_res = generate_architecture_brief(target_label=target_label, target_kind=target_kind)
            if not isinstance(brief_res, NgaError):
                actions_taken.append(
                    {
                        "tool": "brief_gen",
                        "status": "ok",
                        "summary": brief_res.summary,
                    }
                )

        if persist_memory:
            mem_entry = self.vault.store(
                title=f"{intent}:{target_label}",
                body=f"Goal: {clean_prompt}\nActions: {len(actions_taken)}\nSimulationPassed: {sim_passed}",
                namespace=self.namespace,
                tags=[intent, target_kind],
                source="intent_agent",
            )
            if not isinstance(mem_entry, NgaError):
                actions_taken.append(
                    {
                        "tool": "memory_vault.store",
                        "status": "ok",
                        "memory_id": mem_entry.get("id"),
                        "deduplicated": mem_entry.get("deduplicated", False),
                    }
                )

        if self.ledger is not None:
            obl_id = f"turn_{re.sub(r'[^a-zA-Z0-9_]+', '_', target_label).lower()[:32]}_{intent}"
            status = ObligationStatus.VERIFIED if sim_passed else ObligationStatus.IN_PROGRESS
            added = self.ledger.add_obligation(
                obligation_id=obl_id,
                category="agent_turn",
                title=f"{intent}: {clean_prompt[:80]}",
                status=status,
                notes=f"Recalled {len(recalled)} memory item(s); simulation_passed={sim_passed}.",
                evidence_text=clean_prompt[:400],
            )
            if not isinstance(added, NgaError):
                actions_taken.append(
                    {
                        "tool": "ledger.add_obligation",
                        "status": "ok",
                        "handle": added.handle,
                    }
                )

        if self.workspace is not None:
            self.workspace.merkle.append(
                "AGENT_TURN_EXECUTED",
                {
                    "intent": intent,
                    "target_label": target_label,
                    "simulation_passed": sim_passed,
                    "actions_count": len(actions_taken),
                },
            )

        summary = f"Intent '{intent}' completed ({len(actions_taken)} action(s), recalled={len(recalled)})."
        turn_obj = AgentTurnResult(
            intent=intent,
            goal=clean_prompt,
            recalled_memories=recalled,
            actions_taken=actions_taken,
            simulation_passed=sim_passed,
            summary=summary,
            created_at=utc_now_iso(),
        )

        return ToolResponse(
            module="nga.aaire.intent_agent",
            summary=summary,
            simulation_status=SimulationStatus.SIMULATION_PASSED.value if sim_passed else SimulationStatus.SIMULATION_FAILED.value,
            data={"turn": turn_obj.to_dict()},
)
            
