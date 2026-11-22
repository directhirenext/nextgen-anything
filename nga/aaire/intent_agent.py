"""Autonomous intent classifier, tool planner, and sandbox-verified agent runner for nga."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any

from nga.aaire.llm_engine import UniversalLlmEngine
from nga.aaire.memory_vault import AaireMemoryVault, _normalize_namespace
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

_PYTHON_BLOCK_RE = re.compile(r"```(?:python|py)\s*\n([\s\S]*?)```", re.IGNORECASE)
_GENERIC_BLOCK_RE = re.compile(r"```\s*\n([\s\S]*?)```")


@dataclass
class AgentTurnResult:
    """Structured output produced after executing a single autonomous agent turn."""

    intent: str
    goal: str
    execution_mode: str
    recalled_memories: list[dict[str, Any]]
    actions_taken: list[dict[str, Any]]
    simulation_executed: bool
    simulation_passed: bool
    generated_code: str
    summary: str
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "intent": self.intent,
            "goal": self.goal,
            "execution_mode": self.execution_mode,
            "recalled_memories": self.recalled_memories,
            "actions_taken": self.actions_taken,
            "simulation_executed": self.simulation_executed,
            "simulation_passed": self.simulation_passed,
            "generated_code": self.generated_code,
            "summary": self.summary,
            "created_at": self.created_at,
        }


def classify_user_intent(prompt: str) -> str:
    """Classify a user request into a deterministic action intent."""
    text = str(prompt or "").lower()
    if any(k in text for k in ("simulate", "sandbox", "verify code", "test snippet", "run code")):
        return "simulate_code"
    if any(k in text for k in ("build", "create", "synthesize", "generate app", "reconstruct", "add feature")):
        return "build_or_synthesize"
    if any(k in text for k in ("blueprint", "architecture", "brief", "design")):
        return "generate_brief"
    if any(k in text for k in ("remember", "store note", "save memory", "vault")):
        return "store_memory"
    if any(k in text for k in ("inspect", "analyze", "scan", "endpoint", "route")):
        return "inspect_and_plan"
    return "autonomous_task"


def extract_python_candidate(prompt: str) -> str:
    """Extract embedded Python code block safely without misclassifying JSON or plain logs."""
    raw = str(prompt or "")
    py_match = _PYTHON_BLOCK_RE.search(raw)
    if py_match:
        return py_match.group(1).strip()

    gen_match = _GENERIC_BLOCK_RE.search(raw)
    if gen_match:
        snippet = gen_match.group(1).strip()
        if snippet and not snippet.startswith(("{", "[")) and any(
            kw in snippet for kw in ("def ", "class ", "import ", "assert ", "print(", "return ", "for ", "if ")
        ):
            return snippet
    return ""


def _parse_verification_result(outcome: Any) -> tuple[bool, int, str, str]:
    """Normalize return values from ParityVerificationLoop or SimulationGate."""
    if isinstance(outcome, NgaError):
        details = outcome.details if isinstance(outcome.details, dict) else {}
        history = details.get("history") if isinstance(details.get("history"), list) else []
        return False, len(history), outcome.message, ""
    if isinstance(outcome, SimulationReport):
        return bool(outcome.passed), 1, outcome.status.value, ""
    if isinstance(outcome, ToolResponse):
        payload = outcome.data if isinstance(outcome.data, dict) else {}
        history = payload.get("history") if isinstance(payload.get("history"), list) else []
        passed = bool(
            payload.get(
                "passed",
                bool(outcome.ok) and outcome.simulation_status == SimulationStatus.SIMULATION_PASSED.value,
            )
        )
        iters = len(history) if history else int(payload.get("iterations_used", payload.get("attempts", 1)) or 1)
        verified_code = str(payload.get("verified_code", "") or "")
        return passed, iters, outcome.summary, verified_code
    if isinstance(outcome, dict):
        passed = bool(outcome.get("passed", outcome.get("ok", False)))
        iters = int(outcome.get("iterations_used", outcome.get("attempts", 1)) or 1)
        return passed, iters, str(outcome.get("summary", "")), str(outcome.get("verified_code", "") or "")
    return False, 0, "Unknown verification output", ""


class AutonomousIntentAgent:
    """Executes goal-driven turns using memory vault recall, universal LLM (optional), and sandbox gate."""

    def __init__(
        self,
        vault: AaireMemoryVault | None = None,
        simulator: SimulationGate | None = None,
        ledger: ObligationLedger | None = None,
        workspace: NgaWorkspace | None = None,
        llm_engine: UniversalLlmEngine | None = None,
        namespace: str = "agent_core",
    ) -> None:
        self.namespace = _normalize_namespace(namespace)
        self.vault = vault if vault is not None else AaireMemoryVault()
        self.simulator = simulator if simulator is not None else SimulationGate()
        self.ledger = ledger
        self.workspace = workspace
        self.llm = llm_engine if llm_engine is not None else UniversalLlmEngine()
        self.parity_loop = ParityVerificationLoop(
            simulator=self.simulator,
            workspace=self.workspace,
            ledger=self.ledger,
        )

    def _llm_repair_callback(self, bad_code: str, report: SimulationReport, attempt: int) -> str | None:
        """Ask the configured universal LLM to repair failing sandbox code when available."""
        if not self.llm.is_configured():
            return None
        repair_prompt = (
            f"Fix the following Python code (attempt {attempt}) which failed sandbox verification.\n"
            f"Status: {report.status.value}\n"
            f"Failed checks: {report.checks_failed}\n"
            f"Stderr: {report.stderr_preview[:1000]}\n\n"
            f"Code:\n```python\n{bad_code}\n```\n"
            "Return ONLY a single ```python ... ``` code block using safe Python stdlib modules (no os/subprocess/open)."
        )
        res = self.llm.complete(repair_prompt, temperature=0.1)
        if isinstance(res, NgaError):
            return None
        return extract_python_candidate(res.get("text", "")) or None

    def _verify_candidate_code(self, code: str, target_label: str) -> tuple[bool, dict[str, Any], str]:
        """Run code through parity verification loop with optional LLM-assisted repair."""
        candidates = [{"label": target_label, "code": code}]
        repair_fn = self._llm_repair_callback if self.llm.is_configured() else None
        loop_res = self.parity_loop.run_candidates(
            candidates,
            config=ParityLoopConfig(max_iterations=3, stall_threshold=2),
            repair_fn=repair_fn,
        )
        passed, iters, detail, verified_code = _parse_verification_result(loop_res)
        return (
            passed,
            {
                "tool": "parity_loop",
                "status": "passed" if passed else "failed",
                "iterations_used": iters,
                "detail": detail,
            },
            verified_code or (code if passed else ""),
        )

    def run_turn(
        self,
        prompt: str,
        candidate_code: str = "",
        target_label: str = "agent_goal",
        target_kind: str = "web",
        persist_memory: bool = True,
    ) -> ToolResponse | NgaError:
        """Execute a complete autonomous turn with memory recall, optional LLM synthesis, and sandbox gate."""
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
        llm_active = self.llm.is_configured()
        execution_mode = f"universal_llm:{self.llm.detect_protocol()}" if llm_active else "offline_deterministic"

        code_to_test = (candidate_code or "").strip() or extract_python_candidate(clean_prompt)
        if not code_to_test and llm_active and intent in {"simulate_code", "build_or_synthesize", "autonomous_task"}:
            context_notes = "\n".join(f"- {m.get('title', '')}: {m.get('body', '')[:200]}" for m in recalled)
            gen_prompt = (
                f"Goal: {clean_prompt}\n"
                f"Target kind: {target_kind}\n"
                f"Recalled context:\n{context_notes or '(none)'}\n\n"
                "Write self-contained, deterministic Python code with built-in `assert` smoke tests "
                "implementing this goal using safe pure-Python modules (json, sqlite3, re, math, datetime, collections, itertools). "
                "Output ONLY a ```python ... ``` block."
            )
            llm_out = self.llm.complete(gen_prompt)
            if isinstance(llm_out, NgaError):
                actions_taken.append(
                    {
                        "tool": "universal_llm",
                        "status": "error",
                        "error_code": llm_out.error_code,
                        "detail": llm_out.message,
                    }
                )
            else:
                extracted = extract_python_candidate(llm_out.get("text", ""))
                actions_taken.append(
                    {
                        "tool": "universal_llm",
                        "status": "ok",
                        "model": llm_out.get("model", ""),
                        "code_extracted": bool(extracted),
                    }
                )
                if extracted:
                    code_to_test = extracted

        sim_executed = False
        sim_passed = False
        final_verified_code = ""

        if code_to_test:
            sim_executed = True
            sim_passed, action_meta, final_verified_code = self._verify_candidate_code(code_to_test, target_label)
            actions_taken.append(action_meta)

        if intent in {"generate_brief", "inspect_and_plan", "build_or_synthesize"}:
            brief_res = generate_architecture_brief(target_label=target_label, target_kind=target_kind)
            if isinstance(brief_res, NgaError):
                actions_taken.append({"tool": "brief_gen", "status": "error", "detail": brief_res.message})
            else:
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
                body=(
                    f"Goal: {clean_prompt}\n"
                    f"Mode: {execution_mode}\n"
                    f"Actions: {len(actions_taken)}\n"
                    f"SimulationExecuted: {sim_executed}\n"
                    f"SimulationPassed: {sim_passed}"
                ),
                namespace=self.namespace,
                tags=[intent, target_kind],
                source="intent_agent",
            )
            if isinstance(mem_entry, NgaError):
                actions_taken.append({"tool": "memory_vault.store", "status": "error", "detail": mem_entry.message})
            else:
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
            status = (
                ObligationStatus.VERIFIED
                if (sim_executed and sim_passed)
                else ObligationStatus.IN_PROGRESS
            )
            added = self.ledger.add_obligation(
                obligation_id=obl_id,
                category="agent_turn",
                title=f"{intent}: {clean_prompt[:80]}",
                status=status,
                notes=f"Mode={execution_mode}; recalled={len(recalled)}; sim_executed={sim_executed}; sim_passed={sim_passed}.",
                evidence_text=final_verified_code or clean_prompt[:400],
            )
            if isinstance(added, NgaError):
                actions_taken.append({"tool": "ledger.add_obligation", "status": "error", "detail": added.message})
            else:
                actions_taken.append(
                    {
                        "tool": "ledger.add_obligation",
                        "status": "ok",
                        "handle": added.handle,
                        "obligation_status": status.value,
                    }
                )

        if self.workspace is not None:
            self.workspace.merkle.append(
                "AGENT_TURN_EXECUTED",
                {
                    "intent": intent,
                    "execution_mode": execution_mode,
                    "target_label": target_label,
                    "simulation_executed": sim_executed,
                    "simulation_passed": sim_passed,
                    "actions_count": len(actions_taken),
                },
            )

        if sim_executed:
            sim_status = (
                SimulationStatus.SIMULATION_PASSED.value
                if sim_passed
                else SimulationStatus.SIMULATION_FAILED.value
            )
        else:
            sim_status = SimulationStatus.PENDING.value

        summary = (
            f"Intent '{intent}' [{execution_mode}] completed "
            f"({len(actions_taken)} action(s), recalled={len(recalled)}, sim={sim_status})."
        )
        turn_obj = AgentTurnResult(
            intent=intent,
            goal=clean_prompt,
            execution_mode=execution_mode,
            recalled_memories=recalled,
            actions_taken=actions_taken,
            simulation_executed=sim_executed,
            simulation_passed=sim_passed,
            generated_code=final_verified_code,
            summary=summary,
            created_at=utc_now_iso(),
        )

        return ToolResponse(
            module="nga.aaire.intent_agent",
            ok=(not sim_executed) or sim_passed,
            summary=summary,
            simulation_status=sim_status,
            data={"turn": turn_obj.to_dict()},
)
