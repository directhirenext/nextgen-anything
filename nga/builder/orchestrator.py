"""DAG task planner and workflow orchestrator for NextGen-Anything (`nga`)."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any

from nga.core.contracts import ErrorCode, NgaError, ToolResponse, utc_now_iso
from nga.core.security import redact_secrets
from nga.core.workspace import NgaWorkspace


@dataclass
class DagNode:
    """Represents a single task node inside a directed acyclic execution plan."""

    node_id: str
    title: str
    action: str
    depends_on: list[str] = field(default_factory=list)
    params: dict[str, Any] = field(default_factory=dict)
    status: str = "pending"
    output: dict[str, Any] | None = None
    error: dict[str, Any] | None = None


class WorkflowOrchestrator:
    """Builds and executes dependency-ordered DAG plans across `nga` modules with real data passing."""

    def __init__(self, workspace: NgaWorkspace | None = None) -> None:
        self.workspace = workspace if workspace is not None else NgaWorkspace()

    def build_default_plan(self, target: str, target_type: str = "auto") -> list[DagNode] | NgaError:
        """Create a deterministic 4-stage DAG plan for a given non-empty target."""
        clean_target = redact_secrets(str(target or "")).strip()
        if not clean_target:
            return NgaError(
                error_code=ErrorCode.INVALID_INPUT.value,
                module="nga.builder.orchestrator",
                message="DAG plan target cannot be empty.",
                recoverable=True,
                suggested_fix="Provide a non-empty target path, URL, or label.",
            )

        clean_type = str(target_type or "auto").strip() or "auto"
        return [
            DagNode(
                node_id="n1_inspect",
                title="Inspect Target Structure & Contracts",
                action="inspect",
                depends_on=[],
                params={"target": clean_target, "target_type": clean_type},
            ),
            DagNode(
                node_id="n2_ledger",
                title="Populate Reconstruction Obligation Ledger",
                action="ledger_sync",
                depends_on=["n1_inspect"],
                params={"target": clean_target, "target_type": clean_type},
            ),
            DagNode(
                node_id="n3_brief",
                title="Generate Clean-Room Architecture Brief",
                action="brief",
                depends_on=["n2_ledger"],
                params={"target": clean_target, "target_type": clean_type},
            ),
            DagNode(
                node_id="n4_simulate_verify",
                title="Simulate & Verify Ready State in Sandbox",
                action="simulate_check",
                depends_on=["n3_brief"],
                params={"target": clean_target, "target_type": clean_type},
            ),
        ]

    @staticmethod
    def topological_sort(nodes: list[DagNode]) -> list[DagNode] | NgaError:
        """Order DAG nodes respecting dependencies and detect cycles."""
        if not isinstance(nodes, list) or not nodes:
            return NgaError(
                error_code=ErrorCode.INVALID_INPUT.value,
                module="nga.builder.orchestrator",
                message="DAG plan must contain at least one DagNode.",
                recoverable=True,
            )

        by_id: dict[str, DagNode] = {}
        for n in nodes:
            if not isinstance(n, DagNode) or not str(n.node_id).strip():
                return NgaError(
                    error_code=ErrorCode.INVALID_INPUT.value,
                    module="nga.builder.orchestrator",
                    message="Every DAG entry must be a DagNode with a non-empty node_id.",
                    recoverable=True,
                )
            if n.node_id in by_id:
                return NgaError(
                    error_code=ErrorCode.INVALID_INPUT.value,
                    module="nga.builder.orchestrator",
                    message=f"Duplicate node_id found in DAG plan: '{n.node_id}'.",
                    recoverable=True,
                    suggested_fix="Ensure every DagNode has a unique node_id.",
                )
            by_id[n.node_id] = n

        visited: set[str] = set()
        visiting: set[str] = set()
        ordered: list[DagNode] = []

        def _dfs(nid: str) -> NgaError | None:
            if nid in visited:
                return None
            if nid in visiting:
                return NgaError(
                    error_code=ErrorCode.INVALID_INPUT.value,
                    module="nga.builder.orchestrator",
                    message=f"Cycle detected in DAG around node '{nid}'.",
                    recoverable=True,
                    suggested_fix="Remove circular dependencies in depends_on lists.",
                )
            node = by_id.get(nid)
            if node is None:
                return NgaError(
                    error_code=ErrorCode.NOT_FOUND.value,
                    module="nga.builder.orchestrator",
                    message=f"Unknown dependency node_id '{nid}'.",
                    recoverable=True,
                    suggested_fix="Check depends_on references against defined nodes.",
                )
            visiting.add(nid)
            for dep in node.depends_on:
                err = _dfs(dep)
                if err is not None:
                    return err
            visiting.remove(nid)
            visited.add(nid)
            ordered.append(node)
            return None

        for n in nodes:
            err = _dfs(n.node_id)
            if err is not None:
                return err

        return ordered

    def run_plan(self, nodes: list[DagNode], runner_map: dict[str, Any] | None = None) -> ToolResponse | NgaError:
        """Execute DAG nodes in topological order, passing dependency outputs to downstream nodes."""
        ordered = self.topological_sort(nodes)
        if isinstance(ordered, NgaError):
            return ordered

        handlers = runner_map if isinstance(runner_map, dict) else {}
        completed_ids: set[str] = set()
        node_outputs: dict[str, dict[str, Any]] = {}
        execution_log: list[dict[str, Any]] = []
        working_nodes = [deepcopy(n) for n in ordered]

        self.workspace.log_journal("orchestrator", f"Starting DAG plan with {len(working_nodes)} node(s).")

        for node in working_nodes:
            unmet = [d for d in node.depends_on if d not in completed_ids]
            if unmet:
                node.status = "skipped"
                node.error = {"reason": f"Unmet dependencies: {unmet}"}
                execution_log.append(
                    {
                        "node_id": node.node_id,
                        "action": node.action,
                        "status": node.status,
                        "error": node.error,
                    }
                )
                continue

            fn = handlers.get(node.action)
            if not callable(fn):
                missing_err = NgaError(
                    error_code=ErrorCode.TOOL_UNAVAILABLE.value,
                    module="nga.builder.orchestrator",
                    message=f"No executable handler bound for DAG action '{node.action}' at node '{node.node_id}'.",
                    recoverable=True,
                    suggested_fix=f"Provide a callable handler for action '{node.action}' in runner_map.",
                )
                node.status = "failed"
                node.error = missing_err.to_dict()
                self.workspace.merkle.append(
                    "DAG_NODE_FAILED",
                    {"node_id": node.node_id, "action": node.action, "error_code": missing_err.error_code},
                )
                execution_log.append(
                    {
                        "node_id": node.node_id,
                        "action": node.action,
                        "status": node.status,
                        "error": node.error,
                    }
                )
                return NgaError(
                    error_code=missing_err.error_code,
                    module="nga.builder.orchestrator",
                    message=missing_err.message,
                    recoverable=True,
                    suggested_fix=missing_err.suggested_fix,
                    details={"completed_nodes": sorted(completed_ids), "log": execution_log},
                )

            enriched_params = dict(node.params or {})
            dep_payloads = {dep: node_outputs[dep] for dep in node.depends_on if dep in node_outputs}
            if dep_payloads:
                enriched_params["dependency_outputs"] = dep_payloads
                enriched_params["previous_output"] = node_outputs[node.depends_on[-1]]

            try:
                res = fn(enriched_params)
                if isinstance(res, NgaError):
                    node.status = "failed"
                    node.error = res.to_dict()
                    self.workspace.merkle.append(
                        "DAG_NODE_FAILED",
                        {"node_id": node.node_id, "error_code": res.error_code},
                    )
                    execution_log.append(
                        {
                            "node_id": node.node_id,
                            "action": node.action,
                            "status": node.status,
                            "error": node.error,
                        }
                    )
                    return NgaError(
                        error_code=res.error_code,
                        module="nga.builder.orchestrator",
                        message=f"DAG aborted at node '{node.node_id}': {res.message}",
                        recoverable=res.recoverable,
                        suggested_fix=res.suggested_fix,
                        details={"completed_nodes": sorted(completed_ids), "log": execution_log},
                    )

                serialized_out = res.to_dict() if hasattr(res, "to_dict") else (res if isinstance(res, dict) else {"result": res})
                node.status = "completed"
                node.output = serialized_out
                node_outputs[node.node_id] = serialized_out
                completed_ids.add(node.node_id)
                execution_log.append(
                    {
                        "node_id": node.node_id,
                        "action": node.action,
                        "status": node.status,
                        "timestamp": utc_now_iso(),
                    }
                )
            except Exception as exc:
                safe_exc = redact_secrets(str(exc))
                node.status = "failed"
                node.error = {"exception": safe_exc}
                self.workspace.merkle.append(
                    "DAG_NODE_FAILED",
                    {"node_id": node.node_id, "error_code": ErrorCode.INTERNAL_ERROR.value},
                )
                return NgaError(
                    error_code=ErrorCode.INTERNAL_ERROR.value,
                    module="nga.builder.orchestrator",
                    message=f"Unhandled error in DAG node '{node.node_id}': {safe_exc}",
                    recoverable=True,
                    suggested_fix="Inspect node parameters and handler implementation.",
                    details={"log": execution_log},
                )

        self.workspace.merkle.append(
            "DAG_PLAN_COMPLETED",
            {"completed_count": len(completed_ids), "total_nodes": len(working_nodes)},
        )

        return ToolResponse(
            module="nga.builder.orchestrator",
            summary=f"DAG plan finished: {len(completed_ids)}/{len(working_nodes)} node(s) completed.",
            data={
                "completed_nodes": sorted(completed_ids),
                "total_nodes": len(working_nodes),
                "node_outputs": node_outputs,
                "execution_log": execution_log,
            },
        )
        
