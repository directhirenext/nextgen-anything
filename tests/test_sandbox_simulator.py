"""Tests for isolated execution sandbox, simulation gate, repair loop, and stall breaker."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from nga.builder.parity_loop import ParityLoopConfig, ParityVerificationLoop
from nga.core.contracts import ErrorCode, NgaError, SimulationStatus
from nga.runtime.sandbox import ExecutionSandbox
from nga.runtime.simulator import SimulationGate


class SandboxSimulatorTests(unittest.TestCase):
    def test_sandbox_passes_valid_code_and_blocks_unsafe_ast_and_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sbx = ExecutionSandbox(base_sandbox_dir=Path(tmp), timeout_seconds=5.0)
            ok_rep = sbx.run_python_snippet("print('SANDBOX_PASS')", target_label="ok_test")
            self.assertNotIsInstance(ok_rep, NgaError)
            assert not isinstance(ok_rep, NgaError)
            self.assertEqual(ok_rep.status, SimulationStatus.SIMULATION_PASSED)
            self.assertIn("SANDBOX_PASS", ok_rep.stdout_preview)

            blocked_rep = sbx.run_python_snippet("import os\nos.system('id')", target_label="blocked_test")
            self.assertNotIsInstance(blocked_rep, NgaError)
            assert not isinstance(blocked_rep, NgaError)
            self.assertEqual(blocked_rep.status, SimulationStatus.BLOCKED)

            blocked_helper = sbx.run_python_snippet(
                code="import helper_mod\nprint(helper_mod.run())",
                target_label="helper_ast_test",
                files={"helper_mod.py": "import subprocess\ndef run():\n    return subprocess.getoutput('id')\n"},
            )
            self.assertNotIsInstance(blocked_helper, NgaError)
            assert not isinstance(blocked_helper, NgaError)
            self.assertEqual(blocked_helper.status, SimulationStatus.BLOCKED)

            ok_helper = sbx.run_python_snippet(
                code="import helper_ok\nprint('HELPER_VAL:', helper_ok.compute(6))",
                target_label="helper_ok_test",
                files={"helper_ok.py": "def compute(n):\n    return n * 3\n"},
            )
            self.assertNotIsInstance(ok_helper, NgaError)
            assert not isinstance(ok_helper, NgaError)
            self.assertEqual(ok_helper.status, SimulationStatus.SIMULATION_PASSED)
            self.assertIn("HELPER_VAL: 18", ok_helper.stdout_preview)

    def test_sandbox_timeout_termination(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sbx = ExecutionSandbox(base_sandbox_dir=Path(tmp), timeout_seconds=1.0, keep_failed_runs=False)
            rep = sbx.run_python_snippet("while True:\n    pass\n", target_label="infinite_loop")
            self.assertNotIsInstance(rep, NgaError)
            assert not isinstance(rep, NgaError)
            self.assertEqual(rep.status, SimulationStatus.SIMULATION_FAILED)
            self.assertTrue(any("timeout" in c for c in rep.checks_failed))

    def test_simulation_gate_payload_repair_and_parity_stall_breaker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sbx = ExecutionSandbox(base_sandbox_dir=Path(tmp), timeout_seconds=5.0)
            gate = SimulationGate(sandbox=sbx)

            sim_res = gate.simulate_crafted_python(
                code="def add(a, b):\n    return a + b\n",
                smoke_assertions_code="assert add(2, 3) == 5\nprint('ASSERT_OK')\n",
                target_label="add_fn",
            )
            self.assertNotIsInstance(sim_res, NgaError)
            assert not isinstance(sim_res, NgaError)
            self.assertTrue(sim_res.passed)

            payload_check = gate.simulate_tool_payload("sample_tool", {"items": [1, 2, 3]})
            self.assertNotIsInstance(payload_check, NgaError)
            assert not isinstance(payload_check, NgaError)
            self.assertTrue(payload_check.ok)

            loop = ParityVerificationLoop(simulator=gate)

            # Repair callback fixes a failing first attempt into a passing second attempt
            def _repair_once(_bad_code: str, _rep: object, _attempt: int) -> str:
                return "def mul(a, b):\n    return a * b\nassert mul(3, 4) == 12\nprint('REPAIRED_OK')\n"

            repaired_res = loop.run_candidates(
                [{"label": "repair_case", "code": "assert 1 == 2"}],
                config=ParityLoopConfig(max_iterations=3, stall_threshold=3, max_repairs_per_candidate=2),
                repair_fn=_repair_once,
            )
            self.assertNotIsInstance(repaired_res, NgaError)
            assert not isinstance(repaired_res, NgaError)
            self.assertTrue(repaired_res.data.get("passed"))

            # 3 identical errors trigger STALL_DETECTED
            failing_candidates = [
                {"label": "bad_1", "code": "raise ValueError('same_error')"},
                {"label": "bad_2", "code": "raise ValueError('same_error')"},
                {"label": "bad_3", "code": "raise ValueError('same_error')"},
            ]
            stall_res = loop.run_candidates(
                failing_candidates,
                config=ParityLoopConfig(max_iterations=3, stall_threshold=3),
            )
            self.assertIsInstance(stall_res, NgaError)
            assert isinstance(stall_res, NgaError)
            self.assertEqual(stall_res.error_code, ErrorCode.STALL_DETECTED.value)


if __name__ == "__main__":
    unittest.main()
