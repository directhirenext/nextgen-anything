"""Tests for isolated execution sandbox, simulation gate, and 3-strike stall breaker."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from nga.builder.parity_loop import ParityLoopConfig, ParityVerificationLoop
from nga.core.contracts import ErrorCode, NgaError, SimulationStatus
from nga.runtime.sandbox import ExecutionSandbox
from nga.runtime.simulator import SimulationGate


class SandboxSimulatorTests(unittest.TestCase):
    def test_sandbox_passes_valid_code_and_blocks_unsafe_ast(self) -> None:
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

    def test_simulation_gate_and_parity_stall_breaker(self) -> None:
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

            loop = ParityVerificationLoop(simulator=gate)
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
  
