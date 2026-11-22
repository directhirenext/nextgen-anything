"""Tests for multi-file project synthesizer, memory vault, intent agent, and telegram bridge."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from nga.aaire.intent_agent import AutonomousIntentAgent
from nga.aaire.memory_vault import AaireMemoryVault
from nga.aaire.telegram_bridge import TelegramBotBridge
from nga.builder.synthesizer import AutonomousProjectSynthesizer
from nga.core.contracts import ErrorCode, NgaError, SimulationStatus
from nga.core.ledger import ObligationLedger
from nga.core.workspace import NgaWorkspace
from nga.interfaces.cli import main as cli_main
from nga.runtime.sandbox import ExecutionSandbox
from nga.runtime.simulator import SimulationGate


class SynthesizerAndAgentTests(unittest.TestCase):
    def test_synthesizer_generates_verified_multifile_project(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = NgaWorkspace(project_name="synth_proj", base_dir=root / "ws")
            ledger = ObligationLedger(root / "ledger.json", handles=ws.get_handles())
            sbx = ExecutionSandbox(base_sandbox_dir=root / "sbx", timeout_seconds=10.0)
            sim = SimulationGate(sandbox=sbx)

            synth = AutonomousProjectSynthesizer(simulator=sim, workspace=ws, ledger=ledger)
            findings = {
                "endpoints": [
                    {"method": "GET", "path": "/api/items", "status": 200},
                    {"method": "POST", "path": "/api/items", "status": 200},
                ]
            }
            res = synth.synthesize_project(
                app_name="SampleService",
                findings=findings,
                output_dir="out_app",
                base_root=root,
            )
            self.assertNotIsInstance(res, NgaError)
            assert not isinstance(res, NgaError)
            self.assertEqual(res.simulation_status, SimulationStatus.SIMULATION_PASSED.value)
            self.assertTrue((root / "out_app" / "app" / "server.py").is_file())
            self.assertTrue((root / "out_app" / "app" / "public" / "index.html").is_file())
            self.assertTrue((root / "out_app" / "tests" / "test_reconstructed_app.py").is_file())
            self.assertTrue((root / "out_app" / "reconstruction_manifest.json").is_file())

    def test_memory_vault_intent_agent_and_telegram_bridge(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            vault = AaireMemoryVault(root / "vault.sqlite")
            stored = vault.store(
                title="Sandbox Policy",
                body="Always verify generated Python code in an isolated sandbox before output.",
                namespace="agent_ns",
                tags=["policy", "sandbox"],
            )
            self.assertNotIsInstance(stored, NgaError)
            hits = vault.retrieve("isolated sandbox verification", namespace="agent_ns", limit=3)
            self.assertGreaterEqual(len(hits), 1)

            sbx = ExecutionSandbox(base_sandbox_dir=root / "sbx", timeout_seconds=10.0)
            sim = SimulationGate(sandbox=sbx)
            agent = AutonomousIntentAgent(vault=vault, simulator=sim, namespace="agent_ns")
            turn = agent.run_turn(
                prompt="Run sandbox check on math helper",
                candidate_code="def double(n):\n    return n * 2\nassert double(4) == 8\nprint('DOUBLE_OK')\n",
                target_label="double_helper",
            )
            self.assertNotIsInstance(turn, NgaError)
            assert not isinstance(turn, NgaError)
            self.assertEqual(turn.simulation_status, SimulationStatus.SIMULATION_PASSED.value)

            bridge = TelegramBotBridge(allowed_chat_ids=[1001], agent=agent, simulator=sim)
            blocked = bridge.process_update(
                {"update_id": 1, "message": {"chat": {"id": 9999}, "text": "/doctor"}}
            )
            self.assertIsInstance(blocked, NgaError)
            assert isinstance(blocked, NgaError)
            self.assertEqual(blocked.error_code, ErrorCode.SANDBOX_VIOLATION.value)

            allowed = bridge.process_update(
                {"update_id": 2, "message": {"chat": {"id": 1001}, "text": "/sim print('TG_OK')"}}
            )
            self.assertNotIsInstance(allowed, NgaError)
            assert not isinstance(allowed, NgaError)
            self.assertIn("TG_OK", allowed.data.get("reply_text", ""))

    def test_cli_synthesize_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            findings_str = json.dumps({"routes": ["/api/health"]})
            rc = cli_main(
                [
                    "--root",
                    str(root),
                    "synthesize",
                    "--name",
                    "cli_svc",
                    "--findings-json",
                    findings_str,
                    "--out",
                    "cli_out",
                ]
            )
            self.assertEqual(rc, 0)
            self.assertTrue((root / "cli_out" / "app" / "server.py").is_file())


if __name__ == "__main__":
    unittest.main()
      
