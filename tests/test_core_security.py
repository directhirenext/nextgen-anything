"""Tests for core security guards, handles, SQLite cache, workspace lock/Merkle, ledger, plugins & doctor."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import time
import unittest

from nga.core.cache import NgaCache
from nga.core.contracts import HandleRegistry, NgaError, ObligationStatus
from nga.core.doctor import detect_host_platform, run_environment_doctor
from nga.core.ledger import ObligationLedger
from nga.core.plugins import PluginRegistry
from nga.core.security import (
    apply_output_budget,
    check_python_ast_safety,
    redact_secrets,
    safe_resolve_path,
    sanitize_archive_member_name,
    sanitize_headers,
)
from nga.core.workspace import NgaWorkspace, WorkspaceLock


class CoreSecurityTests(unittest.TestCase):
    def test_secret_redaction_and_headers(self) -> None:
        sample = (
            "Authorization: Bearer super_secret_token_1234567890 "
            "api_key=sk_live_9876543210987654 "
            "bot_url=https://api.telegram.org/bot123456789:AAFakeTokenString_123456789012/sendMessage"
        )
        redacted = redact_secrets(sample)
        self.assertNotIn("super_secret_token_1234567890", redacted)
        self.assertNotIn("sk_live_9876543210987654", redacted)
        self.assertNotIn("AAFakeTokenString_123456789012", redacted)

        headers = sanitize_headers(
            [
                {"name": "Authorization", "value": "Bearer secret"},
                {"name": "X-NGA-Token", "value": "tok_xyz"},
                {"name": "Content-Type", "value": "application/json"},
            ]
        )
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(headers["Authorization"], "[REDACTED_HEADER]")
        self.assertEqual(headers["X-NGA-Token"], "[REDACTED_HEADER]")

    def test_path_traversal_symlink_and_archive_member_guard(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ok_inside, resolved_inside = safe_resolve_path(root, "sub/file.txt")
            self.assertTrue(ok_inside)
            self.assertIsInstance(resolved_inside, Path)

            ok_escape, err_escape = safe_resolve_path(root, "../../etc/passwd")
            self.assertFalse(ok_escape)
            self.assertIsInstance(err_escape, NgaError)

            ok_nul, err_nul = safe_resolve_path(root, "sub/bad\x00.txt")
            self.assertFalse(ok_nul)
            self.assertIsInstance(err_nul, NgaError)

            outside_target = root.parent / f"outside_{time.monotonic_ns()}.txt"
            outside_target.write_text("secret", encoding="utf-8")
            try:
                link_path = root / "escape_link.txt"
                try:
                    link_path.symlink_to(outside_target)
                    ok_sym, err_sym = safe_resolve_path(root, "escape_link.txt")
                    self.assertFalse(ok_sym)
                    self.assertIsInstance(err_sym, NgaError)
                except (OSError, NotImplementedError):
                    pass
            finally:
                outside_target.unlink(missing_ok=True)

        ok_member, safe_member = sanitize_archive_member_name("assets/app.js")
        self.assertTrue(ok_member)
        self.assertEqual(safe_member, "assets/app.js")

        for bad_name in ("../evil.sh", "C:windows_ads.txt", "/abs/path.txt", "~\x00bad", "bad\x00.txt"):
            ok_bad, _ = sanitize_archive_member_name(bad_name)
            self.assertFalse(ok_bad, msg=f"Expected rejection for unsafe archive name: {bad_name!r}")

    def test_ast_safety_and_output_budget(self) -> None:
        safe_res = check_python_ast_safety("x = [i * 2 for i in range(5)]\nprint(sum(x))")
        self.assertTrue(safe_res["safe"])

        for dangerous_snippet in (
            "import subprocess\nsubprocess.run(['echo', 'hi'])",
            "import pathlib\nprint(pathlib.Path('.').resolve())",
            "import io\nprint(io.StringIO('x').getvalue())",
            "x = (1).__class__.__base__.__subclasses__()",
            "def f():\n    import sys\n    return sys._getframe().f_builtins",
        ):
            unsafe_res = check_python_ast_safety(dangerous_snippet)
            self.assertFalse(unsafe_res["safe"], msg=f"Expected AST block for: {dangerous_snippet!r}")

        sliced = apply_output_budget("abcdefghij", max_chars=4, offset=2)
        self.assertEqual(sliced["content"], "cdef")
        self.assertTrue(sliced["truncated"])
        self.assertEqual(sliced["next_offset"], 6)

    def test_handles_cache_ttl_workspace_merkle_and_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            reg = HandleRegistry()
            h1 = reg.register("route::/api/health")
            h2 = reg.register("route::/api/jobs")
            self.assertEqual(h1, 1)
            self.assertEqual(h2, 2)
            self.assertEqual(reg.resolve_key(1), "route::/api/health")

            restored = HandleRegistry.from_dict(reg.to_dict())
            self.assertEqual(restored.resolve_key(2), "route::/api/jobs")

            cache = NgaCache(base / "cache.sqlite", ttl_seconds=60)
            cache.set("ns", "key1", {"val": 123})
            self.assertEqual(cache.get("ns", "key1"), {"val": 123})

            short_cache = NgaCache(base / "short_cache.sqlite", ttl_seconds=1)
            short_cache.set("exp_ns", "k_exp", {"temp": True}, ttl_seconds=1)
            time.sleep(1.15)
            self.assertIsNone(short_cache.get("exp_ns", "k_exp"))

            ws = NgaWorkspace(project_name="test_proj", base_dir=base / "ws")
            ws.set_target("demo.html", "web")
            merkle_check = ws.merkle.verify_integrity()
            self.assertTrue(merkle_check["valid"])

            # Tamper with Merkle block and confirm integrity check catches it
            blocks = json.loads(ws.merkle.chain_path.read_text(encoding="utf-8"))
            blocks[-1]["payload"]["tampered"] = True
            ws.merkle.chain_path.write_text(json.dumps(blocks), encoding="utf-8")
            self.assertFalse(ws.merkle.verify_integrity()["valid"])

            # Lock re-entrancy and stale lock recovery
            lock = WorkspaceLock(base / "test.lock", stale_seconds=1)
            with lock:
                with lock:
                    self.assertTrue(lock.lock_path.exists())
            self.assertFalse(lock.lock_path.exists())

            ledger = ObligationLedger(base / "ledger.json", handles=reg)
            obl = ledger.add_obligation("ep_1", "api", "GET /api/items")
            self.assertNotIsInstance(obl, NgaError)
            updated = ledger.update_status("ep_1", ObligationStatus.VERIFIED)
            self.assertNotIsInstance(updated, NgaError)
            self.assertEqual(ledger.coverage_summary()["verified_percent"], 100.0)

            bad_status = ledger.add_obligation("ep_bad", "api", "Bad", status="not_a_real_status")
            self.assertIsInstance(bad_status, NgaError)

    def test_plugins_and_doctor_isolated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            plug_root = base / "plugins"
            sample_plug = plug_root / "echo_tool"
            sample_plug.mkdir(parents=True)
            script_path = sample_plug / "run_tool.py"
            script_path.write_text(
                "import json, sys\n"
                "req = json.loads(sys.stdin.read())\n"
                "print(json.dumps({'echo': req.get('action'), 'ok': True}))\n",
                encoding="utf-8",
            )
            (sample_plug / "plugin.json").write_text(
                json.dumps(
                    {
                        "name": "echo_tool",
                        "version": "1.0.0",
                        "language": "python",
                        "command": [sys.executable, "run_tool.py"],
                    }
                ),
                encoding="utf-8",
            )

            reg = PluginRegistry(plugins_dir=plug_root)
            found = reg.discover()
            self.assertEqual(len(found), 1)
            inv = reg.invoke("echo_tool", action="ping", payload={"x": 1})
            self.assertNotIsInstance(inv, NgaError)
            assert not isinstance(inv, NgaError)
            self.assertTrue(inv.ok)
            self.assertEqual(inv.data["output"]["echo"], "ping")

            host_info = detect_host_platform()
            self.assertIn("os_id", host_info)
            doc = run_environment_doctor(workspace_root=base / "nga_home")
            self.assertTrue(doc.ok)
            self.assertIn("os_platform", doc.data)
            self.assertIn("python_version", doc.data)


if __name__ == "__main__":
    unittest.main()
        
