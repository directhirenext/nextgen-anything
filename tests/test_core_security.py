"""Tests for core security guards, handles, SQLite cache, workspace Merkle log, and ledger."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from nga.core.cache import NgaCache
from nga.core.contracts import HandleRegistry, NgaError, ObligationStatus
from nga.core.ledger import ObligationLedger
from nga.core.security import (
    apply_output_budget,
    check_python_ast_safety,
    redact_secrets,
    safe_resolve_path,
    sanitize_archive_member_name,
    sanitize_headers,
)
from nga.core.workspace import NgaWorkspace


class CoreSecurityTests(unittest.TestCase):
    def test_secret_redaction_and_headers(self) -> None:
        sample = "Authorization: Bearer super_secret_token_1234567890 api_key=sk_live_9876543210987654"
        redacted = redact_secrets(sample)
        self.assertNotIn("super_secret_token_1234567890", redacted)
        self.assertNotIn("sk_live_9876543210987654", redacted)

        headers = sanitize_headers(
            [
                {"name": "Authorization", "value": "Bearer secret"},
                {"name": "Content-Type", "value": "application/json"},
            ]
        )
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertNotEqual(headers["Authorization"], "Bearer secret")

    def test_path_traversal_and_archive_member_guard(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ok_inside, resolved_inside = safe_resolve_path(root, "sub/file.txt")
            self.assertTrue(ok_inside)
            self.assertIsInstance(resolved_inside, Path)

            ok_escape, err_escape = safe_resolve_path(root, "../../etc/passwd")
            self.assertFalse(ok_escape)
            self.assertIsInstance(err_escape, NgaError)

        ok_member, safe_member = sanitize_archive_member_name("assets/app.js")
        self.assertTrue(ok_member)
        self.assertEqual(safe_member, "assets/app.js")

        bad_member, _ = sanitize_archive_member_name("../evil.sh")
        self.assertFalse(bad_member)

    def test_ast_safety_and_output_budget(self) -> None:
        safe_res = check_python_ast_safety("x = [i * 2 for i in range(5)]\nprint(sum(x))")
        self.assertTrue(safe_res["safe"])

        unsafe_res = check_python_ast_safety("import subprocess\nsubprocess.run(['echo', 'hi'])")
        self.assertFalse(unsafe_res["safe"])

        sliced = apply_output_budget("abcdefghij", max_chars=4, offset=2)
        self.assertEqual(sliced["content"], "cdef")
        self.assertTrue(sliced["truncated"])
        self.assertEqual(sliced["next_offset"], 6)

    def test_handles_cache_workspace_and_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            reg = HandleRegistry()
            h1 = reg.register("route::/api/health")
            h2 = reg.register("route::/api/jobs")
            self.assertEqual(h1, 1)
            self.assertEqual(h2, 2)
            self.assertEqual(reg.resolve_key(1), "route::/api/health")

            cache = NgaCache(base / "cache.sqlite", ttl_seconds=60)
            cache.set("ns", "key1", {"val": 123})
            self.assertEqual(cache.get("ns", "key1"), {"val": 123})

            ws = NgaWorkspace(project_name="test_proj", base_dir=base / "ws")
            ws.set_target("demo.html", "web")
            merkle_check = ws.merkle.verify_integrity()
            self.assertTrue(merkle_check["valid"])

            ledger = ObligationLedger(base / "ledger.json", handles=reg)
            obl = ledger.add_obligation("ep_1", "api", "GET /api/items")
            self.assertNotIsInstance(obl, NgaError)
            updated = ledger.update_status("ep_1", ObligationStatus.VERIFIED)
            self.assertNotIsInstance(updated, NgaError)
            self.assertEqual(ledger.coverage_summary()["verified_percent"], 100.0)


if __name__ == "__main__":
    unittest.main()
      
