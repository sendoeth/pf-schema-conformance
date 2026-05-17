#!/usr/bin/env python3
"""
test_conformance.py — Unit tests for schema conformance checker and verifier.

Tests cover:
  - Mismatch checkers (ActionFieldMissing)
  - Snapshot comparison logic
  - Receipt builder
  - Verifier categories
  - CLI integration
  - Edge cases

Run: python3 -m pytest tests/test_conformance.py -v
  OR: python3 tests/test_conformance.py
"""

import copy
import hashlib
import json
import os
import sys
import tempfile
import unittest

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from check_conformance import (
    ActionFieldMissing,
    ConformanceReceiptBuilder,
    MISMATCH_REGISTRY,
    extract_signals,
    sha256_bytes,
    sha256_dict,
    iso_now,
    run_snapshot_check,
    load_schema_requirements,
)
from verify_conformance import (
    run_verification,
    verify_structure,
    verify_receipt_id,
    verify_timestamp,
    verify_producer,
    verify_canonical_schema,
    verify_mismatch,
    verify_patch,
    verify_before,
    verify_after,
    verify_comparison,
    verify_conformance_summary,
    verify_command,
    verify_source_hashes,
    verify_content_hash,
    verify_limitations,
    verify_cross_references,
    is_hex64,
    is_iso_timestamp,
)


# ── Test Fixtures ──────────────────────────────────────────────────────────────

def make_signal(symbol="BTC", action="WITHHOLD", with_weak_symbol=False, **overrides):
    sig = {
        "signal_id": f"pf-{symbol}-{1779000000000}",
        "symbol": symbol,
        "direction": "NEUTRAL",
        "signal_type": "TRANSITION_TIMING",
        "confidence": 0.51,
        "expected_karma": 0.02,
        "horizon_hours": 24,
        "action": action,
        "regime": "SYSTEMIC",
        "regime_confidence": 77,
        "regime_duration_days": 72,
        "proximity": 0.012,
        "voi_included": True,
        "voi_suppressed": False,
        "duration_gated": False,
        "weak_symbol_inverted": action == "INVERT",
        "policy_gates_applied": {
            "weak_symbol": action == "INVERT",
            "duration_gate": False,
            "voi_filter": False,
            "regime_filter": True,
        },
        "timestamp": "2026-05-17T10:00:00.000Z",
    }
    if with_weak_symbol:
        sig["weak_symbol"] = {
            "weakness_score": 0.56,
            "severity": "MODERATE",
            "original_direction": "bullish",
            "inversion_p_value": 0.0039,
        }
    sig.update(overrides)
    return sig


def make_endpoint_data(signals):
    return {
        "schema": "pf-sovereign-signals/v1",
        "producer_id": "post-fiat-signals",
        "generated_at": "2026-05-17T10:00:00.000Z",
        "signals": {
            "published": signals,
            "suppressed": [],
            "total_generated": len(signals),
            "total_published": len(signals),
            "total_suppressed": 0,
        },
    }


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMA_PATH = os.path.join(REPO_ROOT, "producer_signal_schema.json")
RECEIPT_PATH = os.path.join(REPO_ROOT, "conformance_receipt.json")


# ── Helpers Tests ──────────────────────────────────────────────────────────────

class TestHelpers(unittest.TestCase):
    def test_sha256_bytes(self):
        h = sha256_bytes(b"hello")
        self.assertEqual(len(h), 64)
        self.assertTrue(all(c in "0123456789abcdef" for c in h))

    def test_sha256_dict_deterministic(self):
        d = {"a": 1, "b": 2}
        self.assertEqual(sha256_dict(d), sha256_dict(d))

    def test_sha256_dict_order_independent(self):
        d1 = {"a": 1, "b": 2}
        d2 = {"b": 2, "a": 1}
        self.assertEqual(sha256_dict(d1), sha256_dict(d2))

    def test_iso_now_format(self):
        ts = iso_now()
        self.assertTrue(ts.endswith("Z"))
        self.assertIn("T", ts)

    def test_is_hex64_valid(self):
        self.assertTrue(is_hex64("a" * 64))
        self.assertTrue(is_hex64("0123456789abcdef" * 4))

    def test_is_hex64_invalid(self):
        self.assertFalse(is_hex64("a" * 63))
        self.assertFalse(is_hex64("g" * 64))
        self.assertFalse(is_hex64(None))
        self.assertFalse(is_hex64(123))

    def test_is_iso_timestamp_valid(self):
        self.assertTrue(is_iso_timestamp("2026-05-17T10:00:00.000Z"))
        self.assertTrue(is_iso_timestamp("2026-05-17T10:00:00+00:00"))

    def test_is_iso_timestamp_invalid(self):
        self.assertFalse(is_iso_timestamp("not a timestamp"))
        self.assertFalse(is_iso_timestamp(None))


class TestExtractSignals(unittest.TestCase):
    def test_flat_list(self):
        sigs = [{"symbol": "BTC"}]
        self.assertEqual(extract_signals(sigs), sigs)

    def test_nested_published(self):
        data = {"signals": {"published": [{"symbol": "BTC"}], "suppressed": []}}
        result = extract_signals(data)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["symbol"], "BTC")

    def test_nested_with_suppressed(self):
        data = {"signals": {"published": [{"symbol": "BTC"}], "suppressed": [{"symbol": "ETH"}]}}
        result = extract_signals(data)
        self.assertEqual(len(result), 2)

    def test_signals_as_list(self):
        data = {"signals": [{"symbol": "BTC"}]}
        result = extract_signals(data)
        self.assertEqual(len(result), 1)

    def test_empty(self):
        self.assertEqual(extract_signals({}), [])


# ── ActionFieldMissing Tests ──────────────────────────────────────────────────

class TestActionFieldMissing(unittest.TestCase):
    def setUp(self):
        self.checker = ActionFieldMissing()
        self.schema_reqs = (
            load_schema_requirements(SCHEMA_PATH) if os.path.exists(SCHEMA_PATH) else {}
        )

    def test_valid_withhold(self):
        sig = make_signal("BTC", "WITHHOLD")
        result = self.checker.check_signal(sig, self.schema_reqs)
        self.assertTrue(result["passed"])

    def test_valid_execute(self):
        sig = make_signal("BTC", "EXECUTE",
                          policy_gates_applied={"weak_symbol": False, "duration_gate": False,
                                                "voi_filter": False, "regime_filter": False},
                          weak_symbol_inverted=False)
        result = self.checker.check_signal(sig, self.schema_reqs)
        self.assertTrue(result["passed"])

    def test_valid_invert_with_metadata(self):
        sig = make_signal("SOL", "INVERT", with_weak_symbol=True)
        result = self.checker.check_signal(sig, self.schema_reqs)
        self.assertTrue(result["passed"])

    def test_missing_action(self):
        sig = make_signal("BTC", "WITHHOLD")
        del sig["action"]
        result = self.checker.check_signal(sig, self.schema_reqs)
        self.assertFalse(result["passed"])

    def test_invalid_action_enum(self):
        sig = make_signal("BTC", "BUY")
        result = self.checker.check_signal(sig, self.schema_reqs)
        self.assertFalse(result["passed"])

    def test_action_not_string(self):
        sig = make_signal("BTC", "WITHHOLD")
        sig["action"] = 42
        result = self.checker.check_signal(sig, self.schema_reqs)
        self.assertFalse(result["passed"])

    def test_invert_without_weak_symbol_metadata(self):
        sig = make_signal("SOL", "INVERT")
        result = self.checker.check_signal(sig, self.schema_reqs)
        self.assertFalse(result["passed"])

    def test_invert_missing_subfields(self):
        sig = make_signal("SOL", "INVERT")
        sig["weak_symbol"] = {"weakness_score": 0.56}  # Missing severity, original_direction
        result = self.checker.check_signal(sig, self.schema_reqs)
        self.assertFalse(result["passed"])

    def test_policy_inconsistency(self):
        sig = make_signal("BTC", "EXECUTE")  # Says EXECUTE but regime_filter is True
        result = self.checker.check_signal(sig, self.schema_reqs)
        self.assertFalse(result["passed"])

    def test_check_all_all_pass(self):
        signals = [make_signal("BTC"), make_signal("ETH"), make_signal("LINK")]
        result = self.checker.check_all(signals, self.schema_reqs)
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["signals_passed"], 3)

    def test_check_all_all_fail(self):
        signals = [make_signal("BTC"), make_signal("ETH")]
        for s in signals:
            del s["action"]
        result = self.checker.check_all(signals, self.schema_reqs)
        self.assertEqual(result["verdict"], "FAIL")
        self.assertEqual(result["signals_failed"], 2)

    def test_check_all_partial(self):
        s1 = make_signal("BTC")
        s2 = make_signal("ETH")
        del s2["action"]
        result = self.checker.check_all([s1, s2], self.schema_reqs)
        self.assertEqual(result["verdict"], "WARN")

    def test_field_name(self):
        self.assertEqual(self.checker.field_name, "action")

    def test_mismatch_id(self):
        self.assertEqual(self.checker.mismatch_id, "action_field_missing")


# ── Snapshot Comparison Tests ─────────────────────────────────────────────────

class TestSnapshotComparison(unittest.TestCase):
    def setUp(self):
        self.checker = ActionFieldMissing()
        self.schema_reqs = {}

    def test_fail_to_pass(self):
        before = [make_signal("BTC"), make_signal("ETH")]
        for s in before:
            del s["action"]
        after = [make_signal("BTC"), make_signal("ETH")]

        result = run_snapshot_check(before, after, self.checker, self.schema_reqs)
        self.assertEqual(result["before"]["verdict"], "FAIL")
        self.assertEqual(result["after"]["verdict"], "PASS")

    def test_pass_to_pass(self):
        before = [make_signal("BTC")]
        after = [make_signal("BTC")]
        result = run_snapshot_check(before, after, self.checker, self.schema_reqs)
        self.assertEqual(result["before"]["verdict"], "PASS")
        self.assertEqual(result["after"]["verdict"], "PASS")

    def test_per_signal_summary_present(self):
        before = [make_signal("BTC")]
        del before[0]["action"]
        after = [make_signal("BTC")]
        result = run_snapshot_check(before, after, self.checker, self.schema_reqs)
        self.assertIn("per_signal_summary", result["before"])
        self.assertIn("per_signal_summary", result["after"])


# ── Mismatch Registry Tests ──────────────────────────────────────────────────

class TestMismatchRegistry(unittest.TestCase):
    def test_action_field_missing_registered(self):
        self.assertIn("action_field_missing", MISMATCH_REGISTRY)

    def test_registry_classes_instantiable(self):
        for name, cls in MISMATCH_REGISTRY.items():
            instance = cls()
            self.assertTrue(hasattr(instance, "check_signal"))
            self.assertTrue(hasattr(instance, "check_all"))
            self.assertTrue(len(instance.mismatch_id) > 0)


# ── Receipt Builder Tests ────────────────────────────────────────────────────

class TestReceiptBuilder(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not os.path.exists(RECEIPT_PATH):
            cls.receipt = None
            return
        with open(RECEIPT_PATH) as f:
            cls.receipt = json.load(f)

    def test_receipt_exists(self):
        self.assertIsNotNone(self.receipt, "conformance_receipt.json not found")

    def test_receipt_id_format(self):
        self.assertTrue(self.receipt["receipt_id"].startswith("SCR-"))

    def test_schema_version(self):
        self.assertEqual(self.receipt["schema_version"], "1.0.0")

    def test_producer_id(self):
        self.assertEqual(self.receipt["producer_id"], "post-fiat-signals")

    def test_final_verdict_pass(self):
        self.assertEqual(self.receipt["conformance_summary"]["final_verdict"], "PASS")

    def test_status_change_fixed(self):
        self.assertEqual(self.receipt["conformance_summary"]["status_change"], "FIXED")

    def test_before_fail(self):
        self.assertEqual(self.receipt["before"]["result"]["verdict"], "FAIL")

    def test_after_pass(self):
        self.assertEqual(self.receipt["after"]["result"]["verdict"], "PASS")

    def test_all_before_signals_failed(self):
        for s in self.receipt["before"]["result"]["per_signal_summary"]:
            self.assertFalse(s["passed"])

    def test_all_after_signals_passed(self):
        for s in self.receipt["after"]["result"]["per_signal_summary"]:
            self.assertTrue(s["passed"])

    def test_content_hash_valid(self):
        self.assertTrue(is_hex64(self.receipt["content_hash"]))

    def test_content_hash_recomputable(self):
        r = copy.deepcopy(self.receipt)
        r["content_hash"] = "0" * 64
        recomputed = sha256_bytes(json.dumps(r, indent=2, sort_keys=True).encode())
        self.assertEqual(self.receipt["content_hash"], recomputed)

    def test_source_hashes_present(self):
        sh = self.receipt["source_hashes"]
        for key in ["schema", "before_snapshot", "after_snapshot"]:
            self.assertTrue(is_hex64(sh[key]), f"{key} hash invalid")

    def test_limitations_count(self):
        self.assertGreaterEqual(len(self.receipt["limitations"]), 4)

    def test_patch_code_references_action(self):
        self.assertIn("action", self.receipt["patch"]["code_added"])

    def test_mismatch_field_is_action(self):
        self.assertEqual(self.receipt["mismatch"]["field"], "action")


# ── Verifier Category Tests ──────────────────────────────────────────────────

class TestVerifierCategories(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not os.path.exists(RECEIPT_PATH):
            cls.receipt = None
            return
        with open(RECEIPT_PATH) as f:
            cls.receipt = json.load(f)

    def _run_cat(self, fn):
        result = fn(self.receipt)
        self.assertIn("category", result)
        self.assertIn("checks", result)
        return result

    def test_structure(self):
        r = self._run_cat(verify_structure)
        self.assertEqual(r["category"], "structure")
        self.assertTrue(all(c["passed"] for c in r["checks"]))

    def test_receipt_id(self):
        r = self._run_cat(verify_receipt_id)
        self.assertTrue(all(c["passed"] for c in r["checks"]))

    def test_timestamp(self):
        r = self._run_cat(verify_timestamp)
        self.assertTrue(all(c["passed"] for c in r["checks"]))

    def test_producer(self):
        r = self._run_cat(verify_producer)
        self.assertTrue(all(c["passed"] for c in r["checks"]))

    def test_canonical_schema(self):
        r = self._run_cat(verify_canonical_schema)
        self.assertTrue(all(c["passed"] for c in r["checks"]))

    def test_mismatch(self):
        r = self._run_cat(verify_mismatch)
        self.assertTrue(all(c["passed"] for c in r["checks"]))

    def test_patch(self):
        r = self._run_cat(verify_patch)
        self.assertTrue(all(c["passed"] for c in r["checks"]))

    def test_before(self):
        r = self._run_cat(verify_before)
        self.assertTrue(all(c["passed"] for c in r["checks"]))

    def test_after(self):
        r = self._run_cat(verify_after)
        self.assertTrue(all(c["passed"] for c in r["checks"]))

    def test_comparison(self):
        r = self._run_cat(verify_comparison)
        self.assertTrue(all(c["passed"] for c in r["checks"]))

    def test_conformance_summary(self):
        r = self._run_cat(verify_conformance_summary)
        self.assertTrue(all(c["passed"] for c in r["checks"]))

    def test_command(self):
        r = self._run_cat(verify_command)
        self.assertTrue(all(c["passed"] for c in r["checks"]))

    def test_source_hashes(self):
        r = self._run_cat(verify_source_hashes)
        self.assertTrue(all(c["passed"] for c in r["checks"]))

    def test_content_hash(self):
        r = self._run_cat(verify_content_hash)
        self.assertTrue(all(c["passed"] for c in r["checks"]))

    def test_limitations(self):
        r = self._run_cat(verify_limitations)
        self.assertTrue(all(c["passed"] for c in r["checks"]))

    def test_cross_references(self):
        r = self._run_cat(verify_cross_references)
        self.assertTrue(all(c["passed"] for c in r["checks"]))


# ── Verifier Integration Tests ───────────────────────────────────────────────

class TestVerifierIntegration(unittest.TestCase):
    def test_full_verification_grade_a(self):
        if not os.path.exists(RECEIPT_PATH):
            self.skipTest("Receipt not found")
        results = run_verification(RECEIPT_PATH)
        self.assertEqual(results["grade"], "A")
        self.assertEqual(results["total_failed"], 0)

    def test_tampered_verdict_detected(self):
        if not os.path.exists(RECEIPT_PATH):
            self.skipTest("Receipt not found")
        with open(RECEIPT_PATH) as f:
            receipt = json.load(f)
        receipt["conformance_summary"]["final_verdict"] = "FAIL"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(receipt, f, indent=2)
            tmp = f.name
        try:
            results = run_verification(tmp)
            self.assertGreater(results["total_failed"], 0)
        finally:
            os.unlink(tmp)

    def test_tampered_hash_detected(self):
        if not os.path.exists(RECEIPT_PATH):
            self.skipTest("Receipt not found")
        with open(RECEIPT_PATH) as f:
            receipt = json.load(f)
        receipt["content_hash"] = "a" * 64
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(receipt, f, indent=2)
            tmp = f.name
        try:
            results = run_verification(tmp)
            failed_ids = [c["check_id"] for cat in results["categories"]
                         for c in cat["checks"] if not c["passed"]]
            self.assertIn("CH_RECOMPUTED", failed_ids)
        finally:
            os.unlink(tmp)

    def test_missing_field_detected(self):
        if not os.path.exists(RECEIPT_PATH):
            self.skipTest("Receipt not found")
        with open(RECEIPT_PATH) as f:
            receipt = json.load(f)
        del receipt["mismatch"]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(receipt, f, indent=2)
            tmp = f.name
        try:
            results = run_verification(tmp)
            self.assertGreater(results["total_failed"], 0)
        finally:
            os.unlink(tmp)


# ── Edge Cases ───────────────────────────────────────────────────────────────

class TestEdgeCases(unittest.TestCase):
    def test_empty_signal_list(self):
        checker = ActionFieldMissing()
        result = checker.check_all([], {})
        self.assertEqual(result["signals_checked"], 0)
        self.assertEqual(result["verdict"], "PASS")

    def test_signal_with_null_action(self):
        checker = ActionFieldMissing()
        sig = make_signal("BTC")
        sig["action"] = None
        result = checker.check_signal(sig, {})
        self.assertFalse(result["passed"])

    def test_signal_with_empty_action(self):
        checker = ActionFieldMissing()
        sig = make_signal("BTC")
        sig["action"] = ""
        result = checker.check_signal(sig, {})
        self.assertFalse(result["passed"])

    def test_extract_from_deeply_nested(self):
        data = {"signals": {"published": [{"a": 1}], "suppressed": [{"b": 2}]}}
        result = extract_signals(data)
        self.assertEqual(len(result), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
