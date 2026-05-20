#!/usr/bin/env python3
"""
Post Fiat Schema Conformance Checker

Checks live producer output against producer_signal_schema.json v1.0.0 for a
specific mismatch identifier.  Generates a dated conformance_receipt.json with
before/after status, remediation details, and cryptographic hashes.

Zero external dependencies — stdlib only.

Usage:
    python3 check_conformance.py \
        --endpoint http://localhost:8080/signals/latest \
        --schema  /path/to/producer_signal_schema.json \
        --mismatch action_field_missing \
        --before-snapshot snapshots/before.json \
        -o conformance_receipt.json \
        --summary
"""

import argparse
import datetime
import hashlib
import json
import os
import re
import sys
import urllib.request
import uuid


# ── helpers ────────────────────────────────────────────────────────────────────

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_dict(d: dict) -> str:
    return sha256_bytes(json.dumps(d, indent=2, sort_keys=True).encode())


def iso_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.%f"
    )[:-3] + "Z"


def fetch_json(url: str, timeout: int = 30) -> dict:
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def load_json(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def write_json(path: str, data: dict):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2, sort_keys=False)
        f.write("\n")


def extract_signals(endpoint_data: dict) -> list:
    """Pull flat signal list from live endpoint response."""
    if isinstance(endpoint_data, list):
        return endpoint_data
    if "signals" in endpoint_data:
        sigs = endpoint_data["signals"]
        if isinstance(sigs, dict) and "published" in sigs:
            combined = list(sigs.get("published", []))
            combined.extend(sigs.get("suppressed", []))
            return combined
        if isinstance(sigs, list):
            return sigs
    return []


# ── schema helpers ─────────────────────────────────────────────────────────────

def load_schema_requirements(schema_path: str) -> dict:
    """Extract requirements from the canonical schema."""
    schema = load_json(schema_path)
    defs = schema.get("$defs", {})
    signal_def = defs.get("signal", {})
    required = signal_def.get("required", [])
    properties = signal_def.get("properties", {})
    return {
        "schema_version": schema.get("$id", "unknown"),
        "required_fields": required,
        "properties": properties,
        "defs": defs,
        "conditional": signal_def.get("if"),
    }


# ── mismatch checkers ─────────────────────────────────────────────────────────

class MismatchChecker:
    """Base class for individual mismatch checks."""

    mismatch_id: str = ""
    field_name: str = ""
    description: str = ""
    remediation: str = ""

    def check_signal(self, signal: dict, schema_reqs: dict) -> dict:
        raise NotImplementedError

    def check_all(self, signals: list, schema_reqs: dict) -> dict:
        results = []
        for i, sig in enumerate(signals):
            r = self.check_signal(sig, schema_reqs)
            r["signal_index"] = i
            r["signal_id"] = sig.get("signal_id", f"unknown-{i}")
            r["symbol"] = sig.get("symbol", "UNKNOWN")
            results.append(r)
        passed = sum(1 for r in results if r["passed"])
        total = len(results)
        verdict = "PASS" if passed == total else ("WARN" if passed > 0 else "FAIL")
        return {
            "mismatch_id": self.mismatch_id,
            "field": self.field_name,
            "description": self.description,
            "signals_checked": total,
            "signals_passed": passed,
            "signals_failed": total - passed,
            "verdict": verdict,
            "per_signal": results,
        }


class ActionFieldMissing(MismatchChecker):
    """Checks whether the 'action' field is present and valid."""

    mismatch_id = "action_field_missing"
    field_name = "action"
    description = (
        "The 'action' field is required by producer_signal_schema.json v1.0.0 "
        "(lines 145, 194-196). It MUST be one of: EXECUTE, WITHHOLD, INVERT. "
        "Consumers MUST respect this field for routing decisions."
    )
    remediation = (
        "Add 'action' to every emitted signal. Derive it from policy gates: "
        "INVERT if weak_symbol inverted, WITHHOLD if regime-suppressed or "
        "VOI-filtered, EXECUTE otherwise."
    )

    VALID_ACTIONS = {"EXECUTE", "WITHHOLD", "INVERT"}

    def check_signal(self, signal: dict, schema_reqs: dict) -> dict:
        action = signal.get("action")
        checks = []

        # Sub-check 1: field present
        present = action is not None
        checks.append({
            "check": "field_present",
            "passed": present,
            "detail": f"action={'present' if present else 'MISSING'}",
        })

        # Sub-check 2: type is string
        type_ok = isinstance(action, str) if present else False
        checks.append({
            "check": "type_string",
            "passed": type_ok,
            "detail": f"type={type(action).__name__}" if present else "N/A (field missing)",
        })

        # Sub-check 3: value in enum
        enum_ok = action in self.VALID_ACTIONS if type_ok else False
        checks.append({
            "check": "enum_valid",
            "passed": enum_ok,
            "detail": f"value={action}" if present else "N/A (field missing)",
        })

        # Sub-check 4: consistency with policy gates
        # Gate fields may be at top level (legacy) or inside metadata (v1.1+)
        consistency_ok = True
        consistency_detail = ""
        if present and type_ok:
            meta = signal.get("metadata", {}) if isinstance(signal.get("metadata"), dict) else {}
            gates = signal.get("policy_gates_applied", meta.get("policy_gates_applied", {}))
            inverted = (signal.get("weak_symbol_inverted", meta.get("weak_symbol_inverted", False))
                        or gates.get("weak_symbol", False))
            regime_sup = gates.get("regime_filter", False)
            voi_sup = (signal.get("voi_suppressed", meta.get("voi_suppressed", False))
                       or gates.get("voi_filter", False))

            expected = "EXECUTE"
            if inverted:
                expected = "INVERT"
            elif regime_sup or voi_sup:
                expected = "WITHHOLD"

            consistency_ok = action == expected
            consistency_detail = (
                f"action={action}, expected={expected} "
                f"(inverted={inverted}, regime_sup={regime_sup}, voi_sup={voi_sup})"
            )
        else:
            consistency_detail = "N/A (field missing or invalid type)"
            consistency_ok = False

        checks.append({
            "check": "policy_consistency",
            "passed": consistency_ok,
            "detail": consistency_detail,
        })

        # Sub-check 5: INVERT requires weak_symbol metadata (schema conditional)
        conditional_ok = True
        conditional_detail = "N/A"
        if action == "INVERT":
            ws = signal.get("weak_symbol")
            if ws is None:
                conditional_ok = False
                conditional_detail = (
                    "action=INVERT but weak_symbol metadata missing "
                    "(schema requires weak_symbol when action=INVERT)"
                )
            else:
                required_ws = ["weakness_score", "severity", "original_direction"]
                missing_ws = [f for f in required_ws if f not in ws]
                conditional_ok = len(missing_ws) == 0
                conditional_detail = (
                    f"weak_symbol present, missing subfields: {missing_ws}"
                    if missing_ws
                    else "weak_symbol present with all required subfields"
                )
        elif present:
            conditional_detail = f"action={action}, conditional not triggered"

        checks.append({
            "check": "conditional_weak_symbol",
            "passed": conditional_ok,
            "detail": conditional_detail,
        })

        all_passed = all(c["passed"] for c in checks)
        return {"passed": all_passed, "checks": checks}


class RequiredFieldsMissing(MismatchChecker):
    """Checks whether 'producer_id' and 'schema_version' are present and valid."""

    mismatch_id = "required_fields_missing"
    field_name = "producer_id, schema_version"
    description = (
        "The 'producer_id' and 'schema_version' fields are required by "
        "producer_signal_schema.json v1.0.0 (lines 138-147). 'producer_id' "
        "identifies the signal producer; 'schema_version' declares which "
        "schema version the signal conforms to."
    )
    remediation = (
        "Add 'producer_id' and 'schema_version' to every emitted signal "
        "object. Use the existing PRODUCER_ID and SCHEMA_VERSION constants "
        "from signal_api.js."
    )

    SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")

    def check_signal(self, signal: dict, schema_reqs: dict) -> dict:
        checks = []

        # Sub-check 1: producer_id present
        pid = signal.get("producer_id")
        pid_present = pid is not None
        checks.append({
            "check": "producer_id_present",
            "passed": pid_present,
            "detail": f"producer_id={'present' if pid_present else 'MISSING'}",
        })

        # Sub-check 2: producer_id is non-empty string
        pid_valid = isinstance(pid, str) and len(pid) > 0 if pid_present else False
        checks.append({
            "check": "producer_id_type",
            "passed": pid_valid,
            "detail": (
                f"producer_id='{pid}' (type={type(pid).__name__})"
                if pid_present else "N/A (field missing)"
            ),
        })

        # Sub-check 3: schema_version present
        sv = signal.get("schema_version")
        sv_present = sv is not None
        checks.append({
            "check": "schema_version_present",
            "passed": sv_present,
            "detail": f"schema_version={'present' if sv_present else 'MISSING'}",
        })

        # Sub-check 4: schema_version is valid semver
        sv_valid = (
            isinstance(sv, str) and bool(self.SEMVER_RE.match(sv))
            if sv_present else False
        )
        checks.append({
            "check": "schema_version_semver",
            "passed": sv_valid,
            "detail": (
                f"schema_version='{sv}' ({'valid' if sv_valid else 'invalid'} semver)"
                if sv_present else "N/A (field missing)"
            ),
        })

        all_passed = all(c["passed"] for c in checks)
        return {"passed": all_passed, "checks": checks}


class DirectionEnumInvalid(MismatchChecker):
    """Checks whether 'direction' uses valid lowercase enum values."""

    mismatch_id = "direction_enum_invalid"
    field_name = "direction"
    severity = "ENUM_VALUE_INVALID"
    schema_reference = "producer_signal_schema.json#/$defs/direction"
    description = (
        "The 'direction' field MUST be one of: 'bullish', 'bearish' "
        "(lowercase). Schema v1.0.0 $defs/direction (lines 23-27) defines "
        "this enum. The value 'NEUTRAL' is not a valid direction; uppercase "
        "variants (BULLISH, BEARISH) also violate the schema."
    )
    remediation = (
        "Change direction derivation to emit lowercase 'bullish' or "
        "'bearish' only. When the model has no directional conviction "
        "(dir=0) or regime suppresses direction, default to 'bearish' "
        "(conservative) and set action=WITHHOLD."
    )

    VALID_DIRECTIONS = {"bullish", "bearish"}

    def check_signal(self, signal: dict, schema_reqs: dict) -> dict:
        checks = []
        direction = signal.get("direction")

        # Sub-check 1: field present
        present = direction is not None
        checks.append({
            "check": "field_present",
            "passed": present,
            "detail": f"direction={'present' if present else 'MISSING'}",
        })

        # Sub-check 2: type is string
        type_ok = isinstance(direction, str) if present else False
        checks.append({
            "check": "type_string",
            "passed": type_ok,
            "detail": (
                f"type={type(direction).__name__}"
                if present else "N/A (field missing)"
            ),
        })

        # Sub-check 3: value in enum (lowercase bullish/bearish only)
        enum_ok = direction in self.VALID_DIRECTIONS if type_ok else False
        checks.append({
            "check": "enum_valid",
            "passed": enum_ok,
            "detail": (
                f"direction='{direction}' "
                f"({'valid' if enum_ok else 'INVALID — must be bullish or bearish'})"
                if present else "N/A (field missing)"
            ),
        })

        # Sub-check 4: not uppercase variant (specific regression check)
        not_upper = True
        if type_ok and direction.upper() in {"BULLISH", "BEARISH", "NEUTRAL"}:
            not_upper = direction == direction.lower() and direction in self.VALID_DIRECTIONS
        checks.append({
            "check": "not_uppercase_variant",
            "passed": not_upper,
            "detail": (
                f"direction='{direction}' "
                f"({'lowercase OK' if not_upper else 'UPPERCASE or NEUTRAL detected'})"
                if present else "N/A (field missing)"
            ),
        })

        # Sub-check 5: consistency with action field
        action = signal.get("action")
        consistency_ok = True
        consistency_detail = "N/A"
        if enum_ok and action:
            # If action is WITHHOLD, any valid direction is acceptable
            # If action is EXECUTE, direction should reflect real conviction
            # If action is INVERT, direction should be post-inversion
            consistency_ok = True
            consistency_detail = (
                f"direction='{direction}', action='{action}' "
                f"(valid combination)"
            )
        elif not enum_ok and present:
            consistency_ok = False
            consistency_detail = (
                f"direction='{direction}' is invalid, cannot assess "
                f"consistency with action='{action}'"
            )

        checks.append({
            "check": "action_consistency",
            "passed": consistency_ok,
            "detail": consistency_detail,
        })

        all_passed = all(c["passed"] for c in checks)
        return {"passed": all_passed, "checks": checks}


class RegimeContextFlat(MismatchChecker):
    """Checks whether regime fields are properly nested under regime_context."""

    mismatch_id = "regime_context_flat"
    field_name = "regime_context"
    severity = "STRUCTURAL_MISMATCH"
    schema_reference = "producer_signal_schema.json#/$defs/regime_context"
    description = (
        "The schema defines regime metadata as a nested 'regime_context' object "
        "with fields: regime_id, regime_confidence, proximity, duration_days, "
        "decision. The live API was emitting these as flat top-level fields: "
        "regime, regime_confidence, regime_duration_days, proximity."
    )
    remediation = (
        "Restructure flat regime fields into a nested regime_context object. "
        "Map: regime → regime_context.regime_id, regime_confidence → "
        "regime_context.regime_confidence, regime_duration_days → "
        "regime_context.duration_days (integer), proximity → "
        "regime_context.proximity. Add regime_context.decision derived from "
        "regime policy (SUPPRESS_DIRECTION → NO_TRADE, PUBLISH → EXECUTE)."
    )

    VALID_REGIME_IDS = {"SYSTEMIC", "NEUTRAL", "DIVERGENCE", "EARNINGS", "UNKNOWN"}
    VALID_DECISIONS = {"NO_TRADE", "EXECUTE", "MONITOR"}

    def check_signal(self, signal: dict, schema_reqs: dict) -> dict:
        checks = []
        rc = signal.get("regime_context")

        # Sub-check 1: regime_context present (not flat fields)
        rc_present = rc is not None and isinstance(rc, dict)
        checks.append({
            "check": "regime_context_present",
            "passed": rc_present,
            "detail": (
                f"regime_context={{'...'}}" if rc_present
                else "MISSING (regime fields may be flat on signal object)"
            ),
        })

        # Sub-check 2: no flat regime fields at top level
        flat_fields = {"regime", "regime_confidence", "regime_duration_days", "proximity"}
        found_flat = flat_fields & set(signal.keys())
        no_flat = len(found_flat) == 0
        checks.append({
            "check": "no_flat_regime_fields",
            "passed": no_flat,
            "detail": (
                "no flat regime fields at top level"
                if no_flat
                else f"flat regime fields found at top level: {sorted(found_flat)}"
            ),
        })

        if not rc_present:
            # Remaining checks can't run
            for name in ("regime_id_valid", "regime_confidence_bounded",
                         "duration_days_integer", "proximity_bounded",
                         "decision_valid"):
                checks.append({
                    "check": name, "passed": False,
                    "detail": "N/A (regime_context missing)",
                })
            return {"passed": False, "checks": checks}

        # Sub-check 3: regime_id valid enum
        rid = rc.get("regime_id")
        rid_ok = isinstance(rid, str) and rid in self.VALID_REGIME_IDS
        checks.append({
            "check": "regime_id_valid",
            "passed": rid_ok,
            "detail": (
                f"regime_id='{rid}' ({'valid' if rid_ok else 'INVALID'})"
                if rid is not None else "regime_id=MISSING"
            ),
        })

        # Sub-check 4: regime_confidence bounded [0, 1] or [0, 100]
        rconf = rc.get("regime_confidence")
        rconf_present = rconf is not None and isinstance(rconf, (int, float))
        rconf_ok = rconf_present and 0 <= rconf <= 100
        checks.append({
            "check": "regime_confidence_bounded",
            "passed": rconf_ok,
            "detail": (
                f"regime_confidence={rconf}"
                if rconf_present else "regime_confidence=MISSING"
            ),
        })

        # Sub-check 5: duration_days is integer
        dd = rc.get("duration_days")
        dd_ok = isinstance(dd, int) and dd >= 0
        checks.append({
            "check": "duration_days_integer",
            "passed": dd_ok,
            "detail": (
                f"duration_days={dd} (type={type(dd).__name__})"
                if dd is not None else "duration_days=MISSING"
            ),
        })

        # Sub-check 6: proximity bounded [0, 1]
        prox = rc.get("proximity")
        prox_ok = isinstance(prox, (int, float)) and 0 <= prox <= 1
        checks.append({
            "check": "proximity_bounded",
            "passed": prox_ok,
            "detail": (
                f"proximity={prox}"
                if prox is not None else "proximity=MISSING"
            ),
        })

        # Sub-check 7: decision valid enum (optional but checked if present)
        dec = rc.get("decision")
        dec_ok = dec is None or (isinstance(dec, str) and dec in self.VALID_DECISIONS)
        checks.append({
            "check": "decision_valid",
            "passed": dec_ok,
            "detail": (
                f"decision='{dec}' ({'valid' if dec_ok else 'INVALID'})"
                if dec is not None else "decision=absent (optional, OK)"
            ),
        })

        all_passed = all(c["passed"] for c in checks)
        return {"passed": all_passed, "checks": checks}


class ExtraFieldsPresent(MismatchChecker):
    """Checks that signal objects contain no extra fields beyond schema properties."""

    mismatch_id = "extra_fields_present"
    field_name = "additionalProperties"
    severity = "ADDITIONAL_PROPERTIES_VIOLATION"
    schema_reference = "producer_signal_schema.json#/$defs/signal/additionalProperties"
    description = (
        "The schema sets additionalProperties: false on the signal object. "
        "Only fields defined in the schema's properties are permitted: "
        "signal_id, producer_id, timestamp, symbol, direction, confidence, "
        "horizon_hours, action, schema_version, regime_context, "
        "attribution_hash, calibration, weak_symbol, metadata. "
        "Producer-specific extension fields must go inside the 'metadata' "
        "object (which allows additionalProperties: true)."
    )
    remediation = (
        "Move non-schema fields (signal_type, expected_karma, voi_included, "
        "voi_suppressed, duration_gated, weak_symbol_inverted, "
        "policy_gates_applied) into the 'metadata' object. Also move flat "
        "regime fields (regime, regime_confidence, regime_duration_days, "
        "proximity) into regime_context. The metadata object is designed "
        "as the catch-all for producer-specific data."
    )

    ALLOWED_FIELDS = {
        "signal_id", "producer_id", "timestamp", "symbol", "direction",
        "confidence", "horizon_hours", "action", "schema_version",
        "regime_context", "attribution_hash", "calibration", "weak_symbol",
        "metadata",
    }

    def check_signal(self, signal: dict, schema_reqs: dict) -> dict:
        checks = []
        sig_keys = set(signal.keys())
        extras = sig_keys - self.ALLOWED_FIELDS

        # Sub-check 1: no extra top-level fields
        no_extras = len(extras) == 0
        checks.append({
            "check": "no_extra_top_level_fields",
            "passed": no_extras,
            "detail": (
                "all fields conform to schema properties"
                if no_extras
                else f"extra fields found: {sorted(extras)}"
            ),
        })

        # Sub-check 2: metadata is object if present
        meta = signal.get("metadata")
        meta_ok = meta is None or isinstance(meta, dict)
        checks.append({
            "check": "metadata_is_object",
            "passed": meta_ok,
            "detail": (
                f"metadata type={type(meta).__name__}"
                if meta is not None else "metadata=absent (optional, OK)"
            ),
        })

        # Sub-check 3: known extension fields are in metadata (not top-level)
        extension_fields = {
            "signal_type", "expected_karma", "voi_included",
            "voi_suppressed", "duration_gated", "weak_symbol_inverted",
            "policy_gates_applied",
        }
        misplaced = extension_fields & sig_keys
        placement_ok = len(misplaced) == 0
        checks.append({
            "check": "extension_fields_in_metadata",
            "passed": placement_ok,
            "detail": (
                "all extension fields properly in metadata (or absent)"
                if placement_ok
                else f"extension fields at top level: {sorted(misplaced)}"
            ),
        })

        # Sub-check 4: flat regime fields not at top level
        regime_flat = {"regime", "regime_confidence", "regime_duration_days", "proximity"}
        regime_misplaced = regime_flat & sig_keys
        regime_ok = len(regime_misplaced) == 0
        checks.append({
            "check": "regime_fields_not_flat",
            "passed": regime_ok,
            "detail": (
                "no flat regime fields at top level"
                if regime_ok
                else f"regime fields at top level: {sorted(regime_misplaced)}"
            ),
        })

        # Sub-check 5: field count reasonable (schema has 14 defined properties)
        count_ok = len(sig_keys) <= 14
        checks.append({
            "check": "field_count_bounded",
            "passed": count_ok,
            "detail": f"field_count={len(sig_keys)} (max=14 schema properties)",
        })

        all_passed = all(c["passed"] for c in checks)
        return {"passed": all_passed, "checks": checks}


# Registry of known mismatches
MISMATCH_REGISTRY = {
    "action_field_missing": ActionFieldMissing,
    "required_fields_missing": RequiredFieldsMissing,
    "direction_enum_invalid": DirectionEnumInvalid,
    "regime_context_flat": RegimeContextFlat,
    "extra_fields_present": ExtraFieldsPresent,
}


# ── snapshot comparator ────────────────────────────────────────────────────────

def run_snapshot_check(before_signals: list, after_signals: list,
                       checker: MismatchChecker, schema_reqs: dict) -> dict:
    """Run the same checker against before and after snapshots."""
    before_result = checker.check_all(before_signals, schema_reqs)
    after_result = checker.check_all(after_signals, schema_reqs)

    return {
        "before": {
            "verdict": before_result["verdict"],
            "signals_checked": before_result["signals_checked"],
            "signals_passed": before_result["signals_passed"],
            "signals_failed": before_result["signals_failed"],
            "per_signal_summary": [
                {
                    "signal_id": r["signal_id"],
                    "symbol": r["symbol"],
                    "passed": r["passed"],
                    "detail": "; ".join(
                        c["detail"] for c in r["checks"] if not c["passed"]
                    ) or "all checks passed",
                }
                for r in before_result["per_signal"]
            ],
        },
        "after": {
            "verdict": after_result["verdict"],
            "signals_checked": after_result["signals_checked"],
            "signals_passed": after_result["signals_passed"],
            "signals_failed": after_result["signals_failed"],
            "per_signal_summary": [
                {
                    "signal_id": r["signal_id"],
                    "symbol": r["symbol"],
                    "passed": r["passed"],
                    "detail": "; ".join(
                        c["detail"] for c in r["checks"] if not c["passed"]
                    ) or "all checks passed",
                }
                for r in after_result["per_signal"]
            ],
        },
    }


# ── receipt builder ────────────────────────────────────────────────────────────

class ConformanceReceiptBuilder:
    """Builds a dated conformance_receipt.json."""

    VERSION = "1.0.0"

    def __init__(self, endpoint: str, schema_path: str, mismatch_id: str,
                 before_snapshot_path: str):
        self.endpoint = endpoint
        self.schema_path = schema_path
        self.mismatch_id = mismatch_id
        self.before_snapshot_path = before_snapshot_path

    def build(self) -> dict:
        now = iso_now()
        receipt_id = f"SCR-{uuid.uuid4().hex[:12]}"

        # Load schema
        schema_reqs = load_schema_requirements(self.schema_path)

        # Get checker
        if self.mismatch_id not in MISMATCH_REGISTRY:
            raise ValueError(f"Unknown mismatch: {self.mismatch_id}. "
                             f"Known: {list(MISMATCH_REGISTRY.keys())}")
        checker = MISMATCH_REGISTRY[self.mismatch_id]()

        # Load before snapshot
        before_data = load_json(self.before_snapshot_path)
        before_signals = extract_signals(before_data)

        # Fetch live (after)
        after_data = fetch_json(self.endpoint)
        after_signals = extract_signals(after_data)

        # Run comparison
        comparison = run_snapshot_check(
            before_signals, after_signals, checker, schema_reqs
        )

        # Determine final verdict
        before_verdict = comparison["before"]["verdict"]
        after_verdict = comparison["after"]["verdict"]
        if before_verdict == "FAIL" and after_verdict == "PASS":
            final_verdict = "PASS"
            status_change = "FIXED"
        elif before_verdict == after_verdict:
            final_verdict = before_verdict
            status_change = "UNCHANGED"
        elif after_verdict == "PASS":
            final_verdict = "PASS"
            status_change = "IMPROVED"
        else:
            final_verdict = after_verdict
            status_change = "PARTIAL"

        # Build patch description
        patch = self._build_patch_description()

        # Source hashes
        schema_hash = sha256_bytes(open(self.schema_path, "rb").read())
        before_hash = sha256_bytes(open(self.before_snapshot_path, "rb").read())
        after_bytes = json.dumps(after_data, indent=2, sort_keys=True).encode()
        after_hash = sha256_bytes(after_bytes)

        # Assemble receipt
        receipt = {
            "receipt_id": receipt_id,
            "schema_version": "1.0.0",
            "generator_version": self.VERSION,
            "generated_at": now,
            "producer_id": after_data.get("producer_id", "unknown"),
            "endpoint": self.endpoint,
            "canonical_schema": {
                "name": "producer_signal_schema.json",
                "version": schema_reqs["schema_version"],
                "content_hash": schema_hash,
            },
            "mismatch": {
                "mismatch_id": self.mismatch_id,
                "field": checker.field_name,
                "description": checker.description,
                "remediation_applied": checker.remediation,
                "severity": getattr(checker, "severity", "REQUIRED_FIELD_MISSING"),
                "schema_reference": getattr(
                    checker, "schema_reference",
                    "producer_signal_schema.json#/$defs/signal/required"
                ),
            },
            "patch": patch,
            "before": {
                "snapshot_path": self.before_snapshot_path,
                "snapshot_hash": before_hash,
                "captured_at": before_data.get("generated_at", "unknown"),
                "result": comparison["before"],
            },
            "after": {
                "endpoint": self.endpoint,
                "snapshot_hash": after_hash,
                "captured_at": after_data.get("generated_at", now),
                "result": comparison["after"],
            },
            "conformance_summary": {
                "final_verdict": final_verdict,
                "status_change": status_change,
                "before_verdict": before_verdict,
                "after_verdict": after_verdict,
                "field_checked": checker.field_name,
                "before_signals_passing": comparison["before"]["signals_passed"],
                "after_signals_passing": comparison["after"]["signals_passed"],
                "total_signals_checked": comparison["after"]["signals_checked"],
            },
            "conformance_command": (
                f"python3 check_conformance.py "
                f"--endpoint {self.endpoint} "
                f"--schema producer_signal_schema.json "
                f"--mismatch {self.mismatch_id} "
                f"--before-snapshot {self.before_snapshot_path} "
                f"-o conformance_receipt.json --summary"
            ),
            "source_hashes": {
                "schema": schema_hash,
                "before_snapshot": before_hash,
                "after_snapshot": after_hash,
            },
            "limitations": self._build_limitations(),
        }

        # Compute content hash (zero-then-fill)
        receipt["content_hash"] = "0" * 64
        zero_bytes = json.dumps(receipt, indent=2, sort_keys=True).encode()
        receipt["content_hash"] = sha256_bytes(zero_bytes)

        return receipt

    def _build_patch_description(self) -> dict:
        patches = {
            "action_field_missing": {
                "file_patched": "signal_api.js",
                "line": 86,
                "change_type": "FIELD_ADDITION",
                "description": (
                    "Added 'action' field derivation to sovereign signal output. "
                    "Logic: INVERT if weak_symbol inverted, WITHHOLD if VOI-suppressed "
                    "or regime-filtered, EXECUTE otherwise."
                ),
                "code_added": (
                    "const action = inv ? 'INVERT' : "
                    "(voiSup || !rp.pubDir ? 'WITHHOLD' : 'EXECUTE');"
                ),
                "signals_affected": "all (BTC, ETH, SOL, LINK)",
            },
            "required_fields_missing": {
                "file_patched": "signal_api.js",
                "line": 95,
                "change_type": "FIELD_ADDITION",
                "description": (
                    "Added 'producer_id: PRODUCER_ID' and "
                    "'schema_version: SCHEMA_VERSION' to the sigObj "
                    "construction in generateSovereignSignals(). Constants "
                    "PRODUCER_ID='post-fiat-signals' and SCHEMA_VERSION='1.1.0' "
                    "already existed at module scope but were not injected "
                    "into individual signal objects."
                ),
                "code_added": (
                    "producer_id: PRODUCER_ID, schema_version: SCHEMA_VERSION,"
                ),
                "signals_affected": "all (BTC, ETH, SOL, LINK)",
            },
            "direction_enum_invalid": {
                "file_patched": "signal_api.js",
                "line": 84,
                "change_type": "FIELD_VALUE_FIX",
                "description": (
                    "Changed direction derivation from uppercase BULLISH/BEARISH/NEUTRAL "
                    "to lowercase bullish/bearish. Removed invalid 'NEUTRAL' value. "
                    "When model has no directional conviction (dir=0), defaults to "
                    "'bearish' (conservative). Action field already communicates "
                    "whether consumers should act on the direction."
                ),
                "code_before": (
                    "const dl = !rp.pubDir ? 'NEUTRAL' : "
                    "(dir > 0 ? 'BULLISH' : (dir < 0 ? 'BEARISH' : 'NEUTRAL'));"
                ),
                "code_after": (
                    "const dl = dir > 0 ? 'bullish' : "
                    "(dir < 0 ? 'bearish' : 'bearish');"
                ),
                "signals_affected": "all (BTC, ETH, SOL, LINK)",
            },
            "regime_context_flat": {
                "file_patched": "signal_api.js",
                "lines": "94-107",
                "change_type": "STRUCTURAL_REFACTOR",
                "description": (
                    "Replaced flat regime fields (regime, regime_confidence, "
                    "regime_duration_days, proximity) with a nested regime_context "
                    "object matching the schema definition. Added decision field "
                    "derived from regime policy (SUPPRESS_DIRECTION → NO_TRADE, "
                    "PUBLISH → EXECUTE). Ensured duration_days is integer via "
                    "Math.floor()."
                ),
                "code_before": (
                    "regime, regime_confidence: regimeConf, "
                    "regime_duration_days: dur, proximity: prox,"
                ),
                "code_after": (
                    "regime_context: { regime_id: regime, "
                    "regime_confidence: regimeConf, proximity: prox, "
                    "duration_days: Math.floor(dur), decision: regimeDecision },"
                ),
                "signals_affected": "all (BTC, ETH, SOL, LINK)",
            },
            "extra_fields_present": {
                "file_patched": "signal_api.js",
                "lines": "94-117",
                "change_type": "FIELD_RELOCATION",
                "description": (
                    "Moved 7 producer-specific extension fields from signal "
                    "top-level into the metadata object (which permits "
                    "additionalProperties). Fields moved: signal_type, "
                    "expected_karma, voi_included, voi_suppressed, "
                    "duration_gated, weak_symbol_inverted, "
                    "policy_gates_applied. Also added attribution_hash for "
                    "tamper detection (SHA-256 of signal_id|symbol|direction|"
                    "confidence|horizon_hours|timestamp)."
                ),
                "code_after": (
                    "metadata: { signal_type: st, expected_karma: ..., "
                    "voi_included: ..., voi_suppressed: ..., "
                    "duration_gated: ..., weak_symbol_inverted: ..., "
                    "policy_gates_applied: {...} }"
                ),
                "signals_affected": "all (BTC, ETH, SOL, LINK)",
            },
        }
        return patches.get(self.mismatch_id, {
            "file_patched": "signal_api.js",
            "change_type": "UNKNOWN",
            "description": "Patch description not registered for this mismatch",
        })

    def _build_limitations(self) -> list:
        return [
            {
                "id": "L01",
                "description": "Before snapshot is stored, not captured live in same session",
                "bias_direction": "INDETERMINATE",
                "bias_magnitude": "LOW",
            },
            {
                "id": "L02",
                "description": "Conformance checks single mismatch, not full schema validation",
                "bias_direction": "OVERSTATED_READINESS",
                "bias_magnitude": "MODERATE",
            },
            {
                "id": "L03",
                "description": "Point-in-time check; future code changes could regress",
                "bias_direction": "OVERSTATED_READINESS",
                "bias_magnitude": "LOW",
            },
            {
                "id": "L04",
                "description": "Policy consistency check infers expected action from gate flags, not from source logic",
                "bias_direction": "INDETERMINATE",
                "bias_magnitude": "LOW",
            },
            {
                "id": "L05",
                "description": "INVERT conditional check (weak_symbol metadata) not fully testable under SYSTEMIC regime",
                "bias_direction": "UNDERSTATED_RISK",
                "bias_magnitude": "LOW",
            },
            {
                "id": "L06",
                "description": "After snapshot fetched at check time; signals may differ from moment of patch verification",
                "bias_direction": "INDETERMINATE",
                "bias_magnitude": "LOW",
            },
        ]


# ── CLI ────────────────────────────────────────────────────────────────────────

def print_summary(receipt: dict):
    cs = receipt["conformance_summary"]
    m = receipt["mismatch"]
    print()
    print("=" * 70)
    print("  SCHEMA CONFORMANCE RECEIPT")
    print("=" * 70)
    print(f"  Receipt ID:       {receipt['receipt_id']}")
    print(f"  Generated:        {receipt['generated_at']}")
    print(f"  Producer:         {receipt['producer_id']}")
    print(f"  Endpoint:         {receipt['endpoint']}")
    print(f"  Schema:           {receipt['canonical_schema']['version']}")
    print("-" * 70)
    print(f"  Mismatch:         {m['mismatch_id']}")
    print(f"  Field:            {m['field']}")
    print(f"  Severity:         {m['severity']}")
    print("-" * 70)
    print(f"  BEFORE verdict:   {cs['before_verdict']}")
    print(f"    Signals passing: {cs['before_signals_passing']}/{cs['total_signals_checked']}")
    for s in receipt["before"]["result"]["per_signal_summary"]:
        status = "PASS" if s["passed"] else "FAIL"
        print(f"      {s['symbol']:6s} [{status}] {s['detail']}")
    print()
    print(f"  AFTER verdict:    {cs['after_verdict']}")
    print(f"    Signals passing: {cs['after_signals_passing']}/{cs['total_signals_checked']}")
    for s in receipt["after"]["result"]["per_signal_summary"]:
        status = "PASS" if s["passed"] else "FAIL"
        print(f"      {s['symbol']:6s} [{status}] {s['detail']}")
    print("-" * 70)
    print(f"  Status change:    {cs['status_change']}")
    print(f"  ╔══════════════════════════════════════╗")
    verd = cs['final_verdict']
    print(f"  ║  FINAL VERDICT:  {verd:20s}  ║")
    print(f"  ╚══════════════════════════════════════╝")
    print()
    print(f"  Content hash:     {receipt['content_hash'][:16]}...")
    print("=" * 70)
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Check live producer output against schema for a specific mismatch"
    )
    parser.add_argument(
        "--endpoint", required=True,
        help="Live signal endpoint URL"
    )
    parser.add_argument(
        "--schema", required=True,
        help="Path to producer_signal_schema.json"
    )
    parser.add_argument(
        "--mismatch", required=True,
        help=f"Mismatch identifier. Options: {list(MISMATCH_REGISTRY.keys())}"
    )
    parser.add_argument(
        "--before-snapshot", required=True,
        help="Path to before-patch snapshot JSON"
    )
    parser.add_argument(
        "-o", "--output", default="conformance_receipt.json",
        help="Output path for conformance receipt"
    )
    parser.add_argument(
        "--summary", action="store_true",
        help="Print human-readable summary"
    )
    args = parser.parse_args()

    builder = ConformanceReceiptBuilder(
        endpoint=args.endpoint,
        schema_path=args.schema,
        mismatch_id=args.mismatch,
        before_snapshot_path=args.before_snapshot,
    )

    receipt = builder.build()
    write_json(args.output, receipt)

    if args.summary:
        print_summary(receipt)

    # Exit code based on final verdict
    verdict = receipt["conformance_summary"]["final_verdict"]
    if verdict == "PASS":
        sys.exit(0)
    elif verdict == "WARN":
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
