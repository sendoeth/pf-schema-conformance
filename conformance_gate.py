#!/usr/bin/env python3
"""
conformance_gate.py — Live Producer Conformance Gate

Validates live producer output against the frozen Post Fiat producer schema
v1.0.0.  Reads the actual schema file and enforces every constraint: required
fields, type checks, enum values, numeric bounds, string patterns, nested
object shapes, additionalProperties, and the INVERT→weak_symbol conditional.

No adapter translations, no silent normalization — raw schema enforcement.

Exit codes:
  0 = PASS  — all signals conform to the frozen schema
  1 = FAIL  — one or more signals violate the schema
  2 = ERROR — could not reach endpoint, parse response, or load schema

Usage:
  # Live gate (fetch from endpoint)
  python3 conformance_gate.py --endpoint http://localhost:8080/signals/latest

  # Offline gate (validate from file)
  python3 conformance_gate.py --file snapshot.json

  # Machine-readable JSON report
  python3 conformance_gate.py --endpoint URL --json

  # Self-test: prove the gate rejects known-invalid shapes
  python3 conformance_gate.py --self-test

  # Quiet mode (exit code only, no output)
  python3 conformance_gate.py --endpoint URL --quiet

Zero external dependencies — Python 3.8+ stdlib only.
"""

import argparse
import datetime
import hashlib
import json
import os
import re
import sys
import time
import urllib.request

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SCHEMA = os.path.join(SCRIPT_DIR, "producer_signal_schema.json")
GATE_VERSION = "1.0.0"
SCHEMA_FROZEN_ID = "https://postfiat.org/schemas/producer-signal/v1.0.0"


# ── helpers ──────────────────────────────────────────────────────────────────

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def iso_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.%f"
    )[:-3] + "Z"


def fetch_json(url: str, timeout: int = 30) -> dict:
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def extract_signals(data: dict) -> list:
    """Pull flat signal list from endpoint response envelope."""
    if isinstance(data, list):
        return data
    if "signals" in data:
        sigs = data["signals"]
        if isinstance(sigs, dict) and "published" in sigs:
            combined = list(sigs.get("published", []))
            combined.extend(sigs.get("suppressed", []))
            return combined
        if isinstance(sigs, list):
            return sigs
    return []


# ── Schema-Driven Validator ─────────────────────────────────────────────────

class SchemaValidator:
    """
    Validates JSON objects against a subset of JSON Schema Draft 2020-12.

    Supports: type, required, properties, additionalProperties, enum,
    minimum, maximum, minLength, maxLength, pattern, format (date-time),
    $ref resolution, if/then conditional.

    Does NOT support: allOf, anyOf, oneOf at arbitrary depth,
    patternProperties, unevaluatedProperties, $dynamicRef.
    These are not used in producer_signal_schema.json v1.0.0.
    """

    def __init__(self, schema_path: str):
        with open(schema_path) as f:
            self.root = json.load(f)
        self.defs = self.root.get("$defs", {})
        self.schema_id = self.root.get("$id", "unknown")

        # Pre-resolve the signal definition
        self.signal_def = self._resolve({"$ref": "#/$defs/signal"})

    def _resolve(self, node: dict) -> dict:
        """Resolve $ref pointers (single-level, internal only)."""
        if "$ref" not in node:
            return node
        ref = node["$ref"]
        if not ref.startswith("#/$defs/"):
            return node
        name = ref[len("#/$defs/"):]
        target = self.defs.get(name)
        if target is None:
            return node
        # Merge non-$ref keys from the referencing node (e.g. description overrides)
        merged = dict(target)
        for k, v in node.items():
            if k != "$ref":
                merged[k] = v
        return merged

    def validate_signal(self, signal: dict) -> list:
        """Validate a signal dict. Returns list of violation dicts."""
        violations = []
        self._validate_object(signal, self.signal_def, "signal", violations)
        self._check_conditional(signal, self.signal_def, violations)
        return violations

    def _validate_object(self, obj, schema, path, violations):
        """Validate an object against a schema node."""
        if not isinstance(obj, dict):
            violations.append({
                "path": path,
                "rule": "type",
                "expected": "object",
                "actual": type(obj).__name__,
                "message": f"{path}: expected object, got {type(obj).__name__}",
            })
            return

        props = schema.get("properties", {})
        required = schema.get("required", [])
        additional = schema.get("additionalProperties", True)

        # Required fields
        for field in required:
            if field not in obj:
                violations.append({
                    "path": f"{path}.{field}",
                    "rule": "required",
                    "expected": "present",
                    "actual": "missing",
                    "message": f"{path}.{field}: required field missing",
                })

        # additionalProperties
        if additional is False:
            allowed = set(props.keys())
            extras = set(obj.keys()) - allowed
            for extra in sorted(extras):
                violations.append({
                    "path": f"{path}.{extra}",
                    "rule": "additionalProperties",
                    "expected": "not present",
                    "actual": repr(obj[extra])[:60],
                    "message": f"{path}.{extra}: field not allowed by schema (additionalProperties: false)",
                })

        # Per-property validation
        for field, value in obj.items():
            if field not in props:
                continue  # already flagged by additionalProperties if strict
            field_schema = self._resolve(props[field])
            self._validate_value(value, field_schema, f"{path}.{field}", violations)

    def _validate_value(self, value, schema, path, violations):
        """Validate a single value against its schema definition."""
        schema = self._resolve(schema)
        expected_type = schema.get("type")

        # Type check
        if expected_type:
            if not self._type_matches(value, expected_type):
                violations.append({
                    "path": path,
                    "rule": "type",
                    "expected": expected_type,
                    "actual": type(value).__name__,
                    "message": f"{path}: expected type '{expected_type}', got '{type(value).__name__}'",
                })
                return  # Skip further checks if type is wrong

        # Enum
        enum_values = schema.get("enum")
        if enum_values is not None and value not in enum_values:
            violations.append({
                "path": path,
                "rule": "enum",
                "expected": enum_values,
                "actual": value,
                "message": f"{path}: value '{value}' not in enum {enum_values}",
            })

        # String constraints
        if isinstance(value, str):
            min_len = schema.get("minLength")
            if min_len is not None and len(value) < min_len:
                violations.append({
                    "path": path, "rule": "minLength",
                    "expected": f">= {min_len}", "actual": len(value),
                    "message": f"{path}: string length {len(value)} < minLength {min_len}",
                })
            max_len = schema.get("maxLength")
            if max_len is not None and len(value) > max_len:
                violations.append({
                    "path": path, "rule": "maxLength",
                    "expected": f"<= {max_len}", "actual": len(value),
                    "message": f"{path}: string length {len(value)} > maxLength {max_len}",
                })
            pattern = schema.get("pattern")
            if pattern and not re.match(pattern, value):
                violations.append({
                    "path": path, "rule": "pattern",
                    "expected": pattern, "actual": value,
                    "message": f"{path}: value '{value}' does not match pattern '{pattern}'",
                })
            fmt = schema.get("format")
            if fmt == "date-time":
                if not self._is_iso_datetime(value):
                    violations.append({
                        "path": path, "rule": "format",
                        "expected": "date-time (ISO 8601)", "actual": value,
                        "message": f"{path}: '{value}' is not valid ISO 8601 date-time",
                    })

        # Numeric constraints
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            minimum = schema.get("minimum")
            if minimum is not None and value < minimum:
                violations.append({
                    "path": path, "rule": "minimum",
                    "expected": f">= {minimum}", "actual": value,
                    "message": f"{path}: value {value} < minimum {minimum}",
                })
            maximum = schema.get("maximum")
            if maximum is not None and value > maximum:
                violations.append({
                    "path": path, "rule": "maximum",
                    "expected": f"<= {maximum}", "actual": value,
                    "message": f"{path}: value {value} > maximum {maximum}",
                })

        # Nested object
        if expected_type == "object" and isinstance(value, dict):
            self._validate_object(value, schema, path, violations)

        # Array
        if expected_type == "array" and isinstance(value, list):
            min_items = schema.get("minItems")
            if min_items is not None and len(value) < min_items:
                violations.append({
                    "path": path, "rule": "minItems",
                    "expected": f">= {min_items}", "actual": len(value),
                    "message": f"{path}: array length {len(value)} < minItems {min_items}",
                })
            items_schema = schema.get("items")
            if items_schema:
                resolved = self._resolve(items_schema)
                for i, item in enumerate(value):
                    self._validate_value(item, resolved, f"{path}[{i}]", violations)

    def _check_conditional(self, signal, schema, violations):
        """Handle if/then conditional (action=INVERT → weak_symbol required)."""
        if_clause = schema.get("if")
        then_clause = schema.get("then")
        if not if_clause or not then_clause:
            return

        # Check if the condition matches
        if_props = if_clause.get("properties", {})
        condition_met = True
        for field, constraint in if_props.items():
            if "const" in constraint:
                if signal.get(field) != constraint["const"]:
                    condition_met = False
                    break

        if not condition_met:
            return

        # Condition met — enforce then clause
        then_required = then_clause.get("required", [])
        for field in then_required:
            if field not in signal:
                violations.append({
                    "path": f"signal.{field}",
                    "rule": "conditional_required",
                    "expected": f"required when action='{signal.get('action')}'",
                    "actual": "missing",
                    "message": f"signal.{field}: required by conditional (action=INVERT → weak_symbol must be present)",
                })

        # Check nested required fields in then.properties
        then_props = then_clause.get("properties", {})
        for field, sub_schema in then_props.items():
            if field in signal and isinstance(signal[field], dict):
                sub_required = sub_schema.get("required", [])
                for sub_field in sub_required:
                    if sub_field not in signal[field]:
                        violations.append({
                            "path": f"signal.{field}.{sub_field}",
                            "rule": "conditional_required",
                            "expected": "present",
                            "actual": "missing",
                            "message": f"signal.{field}.{sub_field}: required when action=INVERT",
                        })

    @staticmethod
    def _type_matches(value, expected_type: str) -> bool:
        if expected_type == "string":
            return isinstance(value, str)
        if expected_type == "number":
            return isinstance(value, (int, float)) and not isinstance(value, bool)
        if expected_type == "integer":
            return isinstance(value, int) and not isinstance(value, bool)
        if expected_type == "boolean":
            return isinstance(value, bool)
        if expected_type == "object":
            return isinstance(value, dict)
        if expected_type == "array":
            return isinstance(value, list)
        if expected_type == "null":
            return value is None
        return True

    @staticmethod
    def _is_iso_datetime(s: str) -> bool:
        try:
            datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))
            return True
        except (ValueError, TypeError):
            return False


# ── Conformance Gate ─────────────────────────────────────────────────────────

class ConformanceGate:
    """
    Runs the full conformance gate against live or file-based producer output.
    Returns a structured report with deterministic PASS/FAIL verdict.
    """

    def __init__(self, schema_path: str = DEFAULT_SCHEMA):
        self.schema_path = schema_path
        self.validator = SchemaValidator(schema_path)
        with open(schema_path, "rb") as f:
            self.schema_hash = sha256_bytes(f.read())

    def run(self, signals: list, source: str = "unknown") -> dict:
        """Validate a list of signal dicts. Returns gate report."""
        started = time.monotonic()
        now = iso_now()

        if not signals:
            return self._build_report(
                source=source,
                signals_checked=0,
                signal_results=[],
                verdict="FAIL",
                elapsed=time.monotonic() - started,
                timestamp=now,
                error="No signals found in producer output",
            )

        signal_results = []
        all_pass = True

        for i, sig in enumerate(signals):
            violations = self.validator.validate_signal(sig)
            passed = len(violations) == 0
            if not passed:
                all_pass = False

            signal_results.append({
                "index": i,
                "signal_id": sig.get("signal_id", f"unknown-{i}"),
                "symbol": sig.get("symbol", "?"),
                "passed": passed,
                "violation_count": len(violations),
                "violations": violations,
            })

        verdict = "PASS" if all_pass else "FAIL"
        elapsed = time.monotonic() - started

        return self._build_report(
            source=source,
            signals_checked=len(signals),
            signal_results=signal_results,
            verdict=verdict,
            elapsed=elapsed,
            timestamp=now,
        )

    def _build_report(self, source, signals_checked, signal_results,
                      verdict, elapsed, timestamp, error=None):
        signals_passed = sum(1 for r in signal_results if r["passed"])
        total_violations = sum(r["violation_count"] for r in signal_results)

        # Unique violation rules triggered
        rules_triggered = set()
        for r in signal_results:
            for v in r["violations"]:
                rules_triggered.add(v["rule"])

        report = {
            "gate_version": GATE_VERSION,
            "schema_id": self.validator.schema_id,
            "schema_hash": self.schema_hash,
            "timestamp": timestamp,
            "source": source,
            "verdict": verdict,
            "exit_code": 0 if verdict == "PASS" else 1,
            "summary": {
                "signals_checked": signals_checked,
                "signals_passed": signals_passed,
                "signals_failed": signals_checked - signals_passed,
                "total_violations": total_violations,
                "rules_triggered": sorted(rules_triggered),
            },
            "signals": signal_results,
            "elapsed_ms": round(elapsed * 1000, 1),
        }
        if error:
            report["error"] = error
        return report


# ── Built-in Rejection Fixtures ─────────────────────────────────────────────

REJECTION_FIXTURES = [
    {
        "id": "missing_required_fields",
        "description": "Signal missing producer_id, schema_version, action (3 required fields)",
        "expected_rules": {"required"},
        "signal": {
            "signal_id": "test-BTC-1",
            "timestamp": "2026-05-20T12:00:00.000Z",
            "symbol": "BTC",
            "direction": "bullish",
            "confidence": 0.55,
            "horizon_hours": 24,
            # missing: producer_id, schema_version, action
        },
    },
    {
        "id": "direction_uppercase",
        "description": "Direction uses invalid uppercase BULLISH (schema requires lowercase)",
        "expected_rules": {"enum"},
        "signal": {
            "signal_id": "test-ETH-1",
            "producer_id": "test-producer",
            "schema_version": "1.0.0",
            "timestamp": "2026-05-20T12:00:00.000Z",
            "symbol": "ETH",
            "direction": "BULLISH",
            "confidence": 0.60,
            "horizon_hours": 24,
            "action": "EXECUTE",
        },
    },
    {
        "id": "direction_neutral",
        "description": "Direction is NEUTRAL which is not in the enum [bullish, bearish]",
        "expected_rules": {"enum"},
        "signal": {
            "signal_id": "test-SOL-1",
            "producer_id": "test-producer",
            "schema_version": "1.0.0",
            "timestamp": "2026-05-20T12:00:00.000Z",
            "symbol": "SOL",
            "direction": "NEUTRAL",
            "confidence": 0.50,
            "horizon_hours": 24,
            "action": "WITHHOLD",
        },
    },
    {
        "id": "extra_fields_top_level",
        "description": "Signal has extra fields violating additionalProperties: false",
        "expected_rules": {"additionalProperties"},
        "signal": {
            "signal_id": "test-BTC-2",
            "producer_id": "test-producer",
            "schema_version": "1.0.0",
            "timestamp": "2026-05-20T12:00:00.000Z",
            "symbol": "BTC",
            "direction": "bullish",
            "confidence": 0.55,
            "horizon_hours": 24,
            "action": "EXECUTE",
            "signal_type": "DIRECTIONAL",
            "expected_karma": 0.10,
            "voi_included": True,
        },
    },
    {
        "id": "flat_regime_fields",
        "description": "Regime fields flat on signal instead of nested regime_context",
        "expected_rules": {"additionalProperties"},
        "signal": {
            "signal_id": "test-LINK-1",
            "producer_id": "test-producer",
            "schema_version": "1.0.0",
            "timestamp": "2026-05-20T12:00:00.000Z",
            "symbol": "LINK",
            "direction": "bearish",
            "confidence": 0.52,
            "horizon_hours": 24,
            "action": "WITHHOLD",
            "regime": "SYSTEMIC",
            "regime_confidence": 0.77,
            "regime_duration_days": 75,
            "proximity": 0.01,
        },
    },
    {
        "id": "invert_without_weak_symbol",
        "description": "action=INVERT but weak_symbol metadata is missing (conditional violation)",
        "expected_rules": {"conditional_required"},
        "signal": {
            "signal_id": "test-SOL-2",
            "producer_id": "test-producer",
            "schema_version": "1.0.0",
            "timestamp": "2026-05-20T12:00:00.000Z",
            "symbol": "SOL",
            "direction": "bearish",
            "confidence": 0.56,
            "horizon_hours": 24,
            "action": "INVERT",
            # missing: weak_symbol (required when action=INVERT)
        },
    },
    {
        "id": "confidence_out_of_range",
        "description": "Confidence value 1.5 exceeds maximum 1.0",
        "expected_rules": {"maximum"},
        "signal": {
            "signal_id": "test-BTC-3",
            "producer_id": "test-producer",
            "schema_version": "1.0.0",
            "timestamp": "2026-05-20T12:00:00.000Z",
            "symbol": "BTC",
            "direction": "bullish",
            "confidence": 1.5,
            "horizon_hours": 24,
            "action": "EXECUTE",
        },
    },
    {
        "id": "invalid_action_enum",
        "description": "Action value HOLD is not in enum [EXECUTE, WITHHOLD, INVERT]",
        "expected_rules": {"enum"},
        "signal": {
            "signal_id": "test-ETH-2",
            "producer_id": "test-producer",
            "schema_version": "1.0.0",
            "timestamp": "2026-05-20T12:00:00.000Z",
            "symbol": "ETH",
            "direction": "bearish",
            "confidence": 0.60,
            "horizon_hours": 24,
            "action": "HOLD",
        },
    },
    {
        "id": "wrong_type_horizon",
        "description": "horizon_hours is a float (24.5) but schema requires integer",
        "expected_rules": {"type"},
        "signal": {
            "signal_id": "test-BTC-4",
            "producer_id": "test-producer",
            "schema_version": "1.0.0",
            "timestamp": "2026-05-20T12:00:00.000Z",
            "symbol": "BTC",
            "direction": "bullish",
            "confidence": 0.55,
            "horizon_hours": 24.5,
            "action": "EXECUTE",
        },
    },
    {
        "id": "symbol_lowercase",
        "description": "Symbol 'btc' violates pattern ^[A-Z0-9]+$",
        "expected_rules": {"pattern"},
        "signal": {
            "signal_id": "test-btc-5",
            "producer_id": "test-producer",
            "schema_version": "1.0.0",
            "timestamp": "2026-05-20T12:00:00.000Z",
            "symbol": "btc",
            "direction": "bullish",
            "confidence": 0.55,
            "horizon_hours": 24,
            "action": "EXECUTE",
        },
    },
    {
        "id": "regime_context_extra_fields",
        "description": "regime_context has extra fields violating its additionalProperties: false",
        "expected_rules": {"additionalProperties"},
        "signal": {
            "signal_id": "test-BTC-6",
            "producer_id": "test-producer",
            "schema_version": "1.0.0",
            "timestamp": "2026-05-20T12:00:00.000Z",
            "symbol": "BTC",
            "direction": "bullish",
            "confidence": 0.55,
            "horizon_hours": 24,
            "action": "EXECUTE",
            "regime_context": {
                "regime_id": "NEUTRAL",
                "regime_confidence": 0.80,
                "proximity": 0.1,
                "duration_days": 30,
                "custom_field": "not allowed",
            },
        },
    },
    {
        "id": "valid_minimal_signal",
        "description": "Minimal valid signal — should PASS (control fixture)",
        "expected_rules": set(),
        "signal": {
            "signal_id": "test-BTC-valid",
            "producer_id": "test-producer",
            "schema_version": "1.0.0",
            "timestamp": "2026-05-20T12:00:00.000Z",
            "symbol": "BTC",
            "direction": "bullish",
            "confidence": 0.55,
            "horizon_hours": 24,
            "action": "EXECUTE",
        },
    },
]


def run_self_test(schema_path: str) -> tuple:
    """Run all rejection fixtures. Returns (passed, total, details)."""
    validator = SchemaValidator(schema_path)
    results = []
    all_ok = True

    for fixture in REJECTION_FIXTURES:
        violations = validator.validate_signal(fixture["signal"])
        rules_found = {v["rule"] for v in violations}
        expected = fixture["expected_rules"]

        if expected:
            # This fixture should be REJECTED
            expected_hit = bool(expected & rules_found)
            ok = expected_hit
        else:
            # Control fixture: should PASS
            ok = len(violations) == 0

        if not ok:
            all_ok = False

        results.append({
            "fixture_id": fixture["id"],
            "description": fixture["description"],
            "expected_rules": sorted(expected),
            "actual_rules": sorted(rules_found),
            "violation_count": len(violations),
            "passed": ok,
        })

    return all_ok, len(results), results


# ── CLI output ───────────────────────────────────────────────────────────────

def print_report(report: dict):
    """Print human-readable gate report."""
    v = report["verdict"]
    s = report["summary"]

    print()
    print("=" * 70)
    print("  POST FIAT PRODUCER CONFORMANCE GATE")
    print("=" * 70)
    print(f"  Gate version:     {report['gate_version']}")
    print(f"  Schema:           {report['schema_id']}")
    print(f"  Schema hash:      {report['schema_hash'][:16]}...")
    print(f"  Timestamp:        {report['timestamp']}")
    print(f"  Source:           {report['source']}")
    print(f"  Elapsed:          {report['elapsed_ms']} ms")
    print("-" * 70)
    print(f"  Signals checked:  {s['signals_checked']}")
    print(f"  Signals passed:   {s['signals_passed']}")
    print(f"  Signals failed:   {s['signals_failed']}")
    print(f"  Total violations: {s['total_violations']}")
    if s["rules_triggered"]:
        print(f"  Rules triggered:  {', '.join(s['rules_triggered'])}")
    print("-" * 70)

    for sr in report["signals"]:
        status = "PASS" if sr["passed"] else "FAIL"
        print(f"  {sr['symbol']:6s} [{status}] {sr['signal_id']}")
        if not sr["passed"]:
            for v_item in sr["violations"]:
                print(f"           {v_item['path']}: {v_item['message']}")

    if report.get("error"):
        print(f"\n  ERROR: {report['error']}")

    print("-" * 70)
    marker = "PASS" if v == "PASS" else "FAIL"
    print(f"  {'=' * 40}")
    print(f"  |  VERDICT:  {marker:36s}|")
    print(f"  {'=' * 40}")
    print()


def print_self_test(ok: bool, total: int, results: list):
    """Print self-test results."""
    print()
    print("=" * 70)
    print("  CONFORMANCE GATE SELF-TEST")
    print("  Proves the gate rejects known-invalid producer output shapes")
    print("=" * 70)

    for r in results:
        status = "PASS" if r["passed"] else "FAIL"
        expected = r["expected_rules"] if r["expected_rules"] else ["(should pass)"]
        print(f"  [{status}] {r['fixture_id']}")
        print(f"         {r['description']}")
        print(f"         expected rules: {expected}")
        print(f"         actual rules:   {r['actual_rules'] or ['(none — clean)']}")
        print()

    passed = sum(1 for r in results if r["passed"])
    print("-" * 70)
    print(f"  Fixtures: {passed}/{total} passed")
    verdict = "PASS" if ok else "FAIL"
    print(f"  {'=' * 40}")
    print(f"  |  SELF-TEST:  {verdict:34s}|")
    print(f"  {'=' * 40}")
    print()


# ── main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Live producer conformance gate — validates output against frozen schema v1.0.0"
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--endpoint", metavar="URL",
        help="Live signal endpoint URL (e.g. http://localhost:8080/signals/latest)"
    )
    source.add_argument(
        "--file", metavar="PATH",
        help="Path to JSON file containing producer output"
    )
    source.add_argument(
        "--self-test", action="store_true",
        help="Run built-in rejection fixtures to prove the gate works"
    )
    parser.add_argument(
        "--schema", default=DEFAULT_SCHEMA,
        help=f"Path to frozen schema (default: {DEFAULT_SCHEMA})"
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output machine-readable JSON report"
    )
    parser.add_argument(
        "--quiet", action="store_true",
        help="No output, exit code only"
    )
    args = parser.parse_args()

    # Validate schema exists and is the frozen version
    if not os.path.isfile(args.schema):
        print(f"ERROR: Schema file not found: {args.schema}", file=sys.stderr)
        sys.exit(2)

    try:
        with open(args.schema) as f:
            schema_data = json.load(f)
        schema_id = schema_data.get("$id", "")
        if schema_id != SCHEMA_FROZEN_ID:
            print(
                f"WARNING: Schema $id is '{schema_id}', "
                f"expected frozen '{SCHEMA_FROZEN_ID}'",
                file=sys.stderr,
            )
    except (json.JSONDecodeError, IOError) as e:
        print(f"ERROR: Cannot load schema: {e}", file=sys.stderr)
        sys.exit(2)

    # Self-test mode
    if args.self_test:
        ok, total, results = run_self_test(args.schema)
        if args.json:
            json.dump({
                "mode": "self-test",
                "gate_version": GATE_VERSION,
                "passed": ok,
                "fixtures_total": total,
                "fixtures_passed": sum(1 for r in results if r["passed"]),
                "results": results,
            }, sys.stdout, indent=2)
            print()
        elif not args.quiet:
            print_self_test(ok, total, results)
        sys.exit(0 if ok else 1)

    # Need either --endpoint or --file
    if not args.endpoint and not args.file:
        parser.error("One of --endpoint, --file, or --self-test is required")

    # Load producer output
    try:
        if args.endpoint:
            data = fetch_json(args.endpoint)
            source_label = args.endpoint
        else:
            with open(args.file) as f:
                data = json.load(f)
            source_label = args.file
    except Exception as e:
        if not args.quiet:
            print(f"ERROR: Cannot load producer output: {e}", file=sys.stderr)
        sys.exit(2)

    # Extract and validate
    signals = extract_signals(data)
    gate = ConformanceGate(schema_path=args.schema)
    report = gate.run(signals, source=source_label)

    # Output
    if args.json:
        json.dump(report, sys.stdout, indent=2)
        print()
    elif not args.quiet:
        print_report(report)

    sys.exit(report["exit_code"])


if __name__ == "__main__":
    main()
