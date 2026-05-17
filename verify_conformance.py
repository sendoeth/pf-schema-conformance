#!/usr/bin/env python3
"""
verify_conformance.py — Zero-Trust Verifier for Schema Conformance Receipt

Validates a conformance_receipt.json artifact across 16 verification categories
with 200+ individual checks.  Verifies structural integrity, mismatch
documentation, before/after comparison logic, patch description, hash integrity,
limitation disclosure, and cross-reference consistency.

Zero external dependencies. Python 3.8+ stdlib only.

Usage:
    python3 verify_conformance.py conformance_receipt.json
    python3 verify_conformance.py conformance_receipt.json --json
    python3 verify_conformance.py conformance_receipt.json --verbose
"""

import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone


# ── helpers ────────────────────────────────────────────────────────────────────

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_dict(d: dict) -> str:
    return sha256_bytes(json.dumps(d, indent=2, sort_keys=True).encode())


def ck(check_id, passed, detail, severity="LOW"):
    return {"check_id": check_id, "passed": passed, "detail": detail, "severity": severity}


def is_hex64(s):
    return isinstance(s, str) and bool(re.match(r'^[a-f0-9]{64}$', s))


def is_iso_timestamp(s):
    if not isinstance(s, str):
        return False
    try:
        datetime.fromisoformat(s.replace("Z", "+00:00"))
        return True
    except (ValueError, TypeError):
        return False


# ── Category 1: Top-level Structure ───────────────────────────────────────────

def verify_structure(receipt):
    checks = []
    required = [
        "receipt_id", "schema_version", "generator_version", "generated_at",
        "producer_id", "endpoint", "canonical_schema", "mismatch", "patch",
        "before", "after", "conformance_summary", "conformance_command",
        "source_hashes", "limitations", "content_hash"
    ]
    for f in required:
        present = f in receipt
        checks.append(ck(
            f"STRUCT_{f.upper()}",
            present,
            f"'{f}' {'present' if present else 'MISSING'}",
            "CRITICAL" if not present else "LOW"
        ))

    # No unexpected top-level keys
    allowed = set(required)
    extras = set(receipt.keys()) - allowed
    checks.append(ck(
        "STRUCT_NO_EXTRAS",
        len(extras) == 0,
        f"Extra keys: {sorted(extras)}" if extras else "No extra keys",
        "MEDIUM" if extras else "LOW"
    ))

    # Types
    checks.append(ck("STRUCT_RECEIPT_DICT", isinstance(receipt, dict),
                      f"Type: {type(receipt).__name__}", "CRITICAL"))

    return {"category": "structure", "checks": checks}


# ── Category 2: Receipt ID & Version ──────────────────────────────────────────

def verify_receipt_id(receipt):
    checks = []
    rid = receipt.get("receipt_id", "")
    checks.append(ck("RID_PREFIX", isinstance(rid, str) and rid.startswith("SCR-"),
                      f"receipt_id={rid}", "HIGH"))
    checks.append(ck("RID_LENGTH", isinstance(rid, str) and len(rid) >= 10,
                      f"Length={len(rid) if isinstance(rid, str) else 'N/A'}", "MEDIUM"))

    sv = receipt.get("schema_version", "")
    checks.append(ck("RID_SCHEMA_VERSION", isinstance(sv, str) and re.match(r'^\d+\.\d+\.\d+$', sv),
                      f"schema_version={sv}", "HIGH"))

    gv = receipt.get("generator_version", "")
    checks.append(ck("RID_GENERATOR_VERSION", isinstance(gv, str) and re.match(r'^\d+\.\d+\.\d+$', gv),
                      f"generator_version={gv}", "MEDIUM"))

    return {"category": "receipt_id", "checks": checks}


# ── Category 3: Timestamp ─────────────────────────────────────────────────────

def verify_timestamp(receipt):
    checks = []
    gen = receipt.get("generated_at", "")
    parseable = is_iso_timestamp(gen)
    checks.append(ck("TS_PARSEABLE", parseable, f"generated_at={gen}", "HIGH"))

    if parseable:
        ts = datetime.fromisoformat(gen.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        age_days = (now - ts).total_seconds() / 86400
        checks.append(ck("TS_FRESH", age_days < 30,
                          f"Age: {age_days:.1f} days", "MEDIUM"))
        checks.append(ck("TS_NOT_FUTURE", ts <= now,
                          f"{'Future timestamp!' if ts > now else 'Not in future'}", "HIGH"))
    else:
        checks.append(ck("TS_FRESH", False, "Cannot check freshness", "HIGH"))

    return {"category": "timestamp", "checks": checks}


# ── Category 4: Producer Identity ─────────────────────────────────────────────

def verify_producer(receipt):
    checks = []
    pid = receipt.get("producer_id", "")
    checks.append(ck("PROD_ID_PRESENT", isinstance(pid, str) and len(pid) > 0,
                      f"producer_id={pid}", "HIGH"))
    checks.append(ck("PROD_ID_FORMAT", isinstance(pid, str) and re.match(r'^[a-z0-9\-]+$', pid),
                      f"Format: {'valid' if isinstance(pid, str) and re.match(r'^[a-z0-9-]+$', pid) else 'invalid'}", "MEDIUM"))

    ep = receipt.get("endpoint", "")
    checks.append(ck("PROD_ENDPOINT_URL", isinstance(ep, str) and ep.startswith("http"),
                      f"endpoint={ep}", "HIGH"))
    checks.append(ck("PROD_ENDPOINT_SIGNALS", isinstance(ep, str) and "signals" in ep,
                      f"Contains 'signals': {'yes' if 'signals' in str(ep) else 'no'}", "MEDIUM"))

    return {"category": "producer", "checks": checks}


# ── Category 5: Canonical Schema ──────────────────────────────────────────────

def verify_canonical_schema(receipt):
    checks = []
    cs = receipt.get("canonical_schema", {})
    checks.append(ck("SCHEMA_IS_DICT", isinstance(cs, dict), f"Type: {type(cs).__name__}", "HIGH"))

    name = cs.get("name", "")
    checks.append(ck("SCHEMA_NAME", name == "producer_signal_schema.json",
                      f"name={name}", "HIGH"))

    version = cs.get("version", "")
    checks.append(ck("SCHEMA_VERSION_PRESENT", isinstance(version, str) and len(version) > 0,
                      f"version={version}", "HIGH"))
    checks.append(ck("SCHEMA_VERSION_V1", "v1.0.0" in str(version),
                      f"Contains v1.0.0: {'yes' if 'v1.0.0' in str(version) else 'no'}", "MEDIUM"))

    ch = cs.get("content_hash", "")
    checks.append(ck("SCHEMA_HASH_FORMAT", is_hex64(ch),
                      f"Hash format: {'valid hex64' if is_hex64(ch) else 'invalid'}", "HIGH"))

    return {"category": "canonical_schema", "checks": checks}


# ── Category 6: Mismatch Documentation ────────────────────────────────────────

def verify_mismatch(receipt):
    checks = []
    m = receipt.get("mismatch", {})
    checks.append(ck("MISMATCH_IS_DICT", isinstance(m, dict), f"Type: {type(m).__name__}", "HIGH"))

    mid = m.get("mismatch_id", "")
    checks.append(ck("MISMATCH_ID_PRESENT", isinstance(mid, str) and len(mid) > 0,
                      f"mismatch_id={mid}", "HIGH"))
    is_snake = bool(re.match(r'^[a-z_]+$', mid)) if isinstance(mid, str) else False
    checks.append(ck("MISMATCH_ID_SNAKE", is_snake,
                      f"Snake case: {'yes' if is_snake else 'no'}", "LOW"))

    field = m.get("field", "")
    checks.append(ck("MISMATCH_FIELD_PRESENT", isinstance(field, str) and len(field) > 0,
                      f"field={field}", "HIGH"))

    desc = m.get("description", "")
    checks.append(ck("MISMATCH_DESC_PRESENT", isinstance(desc, str) and len(desc) > 20,
                      f"Description length: {len(desc) if isinstance(desc, str) else 0}", "HIGH"))
    checks.append(ck("MISMATCH_DESC_MENTIONS_SCHEMA", "schema" in desc.lower() if isinstance(desc, str) else False,
                      "Description references schema", "MEDIUM"))
    checks.append(ck("MISMATCH_DESC_MENTIONS_FIELD", field in desc if isinstance(desc, str) and isinstance(field, str) else False,
                      f"Description mentions field '{field}'", "MEDIUM"))

    rem = m.get("remediation_applied", "")
    checks.append(ck("MISMATCH_REMEDIATION", isinstance(rem, str) and len(rem) > 10,
                      f"Remediation length: {len(rem) if isinstance(rem, str) else 0}", "HIGH"))

    sev = m.get("severity", "")
    checks.append(ck("MISMATCH_SEVERITY", isinstance(sev, str) and len(sev) > 0,
                      f"severity={sev}", "MEDIUM"))

    ref = m.get("schema_reference", "")
    checks.append(ck("MISMATCH_SCHEMA_REF", isinstance(ref, str) and "producer_signal_schema" in ref,
                      f"schema_reference={ref}", "MEDIUM"))

    return {"category": "mismatch", "checks": checks}


# ── Category 7: Patch Description ─────────────────────────────────────────────

def verify_patch(receipt):
    checks = []
    p = receipt.get("patch", {})
    checks.append(ck("PATCH_IS_DICT", isinstance(p, dict), f"Type: {type(p).__name__}", "HIGH"))

    fp = p.get("file_patched", "")
    checks.append(ck("PATCH_FILE", isinstance(fp, str) and len(fp) > 0,
                      f"file_patched={fp}", "HIGH"))
    checks.append(ck("PATCH_FILE_JS", isinstance(fp, str) and fp.endswith(".js"),
                      f"Is .js file: {'yes' if isinstance(fp, str) and fp.endswith('.js') else 'no'}", "MEDIUM"))

    line = p.get("line")
    checks.append(ck("PATCH_LINE_NUM", isinstance(line, int) and line > 0,
                      f"line={line}", "MEDIUM"))

    ct = p.get("change_type", "")
    checks.append(ck("PATCH_CHANGE_TYPE", isinstance(ct, str) and ct in {"FIELD_ADDITION", "FIELD_MODIFICATION", "FIELD_REMOVAL", "LOGIC_CHANGE"},
                      f"change_type={ct}", "MEDIUM"))

    desc = p.get("description", "")
    checks.append(ck("PATCH_DESCRIPTION", isinstance(desc, str) and len(desc) > 20,
                      f"Description length: {len(desc) if isinstance(desc, str) else 0}", "MEDIUM"))

    code = p.get("code_added", "")
    checks.append(ck("PATCH_CODE_PRESENT", isinstance(code, str) and len(code) > 10,
                      f"Code length: {len(code) if isinstance(code, str) else 0}", "HIGH"))

    field = receipt.get("mismatch", {}).get("field", "")
    checks.append(ck("PATCH_CODE_REFERENCES_FIELD", field in str(code),
                      f"Code mentions '{field}': {'yes' if field in str(code) else 'no'}", "MEDIUM"))

    dl = p.get("derivation_logic")
    checks.append(ck("PATCH_DERIVATION_LOGIC", isinstance(dl, dict) and len(dl) > 0,
                      f"Derivation logic entries: {len(dl) if isinstance(dl, dict) else 0}", "MEDIUM"))

    if isinstance(dl, dict):
        valid_actions = {"EXECUTE", "WITHHOLD", "INVERT"}
        for act in valid_actions:
            checks.append(ck(f"PATCH_LOGIC_{act}", act in dl,
                              f"'{act}' logic: {'present' if act in dl else 'MISSING'}", "MEDIUM"))

    sa = p.get("signals_affected", "")
    checks.append(ck("PATCH_SIGNALS_AFFECTED", isinstance(sa, str) and len(sa) > 0,
                      f"signals_affected={sa}", "LOW"))

    return {"category": "patch", "checks": checks}


# ── Category 8: Before State ──────────────────────────────────────────────────

def verify_before(receipt):
    checks = []
    b = receipt.get("before", {})
    checks.append(ck("BEFORE_IS_DICT", isinstance(b, dict), f"Type: {type(b).__name__}", "HIGH"))

    sp = b.get("snapshot_path", "")
    checks.append(ck("BEFORE_SNAPSHOT_PATH", isinstance(sp, str) and len(sp) > 0,
                      f"snapshot_path={sp}", "HIGH"))

    sh = b.get("snapshot_hash", "")
    checks.append(ck("BEFORE_SNAPSHOT_HASH", is_hex64(sh),
                      f"Hash format: {'valid hex64' if is_hex64(sh) else 'invalid'}", "HIGH"))

    ca = b.get("captured_at", "")
    checks.append(ck("BEFORE_CAPTURED_AT", is_iso_timestamp(ca),
                      f"captured_at={ca}", "MEDIUM"))

    result = b.get("result", {})
    checks.append(ck("BEFORE_RESULT_DICT", isinstance(result, dict),
                      f"Result type: {type(result).__name__}", "HIGH"))

    verdict = result.get("verdict", "")
    checks.append(ck("BEFORE_VERDICT_VALID", verdict in {"PASS", "WARN", "FAIL"},
                      f"verdict={verdict}", "HIGH"))
    checks.append(ck("BEFORE_VERDICT_FAIL", verdict == "FAIL",
                      f"Before should be FAIL (was: {verdict})", "HIGH"))

    sc = result.get("signals_checked", 0)
    checks.append(ck("BEFORE_SIGNALS_CHECKED", isinstance(sc, int) and sc > 0,
                      f"signals_checked={sc}", "MEDIUM"))

    sp_count = result.get("signals_passed", -1)
    sf = result.get("signals_failed", -1)
    checks.append(ck("BEFORE_COUNTS_CONSISTENT", sp_count + sf == sc if isinstance(sp_count, int) and isinstance(sf, int) else False,
                      f"passed({sp_count}) + failed({sf}) == checked({sc})", "MEDIUM"))

    # All signals should have failed before
    pss = result.get("per_signal_summary", [])
    checks.append(ck("BEFORE_PER_SIGNAL_PRESENT", isinstance(pss, list) and len(pss) > 0,
                      f"Per-signal entries: {len(pss) if isinstance(pss, list) else 0}", "MEDIUM"))

    if isinstance(pss, list):
        all_failed = all(not s.get("passed", True) for s in pss)
        checks.append(ck("BEFORE_ALL_SIGNALS_FAILED", all_failed,
                          f"All signals failed: {all_failed}", "HIGH"))
        for i, s in enumerate(pss):
            checks.append(ck(f"BEFORE_SIG_{i}_HAS_ID", isinstance(s.get("signal_id"), str),
                              f"Signal {i} ID: {s.get('signal_id', 'MISSING')}", "LOW"))
            checks.append(ck(f"BEFORE_SIG_{i}_HAS_SYMBOL", isinstance(s.get("symbol"), str),
                              f"Signal {i} symbol: {s.get('symbol', 'MISSING')}", "LOW"))
            checks.append(ck(f"BEFORE_SIG_{i}_DETAIL_MISSING", "MISSING" in str(s.get("detail", "")),
                              f"Signal {i} detail shows MISSING: {'yes' if 'MISSING' in str(s.get('detail', '')) else 'no'}", "MEDIUM"))

    return {"category": "before", "checks": checks}


# ── Category 9: After State ───────────────────────────────────────────────────

def verify_after(receipt):
    checks = []
    a = receipt.get("after", {})
    checks.append(ck("AFTER_IS_DICT", isinstance(a, dict), f"Type: {type(a).__name__}", "HIGH"))

    ep = a.get("endpoint", "")
    checks.append(ck("AFTER_ENDPOINT", isinstance(ep, str) and ep.startswith("http"),
                      f"endpoint={ep}", "HIGH"))

    sh = a.get("snapshot_hash", "")
    checks.append(ck("AFTER_SNAPSHOT_HASH", is_hex64(sh),
                      f"Hash format: {'valid hex64' if is_hex64(sh) else 'invalid'}", "HIGH"))

    ca = a.get("captured_at", "")
    checks.append(ck("AFTER_CAPTURED_AT", is_iso_timestamp(ca),
                      f"captured_at={ca}", "MEDIUM"))

    result = a.get("result", {})
    checks.append(ck("AFTER_RESULT_DICT", isinstance(result, dict),
                      f"Result type: {type(result).__name__}", "HIGH"))

    verdict = result.get("verdict", "")
    checks.append(ck("AFTER_VERDICT_VALID", verdict in {"PASS", "WARN", "FAIL"},
                      f"verdict={verdict}", "HIGH"))
    checks.append(ck("AFTER_VERDICT_PASS", verdict == "PASS",
                      f"After should be PASS (was: {verdict})", "HIGH"))

    sc = result.get("signals_checked", 0)
    checks.append(ck("AFTER_SIGNALS_CHECKED", isinstance(sc, int) and sc > 0,
                      f"signals_checked={sc}", "MEDIUM"))

    sp_count = result.get("signals_passed", -1)
    sf = result.get("signals_failed", -1)
    checks.append(ck("AFTER_COUNTS_CONSISTENT", sp_count + sf == sc if isinstance(sp_count, int) and isinstance(sf, int) else False,
                      f"passed({sp_count}) + failed({sf}) == checked({sc})", "MEDIUM"))

    pss = result.get("per_signal_summary", [])
    checks.append(ck("AFTER_PER_SIGNAL_PRESENT", isinstance(pss, list) and len(pss) > 0,
                      f"Per-signal entries: {len(pss) if isinstance(pss, list) else 0}", "MEDIUM"))

    if isinstance(pss, list):
        all_passed = all(s.get("passed", False) for s in pss)
        checks.append(ck("AFTER_ALL_SIGNALS_PASSED", all_passed,
                          f"All signals passed: {all_passed}", "HIGH"))
        for i, s in enumerate(pss):
            checks.append(ck(f"AFTER_SIG_{i}_HAS_ID", isinstance(s.get("signal_id"), str),
                              f"Signal {i} ID: {s.get('signal_id', 'MISSING')}", "LOW"))
            checks.append(ck(f"AFTER_SIG_{i}_HAS_SYMBOL", isinstance(s.get("symbol"), str),
                              f"Signal {i} symbol: {s.get('symbol', 'MISSING')}", "LOW"))
            checks.append(ck(f"AFTER_SIG_{i}_PASSED", s.get("passed", False),
                              f"Signal {i} passed: {s.get('passed')}", "MEDIUM"))

    return {"category": "after", "checks": checks}


# ── Category 10: Before/After Comparison ──────────────────────────────────────

def verify_comparison(receipt):
    checks = []
    b = receipt.get("before", {})
    a = receipt.get("after", {})
    br = b.get("result", {})
    ar = a.get("result", {})

    # Same number of signals checked
    bsc = br.get("signals_checked", -1)
    asc = ar.get("signals_checked", -1)
    checks.append(ck("CMP_SAME_SIGNAL_COUNT", bsc == asc,
                      f"Before: {bsc}, After: {asc}", "MEDIUM"))

    # Before has fewer passes than after
    bsp = br.get("signals_passed", 0)
    asp = ar.get("signals_passed", 0)
    checks.append(ck("CMP_IMPROVEMENT", asp > bsp,
                      f"Before passed: {bsp}, After passed: {asp}", "HIGH"))

    # Hashes differ
    bh = b.get("snapshot_hash", "")
    ah = a.get("snapshot_hash", "")
    checks.append(ck("CMP_HASHES_DIFFER", bh != ah and is_hex64(bh) and is_hex64(ah),
                      f"Before hash != After hash: {bh != ah}", "HIGH"))

    # Before captured before After
    bca = b.get("captured_at", "")
    aca = a.get("captured_at", "")
    if is_iso_timestamp(bca) and is_iso_timestamp(aca):
        bt = datetime.fromisoformat(bca.replace("Z", "+00:00"))
        at = datetime.fromisoformat(aca.replace("Z", "+00:00"))
        checks.append(ck("CMP_TEMPORAL_ORDER", bt < at,
                          f"Before ({bca}) < After ({aca})", "MEDIUM"))
    else:
        checks.append(ck("CMP_TEMPORAL_ORDER", False, "Cannot parse timestamps", "MEDIUM"))

    # Symbols match between before and after
    bsigs = br.get("per_signal_summary", [])
    asigs = ar.get("per_signal_summary", [])
    if isinstance(bsigs, list) and isinstance(asigs, list):
        bsyms = {s.get("symbol") for s in bsigs}
        asyms = {s.get("symbol") for s in asigs}
        checks.append(ck("CMP_SAME_SYMBOLS", bsyms == asyms,
                          f"Before: {sorted(bsyms)}, After: {sorted(asyms)}", "MEDIUM"))
    else:
        checks.append(ck("CMP_SAME_SYMBOLS", False, "Missing per_signal_summary", "MEDIUM"))

    return {"category": "comparison", "checks": checks}


# ── Category 11: Conformance Summary ─────────────────────────────────────────

def verify_conformance_summary(receipt):
    checks = []
    cs = receipt.get("conformance_summary", {})
    checks.append(ck("CS_IS_DICT", isinstance(cs, dict), f"Type: {type(cs).__name__}", "HIGH"))

    fv = cs.get("final_verdict", "")
    checks.append(ck("CS_VERDICT_VALID", fv in {"PASS", "WARN", "FAIL"},
                      f"final_verdict={fv}", "CRITICAL"))

    sc = cs.get("status_change", "")
    checks.append(ck("CS_STATUS_CHANGE_VALID", sc in {"FIXED", "IMPROVED", "UNCHANGED", "PARTIAL", "REGRESSED"},
                      f"status_change={sc}", "HIGH"))

    bv = cs.get("before_verdict", "")
    av = cs.get("after_verdict", "")
    checks.append(ck("CS_BEFORE_VERDICT_MATCHES", bv == receipt.get("before", {}).get("result", {}).get("verdict"),
                      f"Summary before={bv}, actual={receipt.get('before', {}).get('result', {}).get('verdict')}", "HIGH"))
    checks.append(ck("CS_AFTER_VERDICT_MATCHES", av == receipt.get("after", {}).get("result", {}).get("verdict"),
                      f"Summary after={av}, actual={receipt.get('after', {}).get('result', {}).get('verdict')}", "HIGH"))

    # Fixed = before FAIL, after PASS
    if sc == "FIXED":
        checks.append(ck("CS_FIXED_LOGIC", bv == "FAIL" and av == "PASS",
                          f"FIXED requires FAIL→PASS: {bv}→{av}", "HIGH"))

    fc = cs.get("field_checked", "")
    mf = receipt.get("mismatch", {}).get("field", "")
    checks.append(ck("CS_FIELD_MATCHES_MISMATCH", fc == mf,
                      f"Summary field={fc}, mismatch field={mf}", "MEDIUM"))

    bsp = cs.get("before_signals_passing", -1)
    asp = cs.get("after_signals_passing", -1)
    tsc = cs.get("total_signals_checked", -1)
    checks.append(ck("CS_COUNTS_PRESENT", all(isinstance(x, int) and x >= 0 for x in [bsp, asp, tsc]),
                      f"before_passing={bsp}, after_passing={asp}, total={tsc}", "MEDIUM"))
    checks.append(ck("CS_AFTER_LEQ_TOTAL", asp <= tsc if isinstance(asp, int) and isinstance(tsc, int) else False,
                      f"after_passing({asp}) <= total({tsc})", "MEDIUM"))

    return {"category": "conformance_summary", "checks": checks}


# ── Category 12: Conformance Command ─────────────────────────────────────────

def verify_command(receipt):
    checks = []
    cmd = receipt.get("conformance_command", "")
    checks.append(ck("CMD_PRESENT", isinstance(cmd, str) and len(cmd) > 20,
                      f"Command length: {len(cmd) if isinstance(cmd, str) else 0}", "MEDIUM"))
    checks.append(ck("CMD_HAS_SCRIPT", "check_conformance.py" in cmd,
                      "References check_conformance.py", "MEDIUM"))
    checks.append(ck("CMD_HAS_ENDPOINT", "--endpoint" in cmd,
                      "Has --endpoint flag", "MEDIUM"))
    checks.append(ck("CMD_HAS_SCHEMA", "--schema" in cmd,
                      "Has --schema flag", "MEDIUM"))
    checks.append(ck("CMD_HAS_MISMATCH", "--mismatch" in cmd,
                      "Has --mismatch flag", "MEDIUM"))
    checks.append(ck("CMD_HAS_BEFORE", "--before-snapshot" in cmd,
                      "Has --before-snapshot flag", "MEDIUM"))
    checks.append(ck("CMD_HAS_OUTPUT", "-o" in cmd,
                      "Has -o flag", "LOW"))

    # Mismatch ID in command matches mismatch field
    mid = receipt.get("mismatch", {}).get("mismatch_id", "")
    checks.append(ck("CMD_MISMATCH_CONSISTENT", mid in cmd if isinstance(cmd, str) else False,
                      f"Command contains mismatch_id '{mid}'", "MEDIUM"))

    return {"category": "command", "checks": checks}


# ── Category 13: Source Hashes ────────────────────────────────────────────────

def verify_source_hashes(receipt):
    checks = []
    sh = receipt.get("source_hashes", {})
    checks.append(ck("HASH_IS_DICT", isinstance(sh, dict), f"Type: {type(sh).__name__}", "HIGH"))

    required_hashes = ["schema", "before_snapshot", "after_snapshot"]
    for h in required_hashes:
        val = sh.get(h, "")
        checks.append(ck(f"HASH_{h.upper()}_PRESENT", is_hex64(val),
                          f"{h}: {'valid hex64' if is_hex64(val) else 'invalid or missing'}", "HIGH"))

    # Cross-reference: schema hash matches canonical_schema
    cs_hash = receipt.get("canonical_schema", {}).get("content_hash", "")
    sh_hash = sh.get("schema", "")
    checks.append(ck("HASH_SCHEMA_XREF", cs_hash == sh_hash and is_hex64(cs_hash),
                      f"canonical_schema hash matches source_hashes.schema: {cs_hash == sh_hash}", "HIGH"))

    # Cross-reference: before hash matches before.snapshot_hash
    b_hash = receipt.get("before", {}).get("snapshot_hash", "")
    sh_b = sh.get("before_snapshot", "")
    checks.append(ck("HASH_BEFORE_XREF", b_hash == sh_b and is_hex64(b_hash),
                      f"before.snapshot_hash matches source_hashes.before_snapshot: {b_hash == sh_b}", "HIGH"))

    # Cross-reference: after hash matches after.snapshot_hash
    a_hash = receipt.get("after", {}).get("snapshot_hash", "")
    sh_a = sh.get("after_snapshot", "")
    checks.append(ck("HASH_AFTER_XREF", a_hash == sh_a and is_hex64(a_hash),
                      f"after.snapshot_hash matches source_hashes.after_snapshot: {a_hash == sh_a}", "HIGH"))

    # All three hashes should be different
    all_hashes = [sh.get(h, "") for h in required_hashes]
    unique_hashes = set(h for h in all_hashes if is_hex64(h))
    checks.append(ck("HASH_ALL_UNIQUE", len(unique_hashes) == 3,
                      f"Unique hashes: {len(unique_hashes)}/3", "MEDIUM"))

    return {"category": "source_hashes", "checks": checks}


# ── Category 14: Content Hash (Zero-Then-Fill) ───────────────────────────────

def verify_content_hash(receipt):
    checks = []
    ch = receipt.get("content_hash", "")
    checks.append(ck("CH_PRESENT", is_hex64(ch),
                      f"content_hash: {'valid hex64' if is_hex64(ch) else 'invalid'}", "HIGH"))

    # Recompute using zero-then-fill
    import copy
    receipt_copy = copy.deepcopy(receipt)
    receipt_copy["content_hash"] = "0" * 64
    zero_bytes = json.dumps(receipt_copy, indent=2, sort_keys=True).encode()
    recomputed = sha256_bytes(zero_bytes)
    checks.append(ck("CH_RECOMPUTED", ch == recomputed,
                      f"Stored={ch[:16]}..., Recomputed={recomputed[:16]}...", "CRITICAL"))

    return {"category": "content_hash", "checks": checks}


# ── Category 15: Limitations ─────────────────────────────────────────────────

def verify_limitations(receipt):
    checks = []
    lims = receipt.get("limitations", [])
    checks.append(ck("LIM_IS_LIST", isinstance(lims, list), f"Type: {type(lims).__name__}", "HIGH"))
    checks.append(ck("LIM_COUNT", isinstance(lims, list) and len(lims) >= 4,
                      f"Count: {len(lims) if isinstance(lims, list) else 0} (min 4)", "HIGH"))

    if isinstance(lims, list):
        ids = []
        valid_bias_dir = {"OVERSTATED_READINESS", "UNDERSTATED_RISK", "INDETERMINATE"}
        valid_bias_mag = {"LOW", "MODERATE", "HIGH"}
        for i, lim in enumerate(lims):
            lid = lim.get("id", "")
            ids.append(lid)
            checks.append(ck(f"LIM_{i}_ID", isinstance(lid, str) and len(lid) > 0,
                              f"Limitation {i} ID: {lid}", "LOW"))
            checks.append(ck(f"LIM_{i}_DESC", isinstance(lim.get("description"), str) and len(lim["description"]) > 10,
                              f"Limitation {i} description length: {len(lim.get('description', ''))}", "MEDIUM"))
            checks.append(ck(f"LIM_{i}_BIAS_DIR", lim.get("bias_direction") in valid_bias_dir,
                              f"Limitation {i} bias_direction: {lim.get('bias_direction')}", "MEDIUM"))
            checks.append(ck(f"LIM_{i}_BIAS_MAG", lim.get("bias_magnitude") in valid_bias_mag,
                              f"Limitation {i} bias_magnitude: {lim.get('bias_magnitude')}", "MEDIUM"))

        checks.append(ck("LIM_UNIQUE_IDS", len(set(ids)) == len(ids),
                          f"Unique IDs: {len(set(ids))}/{len(ids)}", "MEDIUM"))

    return {"category": "limitations", "checks": checks}


# ── Category 16: Cross-References ────────────────────────────────────────────

def verify_cross_references(receipt):
    checks = []

    # Producer ID consistent
    pid = receipt.get("producer_id", "")
    checks.append(ck("XREF_PRODUCER_CONSISTENT", isinstance(pid, str) and len(pid) > 0,
                      f"producer_id={pid}", "MEDIUM"))

    # Endpoint consistent between top-level and after
    ep_top = receipt.get("endpoint", "")
    ep_after = receipt.get("after", {}).get("endpoint", "")
    checks.append(ck("XREF_ENDPOINT_CONSISTENT", ep_top == ep_after,
                      f"Top-level={ep_top}, after={ep_after}", "MEDIUM"))

    # Mismatch field consistent with conformance_summary
    mf = receipt.get("mismatch", {}).get("field", "")
    csf = receipt.get("conformance_summary", {}).get("field_checked", "")
    checks.append(ck("XREF_FIELD_CONSISTENT", mf == csf,
                      f"mismatch.field={mf}, summary.field_checked={csf}", "HIGH"))

    # Mismatch ID in command
    mid = receipt.get("mismatch", {}).get("mismatch_id", "")
    cmd = receipt.get("conformance_command", "")
    checks.append(ck("XREF_MISMATCH_IN_CMD", mid in cmd,
                      f"mismatch_id '{mid}' in command: {mid in cmd}", "MEDIUM"))

    # Before/after verdicts match summary
    bv_actual = receipt.get("before", {}).get("result", {}).get("verdict", "")
    av_actual = receipt.get("after", {}).get("result", {}).get("verdict", "")
    bv_summary = receipt.get("conformance_summary", {}).get("before_verdict", "")
    av_summary = receipt.get("conformance_summary", {}).get("after_verdict", "")
    checks.append(ck("XREF_BEFORE_VERDICT", bv_actual == bv_summary,
                      f"Actual={bv_actual}, Summary={bv_summary}", "HIGH"))
    checks.append(ck("XREF_AFTER_VERDICT", av_actual == av_summary,
                      f"Actual={av_actual}, Summary={av_summary}", "HIGH"))

    # Signal counts match
    bsp_actual = receipt.get("before", {}).get("result", {}).get("signals_passed", -1)
    asp_actual = receipt.get("after", {}).get("result", {}).get("signals_passed", -1)
    bsp_summary = receipt.get("conformance_summary", {}).get("before_signals_passing", -1)
    asp_summary = receipt.get("conformance_summary", {}).get("after_signals_passing", -1)
    checks.append(ck("XREF_BEFORE_PASS_COUNT", bsp_actual == bsp_summary,
                      f"Actual={bsp_actual}, Summary={bsp_summary}", "MEDIUM"))
    checks.append(ck("XREF_AFTER_PASS_COUNT", asp_actual == asp_summary,
                      f"Actual={asp_actual}, Summary={asp_summary}", "MEDIUM"))

    tsc_actual = receipt.get("after", {}).get("result", {}).get("signals_checked", -1)
    tsc_summary = receipt.get("conformance_summary", {}).get("total_signals_checked", -1)
    checks.append(ck("XREF_TOTAL_COUNT", tsc_actual == tsc_summary,
                      f"Actual={tsc_actual}, Summary={tsc_summary}", "MEDIUM"))

    return {"category": "cross_references", "checks": checks}


# ── Runner ─────────────────────────────────────────────────────────────────────

ALL_CATEGORIES = [
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
]


def run_verification(receipt_path):
    with open(receipt_path) as f:
        receipt = json.load(f)

    results = []
    total_pass = 0
    total_fail = 0

    for category_fn in ALL_CATEGORIES:
        cat_result = category_fn(receipt)
        cat_pass = sum(1 for c in cat_result["checks"] if c["passed"])
        cat_fail = len(cat_result["checks"]) - cat_pass
        cat_result["passed"] = cat_pass
        cat_result["failed"] = cat_fail
        cat_result["total"] = len(cat_result["checks"])
        total_pass += cat_pass
        total_fail += cat_fail
        results.append(cat_result)

    total = total_pass + total_fail
    pct = (total_pass / total * 100) if total > 0 else 0
    grade = "A" if pct >= 99 else "B" if pct >= 90 else "C" if pct >= 75 else "D" if pct >= 50 else "F"

    return {
        "artifact": receipt_path,
        "verified_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "categories": results,
        "total_checks": total,
        "total_passed": total_pass,
        "total_failed": total_fail,
        "pass_rate": round(pct, 2),
        "grade": grade,
    }


def print_results(results, verbose=False):
    print()
    print("=" * 70)
    print("  CONFORMANCE RECEIPT VERIFICATION")
    print("=" * 70)
    print(f"  Artifact:  {results['artifact']}")
    print(f"  Verified:  {results['verified_at']}")
    print("-" * 70)

    for cat in results["categories"]:
        status = "PASS" if cat["failed"] == 0 else "FAIL"
        print(f"  [{status}] {cat['category']:25s}  {cat['passed']}/{cat['total']}")
        if verbose or cat["failed"] > 0:
            for c in cat["checks"]:
                mark = "+" if c["passed"] else "X"
                print(f"        [{mark}] {c['check_id']:35s} {c['detail']}")

    print("-" * 70)
    print(f"  Total:     {results['total_passed']}/{results['total_checks']} checks passed")
    print(f"  Pass rate: {results['pass_rate']:.1f}%")
    print(f"  ╔══════════════════════════════════════╗")
    print(f"  ║  GRADE:  {results['grade']}                            ║")
    print(f"  ╚══════════════════════════════════════╝")
    print()


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 verify_conformance.py <conformance_receipt.json> [--json] [--verbose]")
        sys.exit(1)

    receipt_path = sys.argv[1]
    json_output = "--json" in sys.argv
    verbose = "--verbose" in sys.argv

    if not os.path.exists(receipt_path):
        print(f"ERROR: File not found: {receipt_path}")
        sys.exit(1)

    results = run_verification(receipt_path)

    if json_output:
        print(json.dumps(results, indent=2))
    else:
        print_results(results, verbose=verbose)

    if results["grade"] in ("D", "F"):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
