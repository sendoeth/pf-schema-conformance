#!/usr/bin/env python3
"""Post Fiat Clean-Room Signal Consumer

Minimal standalone consumer that gates signal ingestion on live schema
conformance. Uses only public Post Fiat API surfaces — no private endpoints,
no team clarification, no adapter translations.

Usage:
    python3 pf_consumer.py [--api URL] [--strict] [--quiet]

    --api URL     Base URL of the Live Signal API (default: http://84.32.34.46:8080)
    --strict      Fail if cross-validation is present but disagrees with gate
    --quiet       Suppress human-readable output; emit only the verdict JSON

Exit codes:
    0  READY      — conformance passed, signals ingested, verdict emitted
    1  CONFORMANCE_FAIL — conformance gate reported violations; ingestion refused
    2  API_ERROR   — could not reach the API or received unexpected response
    3  SIGNAL_INTEGRITY_FAIL — signals fetched but missing schema-required fields

The script emits exactly one JSON object to stdout: the integration verdict.
"""

import argparse
import json
import sys
import time
import urllib.request
import urllib.error
import hashlib
from datetime import datetime, timezone

# ── Schema-required fields (from frozen producer_signal_schema.json v1.0.0) ──
REQUIRED_SIGNAL_FIELDS = [
    'signal_id', 'producer_id', 'timestamp', 'symbol',
    'direction', 'confidence', 'horizon_hours', 'action', 'schema_version'
]

DIRECTION_ENUM = ['bullish', 'bearish']
ACTION_ENUM = ['EXECUTE', 'WITHHOLD', 'INVERT']

# When action=INVERT, weak_symbol must be present with these sub-fields
INVERT_REQUIRED_WEAK_SYMBOL_FIELDS = ['weakness_score', 'severity', 'original_direction']

REGIME_CONTEXT_FIELDS = ['regime_id', 'regime_confidence', 'proximity', 'duration_days', 'decision']
REGIME_ID_ENUM = ['SYSTEMIC', 'NEUTRAL', 'DIVERGENCE', 'EARNINGS', 'UNKNOWN']
REGIME_DECISION_ENUM = ['NO_TRADE', 'EXECUTE', 'MONITOR']


def fetch_json(url, label, timeout=15):
    """Fetch a URL and parse JSON. Returns (data, error_string)."""
    try:
        req = urllib.request.Request(url, headers={'Accept': 'application/json'})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            body = resp.read().decode('utf-8')
            data = json.loads(body)
            return data, None, status
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode('utf-8')
            data = json.loads(body)
            return data, f'HTTP {e.code}', e.code
        except Exception:
            return None, f'HTTP {e.code}: {e.reason}', e.code
    except urllib.error.URLError as e:
        return None, f'Connection failed: {e.reason}', None
    except json.JSONDecodeError as e:
        return None, f'Invalid JSON: {e}', None
    except Exception as e:
        return None, f'Unexpected error: {e}', None


def validate_signal(sig, index):
    """Validate a single signal against schema-required fields and constraints.
    Returns a list of issue strings (empty = valid)."""
    issues = []
    sig_id = sig.get('signal_id', f'signal[{index}]')

    # Required fields
    for field in REQUIRED_SIGNAL_FIELDS:
        if field not in sig:
            issues.append(f'{sig_id}: missing required field "{field}"')

    # Type checks on present fields
    if 'confidence' in sig:
        c = sig['confidence']
        if not isinstance(c, (int, float)):
            issues.append(f'{sig_id}: confidence must be a number, got {type(c).__name__}')
        elif c < 0.0 or c > 1.0:
            issues.append(f'{sig_id}: confidence {c} out of range [0, 1]')

    if 'horizon_hours' in sig:
        h = sig['horizon_hours']
        if not isinstance(h, int) or isinstance(h, bool):
            issues.append(f'{sig_id}: horizon_hours must be integer, got {type(h).__name__}')
        elif h < 1 or h > 8760:
            issues.append(f'{sig_id}: horizon_hours {h} out of range [1, 8760]')

    if 'direction' in sig and sig['direction'] not in DIRECTION_ENUM:
        issues.append(f'{sig_id}: direction "{sig["direction"]}" not in {DIRECTION_ENUM}')

    if 'action' in sig and sig['action'] not in ACTION_ENUM:
        issues.append(f'{sig_id}: action "{sig["action"]}" not in {ACTION_ENUM}')

    if 'symbol' in sig:
        s = sig['symbol']
        if not isinstance(s, str) or not s.isalnum() or s != s.upper():
            issues.append(f'{sig_id}: symbol "{s}" must be uppercase alphanumeric')

    # Conditional: action=INVERT requires weak_symbol with sub-fields
    if sig.get('action') == 'INVERT':
        ws = sig.get('weak_symbol')
        if not ws or not isinstance(ws, dict):
            issues.append(f'{sig_id}: action=INVERT but weak_symbol is missing')
        else:
            for wf in INVERT_REQUIRED_WEAK_SYMBOL_FIELDS:
                if wf not in ws:
                    issues.append(f'{sig_id}: weak_symbol missing required field "{wf}"')

    # Regime context validation (optional but validated if present)
    rc = sig.get('regime_context')
    if rc and isinstance(rc, dict):
        if 'regime_id' in rc and rc['regime_id'] not in REGIME_ID_ENUM:
            issues.append(f'{sig_id}: regime_context.regime_id "{rc["regime_id"]}" not in {REGIME_ID_ENUM}')
        if 'regime_confidence' in rc:
            rc_conf = rc['regime_confidence']
            if isinstance(rc_conf, (int, float)) and (rc_conf < 0 or rc_conf > 1):
                issues.append(f'{sig_id}: regime_context.regime_confidence {rc_conf} out of range [0, 1]')
        if 'decision' in rc and rc['decision'] not in REGIME_DECISION_ENUM:
            issues.append(f'{sig_id}: regime_context.decision "{rc["decision"]}" not in {REGIME_DECISION_ENUM}')

    # Attribution hash verification (optional but verified if present)
    if 'attribution_hash' in sig and all(f in sig for f in ['signal_id', 'symbol', 'direction', 'confidence', 'horizon_hours', 'timestamp']):
        payload = '|'.join(str(sig[f]) for f in ['signal_id', 'symbol', 'direction', 'confidence', 'horizon_hours', 'timestamp'])
        expected = hashlib.sha256(payload.encode()).hexdigest()
        if sig['attribution_hash'] != expected:
            issues.append(f'{sig_id}: attribution_hash mismatch (tamper detected or payload format changed)')

    return issues


def run(api_base, strict=False, quiet=False):
    """Execute the full consumer flow: conformance gate → signal fetch → verdict."""
    started_at = datetime.now(timezone.utc).isoformat()
    log = [] if quiet else None

    def emit(msg):
        if not quiet:
            print(f'  {msg}', file=sys.stderr)

    emit(f'Post Fiat Clean-Room Consumer')
    emit(f'API: {api_base}')
    emit(f'Started: {started_at}')
    emit('')

    # ── Step 1: Fetch conformance status ─────────────────────────────────
    emit('[1/3] Fetching conformance status...')
    conf_url = f'{api_base}/conformance/status'
    conf_data, conf_err, conf_status = fetch_json(conf_url, 'conformance/status')

    if conf_err and conf_data is None:
        verdict = {
            'verdict': 'API_ERROR',
            'ready_to_ingest': False,
            'stage_reached': 'conformance_fetch',
            'error': conf_err,
            'api_base': api_base,
            'conformance_url': conf_url,
            'timestamp': started_at,
        }
        print(json.dumps(verdict, indent=2))
        return 2

    # Extract conformance fields
    gate_verdict = conf_data.get('verdict', 'UNKNOWN') if conf_data else 'UNKNOWN'
    schema_version = conf_data.get('schema_version', 'unknown') if conf_data else 'unknown'
    violation_count = conf_data.get('violation_count', -1) if conf_data else -1
    signals_checked = conf_data.get('signals_checked', 0) if conf_data else 0
    streak = conf_data.get('consecutive_pass_streak', 0) if conf_data else 0

    emit(f'  Verdict: {gate_verdict}')
    emit(f'  Schema: {schema_version}')
    emit(f'  Violations: {violation_count}')
    emit(f'  Streak: {streak} consecutive passes')

    # Cross-validation check (if present and strict mode)
    cross = conf_data.get('cross_validation', {}) if conf_data else {}
    cross_passed = cross.get('passed')
    if strict and cross_passed is False:
        emit(f'  Cross-validation FAILED (strict mode) — refusing ingestion')
        gate_verdict = 'FAIL'

    emit('')

    # ── Step 2: Gate decision ────────────────────────────────────────────
    if gate_verdict != 'PASS' or violation_count != 0:
        emit('[STOP] Conformance gate did not pass — ingestion refused.')
        emit(f'  Gate verdict: {gate_verdict}, violations: {violation_count}')

        # Include per-signal failure details if available
        failed_signals = []
        for ps in (conf_data.get('per_signal', []) if conf_data else []):
            if not ps.get('passed', True):
                failed_signals.append({
                    'signal_id': ps.get('signal_id'),
                    'symbol': ps.get('symbol'),
                    'violations': ps.get('violations', []),
                })

        verdict = {
            'verdict': 'CONFORMANCE_FAIL',
            'ready_to_ingest': False,
            'stage_reached': 'conformance_gate',
            'conformance': {
                'gate_verdict': gate_verdict,
                'schema_version': schema_version,
                'violation_count': violation_count,
                'signals_checked': signals_checked,
                'failed_signals': failed_signals,
            },
            'api_base': api_base,
            'timestamp': started_at,
        }
        print(json.dumps(verdict, indent=2))
        return 1

    emit('[PASS] Conformance gate passed — proceeding to signal fetch.')
    emit('')

    # ── Step 3: Fetch latest signals ─────────────────────────────────────
    emit('[2/3] Fetching latest signals...')
    sig_url = f'{api_base}/signals/latest'
    sig_data, sig_err, sig_status = fetch_json(sig_url, 'signals/latest')

    if sig_err and sig_data is None:
        verdict = {
            'verdict': 'API_ERROR',
            'ready_to_ingest': False,
            'stage_reached': 'signal_fetch',
            'error': sig_err,
            'conformance': {
                'gate_verdict': 'PASS',
                'schema_version': schema_version,
                'violation_count': 0,
            },
            'api_base': api_base,
            'timestamp': started_at,
        }
        print(json.dumps(verdict, indent=2))
        return 2

    # Extract signals from the envelope
    signals_envelope = sig_data.get('signals', {})
    if isinstance(signals_envelope, dict):
        published = signals_envelope.get('published', [])
    elif isinstance(signals_envelope, list):
        published = signals_envelope
    else:
        published = []

    producer_id = sig_data.get('producer_id', 'unknown')
    source_wallet = sig_data.get('source_wallet', 'unknown')
    generated_at = sig_data.get('generated_at', 'unknown')

    emit(f'  Producer: {producer_id}')
    emit(f'  Source wallet: {source_wallet}')
    emit(f'  Signals received: {len(published)}')
    emit('')

    if not published:
        verdict = {
            'verdict': 'API_ERROR',
            'ready_to_ingest': False,
            'stage_reached': 'signal_parse',
            'error': 'No published signals in response',
            'conformance': {
                'gate_verdict': 'PASS',
                'schema_version': schema_version,
                'violation_count': 0,
            },
            'api_base': api_base,
            'timestamp': started_at,
        }
        print(json.dumps(verdict, indent=2))
        return 2

    # ── Step 4: Validate each signal against schema-required fields ──────
    emit('[3/3] Validating signal integrity...')
    all_issues = []
    signal_results = []

    for i, sig in enumerate(published):
        issues = validate_signal(sig, i)
        sym = sig.get('symbol', f'signal[{i}]')
        status = 'PASS' if not issues else 'FAIL'
        emit(f'  {sym}: {status}' + (f' ({len(issues)} issues)' if issues else ''))

        signal_results.append({
            'symbol': sym,
            'signal_id': sig.get('signal_id'),
            'direction': sig.get('direction'),
            'confidence': sig.get('confidence'),
            'action': sig.get('action'),
            'horizon_hours': sig.get('horizon_hours'),
            'passed': len(issues) == 0,
            'issues': issues,
        })
        all_issues.extend(issues)

    emit('')

    if all_issues:
        emit(f'[FAIL] {len(all_issues)} integrity issues found:')
        for issue in all_issues:
            emit(f'  - {issue}')

        verdict = {
            'verdict': 'SIGNAL_INTEGRITY_FAIL',
            'ready_to_ingest': False,
            'stage_reached': 'signal_validation',
            'conformance': {
                'gate_verdict': 'PASS',
                'schema_version': schema_version,
                'violation_count': 0,
            },
            'signals': {
                'count': len(published),
                'passed': sum(1 for r in signal_results if r['passed']),
                'failed': sum(1 for r in signal_results if not r['passed']),
                'issues': all_issues,
                'per_signal': signal_results,
            },
            'producer_id': producer_id,
            'api_base': api_base,
            'timestamp': started_at,
        }
        print(json.dumps(verdict, indent=2))
        return 3

    # ── Verdict: READY ───────────────────────────────────────────────────
    emit('[READY] All checks passed — safe to ingest.')
    emit(f'  {len(published)} signals validated against schema v1.0.0')
    emit(f'  Conformance streak: {streak} consecutive passes')

    # Build the final verdict
    verdict = {
        'verdict': 'READY',
        'ready_to_ingest': True,
        'stage_reached': 'complete',
        'conformance': {
            'gate_verdict': 'PASS',
            'schema_version': schema_version,
            'violation_count': 0,
            'signals_checked': signals_checked,
            'consecutive_pass_streak': streak,
            'cross_validation_passed': cross_passed,
        },
        'signals': {
            'count': len(published),
            'passed': len(published),
            'failed': 0,
            'producer_id': producer_id,
            'source_wallet': source_wallet,
            'generated_at': generated_at,
            'per_signal': signal_results,
        },
        'api_base': api_base,
        'timestamp': started_at,
    }
    print(json.dumps(verdict, indent=2))
    return 0


def main():
    parser = argparse.ArgumentParser(
        description='Post Fiat Clean-Room Signal Consumer — gates ingestion on live schema conformance',
        epilog='Exit codes: 0=READY, 1=CONFORMANCE_FAIL, 2=API_ERROR, 3=SIGNAL_INTEGRITY_FAIL'
    )
    parser.add_argument('--api', default='http://84.32.34.46:8080',
                        help='Base URL of the Live Signal API (default: %(default)s)')
    parser.add_argument('--strict', action='store_true',
                        help='Fail if cross-validation disagrees with the gate')
    parser.add_argument('--quiet', action='store_true',
                        help='Suppress human-readable output; emit only verdict JSON')
    args = parser.parse_args()

    # Normalize URL (strip trailing slash)
    api_base = args.api.rstrip('/')

    sys.exit(run(api_base, strict=args.strict, quiet=args.quiet))


if __name__ == '__main__':
    main()
