#!/usr/bin/env python3
"""Independent cross-validation using jsonschema Draft 2020-12.

Reads the same temp file and schema that conformance_gate.py uses,
validates each signal independently, and outputs a JSON summary.
This provides a second opinion alongside the custom gate validator.
"""
import json
import sys
import os

def main():
    schema_path = sys.argv[1] if len(sys.argv) > 1 else None
    signals_path = sys.argv[2] if len(sys.argv) > 2 else None

    if not schema_path or not signals_path:
        print(json.dumps({'method': 'jsonschema', 'error': 'usage: cross_validate.py <schema> <signals>', 'passed': None}))
        return

    try:
        from jsonschema import Draft202012Validator
    except ImportError:
        print(json.dumps({'method': 'jsonschema', 'error': 'library not installed', 'passed': None}))
        return

    try:
        with open(schema_path) as f:
            schema = json.load(f)
        with open(signals_path) as f:
            signals = json.load(f)

        # Extract signal array from various envelope formats
        if isinstance(signals, list):
            sigs = signals
        elif isinstance(signals, dict):
            sigs = signals.get('signals', signals.get('published', [signals]))
            if isinstance(sigs, dict):
                sigs = sigs.get('published', list(sigs.values()))
        else:
            sigs = [signals]

        if not isinstance(sigs, list):
            sigs = [sigs]

        validator = Draft202012Validator(schema)
        results = []
        for s in sigs:
            errs = list(validator.iter_errors(s))
            results.append({
                'symbol': s.get('symbol', '?'),
                'errors': len(errs),
                'details': [e.message[:120] for e in errs[:3]]
            })

        total_errs = sum(r['errors'] for r in results)
        print(json.dumps({
            'method': 'jsonschema.Draft202012Validator',
            'signals_checked': len(results),
            'total_errors': total_errs,
            'passed': total_errs == 0,
            'per_signal': results
        }))

    except Exception as e:
        print(json.dumps({'method': 'jsonschema', 'error': str(e), 'passed': None}))

if __name__ == '__main__':
    main()
