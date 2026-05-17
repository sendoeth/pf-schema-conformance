# pf-schema-conformance

Close one live producer schema mismatch between `producer_signal_schema.json` v1.0.0 and the live `/signals/latest` endpoint. Includes before/after conformance receipt, conformance runner, verifier, and test suite.

## Mismatch: `action` field missing

The `action` field is required by `producer_signal_schema.json` v1.0.0 (lines 145, 194-196). It must be one of `EXECUTE`, `WITHHOLD`, or `INVERT`. Consumers must respect this field for routing decisions. The live endpoint was missing this field entirely.

## Patch

Added `action` field derivation to `signal_api.js`:

```javascript
const action = inv ? 'INVERT' : (voiSup || !rp.pubDir ? 'WITHHOLD' : 'EXECUTE');
```

Also added `weak_symbol` metadata for INVERT signals (required by schema conditional).

## Run

```bash
python3 check_conformance.py \
  --endpoint http://localhost:8080/signals/latest \
  --schema producer_signal_schema.json \
  --mismatch action_field_missing \
  --before-snapshot snapshots/before.json \
  -o conformance_receipt.json --summary
```

## Verify

```bash
python3 verify_conformance.py conformance_receipt.json
# 171 checks, 16 categories, Grade A
```

## Test

```bash
python3 -m pytest tests/test_conformance.py -v
# 72 tests pass
```

## Result

| State  | Verdict | Signals Passing |
|--------|---------|-----------------|
| Before | FAIL    | 0/4             |
| After  | PASS    | 4/4             |

**Final verdict: PASS (FIXED)**
