# Recon Engine

Scope-safe reconnaissance engine developed for the Ubuntu Bridge Initiative Ethical Hacking track assessment.

## Repository

This repository implements a reconnaissance engine that:

* Enforces scope before opening network connections
* Records requests in an audit ledger
* Discovers authorized services
* Collects raw evidence artifacts
* Produces normalized machine-readable output
* Supports resumable execution
* Preserves provenance from raw evidence to final result

## Environment

Tested on:

* Linux
* Python 3.14+
* No external runtime dependencies required for engine execution

## Repository Layout

```text
recon_engine/
├── cli.py
├── scope.py
├── probe.py
├── normalize.py
├── ledger.py
└── __init__.py

tests/
└── test_fixtures.py

final-run/
├── normalized/
├── raw/
├── report.html
├── foothold-evidence.txt
└── run.json

parser-fixtures.json
assessment-manifest.json
continuity-record.md
integrity-attestation.md
evidence-index.csv
scope-register.csv
```

## Build

Run the assessment engine:

```bash
python -m recon_engine.cli \
  --target 127.0.0.1 \
  --scope lab-runtime-new/scope.csv \
  --output final-run
```

Alternatively:

```bash
make run
```

## Test

Run the published fixture suite:

```bash
pytest tests/test_fixtures.py -v
```

Generate machine-readable test results:

```bash
pytest tests/test_fixtures.py \
  --junitxml=test-results.xml
```

## Scope Enforcement

All outbound destinations are validated through the scope engine before network activity occurs.

Authorized targets are defined in:

```text
lab-runtime-new/scope.csv
```

Out-of-scope destinations are rejected before a socket is opened.

## Output

Primary outputs:

```text
final-run/run.json
final-run/request-ledger.csv
final-run/request-ledger.jsonl
final-run/normalized/assets.jsonl
final-run/report.html
final-run/foothold-evidence.txt
```

## Evidence

Raw evidence is preserved under:

```text
final-run/raw/
raw-output/
```

Every normalized finding retains a locator back to its originating raw artifact.

## Published Fixture Results

Fixture suite:

```text
20 passed
0 failed
```

Machine-readable results:

```text
test-results.xml
```

## Git Revision

Current submission branch:

```text
main
```

Latest commit:

```text
3b1bd90
```
