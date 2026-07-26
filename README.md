# EH-A1 Recon Engine

Scope-safe discovery engine for the UBI Stage 5 Advanced assessment.

## Quick start

```bash
# 1. Start the target
python3 local_lab.py --marker UBI-A5-712868920958 --output lab-runtime

# 2. Run the engine
make run

# 3. Run tests
make test
```

## Architecture

- `scope.py` — Parse scope.csv and enforce before every request
- `discovery.py` — DNS, wildcard baseline, vhost detection
- `probe.py` — HTTP/HTTPS/TLS probes with SNI
- `fingerprint.py` — Service identification
- `normalize.py` — Versioned schema output
- `ledger.py` — Atomic request ledger with resume state
- `cli.py` — Entry point

## Scope enforcement

Every network call is wrapped by `scope.check()` which validates against
`scope.csv` before opening a socket. Out-of-scope destinations are rejected
with zero packets sent.
