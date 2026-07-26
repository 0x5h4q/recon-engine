"""HTTP/HTTPS/TLS probes with SNI, plus signal service protocol."""
from __future__ import annotations

import base64
import hashlib
import json
import socket
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from urllib.error import HTTPError, URLError

from recon_engine.ledger import Ledger, RequestKey
from recon_engine.scope import Scope, ScopeError


@dataclass
class ProbeResult:
    status: int
    body: str
    headers: dict[str, str]
    body_hash: str
    raw_path: Optional[str] = None


def _save_raw(output_dir: Path, host: str, port: int, method: str, path: str,
              status: int, body: str, headers: dict) -> Path:
    """Save raw response to file for evidence."""
    safe_path = path.replace("/", "_").replace("?", "_q") or "root"
    filename = f"{host}_{port}_{method}_{safe_path}_{status}.json"
    raw_dir = output_dir / "raw" / "http"
    raw_dir.mkdir(parents=True, exist_ok=True)
    raw_file = raw_dir / filename

    record = {
        "timestamp": time.time(),
        "host": host,
        "port": port,
        "method": method,
        "path": path,
        "status": status,
        "headers": headers,
        "body": body,
    }
    raw_file.write_text(json.dumps(record, indent=2, sort_keys=True), encoding="utf-8")
    return raw_file


def http_probe(host: str, port: int, path: str = "/",
               headers: Optional[dict[str, str]] = None,
               scope: Optional[Scope] = None,
               ledger: Optional[Ledger] = None,
               output_dir: Optional[Path] = None,
               timeout: float = 5.0) -> Optional[ProbeResult]:
    """Probe an HTTP endpoint. Returns None on scope rejection or error."""
    method = "GET"
    key = RequestKey(host, port, method, path)

    # Resume check
    if ledger and ledger.is_completed(key):
        return None

    # Scope check
    if scope:
        try:
            scope.check(host, port)
        except ScopeError:
            if ledger:
                ledger.record(key, status=0, completed=True)
            return None

    url = f"http://{host}:{port}{path}"
    req_headers = headers or {}
    req = urllib.request.Request(url, headers=req_headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="replace")
            status = response.status
            resp_headers = dict(response.headers)
    except HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        status = e.code
        resp_headers = dict(e.headers)
    except (URLError, TimeoutError, ConnectionRefusedError) as e:
        if ledger:
            ledger.record(key, status=0, completed=True)
        return None

    body_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()[:16]
    raw_path = None
    if output_dir:
        raw_file = _save_raw(output_dir, host, port, method, path, status, body, resp_headers)
        raw_path = str(raw_file)

    if ledger:
        ledger.record(key, status=status, body_hash=body_hash, raw_path=raw_path, completed=True)

    return ProbeResult(status, body, resp_headers, body_hash, raw_path)


def signal_probe(host: str, port: int, command: str,
                 scope: Optional[Scope] = None,
                 ledger: Optional[Ledger] = None) -> Optional[str]:
    """Send a command to the signal service. Returns response text or None."""
    method = command
    key = RequestKey(host, port, method, "line")

    if ledger and ledger.is_completed(key):
        return None

    if scope:
        try:
            scope.check(host, port)
        except ScopeError:
            if ledger:
                ledger.record(key, status=0, completed=True)
            return None

    try:
        with socket.create_connection((host, port), timeout=5.0) as sock:
            # Read banner
            banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
            # Send command
            sock.sendall(f"{command}\r\n".encode("utf-8"))
            response = sock.recv(4096).decode("utf-8", errors="replace").strip()
    except (OSError, TimeoutError) as e:
        if ledger:
            ledger.record(key, status=0, completed=True)
        return None

    if ledger:
        ledger.record(key, status=200, body_hash=hashlib.sha256(response.encode()).hexdigest()[:16], completed=True)

    return response


def parse_signal_route(response: str) -> dict[str, str]:
    """Parse 'route=xxx; proof=yyy' from signal ROUTE response."""
    result = {}
    for part in response.split(";"):
        if "=" in part:
            key, value = part.strip().split("=", 1)
            result[key] = value
    return result


def get_user_txt(host: str, port: int, username: str, password: str,
                 route_key: str, vhost: str,
                 scope: Optional[Scope] = None,
                 ledger: Optional[Ledger] = None,
                 output_dir: Optional[Path] = None) -> Optional[str]:
    """Retrieve the user.txt flag with proper auth."""
    creds = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
    headers = {
    "Host": vhost,
    "Authorization": f"Basic {creds}",
    "X-Route-Key": route_key,
}
    result = http_probe(host, port, "/user.txt", headers=headers,
                       scope=scope, ledger=ledger, output_dir=output_dir)
    if result and result.status == 200:
        return result.body.strip()
    return None
