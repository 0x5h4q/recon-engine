"""Scope enforcement."""
from __future__ import annotations

import csv
import ipaddress
from pathlib import Path


class ScopeError(Exception):
    pass


class Scope:
    def __init__(self, scope_path: Path) -> None:
        self._allowed_pairs: set[tuple[str, int]] = set()
        self._denied_pairs: set[tuple[str, int]] = set()
        self._allowed_hosts: set[str] = set()
        self._denied_hosts: set[str] = set()
        self._cidr_denies: list[ipaddress.IPv4Network] = []
        self._raw_rows: list[dict[str, str]] = []

        self._load(scope_path)

    @classmethod
    def _from_rows(cls, rows: list[dict[str, str]]) -> "Scope":
        import tempfile

        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".csv",
            delete=False,
            newline="",
        ) as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=["asset", "scope", "notes"],
            )
            writer.writeheader()

            for row in rows:
                writer.writerow(row)

            path = Path(handle.name)

        scope = cls(path)
        path.unlink()
        return scope

    def _load(self, path: Path) -> None:
        with path.open(
            "r",
            encoding="utf-8",
        ) as handle:
            reader = csv.DictReader(handle)

            for row in reader:
                self._raw_rows.append(row)

                asset = row["asset"].strip()
                scope = row["scope"].strip().upper()

                if "/" in asset:
                    try:
                        network = ipaddress.IPv4Network(
                            asset,
                            strict=False,
                        )

                        if scope == "OUT":
                            self._cidr_denies.append(network)

                    except ValueError:
                        pass

                    continue

                if ":" in asset:
                    host, port_str = asset.rsplit(":", 1)

                    try:
                        port = int(port_str)
                    except ValueError:
                        continue

                    if scope == "IN":
                        self._allowed_pairs.add((host, port))
                        self._allowed_hosts.add(host)

                    elif scope == "OUT":
                        self._denied_pairs.add((host, port))
                        self._denied_hosts.add(host)

                else:
                    if scope == "IN":
                        self._allowed_hosts.add(asset)

                    elif scope == "OUT":
                        self._denied_hosts.add(asset)

    def check(self, host: str, port: int) -> bool:
        if (host, port) in self._allowed_pairs:
            return True

        try:
            addr = ipaddress.IPv4Address(host)

            for network in self._cidr_denies:
                if addr in network:
                    raise ScopeError(
                        f"{host} matches denied CIDR {network}"
                    )

        except ipaddress.AddressValueError:
            pass

        if host in self._denied_hosts:
            raise ScopeError(f"{host} explicitly denied")

        if (host, port) in self._denied_pairs:
            raise ScopeError(f"{host}:{port} explicitly denied")

        raise ScopeError(f"{host}:{port} not authorized")

    def get_allowed(self) -> list[tuple[str, int]]:
        return sorted(self._allowed_pairs)

    @property
    def rows(self) -> list[dict[str, str]]:
        return self._raw_rows