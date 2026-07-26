"""Versioned schema for normalized observations."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


@dataclass
class Observation:
    schema_version: str = "1.0"

    observed_at: str = field(default_factory=utc_now)

    target: str = ""
    port: int = 0

    protocol: str = ""
    service: str = ""

    source_tool: str = "recon-engine"
    source_file: str = ""

    confidence: str = "high"
    notes: str = ""

    # vhost / http fields
    status: Optional[int] = None
    length: Optional[int] = None
    title: Optional[str] = None
    redirect: Optional[str] = None
    baseline_difference: Optional[str] = None

    parent_observation: Optional[str] = None

    def to_dict(self) -> dict:
        data = asdict(self)

        return {
            k: v
            for k, v in data.items()
            if v is not None
        }

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
        )


def write_assets(
    observations: list[Observation],
    path: Path,
) -> None:

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open(
        "w",
        encoding="utf-8",
    ) as handle:

        for obs in observations:
            handle.write(
                obs.to_json() + "\n"
            )


def write_report(
    observations: list[Observation],
    flag: Optional[str],
    assignment: dict,
    path: Path,
) -> None:

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    rows = []

    for obs in observations:

        rows.append(
            f"""
<tr>
<td>{obs.protocol}</td>
<td>{obs.target}:{obs.port}</td>
<td>{obs.service}</td>
<td>{obs.confidence}</td>
<td>{obs.notes}</td>
</tr>
"""
        )

    if flag:
        flag_html = (
            f"<h2 class='flag'>Foothold: {flag}</h2>"
        )
    else:
        flag_html = "<h2>No foothold obtained</h2>"

    html = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Recon Engine Report</title>
<style>
body {{
    font-family: monospace;
    background: #050508;
    color: #e8e8f0;
    padding: 2rem;
}}
table {{
    border-collapse: collapse;
    width: 100%;
}}
th, td {{
    border: 1px solid #333;
    padding: 0.5rem;
}}
.flag {{
    color: #4ade80;
}}
</style>
</head>
<body>

<h1>EH-A1 Recon Report</h1>

<p>Runtime ID:
{assignment.get("runtime_id", "unknown")}
</p>

<p>Profile:
{assignment.get("profile", "unknown")}
</p>

<p>Generated:
{utc_now()}
</p>

<table>
<tr>
<th>Protocol</th>
<th>Target</th>
<th>Service</th>
<th>Confidence</th>
<th>Notes</th>
</tr>

{''.join(rows)}

</table>

{flag_html}

</body>
</html>
"""

    path.write_text(
        html,
        encoding="utf-8",
    )


def write_run_meta(
    args: dict,
    start_time: str,
    end_time: str,
    exit_status: str,
    path: Path,
) -> None:

    meta = {
        "schema_version": "1.0",
        "engine_version": "1.0.0",
        "start_time": start_time,
        "end_time": end_time,
        "arguments": args,
        "exit_status": exit_status,
    }

    path.write_text(
        json.dumps(
            meta,
            indent=2,
            sort_keys=True,
            default=str,
        ),
        encoding="utf-8",
    )