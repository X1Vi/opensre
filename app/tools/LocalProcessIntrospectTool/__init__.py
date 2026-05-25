"""Tool for introspecting a local process during incident response.

Returns a psutil snapshot and the last 50 stdout lines for a given PID.
The investigation planner calls this to diagnose stuck or misbehaving
local agents from the OpenSRE interactive shell.
"""

from __future__ import annotations

import os
from datetime import UTC
from typing import Any

from app.agents.error_signals import ErrorSignals
from app.agents.probe import ProcessSnapshot, probe
from app.agents.tail import DEFAULT_MAX_BYTES, AttachUnsupported, resolve_target
from app.tools.tool_decorator import tool


def _snapshot_to_dict(snapshot: ProcessSnapshot) -> dict[str, Any]:
    return {
        "pid": snapshot.pid,
        "cpu_percent": snapshot.cpu_percent,
        "rss_mb": snapshot.rss_mb,
        "num_fds": snapshot.num_fds,
        "num_connections": snapshot.num_connections,
        "status": snapshot.status,
        "started_at": snapshot.started_at.astimezone(UTC).isoformat(),
    }


def _read_stdout_tail(pid: int, max_lines: int = 50) -> str | None:
    """Read the last ``max_lines`` lines from the process's stdout.

    Linux: resolves ``/proc/<pid>/fd/1``.
    macOS: resolves fd 1 via ``lsof``.
    Returns ``None`` when the pid doesn't exist, stdout is a pipe/socket/tty,
    or we lack permission — the planner treats ``None`` as "unavailable".
    """
    try:
        target = resolve_target(pid)
    except (AttachUnsupported, OSError):
        return None
    try:
        with open(target.path, "rb") as f:
            offset = max(0, os.fstat(f.fileno()).st_size - DEFAULT_MAX_BYTES)
            if offset > 0:
                f.seek(offset)
            data = f.read()
    except (OSError, PermissionError, FileNotFoundError):
        return None
    lines = data.decode("utf-8", errors="replace").splitlines()
    return "\n".join(lines[-max_lines:])


@tool(
    name="local_process_introspect",
    source="knowledge",
    description=(
        "Introspect a local process: return a psutil resource snapshot "
        "(CPU%, RSS MB, fd count, connection count, status, start time) "
        "and the last 50 lines of stdout. Use this when the planner needs "
        "to diagnose a stuck, high-cpu, or misbehaving local agent during "
        "incident response."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "pid": {
                "type": "integer",
                "description": "Process ID to introspect.",
            },
        },
        "required": ["pid"],
    },
    use_cases=[
        "Diagnosing a stuck or high-cpu local agent during incident response",
        "Checking whether a process is alive and making forward progress",
        "Reading recent stdout output from a local process",
        "Verifying resource usage of a monitored agent",
    ],
    outputs={
        "snapshot": "psutil ProcessSnapshot dict, or null if the PID is inaccessible",
        "stdout_tail": "last 50 stdout lines as a string, or null if stdout cannot be read",
        "error_signals": "error/retry rates per category from recent stdout",
    },
    surfaces=("investigation",),
)
def local_process_introspect(pid: int) -> dict[str, Any]:
    snapshot = probe(pid)
    stdout_tail = _read_stdout_tail(pid)
    error_signals: dict[str, float] = {}
    if stdout_tail:
        signals = ErrorSignals()
        signals.observe(stdout_tail)
        error_signals = signals.rate_per_minute()
    return {
        "snapshot": _snapshot_to_dict(snapshot) if snapshot else None,
        "stdout_tail": stdout_tail,
        "error_signals": error_signals,
    }
