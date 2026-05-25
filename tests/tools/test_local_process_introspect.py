"""Tests for LocalProcessIntrospectTool (function-based, @tool decorated)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from app.agents.probe import ProcessSnapshot
from app.agents.tail import AttachUnsupported
from app.tools.LocalProcessIntrospectTool import local_process_introspect
from tests.tools.conftest import BaseToolContract


class FakeTarget:
    def __init__(self, pid: int, path: Path) -> None:
        self.pid = pid
        self.path = path


class TestLocalProcessIntrospectToolContract(BaseToolContract):
    def get_tool_under_test(self):
        return local_process_introspect.__opensre_registered_tool__


def test_run_returns_snapshot_and_tail() -> None:
    mock_snapshot = ProcessSnapshot(
        pid=1234,
        cpu_percent=4.2,
        rss_mb=256.0,
        num_fds=42,
        num_connections=3,
        status="running",
        started_at=datetime(2026, 5, 23, 12, 0, 0, tzinfo=UTC),
    )
    with (
        patch("app.tools.LocalProcessIntrospectTool.probe", return_value=mock_snapshot),
        patch(
            "app.tools.LocalProcessIntrospectTool._read_stdout_tail",
            return_value="line 1\nline 2",
        ),
    ):
        result = local_process_introspect(pid=1234)

    assert result["snapshot"] is not None
    assert result["snapshot"]["pid"] == 1234
    assert result["snapshot"]["cpu_percent"] == 4.2
    assert result["snapshot"]["rss_mb"] == 256.0
    assert result["snapshot"]["num_fds"] == 42
    assert result["snapshot"]["num_connections"] == 3
    assert result["snapshot"]["status"] == "running"
    assert result["snapshot"]["started_at"] == "2026-05-23T12:00:00+00:00"
    assert result["stdout_tail"] == "line 1\nline 2"


def test_run_handles_missing_pid() -> None:
    with (
        patch("app.tools.LocalProcessIntrospectTool.probe", return_value=None),
        patch(
            "app.tools.LocalProcessIntrospectTool._read_stdout_tail",
            return_value=None,
        ),
    ):
        result = local_process_introspect(pid=99999)

    assert result["snapshot"] is None
    assert result["stdout_tail"] is None


def test_run_handles_no_stdout() -> None:
    mock_snapshot = ProcessSnapshot(
        pid=5678,
        cpu_percent=0.0,
        rss_mb=128.0,
        num_fds=None,
        num_connections=None,
        status="sleeping",
        started_at=datetime(2026, 5, 23, 10, 0, 0, tzinfo=UTC),
    )
    with (
        patch("app.tools.LocalProcessIntrospectTool.probe", return_value=mock_snapshot),
        patch(
            "app.tools.LocalProcessIntrospectTool._read_stdout_tail",
            return_value=None,
        ),
    ):
        result = local_process_introspect(pid=5678)

    assert result["snapshot"] is not None
    assert result["snapshot"]["pid"] == 5678
    assert result["stdout_tail"] is None


SAMPLE_STDOUT = "\n".join(f"line {i}" for i in range(100))


def test_read_stdout_tail_returns_last_50_lines(tmp_path) -> None:
    from app.tools.LocalProcessIntrospectTool import _read_stdout_tail

    log = tmp_path / "stdout.log"
    log.write_text(SAMPLE_STDOUT)
    fake_pid = 9999

    with patch(
        "app.tools.LocalProcessIntrospectTool.resolve_target",
        return_value=FakeTarget(fake_pid, log),
    ):
        tail = _read_stdout_tail(fake_pid, max_lines=50)

    assert tail is not None
    lines = tail.splitlines()
    assert len(lines) == 50
    assert lines[0] == "line 50"
    assert lines[-1] == "line 99"


def test_read_stdout_tail_returns_none_for_resolve_failure() -> None:
    from app.tools.LocalProcessIntrospectTool import _read_stdout_tail

    with patch(
        "app.tools.LocalProcessIntrospectTool.resolve_target",
        side_effect=AttachUnsupported("no such pid"),
    ):
        result = _read_stdout_tail(9999)
    assert result is None


def test_run_returns_error_signals() -> None:
    mock_snapshot = ProcessSnapshot(
        pid=1234,
        cpu_percent=4.2,
        rss_mb=256.0,
        num_fds=42,
        num_connections=3,
        status="running",
        started_at=datetime(2026, 5, 23, 12, 0, 0, tzinfo=UTC),
    )
    with (
        patch("app.tools.LocalProcessIntrospectTool.probe", return_value=mock_snapshot),
        patch(
            "app.tools.LocalProcessIntrospectTool._read_stdout_tail",
            return_value=(
                "Traceback (most recent call last):\n"
                '  File "test.py", line 1, in <module>\n'
                "Error: something broke"
            ),
        ),
    ):
        result = local_process_introspect(pid=1234)

    assert "error_signals" in result
    assert isinstance(result["error_signals"], dict)
    assert result["error_signals"].get("traceback", 0) > 0


def test_run_error_signals_empty_when_no_stdout() -> None:
    mock_snapshot = ProcessSnapshot(
        pid=1234,
        cpu_percent=0.0,
        rss_mb=128.0,
        num_fds=None,
        num_connections=None,
        status="sleeping",
        started_at=datetime(2026, 5, 23, 10, 0, 0, tzinfo=UTC),
    )
    with (
        patch("app.tools.LocalProcessIntrospectTool.probe", return_value=mock_snapshot),
        patch(
            "app.tools.LocalProcessIntrospectTool._read_stdout_tail",
            return_value=None,
        ),
    ):
        result = local_process_introspect(pid=1234)

    assert result["error_signals"] == {}
