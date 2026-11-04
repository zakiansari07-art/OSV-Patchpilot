from pathlib import Path

import pytest

from mcp_client import MCPPolicyError, MCPPolicyProxy


class RecordingClient:
    def __init__(self):
        self.calls = []

    def call(self, server, repo_path, tool, arguments):
        self.calls.append((server, tool, arguments))
        return "written" if tool == "write_file" else "ok"


def test_proxy_allows_repo_file_and_audits_without_contents(tmp_path):
    client = RecordingClient()
    proxy = MCPPolicyProxy(client, database_path=tmp_path / "audit.sqlite3", run_id="t-1")
    assert proxy.call("filesystem", str(tmp_path), "write_file",
                      {"path": "app.py", "content": "private source"}) == "written"
    events = proxy.audit_log.events_for_run("t-1")
    assert client.calls[0][2]["path"] == str(tmp_path / "app.py")
    assert events[0]["tool"] == "write_file"
    assert events[0]["outcome"] == "allowed"
    assert events[0]["server"] == "filesystem"
    assert events[0]["timestamp"].endswith("+00:00")
    assert events[0]["reason"] == ""
    assert "private source" not in str(events)


@pytest.mark.parametrize("path", ["../outside.txt", ".env", "keys/private.pem"])
def test_proxy_rejects_escape_and_likely_secret_paths(tmp_path, path):
    proxy = MCPPolicyProxy(RecordingClient(), database_path=tmp_path / "audit.sqlite3")
    with pytest.raises(MCPPolicyError):
        proxy.call("filesystem", str(tmp_path), "read_text_file", {"path": path})


@pytest.mark.parametrize("files", [["."], ["../outside.py"], [".env"]])
def test_proxy_rejects_unsafe_git_staging(tmp_path, files):
    proxy = MCPPolicyProxy(RecordingClient(), database_path=tmp_path / "audit.sqlite3")
    with pytest.raises(MCPPolicyError):
        proxy.call("git", str(tmp_path), "git_add", {"repo_path": str(tmp_path), "files": files})


def test_proxy_rejects_non_allowlisted_tool(tmp_path):
    proxy = MCPPolicyProxy(RecordingClient(), database_path=tmp_path / "audit.sqlite3")
    with pytest.raises(MCPPolicyError):
        proxy.call("filesystem", str(tmp_path), "delete_file", {"path": str(tmp_path / "x")})


def test_proxy_batches_safe_files_but_rejects_secret_paths(tmp_path):
    client = RecordingClient()
    proxy = MCPPolicyProxy(client, database_path=tmp_path / "audit.sqlite3")
    result = proxy.call(
        "filesystem", str(tmp_path), "read_multiple_files",
        {"paths": ["src/a.py", "tests/test_a.py"]},
    )

    assert result == "ok"
    assert client.calls[0][2]["paths"] == [
        str(tmp_path / "src/a.py"), str(tmp_path / "tests/test_a.py"),
    ]
    with pytest.raises(MCPPolicyError):
        proxy.call(
            "filesystem", str(tmp_path), "read_multiple_files",
            {"paths": ["src/a.py", ".env"]},
        )


def test_audit_log_persists_allowed_denied_and_error_calls(tmp_path):
    database = tmp_path / "audit.sqlite3"
    proxy = MCPPolicyProxy(RecordingClient(), database_path=database, run_id="persistent-thread")
    proxy.call("filesystem", str(tmp_path), "read_text_file", {"path": "app.py"})
    with pytest.raises(MCPPolicyError):
        proxy.call("filesystem", str(tmp_path), "delete_file", {"path": "app.py"})

    class BrokenClient(RecordingClient):
        def call(self, *args, **kwargs):
            raise OSError("server unavailable")

    broken = MCPPolicyProxy(BrokenClient(), database_path=database, run_id="persistent-thread")
    with pytest.raises(OSError):
        broken.call("filesystem", str(tmp_path), "read_text_file", {"path": "app.py"})

    from mcp_client import SQLiteAuditLog
    outcomes = [event["outcome"] for event in SQLiteAuditLog(database).events_for_run("persistent-thread")]
    assert outcomes == ["allowed", "denied", "error"]
