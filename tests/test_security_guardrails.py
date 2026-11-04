from __future__ import annotations

from subprocess import CompletedProcess
from typing import TypedDict
from unittest.mock import Mock

import sandbox_runner
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph

from vulnerability_agent.graph import route_after_approval, route_after_verification
from vulnerability_agent.nodes.verification import node_await_approval, node_verify_patch


def test_secure_runner_strips_secrets(monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", "/usr/bin")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("OPENAI_API_KEY", "openai-secret-value")
    monkeypatch.setenv("GITHUB_TOKEN", "github-secret-value")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "aws-access-secret")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "aws-secret-value")
    monkeypatch.setenv("SSH_AUTH_SOCK", "/tmp/ssh-agent.sock")
    monkeypatch.setenv("SSH_PRIVATE_KEY", "ssh-private-secret")
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["env"] = kwargs["env"]
        captured["timeout"] = kwargs["timeout"]
        return CompletedProcess(command, 0, stdout="ok", stderr="")

    monkeypatch.setattr(sandbox_runner.subprocess, "run", fake_run)
    result = sandbox_runner.run_tests_safely(str(tmp_path), ["pytest", "-q"])

    assert result["passed"] is True
    assert captured["timeout"] == 60
    assert captured["env"]["PATH"] == "/usr/bin"
    assert captured["env"]["HOME"] == str(tmp_path)
    assert captured["env"]["CI"] == "true"
    assert not any(key.startswith(("AWS_", "SSH_")) for key in captured["env"])
    assert "OPENAI_API_KEY" not in captured["env"]
    assert "GITHUB_TOKEN" not in captured["env"]


def test_baseline_failure_is_classified_as_pre_existing():
    baseline = {
        "passed": False,
        "output": "FAILED tests/test_client.py::test_timeout - AssertionError: expected 1\n",
    }
    after_patch = {
        "passed": False,
        "output": "FAILED tests/test_client.py::test_timeout - AssertionError: expected 1\n",
    }
    assert sandbox_runner.classify_test_results(baseline, after_patch) == "baseline_failure_persists"


def test_new_failure_after_passing_baseline_is_not_hidden():
    baseline = {"passed": True, "output": "2 passed"}
    after_patch = {"passed": False, "output": "FAILED tests/test_client.py::test_new - AssertionError: bad"}
    assert sandbox_runner.classify_test_results(baseline, after_patch) == "new_or_changed_failure"


def test_same_baseline_failure_does_not_enter_patch_retry_loop():
    from vulnerability_agent.state import should_retry

    state = {
        "attempt_count": 1,
        "test_results": {
            "passed": False,
            "failure_classification": "baseline_failure_persists",
        },
    }
    assert should_retry(state) == "log_failure"


def test_pre_pr_rescan_blocks_unfixed_advisory():
    finding = {
        "id": "GHSA-TEST-1",
        "package": {"name": "demo", "version": "1.0.0", "ecosystem": "PyPI"},
    }
    scan = {
        "vulnerabilities": [finding],
        "resolved_packages": [{"name": "demo", "version": "1.0.0", "ecosystem": "PyPI"}],
        "package_count": 1,
    }

    result = node_verify_patch(
        {"current_vuln": finding, "repo_path": "/tmp/repo"},
        scan_node=lambda _state: scan,
    )

    assert result["is_verified"] is False
    assert result["error_code"] == "advisory_still_present"
    assert route_after_verification(result) == "record_failure"
    assert "refusing to push or open a PR" in result["error"]


class ApprovalState(TypedDict, total=False):
    is_verified: bool
    approval_granted: bool
    run_status: str
    pr_created: bool


def test_hitl_checkpoint_waits_for_explicit_approval():
    graph_builder = StateGraph(ApprovalState)
    graph_builder.add_node("await_approval", lambda state: node_await_approval(state, deps=Mock()))
    graph_builder.add_node("create_pr", lambda _state: {"pr_created": True})
    graph_builder.add_edge(START, "await_approval")
    graph_builder.add_conditional_edges(
        "await_approval",
        route_after_approval,
        {"create_pr": "create_pr", "end": END},
    )
    graph_builder.add_edge("create_pr", END)
    checkpointer = InMemorySaver()
    graph = graph_builder.compile(checkpointer=checkpointer, interrupt_before=["await_approval"])
    config = {"configurable": {"thread_id": "approval-test"}}

    paused = graph.invoke({"is_verified": True, "approval_granted": False}, config=config)
    snapshot = graph.get_state(config)
    assert snapshot.next == ("await_approval",)
    assert paused.get("pr_created") is not True

    graph.update_state(config, {"approval_granted": True})
    resumed = graph.invoke(None, config=config)

    assert resumed["approval_granted"] is True
    assert resumed["pr_created"] is True
