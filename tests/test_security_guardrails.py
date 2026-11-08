from subprocess import CompletedProcess

import sandbox_runner


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
    pull_request = {
        "passed": False,
        "output": "FAILED tests/test_client.py::test_timeout - AssertionError: expected 1\n",
    }
    assert sandbox_runner.classify_test_results(baseline, pull_request) == "baseline_failure_persists"


def test_new_failure_after_passing_baseline_is_not_hidden():
    baseline = {"passed": True, "output": "2 passed"}
    pull_request = {"passed": False, "output": "FAILED tests/test_client.py::test_new - AssertionError: bad"}
    assert sandbox_runner.classify_test_results(baseline, pull_request) == "new_or_changed_failure"
