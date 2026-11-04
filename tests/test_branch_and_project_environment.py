import os
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

from vulnerability_agent.nodes import pull_requests
from vulnerability_agent.nodes.batch import _is_untracked_virtualenv_line
from vulnerability_agent.nodes.lockfiles import node_regenerate_lockfile
from vulnerability_agent.state import select_test_command
from vulnerability_agent.nodes import pull_requests
from osv_service import group_advisories_by_package
from vulnerability_agent.nodes.batch import node_prepare_worktree, node_cleanup_worktree


def test_test_command_uses_target_repo_venv_for_temporary_worktree(tmp_path, monkeypatch):
    target = tmp_path / "target"
    worktree = tmp_path / "temporary-worktree"
    target.mkdir()
    worktree.mkdir()
    python = target / ".tvenv" / "bin" / "python"
    python.parent.mkdir(parents=True)
    python.touch()
    monkeypatch.delenv("PYTHON", raising=False)

    command, is_node = select_test_command(worktree, project_root=target)

    assert command == [str(python), "-m", "pytest", "-q"]
    assert not is_node


@pytest.mark.parametrize(
    ("status_line", "ignored"),
    [
        ("?? .tvenv/lib/python3.11/site-packages/example.py", True),
        ("?? .venv/bin/python", True),
        (" M .tvenv/pyvenv.cfg", False),
        ("?? important-notes.txt", False),
    ],
)
def test_only_untracked_root_virtualenv_files_are_ignored(status_line, ignored):
    assert _is_untracked_virtualenv_line(status_line) is ignored


def test_pr_branch_repairs_detached_worktree_before_commit(tmp_path, monkeypatch):
    calls = []
    outputs = iter([
        Mock(returncode=0, stdout="", stderr=""),  # current branch: detached
        Mock(returncode=0, stdout="security/fix-aiohttp-ghsa-test", stderr=""),  # valid ref
        Mock(returncode=0, stdout="", stderr=""),  # local branch exists
        Mock(returncode=0, stdout="Switched to branch", stderr=""),  # checkout
    ])

    def fake_run(command, **kwargs):
        calls.append(command)
        return next(outputs)

    monkeypatch.setattr(pull_requests.subprocess, "run", fake_run)

    branch = pull_requests._ensure_pr_branch(
        str(tmp_path), "security/fix-aiohttp-ghsa-test"
    )

    assert branch == "security/fix-aiohttp-ghsa-test"
    assert ["git", "checkout", branch] in calls


def test_pr_branch_rejects_detached_worktree_without_recorded_branch(tmp_path, monkeypatch):
    monkeypatch.setattr(
        pull_requests.subprocess,
        "run",
        lambda *args, **kwargs: Mock(returncode=0, stdout="", stderr=""),
    )

    with pytest.raises(RuntimeError, match="detached"):
        pull_requests._ensure_pr_branch(str(tmp_path), "")


def test_lockfile_regeneration_finds_poetry_in_target_venv(tmp_path, monkeypatch):
    target = tmp_path / "target"
    worktree = tmp_path / "worktree"
    poetry = target / ".tvenv" / "bin" / "poetry"
    poetry.parent.mkdir(parents=True)
    poetry.write_text("#!/bin/sh\nexit 0\n")
    poetry.chmod(0o755)
    worktree.mkdir()
    (worktree / "poetry.lock").write_text("old lock\n")
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["env"] = kwargs["env"]
        (worktree / "poetry.lock").write_text("new lock\n")
        return Mock(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("vulnerability_agent.nodes.lockfiles.subprocess.run", fake_run)
    result = node_regenerate_lockfile(
        {
            "repo_path": str(worktree),
            "main_repo_path": str(target),
            "patch_code": {"pyproject.toml": "[tool.poetry]\n"},
            "original_files": {"pyproject.toml": "[tool.poetry]\n"},
            "changed_files": ["pyproject.toml"],
        },
        deps=None,
    )

    assert captured["command"] == [str(poetry), "lock"]
    assert str(poetry.parent) in captured["env"]["PATH"].split(os.pathsep)
    assert result["lockfile_status"] == "updated"


def _demo_group():
    finding = {
        "id": "GHSA-DEMO",
        "package": {"name": "demo", "version": "1.0.0", "ecosystem": "PyPI"},
        "affected": [{"package": {"name": "demo", "ecosystem": "PyPI"},
                      "ranges": [{"type": "ECOSYSTEM", "events": [
                          {"introduced": "0"}, {"fixed": "2.0.0"},
                      ]}]}],
    }
    return group_advisories_by_package([finding])[0]


@pytest.mark.parametrize("locked_version,should_pass", [("2.1.0", True), ("1.5.0", False)])
def test_poetry_regeneration_verifies_resolved_version_before_validation(
    tmp_path, monkeypatch, locked_version, should_pass,
):
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    old_pyproject = '[tool.poetry.dependencies]\ndemo = "^1.0.0"\n'
    updated_pyproject = '[tool.poetry.dependencies]\ndemo = "^2.0.0"\n'
    old_lock = '[[package]]\nname = "demo"\nversion = "1.0.0"\n'
    updated_lock = f'[[package]]\nname = "demo"\nversion = "{locked_version}"\n'
    (worktree / "poetry.lock").write_text(old_lock)

    def fake_run(_command, **kwargs):
        (worktree / "poetry.lock").write_text(updated_lock)
        return Mock(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("vulnerability_agent.nodes.lockfiles.subprocess.run", fake_run)
    state = {
        "repo_path": str(worktree),
        "manifest_path": "poetry.lock",
        "current_vuln": _demo_group(),
        "patch_code": {"pyproject.toml": updated_pyproject},
        "original_files": {"pyproject.toml": old_pyproject},
        "changed_files": ["pyproject.toml"],
    }
    if should_pass:
        result = node_regenerate_lockfile(state, deps=None)
        assert result["lockfile_verification"]["selected_target"] == "2.0.0"
        assert result["lockfile_verification"]["resolved_version"] == "2.1.0"
        assert "poetry.lock" in result["changed_files"]
    else:
        with pytest.raises(RuntimeError, match="verification failed"):
            node_regenerate_lockfile(state, deps=None)


def test_existing_open_package_pr_prevents_duplicate_push(tmp_path, monkeypatch):
    marker = "<!-- osv-package: pypi:demo -->"
    github = Mock()
    response = Mock()
    response.json.return_value = [{
        "html_url": "https://github.com/example/repo/pull/7",
        "body": marker,
        "head": {"ref": "security/fix-demo"},
    }]
    github.get.return_value = response
    deps = Mock(github_client=github)
    monkeypatch.setattr(pull_requests, "_ensure_pr_branch", lambda _root, branch: branch)
    monkeypatch.setattr(
        pull_requests.subprocess, "run",
        lambda *_args, **_kwargs: Mock(returncode=0, stdout="https://github.com/example/repo.git\n", stderr=""),
    )
    with pytest.raises(RuntimeError, match="already exists for demo"):
        pull_requests.node_create_pull_request({
            "repo_path": str(tmp_path),
            "current_vuln": {"package": {"name": "demo", "ecosystem": "PyPI"}, "advisories": []},
            "is_verified": True,
            "approval_granted": True,
            "branch_name": "security/fix-demo",
            "changed_files": ["requirements.txt"],
            "manifest_path": "requirements.txt",
            "verification_result": {},
        }, deps)
    deps.git_call.assert_not_called()
    github.post.assert_not_called()


def test_worktree_starts_from_refreshed_target_branch(tmp_path):
    def git(repo, *args):
        return subprocess.run(["git", *args], cwd=repo, check=True,
                              capture_output=True, text=True)

    seed = tmp_path / "seed"
    seed.mkdir()
    git(seed, "init", "-b", "main")
    git(seed, "config", "user.name", "Test")
    git(seed, "config", "user.email", "test@example.com")
    (seed / "requirements.txt").write_text("demo==1.0\n")
    git(seed, "add", "requirements.txt")
    git(seed, "commit", "-m", "initial")

    remote = tmp_path / "remote.git"
    subprocess.run(["git", "clone", "--bare", str(seed), str(remote)], check=True, capture_output=True)
    checkout = tmp_path / "checkout"
    subprocess.run(["git", "clone", str(remote), str(checkout)], check=True, capture_output=True)

    concurrent_checkout = tmp_path / "concurrent"
    subprocess.run(["git", "clone", str(remote), str(concurrent_checkout)], check=True, capture_output=True)
    git(concurrent_checkout, "config", "user.name", "Concurrent")
    git(concurrent_checkout, "config", "user.email", "concurrent@example.com")
    (concurrent_checkout / "concurrent.txt").write_text("latest target state\n")
    git(concurrent_checkout, "add", "concurrent.txt")
    git(concurrent_checkout, "commit", "-m", "advance target")
    git(concurrent_checkout, "push", "origin", "main")

    deps = Mock()
    def create_branch(worktree, tool, *, branch_name):
        assert tool == "git_create_branch"
        git(worktree, "checkout", "-b", branch_name)
        return "created"
    deps.git_call.side_effect = create_branch
    result = node_prepare_worktree({
        "repo_path": str(checkout),
        "branch_name": "security/fix-demo",
        "base_branch": "main",
    }, deps)

    assert result["base_commit"] == git(checkout, "rev-parse", "refs/remotes/origin/main").stdout.strip()
    assert (Path(result["repo_path"]) / "concurrent.txt").read_text() == "latest target state\n"
    node_cleanup_worktree(result, deps)
