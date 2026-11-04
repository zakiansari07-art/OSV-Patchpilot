from pathlib import Path
from datetime import datetime, timezone
import json
from unittest.mock import Mock
import pytest
from langgraph.checkpoint.memory import InMemorySaver

from agent_graph import (
    _is_sensitive_path,
    _redact_source,
    apply_search_replace_edits,
    build_graph,
    build_run_report,
    select_test_command,
)
from vulnerability_agent.nodes.patching import (
    find_package_usage_files,
    package_search_terms,
    rank_source_candidates,
    source_excerpt_for_package,
)
from vulnerability_agent.dependencies import AgentDependencies


@pytest.fixture(autouse=True)
def use_targeted_search_in_graph_unit_tests(monkeypatch):
    """Keep graph unit tests offline; the retriever has separate Qdrant tests."""
    def unavailable(_self):
        raise RuntimeError("local vector retrieval is disabled in graph unit tests")

    monkeypatch.setattr(AgentDependencies, "get_code_retriever", unavailable)


def _invoke_with_human_approval(graph, initial_state, thread_id="graph-approval-test"):
    """Exercise the same checkpoint/update/resume cycle used by the CLI."""
    config = {"configurable": {"thread_id": thread_id}}
    result = graph.invoke(initial_state, config=config)
    while graph.get_state(config).next == ("await_approval",):
        graph.update_state(config, {"approval_granted": True})
        result = graph.invoke(None, config=config)
    return result


class FakeMCP:
    def __init__(self):
        self.writes = []
        self.git_calls = []
        self.source_root = None
    def filesystem_read(self, repo_path, relative_path):
        path = Path(repo_path) / relative_path
        return path.read_text() if path.exists() else "demo==1.0\n"
    def filesystem_write(self, repo_path, relative_path, content):
        self.writes.append((relative_path, content))
        return "written"
    def call(self, server, repo_path, tool, arguments):
        if tool == "directory_tree":
            return json.dumps([
                {"name": "app.py", "type": "file"},
                {"name": "config.yaml", "type": "file"},
                {"name": ".env", "type": "file"},
            ])
        if tool == "read_text_file":
            path = Path(arguments["path"])
            if path.exists():
                return path.read_text()
            fallback = Path(self.source_root) / path.name if self.source_root else None
            return fallback.read_text() if fallback and fallback.exists() else "demo==1.0\n"
        if tool == "write_file":
            path = Path(arguments["path"])
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(arguments["content"])
            self.writes.append((path.name, arguments["content"]))
            return "written"
        if tool.startswith("git_"):
            self.git_calls.append((tool, arguments))
            return "On branch main"
        return "[]"
    def git(self, repo_path, tool, **arguments):
        self.git_calls.append((tool, arguments))
        return "On branch main"


class FailingWriteMCP(FakeMCP):
    def call(self, server, repo_path, tool, arguments):
        if tool == "write_file":
            raise OSError("write denied")
        return super().call(server, repo_path, tool, arguments)


class FakeModel:
    def __init__(self):
        self.prompts = []
    def invoke(self, prompt):
        self.prompts.append(prompt)
        if len(self.prompts) == 1:
            edit = {"file": "requirements.txt", "old": "demo==1.0\n", "new": "demo==2.0\n"}
        else:
            edit = {"file": "requirements.txt", "old": "demo==2.0\n", "new": "demo==2.1\n"}
        return Mock(content=json.dumps({"plan": "Patch vulnerable dependency", "edits": [edit]}))


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload
    def json(self):
        return self.payload
    def raise_for_status(self):
        return None


class FakeHTTP:
    async def post(self, *args, **kwargs):
        query = kwargs.get("json", {})
        version = query.get("version")
        vulns = [{
            "id": "OSV-TEST-1", "summary": "bad",
            "affected": [{
                "package": query.get("package", {}),
                "ranges": [{"type": "ECOSYSTEM", "events": [
                    {"introduced": "0"}, {"fixed": "2.0"},
                ]}],
            }],
        }] if version == "1.0" else []
        return FakeResponse({"vulns": vulns})


class EmptyFakeHTTP:
    async def post(self, *args, **kwargs):
        return FakeResponse({"vulns": []})


def test_graph_loops_after_failure_then_creates_pr_on_pass(tmp_path, monkeypatch):
    (tmp_path / ".git").mkdir()
    (tmp_path / "requirements.txt").write_text("demo==1.0\n")
    (tmp_path / "app.py").write_text("def use_demo():\n    return 'source context included'\n")
    (tmp_path / "config.yaml").write_text('api_key: "secret-value"\n')
    (tmp_path / ".env").write_text("GITHUB_TOKEN=never-send-this\n")
    mcp = FakeMCP()
    mcp.source_root = tmp_path
    test_runs = iter([
        {"passed": True, "returncode": 0, "output": "2 passed"},  # clean baseline
        {"passed": False, "returncode": 1, "output": "AssertionError: first"},
        {"passed": True, "returncode": 0, "output": "2 passed"},
    ])
    import agent_graph
    monkeypatch.setattr(agent_graph.subprocess, "run", lambda *a, **kw: Mock(returncode=0, stdout="main" if a[0][-1] == "--show-current" else "git@github.com:owner/repo.git", stderr=""))
    # The test runner is the subprocess invocation with pytest; Git metadata uses its own mocked responses.
    commands = []
    def subprocess_run(command, **kwargs):
        commands.append(command)
        if command[:4] == ["git", "worktree", "add", "--detach"]:
            Path(command[4]).mkdir(parents=True)
        if command[:4] == ["git", "worktree", "remove", "--force"]:
            import shutil
            shutil.rmtree(command[4], ignore_errors=True)
        if "pytest" in command:
            result = next(test_runs)
            return Mock(returncode=result["returncode"], stdout=result["output"], stderr="")
        if command[-2:] == ["branch", "--show-current"]:
            return Mock(returncode=0, stdout="security/osv-test-1-1\n", stderr="")
        if command[-3:] == ["remote", "get-url", "origin"]:
            return Mock(returncode=0, stdout="git@github.com:owner/repo.git\n", stderr="")
        return Mock(returncode=0, stdout="", stderr="")
    monkeypatch.setattr(agent_graph.subprocess, "run", subprocess_run)
    gh = Mock()
    gh.post.return_value = FakeResponse({"html_url": "https://github.com/owner/repo/pull/1"})
    model = FakeModel()
    graph = build_graph(mcp, model=model, http_client=FakeHTTP(), github_client=gh,
                        audit_database_path=tmp_path / "audit.sqlite3",
                        checkpointer=InMemorySaver(), interrupt_before_pr=True)
    result = _invoke_with_human_approval(
        graph, {"repo_path": str(tmp_path), "attempt_count": 0}, "single-finding-approval"
    )
    assert result["attempt_count"] == 2
    assert result["pr_url"].endswith("/pull/1")
    assert len(mcp.writes) == 2
    assert gh.post.called
    assert any(command[:4] == ["git", "push", "--set-upstream", "origin"] for command in commands)
    assert "source context included" not in model.prompts[0]
    assert result["usage_analysis"]
    assert "not prove vulnerable behavior" in result["usage_analysis"][0]["note"]
    assert "secret-value" not in model.prompts[0]
    assert "never-send-this" not in model.prompts[0]
    git_add = next(args for tool, args in mcp.git_calls if tool == "git_add")
    assert git_add["files"] == ["requirements.txt"]
    assert any(tool == "git_create_branch" and args["branch_name"] == "security/fix-demo"
               for tool, args in mcp.git_calls)


def test_graph_processes_each_finding_in_its_own_main_branch_and_summarizes_prs(tmp_path, monkeypatch):
    (tmp_path / ".git").mkdir()
    (tmp_path / "requirements.txt").write_text("alpha==1.0\nbeta==1.0\n")
    mcp = FakeMCP()
    mcp.source_root = tmp_path

    class PackageHTTP:
        async def post(self, _url, *, json):
            package = json["package"]["name"]
            version = json.get("version")
            advisory_ids = (["OSV-ALPHA-1", "OSV-ALPHA-2"] if package == "alpha"
                            else [f"OSV-{package.upper()}-1"])
            vulns = [{
                "id": advisory_id,
                "summary": "test advisory",
                "affected": [{
                    "package": json["package"],
                    "ranges": [{"type": "ECOSYSTEM", "events": [
                        {"introduced": "0"}, {"fixed": "2.0"},
                    ]}],
                }],
            } for advisory_id in advisory_ids] if version == "1.0" else []
            return FakeResponse({"vulns": vulns})

    class TwoPatchModel:
        def __init__(self):
            self.contents = iter([
                "alpha==2.0\\nbeta==1.0\\n",
                "alpha==1.0\\nbeta==2.0\\n",
            ])

        def invoke(self, _prompt):
            import json as json_module
            desired = next(self.contents).replace("\\n", "\n")
            package = "alpha" if desired.startswith("alpha==2.0") else "beta"
            return Mock(content=json_module.dumps({"plan": "Upgrade affected dependency", "edits": [{
                "file": "requirements.txt", "old": f"{package}==1.0\n", "new": f"{package}==2.0\n"
            }]}))

    import agent_graph
    commands = []
    def subprocess_run(command, **kwargs):
        commands.append(command)
        if command[:4] == ["git", "worktree", "add", "--detach"]:
            Path(command[4]).mkdir(parents=True)
        if command[:4] == ["git", "worktree", "remove", "--force"]:
            import shutil
            shutil.rmtree(command[4], ignore_errors=True)
        if "pytest" in command:
            return Mock(returncode=0, stdout="all tests passed", stderr="")
        if command[-3:] == ["remote", "get-url", "origin"]:
            return Mock(returncode=0, stdout="git@github.com:owner/repo.git\n", stderr="")
        if command[-2:] == ["branch", "--show-current"]:
            return Mock(returncode=0, stdout="security/fix-package-osv-test\n", stderr="")
        return Mock(returncode=0, stdout="", stderr="")
    monkeypatch.setattr(agent_graph.subprocess, "run", subprocess_run)
    github = Mock()
    github.post.side_effect = [
        FakeResponse({"html_url": "https://github.com/owner/repo/pull/1"}),
        FakeResponse({"html_url": "https://github.com/owner/repo/pull/2"}),
    ]

    graph = build_graph(
        mcp, model=TwoPatchModel(), http_client=PackageHTTP(), github_client=github,
        audit_database_path=tmp_path / "audit.sqlite3",
        checkpointer=InMemorySaver(), interrupt_before_pr=True,
    )
    result = _invoke_with_human_approval(
        graph, {"repo_path": str(tmp_path), "attempt_count": 0}, "two-finding-approval"
    )

    assert result["run_status"] == "batch_completed"
    patched = result["batch_summary"]["patched"]
    assert [item["package"] for item in patched] == ["alpha", "beta"]
    assert [item["branch"] for item in patched] == ["security/fix-alpha", "security/fix-beta"]
    assert patched[0]["advisory_ids"] == ["OSV-ALPHA-1", "OSV-ALPHA-2"]
    assert [item["pull_request_url"] for item in patched] == [
        "https://github.com/owner/repo/pull/1", "https://github.com/owner/repo/pull/2"
    ]
    assert sum(command[:4] == ["git", "worktree", "add", "--detach"] for command in commands) == 2
    assert all(command[-1] == "refs/remotes/origin/main" for command in commands if command[:4] == ["git", "worktree", "add", "--detach"])
    assert len(github.post.call_args_list) == 2
    assert all(call.kwargs["json"]["base"] == "main" for call in github.post.call_args_list)


def test_failed_finding_is_rolled_back_and_batch_continues(tmp_path, monkeypatch):
    (tmp_path / ".git").mkdir()
    (tmp_path / "requirements.txt").write_text("alpha==1.0\nbeta==1.0\n")
    mcp = FakeMCP()
    mcp.source_root = tmp_path

    class PackageHTTP:
        async def post(self, _url, *, json):
            package = json["package"]["name"]
            advisory = {
                "id": f"OSV-{package.upper()}",
                "affected": [{"package": json["package"], "ranges": [{"type": "ECOSYSTEM", "events": [
                    {"introduced": "0"}, {"fixed": "2.0"},
                ]}]}],
            }
            return FakeResponse({"vulns": [advisory] if json.get("version") == "1.0" else []})

    class TwoPatchModel:
        def __init__(self):
            self.calls = 0

        def invoke(self, _prompt):
            import json as json_module
            self.calls += 1
            if self.calls <= 3:
                old_version = self.calls
                new_version = old_version + 1
                edit = {"file": "requirements.txt", "old": f"alpha=={old_version}.0\n", "new": f"alpha=={new_version}.0\n"}
            else:
                edit = {"file": "requirements.txt", "old": "beta==1.0\n", "new": "beta==2.0\n"}
            return Mock(content=json_module.dumps({"plan": "Upgrade dependency", "edits": [edit]}))

    import agent_graph
    test_run = 0
    commands = []
    def subprocess_run(command, **kwargs):
        nonlocal test_run
        commands.append(command)
        if command[:4] == ["git", "worktree", "add", "--detach"]:
            Path(command[4]).mkdir(parents=True)
        if command[:4] == ["git", "worktree", "remove", "--force"]:
            import shutil
            shutil.rmtree(command[4], ignore_errors=True)
        if "pytest" in command:
            test_run += 1
            # Calls: alpha baseline, three alpha patch attempts, beta baseline, beta post-patch.
            passed = test_run in {1, 5, 6}
            return Mock(returncode=0 if passed else 1,
                        stdout="passed" if passed else "AssertionError: still failing", stderr="")
        if command[-3:] == ["remote", "get-url", "origin"]:
            return Mock(returncode=0, stdout="git@github.com:owner/repo.git\n", stderr="")
        if command[-2:] == ["branch", "--show-current"]:
            return Mock(returncode=0, stdout="security/fix-beta-osv-beta\n", stderr="")
        return Mock(returncode=0, stdout="", stderr="")
    monkeypatch.setattr(agent_graph.subprocess, "run", subprocess_run)
    github = Mock()
    github.post.return_value = FakeResponse({"html_url": "https://github.com/owner/repo/pull/2"})

    graph = build_graph(
        mcp, model=TwoPatchModel(), http_client=PackageHTTP(), github_client=github,
        audit_database_path=tmp_path / "audit.sqlite3",
        checkpointer=InMemorySaver(), interrupt_before_pr=True,
    )
    state = _invoke_with_human_approval(
        graph, {"repo_path": str(tmp_path), "attempt_count": 0}, "failure-then-approval"
    )

    assert state["run_status"] == "batch_partial_failure"
    assert [item["id"] for item in state["batch_summary"]["failed"]] == ["OSV-ALPHA"]
    assert [item["id"] for item in state["batch_summary"]["patched"]] == ["OSV-BETA"]
    assert state["batch_summary"]["patched"][0]["pull_request_url"].endswith("/pull/2")
    assert sum(command[:4] == ["git", "worktree", "add", "--detach"] for command in commands) == 2
    assert sum(command[:4] == ["git", "worktree", "remove", "--force"] for command in commands) == 2


def test_rescan_skips_secondary_finding_resolved_by_first_upgrade(tmp_path, monkeypatch):
    (tmp_path / ".git").mkdir()
    (tmp_path / "requirements.txt").write_text("alpha==1.0\n")
    mcp = FakeMCP()
    mcp.source_root = tmp_path

    class PackageHTTP:
        async def post(self, _url, *, json):
            vulns = ([{
                "id": advisory_id,
                "affected": [{"package": json["package"], "ranges": [{"type": "ECOSYSTEM", "events": [
                    {"introduced": "0"}, {"fixed": "2.0"},
                ]}]}],
            } for advisory_id in ("OSV-ALPHA-1", "OSV-ALPHA-2")]
                     if json.get("version") == "1.0" else [])
            return FakeResponse({"vulns": vulns})

    class UpgradeModel:
        def invoke(self, _prompt):
            return Mock(content=json.dumps({"plan": "Upgrade alpha", "edits": [{
                "file": "requirements.txt", "old": "alpha==1.0\n", "new": "alpha==2.0\n"
            }]}))

    import agent_graph
    commands = []
    def subprocess_run(command, **kwargs):
        commands.append(command)
        if command[:4] == ["git", "worktree", "add", "--detach"]:
            Path(command[4]).mkdir(parents=True)
        if command[:4] == ["git", "worktree", "remove", "--force"]:
            import shutil
            shutil.rmtree(command[4], ignore_errors=True)
        if "pytest" in command:
            return Mock(returncode=0, stdout="passed", stderr="")
        if command[-3:] == ["remote", "get-url", "origin"]:
            return Mock(returncode=0, stdout="git@github.com:owner/repo.git\n", stderr="")
        if command[-2:] == ["branch", "--show-current"]:
            return Mock(returncode=0, stdout="security/fix-alpha-osv-alpha-1\n", stderr="")
        return Mock(returncode=0, stdout="", stderr="")
    monkeypatch.setattr(agent_graph.subprocess, "run", subprocess_run)
    github = Mock()
    github.post.return_value = FakeResponse({"html_url": "https://github.com/owner/repo/pull/3"})

    graph = build_graph(
        mcp, model=UpgradeModel(), http_client=PackageHTTP(), github_client=github,
        audit_database_path=tmp_path / "audit.sqlite3",
        checkpointer=InMemorySaver(), interrupt_before_pr=True,
    )
    state = _invoke_with_human_approval(
        graph, {"repo_path": str(tmp_path), "attempt_count": 0}, "secondary-finding-approval"
    )

    assert state["run_status"] == "batch_completed"
    assert len(state["batch_summary"]["patched"]) == 1
    assert state["batch_summary"]["patched"][0]["advisory_ids"] == ["OSV-ALPHA-1", "OSV-ALPHA-2"]
    assert state["batch_summary"]["skipped"] == []
    assert github.post.call_count == 1
    assert sum(command[:4] == ["git", "worktree", "add", "--detach"] for command in commands) == 1


def test_unverifiable_grouped_ranges_fail_without_branch_or_pr(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / "requirements.txt").write_text("demo==1.0\n")
    mcp = FakeMCP()
    mcp.source_root = tmp_path

    class UnsupportedRangeHTTP:
        async def post(self, _url, *, json):
            package = json["package"]
            findings = [{
                "id": "GHSA-GIT-RANGE",
                "affected": [{"package": package, "ranges": [{
                    "type": "GIT", "events": [{"introduced": "deadbeef"}],
                }]}],
            }] if json.get("version") == "1.0" else []
            return FakeResponse({"vulns": findings})

    github = Mock()
    state = build_graph(
        mcp, model=FakeModel(), http_client=UnsupportedRangeHTTP(),
        github_client=github, audit_database_path=tmp_path / "audit.sqlite3",
    ).invoke({"repo_path": str(tmp_path), "attempt_count": 0, "approval_granted": True})

    assert state["batch_summary"]["failed"][0]["stage"] == "dependency_resolution"
    assert state["batch_summary"]["failed"][0]["code"] == "advisory_range_conflict"
    assert mcp.writes == []
    assert not any(tool == "git_create_branch" for tool, _ in mcp.git_calls)
    github.post.assert_not_called()


def test_retry_routing_respects_attempt_limit():
    from agent_graph import should_retry
    assert should_retry({"test_results": {"passed": False}, "attempt_count": 1}) == "investigate"
    assert should_retry({"test_results": {"passed": True}, "attempt_count": 1}) == "create_pr"
    assert should_retry({"test_results": {"passed": False}, "attempt_count": 3}) == "log_failure"


def test_search_replace_edit_changes_only_the_requested_text():
    updated = apply_search_replace_edits(
        [{"file": "app.py", "old": "return 1", "new": "return 2"}],
        {"app.py": "def value():\n    return 1\n\n# keep this\n"},
    )
    assert updated["app.py"] == "def value():\n    return 2\n\n# keep this\n"


def test_search_replace_edit_rejects_ambiguous_and_missing_matches():
    import pytest

    edit = {"file": "app.py", "old": "return 1", "new": "return 2"}
    with pytest.raises(ValueError, match="found 2"):
        apply_search_replace_edits([edit], {"app.py": "return 1\nreturn 1\n"})
    with pytest.raises(ValueError, match="found 0"):
        apply_search_replace_edits([edit], {"app.py": "return 3\n"})


def test_search_replace_edit_allows_new_file_creation_only_when_marked():
    edit = {"file": "requirements.txt", "old": "", "new": "demo==2.0\n"}
    assert apply_search_replace_edits([edit], {"requirements.txt": ""}, new_files={"requirements.txt"}) == {
        "requirements.txt": "demo==2.0\n"
    }
    import pytest
    with pytest.raises(ValueError, match="empty 'old'"):
        apply_search_replace_edits([edit], {"requirements.txt": ""})


def test_package_search_builds_literal_import_variants(monkeypatch, tmp_path):
    import vulnerability_agent.nodes.patching as patching

    call = {}
    def fake_run(command, **kwargs):
        call["command"] = command
        return Mock(returncode=0, stdout="src/client.py\ntests/test_client.py\n", stderr="")

    monkeypatch.setattr(patching.subprocess, "run", fake_run)
    assert package_search_terms("demo-package") == ["demo-package", "demo_package"]
    assert find_package_usage_files(tmp_path, "demo-package") == ["src/client.py", "tests/test_client.py"]
    assert "-F" in call["command"]
    assert call["command"].count("-e") == 2


def test_targeted_source_files_and_matching_lines_are_prioritized():
    ordered = rank_source_candidates(
        ["z_fallback.py", "src/client.py", "tests/test_client.py"],
        {"src/client.py", "tests/test_client.py"},
    )
    assert ordered[:2] == ["src/client.py", "tests/test_client.py"]
    excerpt = source_excerpt_for_package(
        "far header\nheader one\nheader two\nimport demo_package\ncall_demo()\ntrailer",
        ["demo-package", "demo_package"],
        max_chars=120,
    )
    assert "import demo_package" in excerpt
    assert "call_demo()" in excerpt
    assert "far header" not in excerpt


def test_branch_names_sanitize_package_and_vulnerability_characters():
    from agent_graph import branch_name_for_finding
    name = branch_name_for_finding({
        "package": {"name": "@Scope/pkg.name"},
        "id": "GHSA_ABC-123/DEF",
    })
    assert name == "security/fix-scope-pkg-name"


def test_no_findings_reports_unpinned_versions_without_claiming_patch_exhaustion(tmp_path, capsys):
    (tmp_path / ".git").mkdir()
    (tmp_path / "requirements.txt").write_text("flask\nrequests\n")
    graph = build_graph(FakeMCP(), http_client=EmptyFakeHTTP(), audit_database_path=tmp_path / "audit.sqlite3")
    result = graph.invoke({"repo_path": str(tmp_path), "attempt_count": 0, "approval_granted": True})
    assert "No patch attempts were made" in result["error"]
    assert "flask, requests" in result["error"]
    assert "Exhausted 0" not in capsys.readouterr().out


def test_test_command_uses_npm_script_when_package_lock_is_present(tmp_path):
    (tmp_path / "package.json").write_text('{"scripts":{"test":"vitest"}}')
    (tmp_path / "package-lock.json").write_text('{}')
    assert select_test_command(tmp_path) == (["npm", "test"], True)


def test_test_command_prefers_pnpm_lockfile(tmp_path):
    (tmp_path / "package.json").write_text('{"scripts":{"test":"vitest"}}')
    (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n")
    assert select_test_command(tmp_path) == (["pnpm", "test"], True)


def test_dirty_repository_is_not_modified(tmp_path, monkeypatch):
    (tmp_path / ".git").mkdir()
    (tmp_path / "requirements.txt").write_text("demo==1.0\n")
    import agent_graph
    monkeypatch.setattr(agent_graph.subprocess, "run", lambda *a, **kw: Mock(returncode=0, stdout=" M notes.txt\n", stderr=""))
    mcp = FakeMCP()
    state = build_graph(mcp, model=FakeModel(), http_client=FakeHTTP(), audit_database_path=tmp_path / "audit.sqlite3").invoke(
        {"repo_path": str(tmp_path), "attempt_count": 0, "approval_granted": True}
    )
    assert state["run_status"] == "batch_partial_failure"
    assert "local changes" in state["failed_findings"][0]["error"]
    assert mcp.writes == []
    assert state.get("changed_files", []) == []
    assert state["failed_findings"][0]["branch"] == "security/fix-demo"
    assert not any(tool == "git_create_branch" for tool, _ in mcp.git_calls)


def test_report_contains_attempts_diff_summary_and_redacts_credentials():
    now = datetime.now(timezone.utc)
    report = build_run_report({
        "repo_path": "/tmp/repo", "run_status": "tests_failed", "manifest_path": "uv.lock",
        "package_count": 4, "changed_files": ["app.py"], "patch_diff": 'api_key = "secret-value"\n',
        "test_history": [{"passed": False, "returncode": 1, "output": "failed"}],
        "error_stage": "tests", "error_code": "tests_exhausted", "error": "tests failed",
    }, now, now)
    assert report["status"] == "tests_failed"
    assert report["tests"]["attempts"] == 1
    assert report["patch"]["files"] == ["app.py"]
    assert "secret-value" not in report["patch"]["diff"]
    assert "ghp_1234567890abcdef" not in _redact_source("GITHUB_TOKEN=ghp_1234567890abcdef")
    assert report["failure"]["next_action"]
    assert _is_sensitive_path("config/credentials-prod.yaml")
    assert _is_sensitive_path(".env.local")


def test_failed_patch_write_keeps_branch_and_stage_in_state(tmp_path, monkeypatch):
    (tmp_path / ".git").mkdir()
    (tmp_path / "requirements.txt").write_text("demo==1.0\n")
    import agent_graph
    def subprocess_run(command, **kwargs):
        if command[:4] == ["git", "worktree", "add", "--detach"]:
            Path(command[4]).mkdir(parents=True)
        if command[:4] == ["git", "worktree", "remove", "--force"]:
            import shutil
            shutil.rmtree(command[4], ignore_errors=True)
        return Mock(returncode=0, stdout="", stderr="")
    monkeypatch.setattr(agent_graph.subprocess, "run", subprocess_run)
    state = build_graph(FailingWriteMCP(), model=FakeModel(), http_client=FakeHTTP(), audit_database_path=tmp_path / "audit.sqlite3").invoke(
        {"repo_path": str(tmp_path), "attempt_count": 0, "approval_granted": True}
    )
    assert state["run_status"] == "batch_partial_failure"
    assert state["failed_findings"][0]["stage"] == "patch"
    assert state["failed_findings"][0]["code"] == "patch_write_failed"
    assert state["failed_findings"][0]["branch"] == "security/fix-demo"


class FailingHTTP:
    async def post(self, *args, **kwargs):
        import httpx
        raise httpx.ConnectError("network unavailable")


def test_scan_network_error_is_returned_as_typed_failure(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / "requirements.txt").write_text("demo==1.0\n")
    state = build_graph(FakeMCP(), http_client=FailingHTTP(), audit_database_path=tmp_path / "audit.sqlite3").invoke(
        {"repo_path": str(tmp_path), "attempt_count": 0, "approval_granted": True}
    )
    assert state["run_status"] == "failed"
    assert state["error_stage"] == "scan"
    assert state["error_code"] == "scan_failed"
    assert "network unavailable" in state["error"]
