import json

import main


def test_source_analysis_placeholder_keeps_package_metadata_and_is_not_osv_finding():
    groups = main._group_source_analysis_inputs([{
        "id": "source-analysis:pypi:langchain-core",
        "package": {"name": "langchain-core", "ecosystem": "pypi"},
        "version": "0.2.41", "relationship": "transitive",
        "dependency_paths": [["langchain", "langchain-core"]], "advisories": [],
    }])

    assert len(groups) == 1
    assert groups[0]["package"] == {"name": "langchain-core", "version": "0.2.41", "ecosystem": "pypi"}
    assert groups[0]["advisories"] == []
    assert groups[0]["advisory_ids"] == []
    assert groups[0]["relationship"] == "transitive"


class FakeWorkflow:
    def invoke(self, state, config=None):
        return {
            **state,
            "run_status": "no_findings",
            "package_count": 3,
            "manifest_path": "uv.lock",
            "vulnerabilities": [],
            "scan_warnings": [],
            "test_history": [],
        }

    def get_state(self, config):
        return type("Snapshot", (), {"next": ()})()


class FakePersistence:
    def __init__(self, database_path):
        self.checkpointer = object()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None


def test_cli_writes_json_report_and_returns_success_for_clean_scan(tmp_path, monkeypatch, capsys):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()
    report_path = tmp_path / "agent-report.json"
    saved_report_directory = tmp_path / "saved report"
    monkeypatch.setattr(main, "DEFAULT_REPORT_DIRECTORY", saved_report_directory)
    monkeypatch.setattr(main, "build_graph", lambda **kwargs: FakeWorkflow())
    monkeypatch.setattr(main, "SQLiteAgentPersistence", FakePersistence)

    code = main.main([str(repo), "--report", str(report_path), "--state-db", str(tmp_path / "state.sqlite3")])

    report = json.loads(report_path.read_text())
    archived_reports = list(saved_report_directory.glob("run-*.json"))
    assert code == 0
    assert len(archived_reports) == 1
    assert json.loads(archived_reports[0].read_text()) == report
    assert report["status"] == "no_findings"
    assert report["packages_checked"] == 3
    assert report["phases"][0] == {"name": "scan", "status": "no_findings"}
    assert report["model"]["provider"] == "openai"
    assert json.loads(capsys.readouterr().out)["status"] == "no_findings"


def test_cli_saves_report_automatically_when_report_path_is_not_given(tmp_path, monkeypatch, capsys):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()
    report_directory = tmp_path / "saved report"
    monkeypatch.setattr(main, "DEFAULT_REPORT_DIRECTORY", report_directory)
    monkeypatch.setattr(main, "build_graph", lambda **kwargs: FakeWorkflow())
    monkeypatch.setattr(main, "SQLiteAgentPersistence", FakePersistence)

    code = main.main([str(repo), "--state-db", str(tmp_path / "state.sqlite3")])

    reports = list(report_directory.glob("run-*.json"))
    assert code == 0
    assert len(reports) == 1
    saved = json.loads(reports[0].read_text())
    printed = json.loads(capsys.readouterr().out)
    assert saved["status"] == "no_findings"
    assert saved == printed


def test_approve_flag_discovers_and_resumes_pending_thread(tmp_path, monkeypatch, capsys):
    repo = tmp_path / "repo"
    repo.mkdir()
    shared = {"approved": False, "invoked": False, "next": ("await_approval",)}
    state = {
        "repo_path": str(tmp_path / "worktree"),
        "main_repo_path": str(repo),
        "run_status": "awaiting_human_review",
        "current_vuln": {"id": "GHSA-DEMO", "package": {"name": "demo"}},
        "branch_name": "security/fix-demo-ghsa-demo",
        "changed_files": ["requirements.txt"],
    }

    class ApprovalWorkflow:
        def get_state(self, _config):
            return type("Snapshot", (), {"next": shared["next"], "values": state})()

        def update_state(self, _config, update):
            shared["approved"] = update.get("approval_granted") is True

        def invoke(self, _state, config=None):
            assert config["configurable"]["thread_id"] == "pending-thread"
            assert shared["approved"] is True
            shared["invoked"] = True
            shared["next"] = ()
            state["run_status"] = "pull_request_created"
            state["pr_url"] = "https://github.com/example/demo/pull/1"
            return state

    class ApprovalPersistence(FakePersistence):
        def list_thread_ids(self):
            return ["pending-thread"]

    workflow = ApprovalWorkflow()
    monkeypatch.setattr(main, "build_graph", lambda **_kwargs: workflow)
    monkeypatch.setattr(main, "SQLiteAgentPersistence", ApprovalPersistence)
    monkeypatch.setattr(main, "DEFAULT_REPORT_DIRECTORY", tmp_path / "saved report")

    code = main.main(["--approve", "--state-db", str(tmp_path / "state.sqlite3")])

    output = capsys.readouterr()
    report = json.loads(output.out)
    assert code == 0
    assert shared == {"approved": True, "invoked": True, "next": ()}
    assert "Approving demo / GHSA-DEMO" in output.err
    assert report["observability"]["thread_id"] == "pending-thread"
    assert report["pull_request_url"] == "https://github.com/example/demo/pull/1"
