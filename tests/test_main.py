import json

import pytest

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


def _complete_report():
    return {
        "schema_version": 6,
        "mode": "dependabot_pr_review",
        "status": "review_complete",
        "repository_full_name": "acme/demo",
        "pull_request": {
            "number": 17,
            "author": "dependabot[bot]",
            "head_sha": "abc123",
        },
    }


class FakeReviewGraph:
    def __init__(self, report=None):
        self.report = report or _complete_report()
        self.invocations = []

    def invoke(self, state):
        self.invocations.append(state)
        return {"report": self.report}


def _install_fake_graph(monkeypatch, graph):
    monkeypatch.setattr(main, "build_dependabot_review_graph", lambda **_kwargs: graph)


def test_cli_collects_dependabot_review_and_archives_json(tmp_path, monkeypatch, capsys):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()
    report_path = tmp_path / "evidence.json"
    report_directory = tmp_path / "saved report"
    monkeypatch.setattr(main, "DEFAULT_REPORT_DIRECTORY", report_directory)
    graph = FakeReviewGraph()
    _install_fake_graph(monkeypatch, graph)

    code = main.main([
        str(repo), "--review-pr", "17", "--collect-only",
        "--report", str(report_path), "--state-db", str(tmp_path / "audit.sqlite3"),
    ])

    report = json.loads(report_path.read_text())
    archived = list(report_directory.glob("review-*.json"))
    assert code == 0
    assert graph.invocations[0]["repository"] == str(repo)
    assert graph.invocations[0]["pull_request"] == "17"
    assert graph.invocations[0]["collect_only"] is True
    assert len(archived) == 1
    assert json.loads(archived[0].read_text()) == report
    assert json.loads(capsys.readouterr().out)["status"] == "review_complete"


def test_cli_analyzes_a_collected_report_and_validates_comment_identity(tmp_path, monkeypatch, capsys):
    evidence = tmp_path / "evidence.json"
    evidence.write_text(json.dumps(_complete_report()))
    report_directory = tmp_path / "saved report"
    monkeypatch.setattr(main, "DEFAULT_REPORT_DIRECTORY", report_directory)
    graph = FakeReviewGraph()
    _install_fake_graph(monkeypatch, graph)

    code = main.main([
        "--analyze-report", str(evidence), "--post-comment",
        "--report-artifact-url", "https://github.com/acme/demo/actions/runs/123/artifacts/456",
        "--expected-pr", "17", "--expected-repository", "acme/demo", "--expected-head-sha", "abc123",
    ])

    assert code == 0
    assert graph.invocations[0]["post_comment"] is True
    assert graph.invocations[0]["report"]["report_artifact_url"].endswith("artifacts/456")
    saved = list(report_directory.glob("review-*.json"))
    assert len(saved) == 1
    assert json.loads(capsys.readouterr().out)["status"] == "review_complete"


def test_cli_rejects_collected_report_for_different_pr(tmp_path):
    evidence = tmp_path / "evidence.json"
    evidence.write_text(json.dumps(_complete_report()))

    with pytest.raises(SystemExit) as error:
        main.main([
            "--analyze-report", str(evidence), "--post-comment",
            "--expected-pr", "18", "--expected-repository", "acme/demo", "--expected-head-sha", "abc123",
        ])

    assert error.value.code == 2


def test_cli_exposes_only_dependabot_review_commands(capsys):
    with pytest.raises(SystemExit) as help_exit:
        main.main(["--help"])
    assert help_exit.value.code == 0
    help_text = capsys.readouterr().out
    assert "--review-pr" in help_text
    assert "--analyze-report" in help_text
    assert "--approve" not in help_text
    assert "--resume" not in help_text

    with pytest.raises(SystemExit) as removed_command:
        main.main(["--approve"])
    assert removed_command.value.code == 2
