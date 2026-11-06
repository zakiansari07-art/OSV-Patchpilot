from unittest.mock import AsyncMock, Mock
import pytest

from osv_service import (
    assess_version_affected_by_advisory,
    fixed_versions_for_finding,
    group_advisories_by_package,
    is_version_affected_by_advisory,
    parse_npm_lock,
    parse_package_json,
    parse_python_lock,
    parse_requirements,
    query_osv,
    scan_packages,
    upgrade_guidance_for_finding,
    poetry_constraint_allows,
    verify_group_resolution,
    version_is_at_least,
)


def _range_advisory(events, *, ecosystem="PyPI", range_type="ECOSYSTEM", ranges=None):
    return {
        "id": "GHSA-TEST",
        "package": {"name": "langchain", "version": "0.2.17", "ecosystem": ecosystem},
        "affected": [{
            "package": {"name": "langchain", "ecosystem": ecosystem},
            "ranges": ranges if ranges is not None else [{"type": range_type, "events": events}],
        }],
    }


def test_parse_requirements_handles_versions_and_ignores_options():
    assert parse_requirements("requests==2.31.0\nFlask>=2.0\n-r base.txt\n# comment") == [
        {"name": "requests", "version": "2.31.0", "ecosystem": "PyPI"},
        {"name": "Flask", "version": "", "ecosystem": "PyPI"},
    ]


def test_requirement_ranges_are_not_mistaken_for_installed_versions():
    assert parse_requirements("requests>=2.0\nFlask==3.0.2\n") == [
        {"name": "requests", "version": "", "ecosystem": "PyPI"},
        {"name": "Flask", "version": "3.0.2", "ecosystem": "PyPI"},
    ]


def test_npm_lock_supplies_resolved_versions_and_scoped_names():
    lock = '{"lockfileVersion":3,"packages":{"":{"name":"demo"},"node_modules/react":{"version":"18.2.0"},"node_modules/@scope/tool":{"version":"1.4.1"}}}'
    assert parse_npm_lock(lock) == [
        {"name": "react", "version": "18.2.0", "ecosystem": "npm"},
        {"name": "@scope/tool", "version": "1.4.1", "ecosystem": "npm"},
    ]


def test_python_lock_supplies_resolved_versions():
    lock = 'version = 1\n\n[[package]]\nname = "requests"\nversion = "2.31.0"\n'
    assert parse_python_lock(lock) == [
        {"name": "requests", "version": "2.31.0", "ecosystem": "PyPI"}
    ]


def test_package_json_ranges_are_not_reported_as_resolved_versions():
    assert parse_package_json('{"dependencies":{"react":"^18.2.0","lodash":"4.17.21"}}') == [
        {"name": "react", "version": "", "ecosystem": "npm"},
        {"name": "lodash", "version": "4.17.21", "ecosystem": "npm"},
    ]


def test_upgrade_guidance_uses_earliest_newer_osv_fixed_version():
    finding = {
        "id": "GHSA-test",
        "package": {"name": "demo", "version": "1.4.0", "ecosystem": "PyPI"},
        "affected": [{
            "package": {"name": "demo", "ecosystem": "PyPI"},
            "ranges": [{"type": "ECOSYSTEM", "events": [
                {"introduced": "0"}, {"fixed": "1.2.0"},
            ]}, {"type": "ECOSYSTEM", "events": [
                {"introduced": "1.3.0"}, {"fixed": "1.5.2"},
            ]}],
        }],
    }
    guidance = upgrade_guidance_for_finding(finding)
    assert guidance["recommended_version"] == "1.5.2"
    assert guidance["fixed_versions"] == ["1.5.2"]
    assert guidance["status"] == "candidate_available"


def test_upgrade_guidance_handles_npm_versions_and_ignores_git_ranges():
    finding = {
        "package": {"name": "demo", "version": "2.3.0", "ecosystem": "npm"},
        "affected": [{
            "package": {"name": "demo", "ecosystem": "npm"},
            "ranges": [
                {"type": "GIT", "events": [{"introduced": "abc"}, {"fixed": "def"}]},
                {"type": "SEMVER", "events": [
                    {"introduced": "0"}, {"fixed": "2.4.1"},
                ]},
            ],
        }],
    }
    assert fixed_versions_for_finding(finding) == ["2.4.1"]


def test_upgrade_guidance_does_not_guess_when_osv_has_no_fixed_version():
    finding = {
        "package": {"name": "demo", "version": "1.0", "ecosystem": "PyPI"},
        "affected": [{
            "package": {"name": "demo", "ecosystem": "PyPI"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
        }],
    }
    guidance = upgrade_guidance_for_finding(finding)
    assert guidance["recommended_version"] == ""
    assert guidance["status"] == "no_orderable_fixed_version"


def _ranged_finding(advisory_id, fixed, current="1.0.0", *, introduced="0", name="demo"):
    return {
        "id": advisory_id,
        "package": {"name": name, "version": current, "ecosystem": "PyPI"},
        "affected": [{
            "package": {"name": name, "ecosystem": "PyPI"},
            "ranges": [{"type": "ECOSYSTEM", "events": [
                {"introduced": introduced}, {"fixed": fixed},
            ]}],
        }],
    }


def test_group_advisories_selects_smallest_declared_version_outside_all_ranges():
    findings = [_ranged_finding("GHSA-ONE", "2.0.0"), _ranged_finding("GHSA-TWO", "3.0.0")]
    group, = group_advisories_by_package(findings)
    assert group["advisory_ids"] == ["GHSA-ONE", "GHSA-TWO"]
    assert group["upgrade_guidance"]["recommended_version"] == "3.0.0"
    assert group["resolution_status"] == "candidate_available"
    assert len(group["advisories"]) == 2


def test_group_advisories_fails_closed_when_any_range_is_unknown_or_unfixed():
    fixed = _ranged_finding("GHSA-FIXED", "2.0.0")
    unbounded = {
        "id": "GHSA-UNFIXED",
        "package": fixed["package"],
        "affected": [{
            "package": {"name": "demo", "ecosystem": "PyPI"},
            "ranges": [{"type": "GIT", "events": [{"introduced": "deadbeef"}]}],
        }],
    }
    group, = group_advisories_by_package([fixed, unbounded])
    assert group["resolution_status"] == "conflict_requires_review"
    assert "no version range that can be verified" in group["upgrade_guidance"]["reason"]


def test_range_checker_uses_inclusive_last_affected_boundary():
    finding = {
        "id": "GHSA-LAST",
        "package": {"name": "demo", "version": "1.0.0", "ecosystem": "PyPI"},
        "affected": [{
            "package": {"name": "demo", "ecosystem": "PyPI"},
            "ranges": [{"type": "ECOSYSTEM", "events": [
                {"introduced": "1.0.0"}, {"last_affected": "1.5.0"},
            ]}],
        }],
    }
    assert is_version_affected_by_advisory(finding, "1.5.0")
    assert not is_version_affected_by_advisory(finding, "1.5.1")


def test_deterministic_assessment_marks_version_below_fixed_boundary_affected():
    finding = _range_advisory([{"introduced": "0"}, {"fixed": "0.3.30"}])
    result = assess_version_affected_by_advisory(finding, "0.2.17")
    assert result["status"] == "affected"
    assert result["assessment_status"] == "complete"
    assert result["confidence"] == "deterministic"


@pytest.mark.parametrize(("version", "expected"), [
    ("0.2.17", "affected"),
    ("0.3.30", "not_affected"),
    ("0.4.0", "not_affected"),
])
def test_fixed_boundary_is_exclusive(version, expected):
    finding = _range_advisory([{"introduced": "0"}, {"fixed": "0.3.30"}])
    assert assess_version_affected_by_advisory(finding, version)["status"] == expected


def test_multiple_osv_ranges_are_treated_as_union():
    finding = _range_advisory([], ranges=[
        {"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]},
        {"type": "ECOSYSTEM", "events": [{"introduced": "3.0.0"}, {"last_affected": "3.5.0"}]},
    ])
    assert assess_version_affected_by_advisory(finding, "1.5.0")["status"] == "affected"
    assert assess_version_affected_by_advisory(finding, "2.5.0")["status"] == "not_affected"
    assert assess_version_affected_by_advisory(finding, "3.5.0")["status"] == "affected"
    assert assess_version_affected_by_advisory(finding, "3.5.1")["status"] == "not_affected"


def test_multiple_intervals_in_one_osv_event_timeline_are_evaluated():
    finding = _range_advisory([
        {"introduced": "1.0.0"}, {"fixed": "2.0.0"},
        {"introduced": "3.0.0"}, {"fixed": "4.0.0"},
    ])
    assert assess_version_affected_by_advisory(finding, "1.5.0")["status"] == "affected"
    assert assess_version_affected_by_advisory(finding, "2.5.0")["status"] == "not_affected"
    assert assess_version_affected_by_advisory(finding, "3.5.0")["status"] == "affected"


def test_limit_star_is_osv_infinity():
    finding = _range_advisory([{"introduced": "1.0.0"}, {"limit": "*"}])
    assert assess_version_affected_by_advisory(finding, "2.0.0")["status"] == "affected"


def test_open_introduced_range_without_fixed_version_remains_affected():
    finding = _range_advisory([{"introduced": "1.0.0"}])
    assert assess_version_affected_by_advisory(finding, "2.0.0")["status"] == "affected"


def test_limit_event_is_exclusive():
    finding = _range_advisory([{"introduced": "1.0.0"}, {"limit": "2.0.0"}])
    assert assess_version_affected_by_advisory(finding, "1.9.9")["status"] == "affected"
    assert assess_version_affected_by_advisory(finding, "2.0.0")["status"] == "not_affected"


def test_unsupported_range_type_and_invalid_version_are_unknown():
    unsupported = _range_advisory([{"introduced": "0"}, {"fixed": "1.0.0"}], range_type="GIT")
    malformed_version = _range_advisory([{"introduced": "0"}, {"fixed": "1.0.0"}])
    assert assess_version_affected_by_advisory(unsupported, "0.5.0")["status"] == "unknown"
    assert assess_version_affected_by_advisory(malformed_version, "not-a-version")["status"] == "unknown"


def test_semver_range_uses_semver_ordering_for_prereleases():
    finding = _range_advisory(
        [{"introduced": "1.0.0-beta.1"}, {"fixed": "1.0.0"}],
        ecosystem="npm", range_type="SEMVER",
    )
    assert assess_version_affected_by_advisory(finding, "1.0.0-beta.2")["status"] == "affected"
    assert assess_version_affected_by_advisory(finding, "1.0.0")["status"] == "not_affected"


def test_npm_semver_fixed_target_comparison_handles_prereleases():
    assert version_is_at_least("2.4.0", "2.3.9", "npm")
    assert not version_is_at_least("2.4.0-beta.1", "2.4.0", "npm")


def test_poetry_constraint_and_lockfile_verification():
    finding = _ranged_finding("GHSA-ONE", "2.0.0")
    group, = group_advisories_by_package([finding])
    assert poetry_constraint_allows("^2.0.0", "2.4.1")
    assert not poetry_constraint_allows("^2.0.0", "3.0.0")
    result = verify_group_resolution(
        group,
        [{"name": "demo", "version": "2.1.0", "ecosystem": "PyPI"}],
        '[tool.poetry.dependencies]\npython = ">=3.10"\ndemo = "^2.0.0"\n',
    )
    assert result == {
        "package": "demo", "selected_target": "2.0.0",
        "resolved_version": "2.1.0", "constraint": "^2.0.0",
    }


def test_lock_verification_rejects_unsafe_or_out_of_constraint_resolution():
    finding = _ranged_finding("GHSA-ONE", "2.0.0")
    group, = group_advisories_by_package([finding])
    with pytest.raises(ValueError, match="violates pyproject.toml constraint"):
        verify_group_resolution(
            group, [{"name": "demo", "version": "3.0.0"}],
            '[tool.poetry.dependencies]\ndemo = "^2.0.0"\n',
        )
    with pytest.raises(ValueError, match="older than selected safe target"):
        verify_group_resolution(
            group, [{"name": "demo", "version": "1.5.0"}],
            '[tool.poetry.dependencies]\ndemo = "*"\n',
        )


@pytest.mark.asyncio
async def test_query_osv_parses_vulnerabilities():
    # httpx.Response.json() and raise_for_status() are synchronous methods;
    # only AsyncClient.post() is awaited.
    response = Mock()
    response.json.return_value = {"vulns": [{"id": "OSV-TEST-1", "summary": "test vuln"}]}
    response.raise_for_status.return_value = None
    client = AsyncMock()
    client.post.return_value = response
    result = await query_osv({"name": "demo", "version": "1.2", "ecosystem": "PyPI"}, client)
    assert result[0]["id"] == "OSV-TEST-1"
    assert client.post.call_args.kwargs["json"]["version"] == "1.2"


@pytest.mark.asyncio
async def test_scan_packages_attaches_package_to_vulnerability():
    response = Mock()
    response.json.return_value = {"vulns": [{"id": "OSV-1"}]}
    client = AsyncMock()
    client.post.return_value = response
    findings = await scan_packages([{"name": "demo", "version": "1.0", "ecosystem": "PyPI"}], client)
    assert findings == [{"id": "OSV-1", "package": {"name": "demo", "version": "1.0", "ecosystem": "PyPI"}}]
