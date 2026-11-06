"""Dependency manifest parsing and Google OSV API helpers."""
from __future__ import annotations

import asyncio
import hashlib
import re
from pathlib import Path
from typing import Any

import httpx
from packaging.version import InvalidVersion, Version
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.requirements import InvalidRequirement, Requirement

OSV_QUERY_URL = "https://api.osv.dev/v1/query"


def fixed_versions_for_finding(
    finding: dict[str, Any], package: dict[str, str] | None = None
) -> list[str]:
    """Return OSV fixed-version boundaries after the installed version.

    OSV ranges encode fixes as ``events[].fixed``. A candidate is advisory
    guidance, not a compatibility guarantee; the workflow still tests and
    re-queries OSV after applying it.
    """
    package = package or finding.get("package", {})
    installed = str(package.get("version", ""))
    ecosystem = str(package.get("ecosystem", "")).casefold()
    name = _normalized_package_name(str(package.get("name", "")), ecosystem)
    if not installed or ecosystem not in {"pypi", "npm"}:
        return []
    try:
        installed_version = Version(installed.lstrip("v"))
    except InvalidVersion:
        return []

    candidates: set[str] = set()
    for affected in finding.get("affected", []):
        affected_package = affected.get("package", {})
        if (_normalized_package_name(str(affected_package.get("name", "")), ecosystem) != name
                or str(affected_package.get("ecosystem", "")).casefold() != ecosystem):
            continue
        for version_range in affected.get("ranges", []):
            # Only ranges with implemented version semantics can provide targets.
            if str(version_range.get("type", "")).upper() not in {"ECOSYSTEM", "SEMVER"}:
                continue
            for event in version_range.get("events", []):
                fixed = event.get("fixed")
                if not fixed:
                    continue
                fixed = str(fixed)
                try:
                    if Version(fixed.lstrip("v")) > installed_version:
                        candidates.add(fixed)
                except InvalidVersion:
                    # An unorderable version is not safe to recommend.
                    continue
    try:
        return sorted(candidates, key=lambda value: Version(value.lstrip("v")))
    except InvalidVersion:
        return []


def _normalized_package_name(name: str, ecosystem: str) -> str:
    """Normalize registry names when matching OSV affected package records."""
    normalized = name.casefold()
    return re.sub(r"[-_.]+", "-", normalized) if ecosystem == "pypi" else normalized


def upgrade_guidance_for_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Summarize OSV's earliest declared fixed version for the current package."""
    package = finding.get("package", {})
    versions = fixed_versions_for_finding(finding, package)
    return {
        "source": "OSV affected range events",
        "current_version": str(package.get("version", "")),
        "recommended_version": versions[0] if versions else "",
        "fixed_versions": versions,
        "status": "candidate_available" if versions else "no_orderable_fixed_version",
        "note": (
            "Use the earliest OSV fixed version newer than the detected version; "
            "compatibility must still be checked by tests and a post-patch OSV scan."
            if versions else
            "OSV did not provide an orderable fixed version for this package and advisory; do not guess an upgrade."
        ),
    }


def _version_key(value: str, ecosystem: str) -> Any:
    """Parse versions conservatively for the ecosystems supported by OSV."""
    if ecosystem.casefold() == "npm":
        return _semver_key(value, allow_v=True)
    try:
        return Version(value.lstrip("v"))
    except InvalidVersion as exc:
        raise ValueError(f"Unsupported PyPI version: {value!r}") from exc


def _semver_key(value: str, *, allow_v: bool = False) -> tuple[int, int, int, tuple[Any, ...]]:
    """Strict SemVer ordering for OSV SEMVER ranges and npm ecosystem versions."""
    if value == "0":  # OSV uses this as the lower-bound sentinel for all versions.
        return 0, 0, 0, (-1,)
    prefix = "v?" if allow_v else ""
    match = re.fullmatch(
        prefix + r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
        r"(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?",
        value,
    )
    if not match:
        raise ValueError(f"Unsupported semantic version: {value!r}")
    major, minor, patch, prerelease = match.groups()
    identifiers: list[tuple[int, Any]] = []
    if prerelease:
        for part in prerelease.split("."):
            if not part:
                raise ValueError(f"Unsupported semantic version: {value!r}")
            if part.isdigit():
                if len(part) > 1 and part.startswith("0"):
                    raise ValueError(f"Unsupported semantic version: {value!r}")
                identifiers.append((0, int(part)))
            else:
                identifiers.append((1, part))
        # For equal core versions, a release sorts after all prereleases.
        prerelease_key: tuple[Any, ...] = (0, *identifiers)
    else:
        prerelease_key = (1,)
    return int(major), int(minor), int(patch), prerelease_key


def is_version_affected_by_advisory(
    finding: dict[str, Any], version: str,
) -> bool:
    """Evaluate OSV's supported ranges; unsupported evidence raises instead of becoming false."""
    package = finding.get("package", {})
    ecosystem = str(package.get("ecosystem", ""))
    name = _normalized_package_name(str(package.get("name", "")), ecosystem)
    candidate = _version_key(version, ecosystem)
    matching_entries = [
        item for item in finding.get("affected", [])
        if _normalized_package_name(str(item.get("package", {}).get("name", "")), ecosystem) == name
        and str(item.get("package", {}).get("ecosystem", "")).casefold() == ecosystem.casefold()
    ]
    if not matching_entries:
        raise ValueError(f"OSV advisory {finding.get('id', '')} has no matching affected package data")

    has_verifiable_data = False
    unknown_reasons: list[str] = []

    def range_contains(version_range: dict[str, Any]) -> bool:
        range_type = str(version_range.get("type", "")).upper()
        if range_type not in {"ECOSYSTEM", "SEMVER"}:
            raise ValueError(f"OSV advisory {finding.get('id', '')} uses unsupported range type {range_type!r}")
        events = version_range.get("events")
        if not isinstance(events, list) or not events:
            raise ValueError(f"OSV advisory {finding.get('id', '')} has an empty or invalid version range")
        compare = _semver_key if range_type == "SEMVER" else lambda value: _version_key(value, ecosystem)
        range_candidate = compare(version)
        start: Any | None = None
        active = False
        for event in events:
            if not isinstance(event, dict) or len(event) != 1:
                raise ValueError(f"OSV advisory {finding.get('id', '')} has an invalid range event")
            kind, raw_boundary = next(iter(event.items()))
            if kind == "introduced":
                if active:
                    raise ValueError(f"OSV advisory {finding.get('id', '')} has overlapping range events")
                start = compare(str(raw_boundary))
                active = True
                continue
            if kind not in {"fixed", "last_affected", "limit"}:
                raise ValueError(f"OSV advisory {finding.get('id', '')} contains unsupported range event {kind!r}")
            if not active or start is None:
                raise ValueError(f"OSV advisory {finding.get('id', '')} has a closing event without an introduced event")
            if kind == "limit" and raw_boundary == "*":  # OSV's special infinity limit.
                matched = start <= range_candidate
            elif kind == "fixed":
                boundary = compare(str(raw_boundary))
                if start >= boundary:
                    raise ValueError(f"OSV advisory {finding.get('id', '')} has an invalid fixed boundary")
                matched = start <= range_candidate < boundary
            elif kind == "last_affected":
                boundary = compare(str(raw_boundary))
                if start > boundary:
                    raise ValueError(f"OSV advisory {finding.get('id', '')} has an invalid last_affected boundary")
                matched = start <= range_candidate <= boundary
            else:  # OSV limit is the exclusive end of the current interval.
                boundary = compare(str(raw_boundary))
                if start >= boundary:
                    raise ValueError(f"OSV advisory {finding.get('id', '')} has an invalid limit boundary")
                matched = start <= range_candidate < boundary
            if matched:
                return True
            active, start = False, None
        return bool(active and start is not None and start <= range_candidate)

    for affected in matching_entries:
        versions = affected.get("versions") or []
        if versions:
            has_verifiable_data = True
            for listed_version in versions:
                try:
                    if _version_key(str(listed_version), ecosystem) == candidate:
                        return True
                except (ValueError, TypeError) as exc:
                    unknown_reasons.append(f"Invalid explicit affected version: {exc}")
        for version_range in affected.get("ranges", []):
            has_verifiable_data = True
            try:
                if range_contains(version_range):
                    return True
            except (ValueError, TypeError, KeyError) as exc:
                unknown_reasons.append(str(exc))
    if unknown_reasons:
        raise ValueError(("no version range that can be verified: " + "; ".join(dict.fromkeys(unknown_reasons)))[:500])
    if not has_verifiable_data:
        raise ValueError(f"OSV advisory {finding.get('id', '')} has no version range that can be verified")
    return False


def assess_version_affected_by_advisory(
    finding: dict[str, Any], version: str | None = None,
) -> dict[str, Any]:
    """Return deterministic affected status; malformed or unsupported evidence stays unknown."""
    package = finding.get("package", {})
    installed = str(version if version is not None else package.get("version", "")) if isinstance(package, dict) else str(version or "")
    try:
        affected = is_version_affected_by_advisory(finding, installed)
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        return {
            "status": "unknown", "assessment_status": "unknown", "confidence": "unknown",
            "installed_version": installed, "reason": str(exc)[:500] or "OSV version evidence could not be evaluated.",
        }
    return {
        "status": "affected" if affected else "not_affected",
        "assessment_status": "complete", "confidence": "deterministic",
        "installed_version": installed,
        "reason": (
            "Installed version matches an OSV affected range or explicit affected version."
            if affected else "Installed version is outside the supported OSV affected ranges and explicit affected versions."
        ),
    }


def version_is_at_least(version: str, minimum: str, ecosystem: str) -> bool:
    """Compare an installed resolution to an OSV-selected minimum version."""
    try:
        return _version_key(version, ecosystem) >= _version_key(minimum, ecosystem)
    except ValueError:
        return False


def group_advisories_by_package(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build one remediation item per normalized package and find a common OSV fixed version."""
    packages: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for finding in findings:
        package = finding.get("package", {})
        ecosystem = str(package.get("ecosystem", ""))
        key = (ecosystem.casefold(), _normalized_package_name(str(package.get("name", "")), ecosystem))
        packages.setdefault(key, []).append(finding)

    grouped: list[dict[str, Any]] = []
    for (ecosystem_key, package_key), advisories in packages.items():
        first_package = dict(advisories[0].get("package", {}))
        installed = str(first_package.get("version", ""))
        ids = sorted({str(item.get("id", "unknown")) for item in advisories})
        base = {
            "id": ids[0] if len(ids) == 1 else "GROUP-" + hashlib.sha256("|".join(ids).encode()).hexdigest()[:12],
            "summary": f"{len(ids)} OSV advisories affect {first_package.get('name', package_key)}" if len(ids) > 1 else advisories[0].get("summary", ""),
            "package": first_package,
            "advisories": advisories,
            "advisory_ids": ids,
        }
        try:
            current_key = _version_key(installed, ecosystem_key)
            candidates: set[str] = set()
            for advisory in advisories:
                affected_entries = advisory.get("affected", [])
                matching = [
                    item for item in affected_entries
                    if _normalized_package_name(str(item.get("package", {}).get("name", "")), ecosystem_key) == package_key
                    and str(item.get("package", {}).get("ecosystem", "")).casefold() == ecosystem_key
                ]
                if not matching:
                    raise ValueError(f"OSV advisory {advisory.get('id', '')} has no matching affected package data")
                for affected in matching:
                    for version_range in affected.get("ranges", []):
                        if str(version_range.get("type", "")).upper() not in {"ECOSYSTEM", "SEMVER"}:
                            continue
                        for event in version_range.get("events", []):
                            fixed = event.get("fixed")
                            if fixed:
                                fixed_text = str(fixed)
                                if _version_key(fixed_text, ecosystem_key) > current_key:
                                    candidates.add(fixed_text)
            selected = ""
            for candidate in sorted(candidates, key=lambda item: _version_key(item, ecosystem_key)):
                if all(not is_version_affected_by_advisory(advisory, candidate) for advisory in advisories):
                    selected = candidate
                    break
            if not selected:
                raise ValueError("No OSV-declared fixed version is outside every grouped advisory range")
            base["upgrade_guidance"] = {
                "source": "intersection of OSV fixed-version events",
                "current_version": installed,
                "recommended_version": selected,
                "fixed_versions": sorted(candidates, key=lambda item: _version_key(item, ecosystem_key)),
                "advisory_ids": ids,
                "range_reasoning": [
                    f"{advisory.get('id', 'unknown')}: candidate {selected} is outside the supplied affected ranges"
                    for advisory in advisories
                ],
                "status": "candidate_available",
            }
            base["resolution_status"] = "candidate_available"
        except (ValueError, TypeError) as exc:
            base["upgrade_guidance"] = {
                "source": "OSV affected range intersection",
                "current_version": installed,
                "recommended_version": "",
                "advisory_ids": ids,
                "status": "conflict_requires_review",
                "reason": str(exc),
            }
            base["resolution_status"] = "conflict_requires_review"
        grouped.append(base)
    return grouped


def poetry_constraint_allows(constraint: Any, version: str) -> bool:
    """Check common Poetry constraint forms against a resolved lock version."""
    if isinstance(constraint, dict):
        constraint = constraint.get("version", "")
    text = str(constraint or "*").strip()
    if text in {"", "*"}:
        return True
    try:
        resolved = Version(version)
    except InvalidVersion:
        return False
    if text.startswith("^"):
        try:
            lower = Version(text[1:])
        except InvalidVersion:
            return False
        parts = list(lower.release) + [0, 0, 0]
        index = next((i for i, part in enumerate(parts[:3]) if part), 2)
        upper_parts = parts[:index + 1]
        upper_parts[-1] += 1
        upper = Version(".".join(map(str, upper_parts)))
        return lower <= resolved < upper
    if text.startswith("~") and not text.startswith("~="):
        try:
            lower = Version(text[1:])
            parts = list(lower.release) + [0, 0, 0]
            upper = Version(f"{parts[0]}.{parts[1] + 1}.0")
            return lower <= resolved < upper
        except InvalidVersion:
            return False
    pep440 = text.replace(",", ",")
    if re.fullmatch(r"[0-9][A-Za-z0-9.+!_-]*", pep440):
        pep440 = f"=={pep440}"
    try:
        return resolved in SpecifierSet(pep440)
    except InvalidSpecifier:
        return False


def poetry_declared_constraint(content: str, package_name: str) -> Any | None:
    """Find a package constraint in Poetry or PEP 621 project dependency tables."""
    try:
        import tomllib
    except ImportError:  # Python 3.10
        import tomli as tomllib  # type: ignore[no-redef]
    try:
        data = tomllib.loads(content)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"Cannot parse pyproject.toml for dependency verification: {exc}") from exc
    wanted = _normalized_package_name(package_name, "pypi")
    tool = data.get("tool", {}).get("poetry", {})
    tables = [tool.get("dependencies", {})]
    tables.extend(
        group.get("dependencies", {})
        for group in (tool.get("group", {}) or {}).values()
        if isinstance(group, dict)
    )
    for dependencies in tables:
        for name, constraint in (dependencies or {}).items():
            if _normalized_package_name(str(name), "pypi") == wanted:
                return constraint
    project = data.get("project", {})
    requirements = list(project.get("dependencies", []) or [])
    for optional in (project.get("optional-dependencies", {}) or {}).values():
        requirements.extend(optional or [])
    for raw_requirement in requirements:
        try:
            requirement = Requirement(str(raw_requirement))
        except InvalidRequirement:
            continue
        if _normalized_package_name(requirement.name, "pypi") == wanted:
            return str(requirement.specifier) or "*"
    return None


def verify_group_resolution(
    group: dict[str, Any],
    locked_packages: list[dict[str, str]],
    pyproject_content: str,
) -> dict[str, str]:
    """Verify Poetry's resolved version satisfies the declaration and every OSV range."""
    package = group.get("package", {})
    name = str(package.get("name", ""))
    target = str(group.get("upgrade_guidance", {}).get("recommended_version", ""))
    normalized = _normalized_package_name(name, "pypi")
    lock_entry = next(
        (item for item in locked_packages
         if _normalized_package_name(str(item.get("name", "")), "pypi") == normalized),
        None,
    )
    if not target or not lock_entry:
        raise ValueError(f"{name}: selected target or resolved poetry.lock entry is missing")
    locked_version = str(lock_entry.get("version", ""))
    constraint = poetry_declared_constraint(pyproject_content, name)
    if constraint is None:
        raise ValueError(f"{name}: pyproject.toml has no direct dependency declaration to validate")
    if not poetry_constraint_allows(constraint, target):
        raise ValueError(f"{name}: selected target {target} is outside the pyproject.toml constraint {constraint!r}")
    if not poetry_constraint_allows(constraint, locked_version):
        raise ValueError(f"{name}: locked version {locked_version} violates pyproject.toml constraint {constraint!r}")
    ecosystem = str(package.get("ecosystem", "PyPI"))
    if _version_key(locked_version, ecosystem) < _version_key(target, ecosystem):
        raise ValueError(f"{name}: locked version {locked_version} is older than selected safe target {target}")
    for advisory in group.get("advisories", []):
        if is_version_affected_by_advisory(advisory, locked_version):
            raise ValueError(
                f"{name} {locked_version} remains in advisory {advisory.get('id', 'unknown')}'s affected range"
            )
    return {"package": name, "selected_target": target,
            "resolved_version": locked_version, "constraint": str(constraint)}


def parse_requirements(content: str) -> list[dict[str, str]]:
    """Parse simple pinned/ranged requirements.txt entries into OSV packages.

    Editable/VCS requirements and pip options are ignored because OSV needs a
    package name and ecosystem; callers can add support for those explicitly.
    """
    packages: list[dict[str, str]] = []
    for raw in content.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "http:", "https:")):
            continue
        match = re.match(r"^([A-Za-z0-9_.-]+)\s*(?:\[[^]]+\])?\s*(.*)$", line)
        if not match:
            continue
        name, spec = match.groups()
        # A range such as >=2.0 does not tell us which version is installed.
        # Only an exact ==/=== pin is safe to send as the OSV query version.
        version_match = re.fullmatch(r"\s*={2,3}\s*([A-Za-z0-9_.+!-]+)\s*", spec)
        version = version_match.group(1) if version_match and "*" not in version_match.group(1) else ""
        packages.append({"name": name, "version": version, "ecosystem": "PyPI"})
    return packages


def parse_package_json(content: str) -> list[dict[str, str]]:
    """Parse direct npm dependencies, treating only exact versions as resolved."""
    import json
    data = json.loads(content)
    result: list[dict[str, str]] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        for name, version in (data.get(section) or {}).items():
            version_text = str(version).strip()
            # Semver ranges (including ^, ~, >=, tags and workspace specs)
            # are not the installed version. A lockfile parser supplies that.
            exact = re.fullmatch(r"(?:=|v)?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)", version_text)
            clean_version = exact.group(1) if exact else ""
            result.append({"name": name, "version": clean_version, "ecosystem": "npm"})
    return result


def parse_npm_lock(content: str) -> list[dict[str, str]]:
    """Read resolved npm package versions from package-lock v2/v3 or v1."""
    import json

    data = json.loads(content)
    result: dict[str, str] = {}
    packages = data.get("packages") or {}
    for lock_path, entry in packages.items():
        if not lock_path or not isinstance(entry, dict) or not entry.get("version"):
            continue
        marker = "/node_modules/"
        if lock_path.startswith("node_modules/"):
            name = lock_path[len("node_modules/"):]
        elif marker in lock_path:
            name = lock_path.rsplit(marker, 1)[1]
        else:
            continue
        # A scoped package has one slash in its package name; nested paths have
        # already been cut off at the final node_modules marker.
        result[name] = str(entry["version"])

    # package-lock v1 stores nested dependency records instead of `packages`.
    def walk_v1(dependencies: dict[str, Any]) -> None:
        for name, entry in dependencies.items():
            if isinstance(entry, dict):
                if entry.get("version"):
                    result[name] = str(entry["version"])
                walk_v1(entry.get("dependencies") or {})

    walk_v1(data.get("dependencies") or {})
    return [{"name": name, "version": version, "ecosystem": "npm"} for name, version in result.items()]


def parse_python_lock(content: str) -> list[dict[str, str]]:
    """Read resolved package records from uv.lock or poetry.lock TOML."""
    try:
        import tomllib
    except ImportError:  # Python 3.10
        import tomli as tomllib  # type: ignore[no-redef]
    data = tomllib.loads(content)
    result: list[dict[str, str]] = []
    for package in data.get("package", data.get("packages", [])):
        name, version = package.get("name"), package.get("version")
        if name and version:
            result.append({"name": str(name), "version": str(version), "ecosystem": "PyPI"})
    return result


async def query_osv(package: dict[str, str], client: httpx.AsyncClient | None = None) -> list[dict[str, Any]]:
    """Query OSV for a single package. A versionless query checks the package broadly."""
    payload: dict[str, Any] = {"package": {"name": package["name"], "ecosystem": package["ecosystem"]}}
    if package.get("version"):
        payload["version"] = package["version"]
    owned = client is None
    http = client or httpx.AsyncClient(timeout=20.0)
    try:
        response = await http.post(OSV_QUERY_URL, json=payload)
        response.raise_for_status()
        body = response.json()
        if not isinstance(body, dict) or not isinstance(body.get("vulns", []), list):
            raise RuntimeError(f"OSV returned an invalid response for {package['name']}")
        return body.get("vulns", [])
    except httpx.HTTPError as exc:
        raise RuntimeError(f"OSV query failed for {package['name']}: {exc}") from exc
    finally:
        if owned:
            await http.aclose()


async def scan_packages(
    packages: list[dict[str, str]],
    client: httpx.AsyncClient | None = None,
    *,
    max_concurrency: int = 8,
) -> list[dict[str, Any]]:
    """Query OSV concurrently with a small bound, preserving package order.

    OSV calls are independent, so bounded concurrency reduces scan latency
    without creating an unbounded burst against the public API. ``gather``
    preserves input ordering, which keeps report and branch ordering stable.
    """
    if max_concurrency < 1:
        raise ValueError("max_concurrency must be at least 1")
    semaphore = asyncio.Semaphore(max_concurrency)

    async def scan_one(package: dict[str, str]) -> list[dict[str, Any]]:
        async with semaphore:
            findings = await query_osv(package, client)
            return [{**vulnerability, "package": package} for vulnerability in findings]

    groups = await asyncio.gather(*(scan_one(package) for package in packages))
    return [finding for group in groups for finding in group]


def read_manifest(repo_path: str | Path, content: str | None = None) -> tuple[str, list[dict[str, str]]]:
    """Read and parse the first supported manifest in a repository."""
    root = Path(repo_path)
    if (root / "requirements.txt").is_file():
        text = content if content is not None else (root / "requirements.txt").read_text(encoding="utf-8")
        return "requirements.txt", parse_requirements(text)
    if (root / "package.json").is_file():
        text = content if content is not None else (root / "package.json").read_text(encoding="utf-8")
        return "package.json", parse_package_json(text)
    raise FileNotFoundError("No requirements.txt or package.json found")


def merge_resolved_packages(*groups: list[dict[str, str]]) -> list[dict[str, str]]:
    """Deduplicate package records, preferring the last (usually locked) version."""
    merged: dict[tuple[str, str], dict[str, str]] = {}
    for group in groups:
        for package in group:
            key = (package["ecosystem"], package["name"].lower())
            previous = merged.get(key, {})
            if package.get("version") or not previous.get("version"):
                merged[key] = package
    return list(merged.values())
