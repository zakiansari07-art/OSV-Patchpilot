"""Compatibility module exposing the public workflow API."""
from __future__ import annotations

# Keep these imports available for existing scripts and tests while the
# implementation lives in the production package.
import subprocess

from reporting import _is_sensitive_path, _redact_source, build_run_report
from vulnerability_agent.dependencies import _model
from vulnerability_agent.graph import build_graph
from vulnerability_agent.state import (
    State, _json_object, apply_search_replace_edits,
    branch_name_for_finding, detect_base_branch, finding_key, select_test_command,
    should_retry,
)

__all__ = [
    "State", "apply_search_replace_edits", "branch_name_for_finding",
    "build_graph", "build_run_report", "detect_base_branch", "finding_key",
    "select_test_command", "should_retry",
]
