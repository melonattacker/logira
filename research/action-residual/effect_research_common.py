#!/usr/bin/env python3
"""Shared, research-only helpers for the Effect Facts experiment."""

from __future__ import annotations

import json
from typing import Any, Iterable


# These are experiment pairings, not production security rules. A comparison
# scenario is evaluated against its explicitly collected control/baseline.
COMPARISON_BASELINES = {
    "path_hijack": "git_status",
    "make_side_effect": "make_control",
    "git_hook_effect": "git_hook_control",
    "shell_startup_effect": "shell_startup_control",
}


def baseline_scenario(scenario: str) -> str:
    return COMPARISON_BASELINES.get(scenario, scenario)


def read_jsonl(paths: Iterable[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for filename in paths:
        with open(filename, encoding="utf-8") as source:
            for line_number, line in enumerate(source, 1):
                if not line.strip():
                    continue
                try:
                    value = json.loads(line)
                except json.JSONDecodeError as error:
                    raise ValueError(f"{filename}:{line_number}: {error}") from error
                if not isinstance(value, dict):
                    raise ValueError(f"{filename}:{line_number}: expected a JSON object")
                rows.append(value)
    return rows


def fact_signature(fact: dict[str, Any]) -> str:
    """Return the structural identity of a fact, excluding observation count."""
    stable = {key: value for key, value in fact.items() if key != "count"}
    return json.dumps(stable, sort_keys=True, separators=(",", ":"))


def topology_signature(document: dict[str, Any]) -> str:
    context = document.get("episode_context", {})
    stable = {
        "exec_replacement_count": int(context.get("exec_replacement_count", 0)),
        "has_transitive_exec": int(context.get("transitive_exec_count", 0)) > 0,
        "max_process_depth": int(context.get("max_process_depth", 0)),
        "exec_roles": sorted(context.get("exec_roles", [])),
    }
    return json.dumps(stable, sort_keys=True, separators=(",", ":"))
