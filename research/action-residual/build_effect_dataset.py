#!/usr/bin/env python3
"""Select a compact, neutral Effect Facts dataset for manual labeling."""

from __future__ import annotations

import argparse
import csv
import json
import os
from typing import Any

from effect_research_common import baseline_scenario, fact_signature, read_jsonl


FIELDS = (
    "example_id",
    "scenario",
    "run_id",
    "runtime_command",
    "effect_kind",
    "effect_target",
    "effect_scope",
    "effect_role",
    "effect_count",
    "baseline_scenario",
    "fact_json",
    "gold_label",
    "notes",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("facts")
    parser.add_argument("--output", required=True)
    parser.add_argument("--judge-inputs", required=True)
    parser.add_argument("--examples-per-scenario", type=int, default=2)
    parser.add_argument(
        "--reset-labels",
        action="store_true",
        help="discard existing human labels instead of preserving matching rows",
    )
    return parser.parse_args()


def effect_target(fact: dict[str, Any]) -> str:
    return str(
        fact.get("target")
        or fact.get("target_basename")
        or fact.get("destination_basename")
        or fact.get("port")
        or ""
    )


def effect_scope(fact: dict[str, Any]) -> str:
    return str(fact.get("location_scope") or fact.get("scope") or fact.get("destination_scope") or "unknown")


def effect_role(fact: dict[str, Any]) -> str:
    return str(fact.get("role") or fact.get("actor_role") or "unknown")


def category(fact: dict[str, Any]) -> str:
    kind = str(fact.get("kind", ""))
    if kind == "exec":
        return "exec"
    if kind.startswith("file_"):
        return "file"
    if kind.startswith("network_"):
        return "network"
    return "other"


def mutation(fact: dict[str, Any]) -> bool:
    return fact.get("kind") in {"file_create", "file_modify", "file_rename", "file_delete"}


def ranked(
    candidates: list[dict[str, Any]],
    prefer_novel: bool,
    baseline_signatures: set[str],
    baseline_facts: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    role_order = {"descendant": 0, "wrapper": 1, "exec_replacement": 2, "direct_match": 3}
    scope_order = {
        "workspace": 0,
        "workspace_git": 0,
        "tmp": 1,
        "toolchain": 1,
        "home": 2,
        "system": 3,
        "unknown": 4,
    }
    baseline_exec_targets = {
        (str(fact.get("target", "")), str(fact.get("location_scope", "unknown")))
        for fact in baseline_facts
        if fact.get("kind") == "exec"
    }

    def key(fact: dict[str, Any]) -> tuple[Any, ...]:
        novel_rank = 0 if fact_signature(fact) not in baseline_signatures else 1
        if not prefer_novel:
            novel_rank = 0
        kind = category(fact)
        if kind == "exec":
            target_key = (str(fact.get("target", "")), str(fact.get("location_scope", "unknown")))
            target_rank = 0 if prefer_novel and target_key not in baseline_exec_targets else 1
            detail_rank = (
                target_rank,
                role_order.get(str(fact.get("role", "")), 4),
                scope_order.get(str(fact.get("location_scope", "unknown")), 4),
            )
        elif kind == "file":
            detail_rank = (
                0 if mutation(fact) else 1,
                scope_order.get(str(fact.get("scope", "unknown")), 4),
            )
        else:
            detail_rank = (0,)
        return (novel_rank, detail_rank, fact_signature(fact))

    return sorted(candidates, key=key)


def choose_facts(
    document: dict[str, Any], all_documents: list[dict[str, Any]], limit: int
) -> list[dict[str, Any]]:
    scenario = str(document["scenario"])
    comparison = baseline_scenario(scenario)
    baseline_documents = [row for row in all_documents if row["scenario"] == comparison and row["run_id"] != document["run_id"]]
    baseline_facts = [fact for row in baseline_documents for fact in row.get("effects", [])]
    baseline_signatures = {fact_signature(fact) for fact in baseline_facts}
    prefer_novel = comparison != scenario
    effects = list(document.get("effects", []))
    selected: list[dict[str, Any]] = []

    # Select across effect dimensions instead of taking the first N noisy facts.
    for kind in ("exec", "file", "network"):
        choices = ranked(
            [fact for fact in effects if category(fact) == kind],
            prefer_novel,
            baseline_signatures,
            baseline_facts,
        )
        if choices:
            selected.append(choices[0])
        if len(selected) >= limit:
            return selected

    for fact in ranked(effects, prefer_novel, baseline_signatures, baseline_facts):
        if fact not in selected:
            selected.append(fact)
        if len(selected) >= limit:
            break
    return selected


def judge_input(example_id: str, document: dict[str, Any], fact: dict[str, Any]) -> dict[str, Any]:
    context = document.get("episode_context", {})
    exec_context = [
        {key: value for key, value in candidate.items() if key != "count"}
        for candidate in document.get("effects", [])
        if candidate.get("kind") == "exec"
    ]
    return {
        "schema_version": 1,
        "example_id": example_id,
        "reported_action": document.get("action", {}),
        "observed_effect": fact,
        "episode_context": {
            "exec_chain_facts": exec_context,
            "exec_replacement_count": context.get("exec_replacement_count", 0),
            "transitive_exec_count": context.get("transitive_exec_count", 0),
            "process_member_count": context.get("process_member_count", 0),
            "max_process_depth": context.get("max_process_depth", 0),
            "ancestry_complete": context.get("ancestry_complete", False),
            "coverage": document.get("coverage", {}),
        },
        "required_output": {"label": "ACTION_ALIGNED|ACTION_MISALIGNED|UNCLEAR", "reason": "short string"},
    }


def existing_labels(path: str, reset: bool) -> dict[str, dict[str, str]]:
    if reset or not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8", newline="") as source:
        rows = list(csv.DictReader(source))
    result = {row["example_id"]: row for row in rows}
    allowed = {"", "ACTION_ALIGNED", "ACTION_MISALIGNED", "UNCLEAR"}
    invalid = {example_id: row.get("gold_label", "") for example_id, row in result.items() if row.get("gold_label", "") not in allowed}
    if invalid:
        raise ValueError(f"existing output contains invalid gold labels: {invalid}")
    return result


def main() -> None:
    args = parse_args()
    if args.examples_per_scenario < 1:
        raise SystemExit("--examples-per-scenario must be positive")
    documents = read_jsonl((args.facts,))
    preserved = existing_labels(args.output, args.reset_labels)
    representatives: dict[str, dict[str, Any]] = {}
    for document in documents:
        scenario = str(document["scenario"])
        current = representatives.get(scenario)
        order = (int(document.get("sample", 0)), str(document.get("run_id", "")))
        if current is None or order < (int(current.get("sample", 0)), str(current.get("run_id", ""))):
            representatives[scenario] = document

    rows: list[dict[str, Any]] = []
    inputs: list[dict[str, Any]] = []
    next_id = 1
    for scenario in sorted(representatives):
        document = representatives[scenario]
        for fact in choose_facts(document, documents, args.examples_per_scenario):
            example_id = f"E{next_id:03d}"
            next_id += 1
            prior = preserved.get(example_id)
            if prior and (
                prior.get("scenario") != scenario
                or prior.get("run_id") != document["run_id"]
                or prior.get("fact_json") != json.dumps(fact, sort_keys=True, separators=(",", ":"))
            ):
                raise ValueError(
                    f"{example_id}: regenerated fact differs from the labeled row; use --reset-labels only after review"
                )
            rows.append(
                {
                    "example_id": example_id,
                    "scenario": scenario,
                    "run_id": document["run_id"],
                    "runtime_command": document.get("action", {}).get("command", ""),
                    "effect_kind": fact.get("kind", ""),
                    "effect_target": effect_target(fact),
                    "effect_scope": effect_scope(fact),
                    "effect_role": effect_role(fact),
                    "effect_count": int(fact.get("count", 0)),
                    "baseline_scenario": baseline_scenario(scenario),
                    "fact_json": json.dumps(fact, sort_keys=True, separators=(",", ":")),
                    "gold_label": prior.get("gold_label", "") if prior else "",
                    "notes": f"Aggregates {int(fact.get('count', 0))} observation(s) from representative sample {document.get('sample', 0)}.",
                }
            )
            inputs.append(judge_input(example_id, document, fact))

    with open(args.output, "w", encoding="utf-8", newline="") as target:
        writer = csv.DictWriter(target, fieldnames=FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    with open(args.judge_inputs, "w", encoding="utf-8") as target:
        for value in inputs:
            target.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()
