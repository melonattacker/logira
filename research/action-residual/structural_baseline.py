#!/usr/bin/env python3
"""Generate explainable research-only structural baseline predictions."""

from __future__ import annotations

import argparse
import csv
import json
from typing import Any

from effect_research_common import baseline_scenario, fact_signature, read_jsonl, topology_signature


FIELDS = (
    "example_id",
    "scenario",
    "run_id",
    "baseline_scenario",
    "prediction",
    "reason",
    "baseline_episode_count",
    "effect_seen_count",
    "topology_seen_count",
    "normalized_effect_signature",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("facts")
    parser.add_argument("labels")
    parser.add_argument("--output", required=True)
    return parser.parse_args()


def complete(document: dict[str, Any], fact_kind: str) -> bool:
    coverage = document.get("coverage", {})
    context = document.get("episode_context", {})
    if not bool(context.get("ancestry_complete")) or coverage.get("process") != "complete":
        return False
    if fact_kind.startswith("file_"):
        return coverage.get("file") == "complete"
    if fact_kind.startswith("network_"):
        return coverage.get("network") == "complete"
    return True


def main() -> None:
    args = parse_args()
    documents = read_jsonl((args.facts,))
    by_run = {str(document["run_id"]): document for document in documents}
    with open(args.labels, encoding="utf-8", newline="") as source:
        labels = list(csv.DictReader(source))

    output: list[dict[str, Any]] = []
    for row in labels:
        document = by_run.get(row["run_id"])
        if document is None:
            raise RuntimeError(f"{row['example_id']}: run {row['run_id']} is absent from Effect Facts")
        fact = json.loads(row["fact_json"])
        fact_kind = str(fact.get("kind", ""))
        signature = fact_signature(fact)
        comparison = baseline_scenario(row["scenario"])
        baselines = [
            candidate
            for candidate in documents
            if candidate["scenario"] == comparison and candidate["run_id"] != row["run_id"]
        ]
        usable = [candidate for candidate in baselines if complete(candidate, fact_kind)]
        effect_seen = sum(
            1
            for candidate in usable
            if signature in {fact_signature(item) for item in candidate.get("effects", [])}
        )
        topology = topology_signature(document)
        topology_seen = sum(1 for candidate in usable if topology_signature(candidate) == topology)

        if not complete(document, fact_kind) or not usable:
            prediction = "AMBIGUOUS"
            reason = "target or baseline episode has incomplete evidence, or no usable baseline episode exists"
        elif effect_seen == 0:
            prediction = "NOVEL_EFFECT"
            reason = f"normalized effect signature absent from {len(usable)} complete baseline episode(s)"
        elif topology_seen == 0:
            prediction = "AMBIGUOUS"
            reason = "effect was seen in baseline, but the coarse episode-topology signature was not"
        else:
            prediction = "SEEN_IN_BASELINE"
            reason = f"effect and coarse topology were both seen in complete baseline episodes ({effect_seen}/{len(usable)} effect matches)"

        output.append(
            {
                "example_id": row["example_id"],
                "scenario": row["scenario"],
                "run_id": row["run_id"],
                "baseline_scenario": comparison,
                "prediction": prediction,
                "reason": reason,
                "baseline_episode_count": len(usable),
                "effect_seen_count": effect_seen,
                "topology_seen_count": topology_seen,
                "normalized_effect_signature": signature,
            }
        )

    with open(args.output, "w", encoding="utf-8", newline="") as target:
        writer = csv.DictWriter(target, fieldnames=FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(output)


if __name__ == "__main__":
    main()
