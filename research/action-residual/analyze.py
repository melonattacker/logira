#!/usr/bin/env python3
"""Extract descriptive ExecutionEpisode features from research run manifests."""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
from pathlib import Path
import statistics
import subprocess
from typing import Any, Iterable


NUMERIC_FEATURES = (
    "duration_seconds",
    "exec_count",
    "wrapper_count",
    "transitive_exec_count",
    "process_member_count",
    "max_process_depth",
    "exec_replacement_count",
    "fork_only_process_count",
    "file_effect_count",
    "file_create_count",
    "file_modify_count",
    "file_rename_count",
    "file_delete_count",
    "network_effect_count",
    "unique_destination_count",
    "workspace_file_effect_count",
    "non_workspace_file_effect_count",
    "localhost_network_count",
    "non_local_network_count",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifests", nargs="+")
    parser.add_argument("--logira", default="./logira")
    parser.add_argument("--logira-home", default=os.environ.get("LOGIRA_HOME", ""))
    parser.add_argument("--features", required=True)
    parser.add_argument("--csv")
    parser.add_argument("--summary", required=True)
    return parser.parse_args()


def read_jsonl(paths: Iterable[str]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for name in paths:
        with open(name, encoding="utf-8") as source:
            for line in source:
                if line.strip():
                    records.append(json.loads(line))
    return records


def residual(logira: str, logira_home: str, run_id: str) -> dict[str, Any]:
    env = os.environ.copy()
    if logira_home:
        env["LOGIRA_HOME"] = logira_home
    completed = subprocess.run(
        [logira, "residual", run_id, "--effects", "--json"],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )
    return json.loads(completed.stdout)


def basename(filename: str) -> str:
    return os.path.basename(filename.rstrip("/"))


def under(path: str, root: str) -> bool:
    if not path or not root or not os.path.isabs(path):
        return False
    try:
        return os.path.commonpath([path, root]) == os.path.normpath(root)
    except ValueError:
        return False


def max_process_depth(members: list[dict[str, Any]]) -> int:
    identities = {
        (int(member.get("tid", 0)), int(member.get("task_start_kernel_ns", 0))): member
        for member in members
    }
    memo: dict[tuple[int, int], int] = {}

    def depth(identity: tuple[int, int], visiting: set[tuple[int, int]]) -> int:
        if identity in memo:
            return memo[identity]
        if identity in visiting:
            return 0
        member = identities[identity]
        parent = (
            int(member.get("parent_tid", 0)),
            int(member.get("parent_task_start_kernel_ns", 0)),
        )
        value = 1 + depth(parent, visiting | {identity}) if parent in identities else 0
        memo[identity] = value
        return value

    return max((depth(identity, set()) for identity in identities), default=0)


def is_loopback(address: str) -> bool:
    try:
        return ipaddress.ip_address(address).is_loopback
    except ValueError:
        return False


def sanitize(command: str, cwd: str) -> str:
    value = command
    if cwd:
        value = value.replace(cwd, "<repo>")
    home = str(Path.home())
    if home:
        value = value.replace(home, "<home>")
    return value


def extract(record: dict[str, Any], document: dict[str, Any]) -> dict[str, Any]:
    report = document["report"]
    episodes = report.get("episodes", [])
    matched = [finding for finding in report.get("findings", []) if finding.get("classification") == "MATCHED"]
    if len(episodes) != 1 or len(matched) != 1:
        raise RuntimeError(
            f"{record['run_id']}: expected one MATCHED episode, got episodes={len(episodes)} matched={len(matched)} counts={report.get('counts')}"
        )
    episode = episodes[0]
    finding = matched[0]
    execs = episode.get("exec_members", [])
    processes = episode.get("process_members", [])
    files = episode.get("file_effects", [])
    networks = episode.get("network_effects", [])
    cwd = document.get("meta", {}).get("cwd", "")
    coverage = document.get("meta", {}).get("coverage", {})
    agent_coverage = coverage.get("agent", {})

    exec_pids = {int(member.get("pid", 0)) for member in execs}
    exec_names = sorted({basename(member.get("filename", "")) for member in execs if member.get("filename")})
    transitive_names = sorted(
        {
            basename(member.get("filename", ""))
            for member in execs
            if member.get("filename") and member.get("role") not in ("direct_match", "wrapper")
        }
    )
    destinations = {
        (effect.get("dst_ip", ""), int(effect.get("dst_port", 0)))
        for effect in networks
        if effect.get("dst_ip")
    }
    workspace_files = sum(
        1
        for effect in files
        if under(effect.get("path", ""), cwd) or under(effect.get("path2", ""), cwd)
    )
    direct = episode.get("direct_match") or {}
    start = int(episode.get("action_start_ts", 0))
    end = int(episode.get("action_end_ts", start))

    return {
        "scenario": record["scenario"],
        "sample": int(record["sample"]),
        "run_id": record["run_id"],
        "runtime_command": sanitize(episode.get("command", record.get("runtime_command", "")), cwd),
        "classification": finding["classification"],
        "confidence": episode.get("confidence", finding.get("confidence", "")),
        "duration_seconds": round(max(0, end - start) / 1_000_000_000, 6),
        "exec_count": len(execs),
        "wrapper_count": int(episode.get("summary", {}).get("wrappers", 0)),
        "transitive_exec_count": int(episode.get("summary", {}).get("transitive_execs", 0)),
        "process_member_count": len(processes),
        "max_process_depth": max_process_depth(processes),
        "exec_replacement_count": sum(1 for member in execs if member.get("role") == "exec_replacement"),
        "fork_only_process_count": sum(1 for member in processes if int(member.get("tid", 0)) not in exec_pids),
        "file_effect_count": len(files),
        "file_create_count": sum(1 for effect in files if effect.get("op") in ("create", "create_or_open")),
        "file_modify_count": sum(1 for effect in files if effect.get("op") == "modify"),
        "file_rename_count": sum(1 for effect in files if effect.get("op") == "rename"),
        "file_delete_count": sum(1 for effect in files if effect.get("op") == "delete"),
        "network_effect_count": len(networks),
        "unique_destination_count": len(destinations),
        "ancestry_complete": bool(episode.get("ancestry_complete")),
        "agent_capture": agent_coverage.get("capture", "unknown"),
        "agent_interpretation": agent_coverage.get("interpretation", "unknown"),
        "agent_lines_seen": int(agent_coverage.get("lines_seen", 0)),
        "agent_lines_persisted": int(agent_coverage.get("lines_persisted", 0)),
        "process_capture": episode.get("process_capture", "unknown"),
        "file_capture": episode.get("file_capture", "unknown"),
        "network_capture": episode.get("network_capture", "unknown"),
        "unique_exec_basenames": exec_names,
        "direct_match_executable": basename(direct.get("filename", "")),
        "transitive_exec_basenames": transitive_names,
        "workspace_file_effect_count": workspace_files,
        "non_workspace_file_effect_count": len(files) - workspace_files,
        "localhost_network_count": sum(1 for effect in networks if is_loopback(effect.get("dst_ip", ""))),
        "non_local_network_count": sum(1 for effect in networks if effect.get("dst_ip") and not is_loopback(effect.get("dst_ip", ""))),
    }


def distribution(values: list[float | int]) -> dict[str, Any]:
    distinct = sorted(set(values))
    return {
        "min": min(values),
        "median": statistics.median(values),
        "max": max(values),
        "distinct": distinct,
    }


def summarize(features: list[dict[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for scenario in sorted({row["scenario"] for row in features}):
        rows = [row for row in features if row["scenario"] == scenario]
        result[scenario] = {
            "n": len(rows),
            "numeric": {name: distribution([row[name] for row in rows]) for name in NUMERIC_FEATURES},
            "ancestry_complete": sum(1 for row in rows if row["ancestry_complete"]),
            "confidence": sorted({row["confidence"] for row in rows}),
            "agent_capture": sorted({row["agent_capture"] for row in rows}),
            "agent_interpretation": sorted({row["agent_interpretation"] for row in rows}),
            "process_capture": sorted({row["process_capture"] for row in rows}),
            "file_capture": sorted({row["file_capture"] for row in rows}),
            "network_capture": sorted({row["network_capture"] for row in rows}),
            "exec_basename_sets": sorted({tuple(row["unique_exec_basenames"]) for row in rows}),
        }
    return result


def main() -> None:
    args = parse_args()
    records = read_jsonl(args.manifests)
    features = [extract(record, residual(args.logira, args.logira_home, record["run_id"])) for record in records]
    features.sort(key=lambda row: (row["scenario"], row["sample"], row["run_id"]))

    with open(args.features, "w", encoding="utf-8") as target:
        for row in features:
            target.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
    if args.csv:
        with open(args.csv, "w", encoding="utf-8", newline="") as target:
            writer = csv.DictWriter(target, fieldnames=list(features[0]))
            writer.writeheader()
            for row in features:
                writer.writerow({key: ";".join(value) if isinstance(value, list) else value for key, value in row.items()})
    with open(args.summary, "w", encoding="utf-8") as target:
        json.dump(summarize(features), target, indent=2, sort_keys=True)
        target.write("\n")


if __name__ == "__main__":
    main()
