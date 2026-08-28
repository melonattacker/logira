#!/usr/bin/env python3
"""Export normalized Effect Facts from existing MATCHED ExecutionEpisodes."""

from __future__ import annotations

import argparse
from collections import Counter
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any, Iterable

from effect_research_common import read_jsonl


MUTATION_OPERATIONS = {"create", "modify", "rename", "delete"}
RANDOM_NAME = re.compile(
    r"(?:^[0-9a-f]{12,}$|[0-9a-f]{20,}|[0-9]{6,}|"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
    re.IGNORECASE,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifests", nargs="+")
    parser.add_argument("--logira", default="./logira")
    parser.add_argument("--logira-home", default=os.environ.get("LOGIRA_HOME", ""))
    parser.add_argument("--output", required=True)
    return parser.parse_args()


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
    value = json.loads(completed.stdout)
    if not isinstance(value, dict):
        raise ValueError(f"{run_id}: residual output is not a JSON object")
    return value


def under(path: str, root: str) -> bool:
    if not path or not root or not os.path.isabs(path) or not os.path.isabs(root):
        return False
    try:
        return os.path.commonpath((os.path.normpath(path), os.path.normpath(root))) == os.path.normpath(root)
    except ValueError:
        return False


def executable_scope(path: str, workspace: str, home: str) -> str:
    if not path or not os.path.isabs(path):
        return "unknown"
    normalized = os.path.normpath(path)
    if "/.cache/go-build/" in normalized:
        return "toolchain"
    if under(normalized, workspace):
        return "workspace"
    if any(under(normalized, root) for root in ("/tmp", "/var/tmp", "/dev/shm")):
        return "tmp"
    if any(marker in normalized for marker in ("/.cache/go-build/", "/go/pkg/mod/", "/pkg/tool/")) or under(
        normalized, "/usr/local/go"
    ):
        return "toolchain"
    if under(normalized, home):
        return "home"
    if any(under(normalized, root) for root in ("/bin", "/sbin", "/usr", "/lib", "/lib64", "/opt")):
        return "system"
    return "unknown"


def file_scope(path: str, workspace: str, home: str) -> str:
    if not path or not os.path.isabs(path):
        return "unknown"
    normalized = os.path.normpath(path)
    if "/.cache/go-build/" in normalized:
        return "tmp"
    if under(normalized, workspace):
        relative = os.path.relpath(normalized, workspace)
        if ".git" in Path(relative).parts:
            return "workspace_git"
        return "workspace"
    if any(under(normalized, root) for root in ("/tmp", "/var/tmp", "/dev/shm")):
        return "tmp"
    if under(normalized, home):
        return "home"
    if any(
        under(normalized, root)
        for root in ("/bin", "/sbin", "/usr", "/lib", "/lib64", "/etc", "/var", "/dev", "/proc", "/sys", "/run", "/opt")
    ):
        return "system"
    return "unknown"


def network_scope(address: str) -> str:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return "unknown"
    if parsed.is_loopback:
        return "localhost"
    if parsed.is_private or parsed.is_link_local:
        return "private"
    if parsed.is_global:
        return "external"
    return "unknown"


def basename(path: str) -> str:
    value = os.path.basename(path.rstrip("/"))
    return normalize_basename(value)


def normalize_basename(value: str) -> str:
    if not value:
        return ""
    stem, extension = os.path.splitext(value)
    if (
        len(value) > 80
        or RANDOM_NAME.search(value)
        or re.fullmatch(
            r"(?:b[0-9]{3,}|[0-9]{3,}|tmp_obj_[0-9A-Za-z]{6,}|(?:go-build|tmp)[-_]?[0-9A-Za-z]+)",
            stem,
        )
    ):
        return "<generated>" + extension.lower()[:16]
    return value


def extension(path: str) -> str:
    suffix = os.path.splitext(os.path.basename(path.rstrip("/")))[1].lower()
    if 1 < len(suffix) <= 16 and re.fullmatch(r"\.[a-z0-9_+-]+", suffix):
        return suffix
    return ""


def sanitize_command(command: str, workspace: str, home: str) -> str:
    value = command
    for raw, replacement in ((workspace, "<workspace>"), (home, "<home>")):
        if raw:
            value = value.replace(raw, replacement)
    value = re.sub(r"/(?:home|Users)/[^/\s\"'`]+", "<home>", value)
    value = re.sub(r"/(?:tmp|var/tmp|dev/shm)/[^\s\"'`]+", "<tmp>", value)
    return value


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
        result = 1 + depth(parent, visiting | {identity}) if parent in identities else 0
        memo[identity] = result
        return result

    return max((depth(identity, set()) for identity in identities), default=0)


def operation(raw: str) -> str:
    return {
        "open": "read",
        "create": "create",
        "create_or_open": "create",
        "modify": "modify",
        "rename": "rename",
        "delete": "delete",
        "chdir": "chdir",
    }.get(raw, "unknown")


def actor_for(effect: dict[str, Any], exec_by_seq: dict[int, dict[str, str]]) -> dict[str, str]:
    exec_seq = int(effect.get("process_exec_seq", 0))
    if exec_seq in exec_by_seq:
        return exec_by_seq[exec_seq]
    if effect.get("attribution") == "task_instance_no_exec":
        return {"actor": "", "actor_role": "pre_exec"}
    return {"actor": "", "actor_role": "unknown"}


def add_fact(counter: Counter[str], facts: dict[str, dict[str, Any]], fact: dict[str, Any]) -> None:
    key = json.dumps(fact, sort_keys=True, separators=(",", ":"))
    counter[key] += 1
    facts[key] = fact


def normalize_effects(episode: dict[str, Any], workspace: str, home: str) -> list[dict[str, Any]]:
    counts: Counter[str] = Counter()
    facts: dict[str, dict[str, Any]] = {}
    exec_by_seq: dict[int, dict[str, str]] = {}

    for member in episode.get("exec_members") or []:
        actor = {
            "actor": basename(str(member.get("filename", ""))),
            "actor_role": str(member.get("role", "unknown")),
        }
        exec_by_seq[int(member.get("seq", 0))] = actor
        fact = {
            "kind": "exec",
            "target": actor["actor"],
            "location_scope": executable_scope(str(member.get("filename", "")), workspace, home),
            "role": actor["actor_role"],
        }
        add_fact(counts, facts, fact)

    for effect in episode.get("file_effects") or []:
        raw_op = str(effect.get("op", ""))
        normalized_op = operation(raw_op)
        path = str(effect.get("path", ""))
        fact: dict[str, Any] = {
            "kind": f"file_{normalized_op}",
            "scope": file_scope(path, workspace, home),
            "observed_op": raw_op or "unknown",
            **actor_for(effect, exec_by_seq),
        }
        suffix = extension(path)
        if suffix:
            fact["extension"] = suffix
        # Workspace and system names can preserve distinctions such as a marker
        # file or .git lock. Home/tmp names are both privacy-sensitive and
        # dominated by run-local build artifacts, so extension/scope is enough.
        if normalized_op in MUTATION_OPERATIONS and fact["scope"] in {"workspace", "workspace_git", "system"}:
            fact["target_basename"] = basename(path)
        if normalized_op == "rename":
            path2 = str(effect.get("path2", ""))
            fact["destination_scope"] = file_scope(path2, workspace, home)
            if fact["destination_scope"] in {"workspace", "workspace_git", "system"}:
                fact["destination_basename"] = basename(path2)
        add_fact(counts, facts, fact)

    for effect in episode.get("network_effects") or []:
        address = str(effect.get("dst_ip", ""))
        fact = {
            "kind": f"network_{effect.get('op') or 'activity'}",
            "destination_scope": network_scope(address),
            "port": int(effect.get("dst_port", 0)),
            "proto": str(effect.get("proto", "unknown")),
            **actor_for(effect, exec_by_seq),
        }
        add_fact(counts, facts, fact)

    result = []
    for key in sorted(facts):
        result.append({**facts[key], "count": counts[key]})
    return result


def normalize_episode(
    record: dict[str, Any], document: dict[str, Any], episode: dict[str, Any], episode_index: int
) -> dict[str, Any]:
    meta = document.get("meta", {})
    workspace = str(meta.get("cwd", ""))
    home = str(Path.home())
    execs = episode.get("exec_members") or []
    processes = episode.get("process_members") or []
    direct = episode.get("direct_match") or {}
    summary = episode.get("summary") or {}
    role_counts = Counter(str(member.get("role", "unknown")) for member in execs)
    exec_pids = {int(member.get("pid", 0)) for member in execs}
    effects = normalize_effects(episode, workspace, home)
    return {
        "schema_version": 1,
        "scenario": str(record.get("scenario", "unknown")),
        "sample": int(record.get("sample", 0)),
        "run_id": str(record.get("run_id", "")),
        "episode_index": episode_index,
        "action": {
            "command": sanitize_command(str(episode.get("command", record.get("runtime_command", ""))), workspace, home),
            "direct_exec": basename(str(direct.get("filename", ""))),
            "direct_exec_scope": executable_scope(str(direct.get("filename", "")), workspace, home),
            "confidence": str(episode.get("confidence", "")),
        },
        "episode_context": {
            "exec_count": len(execs),
            "transitive_exec_count": int(summary.get("transitive_execs", 0)),
            "process_member_count": len(processes),
            "max_process_depth": max_process_depth(processes),
            "exec_replacement_count": role_counts.get("exec_replacement", 0),
            "fork_only_process_count": sum(1 for member in processes if int(member.get("tid", 0)) not in exec_pids),
            "exec_roles": sorted(role_counts),
            "ancestry_complete": bool(episode.get("ancestry_complete")),
        },
        "coverage": {
            "process": str(episode.get("process_capture", "unknown")),
            "file": str(episode.get("file_capture", "unknown")),
            "network": str(episode.get("network_capture", "unknown")),
        },
        "source_observation_counts": {
            "exec": len(execs),
            "file": len(episode.get("file_effects") or []),
            "network": len(episode.get("network_effects") or []),
        },
        "effects": effects,
    }


def extract(record: dict[str, Any], document: dict[str, Any]) -> list[dict[str, Any]]:
    report = document.get("report", {})
    matched_items = {
        str(finding.get("item_id", ""))
        for finding in report.get("findings", [])
        if finding.get("classification") == "MATCHED"
    }
    result = []
    for index, episode in enumerate(report.get("episodes", []), 1):
        if str(episode.get("item_id", "")) not in matched_items:
            continue
        result.append(normalize_episode(record, document, episode, index))
    if not result:
        raise RuntimeError(f"{record.get('run_id')}: no MATCHED ExecutionEpisode found")
    return result


def main() -> None:
    args = parse_args()
    records = read_jsonl(args.manifests)
    output: list[dict[str, Any]] = []
    for record in records:
        output.extend(extract(record, residual(args.logira, args.logira_home, str(record["run_id"]))))
    output.sort(key=lambda row: (row["scenario"], row["sample"], row["run_id"], row["episode_index"]))
    with open(args.output, "w", encoding="utf-8") as target:
        for row in output:
            target.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()
