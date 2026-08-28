#!/usr/bin/env python3
"""Focused tests for research-only Effect Facts tooling."""

from __future__ import annotations

import unittest

from effect_research_common import baseline_scenario, fact_signature
from evaluate_effect_labels import evaluate
from export_effect_facts import executable_scope, file_scope, network_scope, normalize_basename, sanitize_command
from run_semantic_judge import schema


class NormalizationTest(unittest.TestCase):
    def test_path_scopes_preserve_indirection(self) -> None:
        workspace = "/home/alice/project"
        home = "/home/alice"
        self.assertEqual(executable_scope("/home/alice/project/bin/git", workspace, home), "workspace")
        self.assertEqual(executable_scope("/usr/bin/git", workspace, home), "system")
        self.assertEqual(executable_scope("/tmp/tool/git", workspace, home), "tmp")
        self.assertEqual(executable_scope("/usr/local/go/pkg/tool/linux_amd64/compile", workspace, home), "toolchain")
        self.assertEqual(executable_scope("/home/alice/project/.cache/go-build/aa/test", workspace, home), "toolchain")

    def test_file_scopes_and_git_scope(self) -> None:
        workspace = "/home/alice/project"
        home = "/home/alice"
        self.assertEqual(file_scope("/home/alice/project/.git/HEAD", workspace, home), "workspace_git")
        self.assertEqual(file_scope("/home/alice/project/out.txt", workspace, home), "workspace")
        self.assertEqual(file_scope("/home/alice/project/.cache/go-build/aa/object", workspace, home), "tmp")
        self.assertEqual(file_scope("/home/alice/notes.txt", workspace, home), "home")
        self.assertEqual(file_scope("/etc/hosts", workspace, home), "system")

    def test_random_names_and_sensitive_paths_are_removed(self) -> None:
        self.assertEqual(normalize_basename("pack-998722b2093ed6652a04f25bc7078baacfd5fd19.idx"), "<generated>.idx")
        self.assertEqual(normalize_basename("b001"), "<generated>")
        self.assertEqual(normalize_basename("tmp_obj_1UrJkX"), "<generated>")
        command = "cat /home/alice/secret && touch /tmp/random-123/file"
        sanitized = sanitize_command(command, "/home/alice/project", "/home/alice")
        self.assertNotIn("alice", sanitized)
        self.assertNotIn("random-123", sanitized)

    def test_network_scopes(self) -> None:
        self.assertEqual(network_scope("127.0.0.1"), "localhost")
        self.assertEqual(network_scope("10.0.0.1"), "private")
        self.assertEqual(network_scope("1.1.1.1"), "external")
        self.assertEqual(network_scope(""), "unknown")

    def test_fact_signature_ignores_only_count(self) -> None:
        left = {"kind": "exec", "target": "git", "location_scope": "system", "count": 1}
        right = {"kind": "exec", "target": "git", "location_scope": "system", "count": 9}
        different = {"kind": "exec", "target": "git", "location_scope": "workspace", "count": 1}
        self.assertEqual(fact_signature(left), fact_signature(right))
        self.assertNotEqual(fact_signature(left), fact_signature(different))

    def test_comparison_pairing_is_explicit(self) -> None:
        self.assertEqual(baseline_scenario("path_hijack"), "git_status")
        self.assertEqual(baseline_scenario("go_test"), "go_test")

    def test_evaluation_metrics(self) -> None:
        gold = {
            "E1": "ACTION_ALIGNED",
            "E2": "ACTION_MISALIGNED",
            "E3": "UNCLEAR",
            "E4": "ACTION_ALIGNED",
        }
        predicted = {
            "E1": "ACTION_ALIGNED",
            "E2": "ACTION_ALIGNED",
            "E3": "UNCLEAR",
            "E4": "UNCLEAR",
        }
        result = evaluate(gold, predicted)
        metrics = result["primary_binary_metrics"]
        self.assertEqual(metrics["evaluated_count"], 2)
        self.assertEqual(metrics["confusion_matrix"]["ACTION_MISALIGNED"]["ACTION_ALIGNED"], 1)
        self.assertEqual(metrics["per_class"]["ACTION_ALIGNED"]["precision"], 0.5)
        self.assertEqual(metrics["per_class"]["ACTION_MISALIGNED"]["recall"], 0.0)
        self.assertEqual(metrics["macro_f1"], 0.333333)
        self.assertEqual(result["human"]["label_coverage"], 0.75)
        self.assertEqual(result["judge"]["abstention_rate"], 0.5)
        self.assertTrue(result["human_unclear_agreement"]["all_human_unclear_agreed"])

    def test_semantic_judge_schema_allows_abstention(self) -> None:
        result_schema = schema(30)
        labels = result_schema["properties"]["results"]["items"]["properties"]["label"]["enum"]
        self.assertEqual(labels, ["ACTION_ALIGNED", "ACTION_MISALIGNED", "UNCLEAR"])
        self.assertEqual(result_schema["properties"]["results"]["minItems"], 30)


if __name__ == "__main__":
    unittest.main()
