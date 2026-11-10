import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent import OllamaToolAgent, OllamaToolCallChecker, ScriptedVulnerableAgent
from defenses import DefenseProfile
from harness import Result, render_report, run_suite, summary_rows


class FakeResponse:
    def __init__(self, model_text: str) -> None:
        self.model_text = model_text

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        return False

    def read(self) -> bytes:
        return json.dumps({"message": {"content": self.model_text}}).encode()


class HarnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.results = run_suite(ScriptedVulnerableAgent(), trials=1)

    def test_baseline_is_vulnerable(self) -> None:
        baseline = [result for result in self.results if result.defense == "baseline"]
        self.assertTrue(all(result.injection_succeeded for result in baseline))

    def test_layered_defense_blocks_sensitive_actions(self) -> None:
        layered = [result for result in self.results if result.defense == "layered_defense"]
        self.assertTrue(all(not result.injection_succeeded for result in layered))
        self.assertTrue(all(not result.sensitive_action_executed for result in layered))

    def test_report_has_comparison_table(self) -> None:
        report = render_report(self.results)
        self.assertIn("| Defense | Attack success rate |", report)
        self.assertEqual(summary_rows(self.results)[0][1], 100)

    def test_agent_rejects_json_array(self) -> None:
        with patch("agent.urlopen", return_value=FakeResponse("[]")):
            action = OllamaToolAgent("test").propose("Summarize", "text", DefenseProfile("baseline"))
        self.assertEqual(action.tool, "none")

    def test_checker_rejects_string_false_and_non_object(self) -> None:
        with patch("agent.urlopen", return_value=FakeResponse('{"allow":"false","reason":"x"}')):
            self.assertEqual(OllamaToolCallChecker("test").review("read_document", {}, "Summarize"), (False, "x"))
        with patch("agent.urlopen", return_value=FakeResponse("[]")):
            allowed, reason = OllamaToolCallChecker("test").review("read_document", {}, "Summarize")
        self.assertFalse(allowed)
        self.assertIn("not an object", reason)

    def test_report_escapes_model_derived_table_text(self) -> None:
        result = Result(
            trial=1,
            attack="attack",
            technique="test",
            defense="checker_agent",
            proposed_tool="export|secret",
            tool_executed=False,
            blocked_by="checker: one|two\nthree",
            injection_succeeded=False,
            sensitive_action_executed=False,
        )
        row = render_report([result]).split("## Per-attack results\n", 1)[1].splitlines()[2]
        self.assertEqual(row.count("|"), 9)


if __name__ == "__main__":
    unittest.main()
