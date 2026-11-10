"""CLI entry point for the safe prompt-injection red-team harness."""

from __future__ import annotations

import argparse

from agent import OllamaToolAgent, OllamaToolCallChecker, ScriptedVulnerableAgent
from harness import render_report, run_suite


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate simulated prompt-injection defenses.")
    parser.add_argument("--model", default="llama3.2", help="Ollama model used for the test agent.")
    parser.add_argument("--ollama-url", default="http://localhost:11434", help="Ollama API base URL.")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run the deterministic offline test agent; no Ollama service is needed.",
    )
    parser.add_argument("--trials", type=int, default=3, help="Independent runs per attack and defense (default: 3).")
    parser.add_argument("--output", help="Optional path for the Markdown report.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.trials < 1:
        raise SystemExit("Trials must be at least 1.")
    agent = ScriptedVulnerableAgent() if args.dry_run else OllamaToolAgent(args.model, args.ollama_url)
    checker = None if args.dry_run else OllamaToolCallChecker(args.model, args.ollama_url)
    results = run_suite(agent, checker=checker, trials=args.trials)
    report = render_report(results)
    print(report)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as report_file:
            report_file.write(report + "\n")


if __name__ == "__main__":
    main()
