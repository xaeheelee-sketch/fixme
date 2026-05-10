"""Print the LangGraph structure of the LLM fixer.

Outputs Mermaid source. Construction is mocked so this runs without the LLM gateway.

Usage:
  python scripts/draw_graph.py
  python scripts/draw_graph.py --out graph.mmd
"""
from __future__ import annotations
import argparse
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=None)
    args = parser.parse_args()

    fake_module = MagicMock()
    fake_module.ChatOpenAI = MagicMock(return_value=MagicMock())
    sys.modules["langchain_openai"] = fake_module

    from fixme.budget import TokenBudget
    from fixme.config import (
        Config, ScopeConfig, ModelsConfig, LimitsConfig, RunnersConfig, PathsConfig,
    )
    from fixme.llm_fixer import LlmFixer
    from fixme.tracer import JsonlTracer

    config = Config(
        run_id="draw",
        api_base="http://localhost",
        api_key_env="UNUSED",
        scope=ScopeConfig(enabled_cwes=[], min_severity="Low"),
        models=ModelsConfig(triage="m", fixer="m", analyzer="m"),
        limits=LimitsConfig(),
        runners=RunnersConfig(build_cmd="", test_cmd="", metis_cmd=""),
        paths=PathsConfig(),
    )
    with tempfile.TemporaryDirectory() as td:
        tracer = JsonlTracer(Path(td) / "trace.jsonl")
        budget = TokenBudget(1000)
        fixer = LlmFixer(config, budget, tracer, MagicMock(), MagicMock(), Path(td))

    mermaid = fixer.graph.get_graph().draw_mermaid()
    if args.out:
        Path(args.out).write_text(mermaid, encoding="utf-8")
        print(f"Wrote {args.out}")
    else:
        print(mermaid)
    return 0


if __name__ == "__main__":
    sys.exit(main())
