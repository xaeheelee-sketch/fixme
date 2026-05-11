"""LLM 게이트웨이 연결성 점검.

사내 폐쇄망에서 가장 먼저 돌려보는 단계. 게이트웨이가 닿는지, 모델이 응답하는지,
구조화 출력(tool calling)이 동작하는지를 한 호출로 검증한다.

Usage:
    set INTERNAL_LLM_API_KEY=...
    python scripts/check_llm.py --config config.yaml
    python scripts/check_llm.py --config config.yaml --model triage      # 특정 모델만
    python scripts/check_llm.py --config config.yaml --no-structured    # 단순 chat만
"""
from __future__ import annotations
import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from langchain_openai import ChatOpenAI
from pydantic import BaseModel

from fixme.config import load_config


class PingResult(BaseModel):
    ok: bool
    message: str


def _check(config, model_name: str, structured: bool) -> int:
    print(f"  Endpoint: {config.api_base}")
    print(f"  Model:    {model_name}")
    print(f"  Key var:  {config.api_key_env} ({'set' if config.api_key else 'EMPTY'})")
    if not config.api_key:
        print(f"  ERROR: env var {config.api_key_env} is empty", file=sys.stderr)
        return 1

    llm = ChatOpenAI(
        model=model_name,
        base_url=config.api_base,
        api_key=config.api_key,
        temperature=0.0,
        max_tokens=32,
        timeout=15,
    )
    if structured:
        llm = llm.with_structured_output(PingResult)

    t0 = time.time()
    try:
        if structured:
            resp = llm.invoke([
                {"role": "system", "content": "Respond with ok=true and message='pong'."},
                {"role": "user", "content": "ping"},
            ])
            elapsed = (time.time() - t0) * 1000
            print(f"  OK ({elapsed:.0f} ms) — structured: ok={resp.ok}, message={resp.message!r}")
        else:
            resp = llm.invoke([{"role": "user", "content": "Reply with one word: pong"}])
            elapsed = (time.time() - t0) * 1000
            content = getattr(resp, "content", str(resp))
            print(f"  OK ({elapsed:.0f} ms) — content: {content!r}")
        return 0
    except Exception as exc:
        elapsed = (time.time() - t0) * 1000
        print(f"  FAIL ({elapsed:.0f} ms): {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument(
        "--model", choices=["triage", "fixer", "analyzer", "all"], default="all",
        help="Which configured model to ping. Default: all three.",
    )
    parser.add_argument(
        "--no-structured", action="store_true",
        help="Skip with_structured_output check (use only when tool calling is unsupported).",
    )
    args = parser.parse_args()

    config = load_config(args.config)
    structured = not args.no_structured

    targets = (
        [args.model] if args.model != "all"
        else ["triage", "fixer", "analyzer"]
    )
    rc = 0
    for t in targets:
        model_name = getattr(config.models, t)
        print(f"\n[{t}]")
        rc |= _check(config, model_name, structured)
    return rc


if __name__ == "__main__":
    sys.exit(main())
