"""Opt-in CLI for one live, synthetic Northstar research question."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

from .fga_http import ConfigurationError, FgaHttpAuthorizer
from .openai_adapter import OpenAIResponsesAdapter
from .research import ResearchAgent, ResearchError, TRUSTED_ACTOR_KEY, gateway_from_manifest


ROOT = Path(__file__).resolve().parents[1]


def _manifest() -> dict:
    value = os.environ.get("FGA_LIVE_MANIFEST")
    if not value:
        raise ValueError("FGA_LIVE_MANIFEST is required.")
    path = Path(value).resolve()
    if path.parent != (ROOT / ".fga-live").resolve() or not path.name.startswith("fixture-"):
        raise ValueError("FGA_LIVE_MANIFEST must be a generated file in .fga-live/.")
    if path.stat().st_size > 65_536:
        raise ValueError("FGA_LIVE_MANIFEST is too large.")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("FGA_LIVE_MANIFEST is invalid.")
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run one synthetic Northstar research question.")
    parser.add_argument("question", help="One quoted investment research question")
    args = parser.parse_args(argv)
    if os.environ.get("FGA_LIVE") != "1":
        parser.error("Set FGA_LIVE=1 to opt in to the live research smoke test.")
    if os.environ.get("FGA_ADMIN_API_KEY"):
        parser.error("Unset FGA_ADMIN_API_KEY; this command accepts only the check key.")
    model = os.environ.get("OPENAI_MODEL", "")
    if not model.strip():
        parser.error("Set OPENAI_MODEL to a Responses-compatible model.")

    try:
        gateway, aliases = gateway_from_manifest(_manifest(), FgaHttpAuthorizer.from_environment())
        agent = ResearchAgent(
            OpenAIResponsesAdapter(), gateway, aliases, actor_key=TRUSTED_ACTOR_KEY, model=model
        )
        result = agent.research(args.question)
    except (ConfigurationError, ResearchError, ValueError, OSError, ImportError):
        print("Research smoke failed; verify the disposable service and environment.", file=sys.stderr)
        return 1
    print(result.summary)
    if result.source:
        print(f"Source: {result.source} (synthetic)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
