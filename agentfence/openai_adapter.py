"""Small, opt-in wrapper around the official OpenAI Responses client."""

from __future__ import annotations

import os
from typing import Any


class OpenAIResponsesAdapter:
    def __init__(self, *, api_key: str | None = None) -> None:
        key = api_key if api_key is not None else os.environ.get("OPENAI_API_KEY")
        if not key:
            raise ValueError("OPENAI_API_KEY is required.")
        from openai import OpenAI

        self._client = OpenAI(api_key=key, timeout=20.0, max_retries=0)

    def create(self, **kwargs: Any) -> Any:
        return self._client.responses.create(**kwargs)
