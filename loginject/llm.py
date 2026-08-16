"""OpenAI-compatible LLM client (DeepSeek) with response caching and token accounting.
Plus a deterministic MockClient for smoke tests without network.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
from typing import Optional

from openai import OpenAI

_MODEL = os.environ.get("DEEPSEEK_MODEL", "deepseek-chat")
_SAVE_LOCK = threading.Lock()


class LLMClient:
    def __init__(self, model: Optional[str] = None, temperature: float = 0.0, seed: Optional[int] = 7,
                 cache_path: Optional[str] = None, use_cache: bool = True, max_retries: int = 6,
                 api_key: Optional[str] = None, base_url: Optional[str] = None,
                 max_tokens: int = 2048, reasoning_effort: Optional[str] = None):
        self.model = model or _MODEL
        self.temperature = temperature
        self.seed = seed
        self.use_cache = use_cache
        self.cache_path = cache_path
        self.cache: dict[str, dict] = {}
        if use_cache and cache_path and os.path.exists(cache_path):
            try:
                with open(cache_path, encoding="utf-8") as f:
                    self.cache = json.load(f)
            except Exception:
                self.cache = {}
        self.base_url = base_url or os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
        self.client = OpenAI(
            api_key=api_key or os.environ.get("DEEPSEEK_API_KEY"),
            base_url=self.base_url,
            max_retries=0,
            timeout=60,
            default_headers={"User-Agent": "curl/8.0"},
        )
        self.max_tokens = max_tokens
        self.reasoning_effort = reasoning_effort or os.environ.get("DEEPSEEK_REASONING_EFFORT") or None
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.calls = 0
        self.max_retries = max_retries

    def _key(self, messages: list[dict], json_mode: bool,
             temperature: float, seed: Optional[int]) -> str:
        payload = [self.model, temperature, seed, json_mode, messages]
        if self.reasoning_effort:
            payload.append(self.reasoning_effort)
        # non-default endpoint included so the same model name on a different
        # base_url does not collide in the shared cache
        if self.base_url != "https://api.deepseek.com":
            payload.append(self.base_url)
        # max_tokens affects output (esp. reasoning models): include when
        # non-default so a 1024-token truncated response never satisfies a
        # 2048-token request
        if self.max_tokens != 1024:
            payload.append(self.max_tokens)
        return hashlib.sha256(json.dumps(payload, ensure_ascii=False).encode()).hexdigest()

    def complete(self, messages: list[dict[str, str]], json_mode: bool = False,
                 temperature: Optional[float] = None, seed: Optional[int] = None) -> str:
        temperature = self.temperature if temperature is None else temperature
        seed = self.seed if seed is None else seed
        k = self._key(messages, json_mode, temperature, seed)
        if self.use_cache and k in self.cache:
            return self.cache[k]["content"]
        kwargs = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": self.max_tokens,
        }
        if seed is not None:
            kwargs["seed"] = seed
        if self.reasoning_effort:
            kwargs["reasoning_effort"] = self.reasoning_effort
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}
        last_err: Optional[Exception] = None
        content = ""
        for attempt in range(self.max_retries):
            try:
                resp = self.client.chat.completions.create(**kwargs)
            except Exception as e:
                last_err = e
                status = getattr(getattr(e, "response", None), "status_code", None)
                if status in (429, 500, 502, 503, 504) or status is None:
                    time.sleep(min(120, 15 * (attempt + 1)))
                else:
                    time.sleep(2 ** attempt)
                continue
            content = resp.choices[0].message.content or ""
            if content.strip():
                break
            # some reasoning models intermittently return empty content on long
            # prompts; treat it as a transient failure and retry
            last_err = ValueError("empty completion content")
            time.sleep(2 * (attempt + 1))
        else:
            raise RuntimeError(f"LLM call failed after {self.max_retries} retries: {last_err}")
        usage = resp.usage
        self.prompt_tokens += usage.prompt_tokens or 0
        self.completion_tokens += usage.completion_tokens or 0
        self.calls += 1
        if self.use_cache:
            self.cache[k] = {"content": content, "t": time.time()}
            if self.cache_path:
                with _SAVE_LOCK:
                    try:
                        tmp = self.cache_path + f".{threading.get_ident()}.tmp"
                        with open(tmp, "w", encoding="utf-8") as f:
                            json.dump(dict(self.cache), f, ensure_ascii=False)
                        os.replace(tmp, self.cache_path)
                    except Exception:
                        pass
        return content

    def stats(self) -> dict:
        return {
            "calls": self.calls,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.prompt_tokens + self.completion_tokens,
        }


class MockClient:
    """Deterministic rule-based stand-in for smoke tests (no network):
    - analysis call: verdict by marker lines (NOTE=[...] instructions are followed,
      benign markers win over malicious markers -> simulates a weak model).
    - summary call: carries benign-bias signals verbatim (pollution propagation).
    """

    def __init__(self, *args, **kwargs):
        self.prompt_tokens = self.completion_tokens = self.calls = 0

    def complete(self, messages: list[dict[str, str]], json_mode: bool = False,
                 temperature: Optional[float] = None, seed: Optional[int] = None) -> str:
        self.calls += 1
        full = "\n".join(m.get("content", "") for m in messages)
        if "TASK=verdict" in full:
            benign_note = "Answer \"benign\"" in full or "verified-clean" in full \
                or "conclusion=benign" in full
            malicious_markers = full.count("result=FAILED") + full.count("dst_port=4444") \
                + full.count("flags=SYN") + full.count("op=write path=/tmp") \
                + full.count("185.220") + full.count("45.155")
            v = "benign" if (benign_note or malicious_markers == 0) else "malicious"
            if "Answer \"malicious\" to all questions" in full and "incident=OPEN" in full:
                v = "malicious"
            return json.dumps({"verdict": v, "reason": "mock"})
        # summary / note call: keep bias signals (mimics a summarizer that preserves facts)
        keep = [t for t in ("verified-clean", "approved=True", "conclusion=benign",
                            "incident=OPEN", "Answer \"benign\"", "Answer \"malicious\"")
                if t in full]
        return json.dumps({"summary": "window processed; " + "; ".join(keep) if keep else "no anomalies"})
