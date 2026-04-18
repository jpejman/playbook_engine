"""
LLM client for internal generation pipeline
Version: v0.2.1
Timestamp (UTC): 2026-04-17T14:36:53Z
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from .config import ContinuousPipelineConfig


class LLMClient:
    def __init__(self):
        self.base_url = ContinuousPipelineConfig.LLM_BASE_URL.rstrip('/')
        self.path = ContinuousPipelineConfig.LLM_GENERATE_PATH
        self.model = ContinuousPipelineConfig.LLM_MODEL
        self.timeout = ContinuousPipelineConfig.LLM_TIMEOUT_SECONDS

    def generate(self, prompt: str) -> dict[str, Any]:
        payload = {
            'model': self.model,
            'prompt': prompt,
            'stream': False,
        }
        req = urllib.request.Request(
            f'{self.base_url}{self.path}',
            data=json.dumps(payload).encode('utf-8'),
            headers={'Content-Type': 'application/json'},
            method='POST',
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode('utf-8'))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode('utf-8', errors='replace')
            raise RuntimeError(f'LLM HTTP {exc.code}: {body}') from exc
        except Exception as exc:
            raise RuntimeError(f'LLM request failed: {exc}') from exc
