"""
LLM client for continuous_pipeline_v0_3_0
Version: v0.3.0
Purpose:
- Call Ollama-compatible /api/generate endpoint
- Support explicit model override per evaluation run
- Preserve v0.2.1-compatible config fallback behavior
- Handle both streaming and non-streaming response formats safely
"""

from __future__ import annotations

import json
import logging
import urllib.request
import urllib.error
from typing import Any, Dict, Optional

from .config import ContinuousPipelineConfig

logger = logging.getLogger(__name__)


class LLMClient:
    def __init__(self):
        self.base_url = ContinuousPipelineConfig.LLM_BASE_URL.rstrip("/")
        self.generate_path = ContinuousPipelineConfig.LLM_GENERATE_PATH
        self.default_model = ContinuousPipelineConfig.LLM_MODEL
        self.default_timeout_seconds = ContinuousPipelineConfig.LLM_TIMEOUT_SECONDS
        self.url = f"{self.base_url}{self.generate_path}"

    def generate(
        self,
        prompt: str,
        model: Optional[str] = None,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Generate text from the configured LLM endpoint.

        Model resolution:
        1. explicit `model` argument
        2. ContinuousPipelineConfig.LLM_MODEL

        Returns:
            {
                "response": "<final text>",
                "model": "<resolved model>",
                "done": True/False,
                "raw": <raw parsed payload or list of chunks>
            }
        """
        resolved_model = model or self.default_model
        resolved_timeout = timeout_seconds or self.default_timeout_seconds

        if not prompt or not prompt.strip():
            raise RuntimeError("LLM generate called with empty prompt")

        payload = {
            "model": resolved_model,
            "prompt": prompt,
            "stream": False,
        }

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        logger.info(
            "LLM generate request: model=%s timeout=%ss prompt_len=%s",
            resolved_model,
            resolved_timeout,
            len(prompt),
        )

        try:
            with urllib.request.urlopen(req, timeout=resolved_timeout) as resp:
                raw_bytes = resp.read()
                raw_text = raw_bytes.decode("utf-8", errors="replace").strip()

        except urllib.error.HTTPError as exc:
            error_body = ""
            try:
                error_body = exc.read().decode("utf-8", errors="replace")
            except Exception:
                pass
            raise RuntimeError(
                f"LLM request failed: HTTP {exc.code} {exc.reason}. Body: {error_body}"
            ) from exc

        except urllib.error.URLError as exc:
            raise RuntimeError(f"LLM request failed: {exc.reason}") from exc

        except TimeoutError as exc:
            raise RuntimeError(f"LLM request failed: timed out") from exc

        except Exception as exc:
            raise RuntimeError(f"LLM request failed: {exc}") from exc

        if not raw_text:
            raise RuntimeError("LLM returned empty response body")

        logger.debug("LLM raw response preview: %s", raw_text[:1000])

        parsed = self._parse_ollama_response(raw_text, resolved_model)

        response_text = parsed.get("response", "")
        if not response_text or not str(response_text).strip():
            raise RuntimeError(
                f"LLM returned no usable response text. Parsed payload: {json.dumps(parsed, ensure_ascii=False)[:2000]}"
            )

        logger.info(
            "LLM generate success: model=%s response_len=%s",
            parsed.get("model", resolved_model),
            len(response_text),
        )

        return parsed

    def _parse_ollama_response(self, raw_text: str, resolved_model: str) -> Dict[str, Any]:
        """
        Handle:
        1. Standard single JSON object
        2. NDJSON / line-delimited streaming-style chunks
        """
        # First try standard single JSON object
        try:
            obj = json.loads(raw_text)
            return self._normalize_payload(obj, resolved_model)
        except json.JSONDecodeError:
            pass

        # Fallback: line-delimited JSON chunks
        lines = [line.strip() for line in raw_text.splitlines() if line.strip()]
        if not lines:
            raise RuntimeError("LLM response parse failed: empty non-JSON response")

        chunks = []
        combined_response_parts = []
        last_model = resolved_model
        done_flag = False

        for idx, line in enumerate(lines, start=1):
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    f"LLM response parse failed on line {idx}: {exc}. Raw line: {line[:500]}"
                ) from exc

            chunks.append(obj)

            if "model" in obj and obj["model"]:
                last_model = obj["model"]

            if "response" in obj and obj["response"] is not None:
                combined_response_parts.append(str(obj["response"]))

            if obj.get("done") is True:
                done_flag = True

        combined_response = "".join(combined_response_parts).strip()

        normalized = {
            "response": combined_response,
            "model": last_model,
            "done": done_flag,
            "raw": chunks,
        }

        if not combined_response:
            raise RuntimeError(
                f"LLM response parse failed: parsed streaming chunks but no response text found. Raw lines preview: {raw_text[:2000]}"
            )

        return normalized

    def _normalize_payload(self, obj: Dict[str, Any], resolved_model: str) -> Dict[str, Any]:
        """
        Normalize Ollama /api/generate response object into a stable shape.
        """
        if not isinstance(obj, dict):
            raise RuntimeError(f"LLM returned non-object JSON: {type(obj).__name__}")

        response_text = obj.get("response", "")
        model = obj.get("model") or resolved_model
        done = bool(obj.get("done", True))

        normalized = {
            "response": response_text,
            "model": model,
            "done": done,
            "raw": obj,
        }

        return normalized