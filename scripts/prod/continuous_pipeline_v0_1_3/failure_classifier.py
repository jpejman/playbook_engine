"""
Failure classifier
Version: v0.1.3
Timestamp (UTC): 2026-04-15
"""

from typing import Optional
from .config import ContinuousPipelineWorkerConfig


class FailureClassifier:
    def classify(self, error_message: str, pipeline_status: Optional[str] = None, qa_result: Optional[str] = None) -> tuple[str, bool]:
        msg = (error_message or "").lower()
        pipeline_status = pipeline_status or ""

        if pipeline_status == "partial" and qa_result is None:
            return "QA_VALIDATION_FAIL", False

        if "already in production" in msg:
            return "ALREADY_IN_PRODUCTION", False

        if "ollama" in msg or "llm" in msg:
            return "LLM_ERROR", True

        if "opensearch" in msg or "retrieval" in msg:
            return "RETRIEVAL_ERROR", True

        if "database" in msg or "storage" in msg:
            return "STORAGE_FAIL", False

        if "timeout" in msg or "connection" in msg:
            return "INFRA_ERROR", True

        return "UNKNOWN_ERROR", True