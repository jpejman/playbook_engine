"""
Failure classifier
Version: v0.1.4-statusfix
Timestamp (UTC): 2026-04-15
"""

from typing import Any, Optional


class FailureClassifier:
    def classify(
        self,
        error_message: str,
        pipeline_status: Optional[str] = None,
        qa_result: Optional[str] = None,
        qa_feedback: Optional[Any] = None,
        generation_status: Optional[str] = None,
    ) -> tuple[str, bool]:
        msg = (error_message or "").lower()
        pipeline_status = pipeline_status or ""
        qa_result = qa_result or ""
        generation_status = generation_status or ""

        feedback_text = ""
        if isinstance(qa_feedback, dict):
            errors = qa_feedback.get("errors", [])
            if isinstance(errors, list):
                feedback_text = " | ".join(str(e) for e in errors).lower()
            else:
                feedback_text = str(errors).lower()
        elif qa_feedback is not None:
            feedback_text = str(qa_feedback).lower()

        combined = f"{msg} | {feedback_text}"

        if "already in production" in combined:
            return "ALREADY_IN_PRODUCTION", False

        if "missing 'playbook' key" in combined or 'missing "playbook" key' in combined:
            return "QA_MISSING_PLAYBOOK_KEY", False

        if "json parse error" in combined or "parse error" in combined or "parse_failure" in combined:
            return "QA_PARSE_FAILURE", False

        if generation_status == "failed" or pipeline_status == "failed":
            if "ollama" in combined or "llm" in combined:
                return "LLM_ERROR", True
            if "opensearch" in combined or "retrieval" in combined:
                return "RETRIEVAL_ERROR", True
            if "database" in combined or "storage" in combined:
                return "STORAGE_FAIL", False
            if "timeout" in combined or "connection" in combined:
                return "INFRA_ERROR", True
            return "GENERATION_FAILED", False

        if pipeline_status == "partial":
            if qa_result in {"rejected", "needs_revision"}:
                return "QA_VALIDATION_FAIL", False
            return "QA_VALIDATION_FAIL", False

        if "ollama" in combined or "llm" in combined:
            return "LLM_ERROR", True

        if "opensearch" in combined or "retrieval" in combined:
            return "RETRIEVAL_ERROR", True

        if "database" in combined or "storage" in combined:
            return "STORAGE_FAIL", False

        if "timeout" in combined or "connection" in combined:
            return "INFRA_ERROR", True

        return "UNKNOWN_ERROR", True