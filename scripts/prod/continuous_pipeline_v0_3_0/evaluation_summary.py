"""
Evaluation summary for continuous_pipeline_v0_3_0
Version: v0.3.0 (summary contract fix)

Purpose:
- Accept either:
  1. runner summary dict
  2. raw list of result dicts
- Print stable summary output
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Union

logger = logging.getLogger(__name__)


class EvaluationSummary:
    def generate_summary(
        self,
        results: Union[Dict[str, Any], List[Dict[str, Any]]],
        evaluation_batch_id: str,
        evaluation_label: str | None,
        models: List[str],
        cves: List[str],
    ) -> None:
        summary = self._normalize_results(results, models, cves, evaluation_batch_id, evaluation_label)

        logger.info("=" * 80)
        logger.info("EVALUATION SUMMARY")
        logger.info("=" * 80)
        logger.info("Evaluation Batch ID: %s", summary["evaluation_batch_id"])
        logger.info("Evaluation Label: %s", summary["evaluation_label"])
        logger.info("Total CVEs: %s", len(summary["cves"]))
        logger.info("Total Models: %s", len(summary["models"]))
        logger.info("Total Runs Attempted: %s", summary["total_attempted"])
        logger.info("Completed: %s", summary["completed"])
        logger.info("Failed: %s", summary["failed"])

        success_rate = 0.0
        if summary["total_attempted"] > 0:
            success_rate = (summary["completed"] / summary["total_attempted"]) * 100.0
        logger.info("Success Rate: %.1f%%", success_rate)

        logger.info("\nModel Statistics:")
        for model in summary["models"]:
            stats = summary["model_stats"].get(
                model,
                {"completed": 0, "failed": 0, "avg_duration": 0.0},
            )
            logger.info("  %s:", model)
            logger.info("    Completed: %s", stats.get("completed", 0))
            logger.info("    Failed: %s", stats.get("failed", 0))
            logger.info("    Avg Duration: %.2fs", float(stats.get("avg_duration", 0.0)))

        logger.info("\nDetailed Results:")
        for result in summary["results"]:
            cve_id = result.get("cve_id", "unknown")
            model = result.get("model", "unknown")
            status = result.get("status", "unknown").upper()
            duration = float(result.get("duration", 0.0) or 0.0)

            logger.info("  %s - %s: %s (%.2fs)", cve_id, model, status, duration)

            if status == "FAILED":
                logger.info("    Error: %s", result.get("error", "unknown"))

            validation_errors = result.get("validation_errors") or []
            if validation_errors:
                logger.info("    Validation Errors: %s", validation_errors)

        logger.info("=" * 80)

    def _normalize_results(
        self,
        results: Union[Dict[str, Any], List[Dict[str, Any]]],
        models: List[str],
        cves: List[str],
        evaluation_batch_id: str,
        evaluation_label: str | None,
    ) -> Dict[str, Any]:
        """
        Accept either:
        - raw list of per-run dicts
        - runner summary dict containing 'results'
        """
        if isinstance(results, dict):
            raw_results = results.get("results", [])
            normalized_models = results.get("models", models)
            normalized_cves = results.get("cves", cves)
            batch_id = results.get("evaluation_batch_id", evaluation_batch_id)
            label = results.get("evaluation_label", evaluation_label)
        elif isinstance(results, list):
            raw_results = results
            normalized_models = models
            normalized_cves = cves
            batch_id = evaluation_batch_id
            label = evaluation_label
        else:
            raise TypeError(f"Unsupported results type: {type(results).__name__}")

        if not isinstance(raw_results, list):
            raise TypeError(f"Expected results list, got: {type(raw_results).__name__}")

        for idx, item in enumerate(raw_results):
            if not isinstance(item, dict):
                raise TypeError(
                    f"Expected each result item to be dict, got {type(item).__name__} at index {idx}"
                )

        completed = sum(1 for r in raw_results if r.get("status") == "completed")
        failed = sum(1 for r in raw_results if r.get("status") == "failed")

        model_stats: Dict[str, Dict[str, Any]] = {}
        for model in normalized_models:
            model_results = [r for r in raw_results if r.get("model") == model]
            model_completed = sum(1 for r in model_results if r.get("status") == "completed")
            model_failed = sum(1 for r in model_results if r.get("status") == "failed")
            durations = [
                float(r.get("duration", 0.0) or 0.0)
                for r in model_results
            ]
            avg_duration = (sum(durations) / len(durations)) if durations else 0.0

            model_stats[model] = {
                "completed": model_completed,
                "failed": model_failed,
                "avg_duration": avg_duration,
            }

        return {
            "evaluation_batch_id": batch_id,
            "evaluation_label": label,
            "cves": normalized_cves,
            "models": normalized_models,
            "total_attempted": len(raw_results),
            "completed": completed,
            "failed": failed,
            "results": raw_results,
            "model_stats": model_stats,
        }