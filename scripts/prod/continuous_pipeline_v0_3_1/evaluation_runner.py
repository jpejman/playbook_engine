"""
Evaluation runner for continuous_pipeline_v0_3_0
Version: v0.3.0 (constructor + executor contract fixed)
Purpose:
- Run CVE x Model evaluations
- Match evaluate_models_v0_3_0.py constructor expectations
- Pass the correct payload argument into PipelineExecutor
- Support sequential and parallel execution
"""

from __future__ import annotations

import logging
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

from .pipeline_executor import PipelineExecutor
from .generation_payload_builder import GenerationPayloadBuilder
from .db_clients import PlaybookEngineClient
from .opensearch_client import OpenSearchClient

logger = logging.getLogger(__name__)


class EvaluationRunner:
    def __init__(
        self,
        evaluation_batch_id: str,
        evaluation_label: Optional[str] = None,
        execution_mode: str = "sequential",
        max_workers: Optional[int] = None,
        timeout: int = 300,
        fail_fast: bool = False,
    ):
        self.db = PlaybookEngineClient()
        self.os = OpenSearchClient()
        self.pipeline_executor = PipelineExecutor()
        self.payload_builder = GenerationPayloadBuilder(self.db, self.os)

        self.evaluation_batch_id = evaluation_batch_id
        self.evaluation_label = evaluation_label
        self.execution_mode = execution_mode
        self.max_workers = max_workers
        self.timeout = timeout
        self.fail_fast = fail_fast

        logger.info(
            "Initialized EvaluationRunner with batch_id: %s",
            self.evaluation_batch_id,
        )

    def run_evaluation(
        self,
        cves: List[str],
        models: List[str],
        force: bool = False,
    ) -> Dict[str, Any]:
        logger.info(
            "Starting evaluation for %s CVEs across %s models",
            len(cves),
            len(models),
        )
        logger.info("CVEs: %s", cves)
        logger.info("Models: %s", models)

        results: List[Dict[str, Any]] = []

        if self.execution_mode == "parallel":
            workers = self.max_workers or min(4, max(1, len(cves) * len(models)))
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = [
                    executor.submit(
                        self._run_single_evaluation,
                        cve_id,
                        model,
                        force,
                    )
                    for cve_id in cves
                    for model in models
                ]

                for future in as_completed(futures):
                    result = future.result()
                    results.append(result)
                    if self.fail_fast and result["status"] == "failed":
                        logger.warning("Fail-fast enabled; stopping after first failure")
                        break
        else:
            for cve_id in cves:
                for model in models:
                    result = self._run_single_evaluation(
                        cve_id,
                        model,
                        force,
                    )
                    results.append(result)
                    if self.fail_fast and result["status"] == "failed":
                        logger.warning("Fail-fast enabled; stopping after first failure")
                        return self._build_summary(cves, models, results)

        return self._build_summary(cves, models, results)

    def _run_single_evaluation(
        self,
        cve_id: str,
        model: str,
        force: bool,
    ) -> Dict[str, Any]:
        start_time = time.time()

        logger.info(
            "Starting evaluation for %s with model %s",
            cve_id,
            model,
        )

        try:
            payload = self.payload_builder.build_generation_payload(cve_id)

            result = self.pipeline_executor.execute(
                cve_id=cve_id,
                model=model,
                evaluation_mode=True,
                evaluation_batch_id=self.evaluation_batch_id,
                evaluation_label=self.evaluation_label,
                provided_generation_payload=payload,
                timeout_seconds=self.timeout,
                force=force,
                creator_script="scripts.prod.continuous_pipeline_v0_3_0.evaluate_models_v0_3_0",
            )

            duration = round(time.time() - start_time, 3)

            pipeline_status = result.get("pipeline_status", "success")
            # In v0.3.1, partial_success is also considered a success
            success = pipeline_status in {"success", "validation_failed", "partial_success"}

            output: Dict[str, Any] = {
                "cve_id": cve_id,
                "model": model,
                "status": "completed" if success else "failed",
                "duration": duration,
                "pipeline_status": pipeline_status,
                "generation_run_id": result.get("generation_run_id"),
                "context_snapshot_id": result.get("context_snapshot_id"),
                "retrieval_run_id": result.get("retrieval_run_id"),
                "validation_passed": result.get("validation_passed"),
                "validation_grade": result.get("validation_grade", "HARD_FAIL"),
                "parse_passed": result.get("parse_passed", False),
                "repair_applied": result.get("repair_applied", False),
                "normalization_applied": result.get("normalization_applied", False),
                "semantic_utility_flag": result.get("semantic_utility_flag", False),
                "validation_errors": result.get("validation_errors", []),
                "error": result.get("error"),
                "result": result,
            }

            if output["status"] == "completed":
                logger.info(
                    "Completed evaluation for %s with %s in %.3fs (generation_run_id=%s)",
                    cve_id,
                    model,
                    duration,
                    output["generation_run_id"],
                )
            else:
                logger.error(
                    "Evaluation failed for %s with %s: %s",
                    cve_id,
                    model,
                    output["error"] or "unknown failure",
                )

            return output

        except Exception as e:
            logger.error(
                "Unexpected error during evaluation of %s with %s: %s",
                cve_id,
                model,
                e,
            )
            logger.error("Traceback: %s", traceback.format_exc())

            duration = round(time.time() - start_time, 3)

            return {
                "cve_id": cve_id,
                "model": model,
                "status": "failed",
                "duration": duration,
                "error": str(e),
            }

    def _build_summary(
        self,
        cves: List[str],
        models: List[str],
        results: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        completed = sum(1 for r in results if r.get("status") == "completed")
        failed = sum(1 for r in results if r.get("status") == "failed")

        model_stats: Dict[str, Dict[str, Any]] = {}
        for model in models:
            model_results = [r for r in results if r.get("model") == model]
            model_completed = sum(1 for r in model_results if r.get("status") == "completed")
            model_failed = sum(1 for r in model_results if r.get("status") == "failed")
            durations = [r.get("duration", 0.0) for r in model_results if r.get("duration") is not None]
            avg_duration = (sum(durations) / len(durations)) if durations else 0.0

            model_stats[model] = {
                "completed": model_completed,
                "failed": model_failed,
                "avg_duration": avg_duration,
            }

        return {
            "evaluation_batch_id": self.evaluation_batch_id,
            "evaluation_label": self.evaluation_label,
            "cves": cves,
            "models": models,
            "total_attempted": len(cves) * len(models),
            "completed": completed,
            "failed": failed,
            "results": results,
            "model_stats": model_stats,
        }