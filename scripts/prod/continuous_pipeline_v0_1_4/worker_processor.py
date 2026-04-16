"""
Worker processor bridge
Version: v0.1.4-statusfix
Timestamp (UTC): 2026-04-15
"""

from .models import WorkerProcessResult
from .production_guard import ProductionPlaybookGuard
from .failure_classifier import FailureClassifier
from .db_clients import PlaybookEngineClient


class WorkerProcessor:
    """
    Bridge into the existing proven direct-CVE processing path.
    This class does not modify original code; it only imports and invokes it.
    """

    def __init__(self):
        self.production_guard = ProductionPlaybookGuard()
        self.failure_classifier = FailureClassifier()
        self.db = PlaybookEngineClient()

    def _fetch_latest_qa_for_generation_run(self, generation_run_id: int):
        if generation_run_id is None:
            return None

        return self.db.fetch_one(
            """
            SELECT id, generation_run_id, qa_result, qa_score, qa_feedback, created_at
            FROM public.qa_runs
            WHERE generation_run_id = %s
            ORDER BY id DESC
            LIMIT 1
            """,
            (generation_run_id,),
        )

    def process(self, cve_id: str) -> WorkerProcessResult:
        try:
            if self.production_guard.exists(cve_id):
                return WorkerProcessResult(
                    cve_id=cve_id,
                    success=True,
                    skipped=True,
                    error=None,
                    failure_type="ALREADY_IN_PRODUCTION",
                    retryable=False,
                    pipeline_status="skipped_already_in_production"
                )

            from scripts.prod.phase1_direct_cve_runner import Phase1DirectCVERunner

            runner = Phase1DirectCVERunner(cve_id)
            results = runner.run_pipeline()

            execution_status = results.get("execution_status", "failed")
            pipeline_status = results.get("pipeline_status", "failed")
            generation_run_id = results.get("generation_run_id")
            generation_status = results.get("generation_status")
            context_snapshot_id = results.get("context_snapshot_id")

            qa_row = self._fetch_latest_qa_for_generation_run(generation_run_id) if generation_run_id is not None else None
            qa_result = results.get("qa_result")
            qa_score = results.get("qa_score")
            qa_feedback = None

            if qa_row:
                qa_result = qa_row.get("qa_result", qa_result)
                qa_score = qa_row.get("qa_score", qa_score)
                qa_feedback = qa_row.get("qa_feedback")

            success = (
                execution_status == "completed"
                and pipeline_status == "success"
                and generation_run_id is not None
            )

            if success:
                return WorkerProcessResult(
                    cve_id=cve_id,
                    success=True,
                    skipped=False,
                    error=None,
                    failure_type=None,
                    retryable=False,
                    generation_run_id=generation_run_id,
                    context_snapshot_id=context_snapshot_id,
                    qa_result=qa_result,
                    qa_score=qa_score,
                    pipeline_status=pipeline_status
                )

            error_parts = [
                f"execution_status={execution_status}",
                f"pipeline_status={pipeline_status}",
                f"generation_run_id={generation_run_id}",
            ]

            if generation_status is not None:
                error_parts.append(f"generation_status={generation_status}")
            if qa_result is not None:
                error_parts.append(f"qa_result={qa_result}")
            if qa_score is not None:
                error_parts.append(f"qa_score={qa_score}")

            if qa_feedback:
                error_parts.append(f"qa_feedback={qa_feedback}")

            error_message = "Pipeline failed: " + ", ".join(str(p) for p in error_parts)

            failure_type, retryable = self.failure_classifier.classify(
                error_message=error_message,
                pipeline_status=pipeline_status,
                qa_result=qa_result,
                qa_feedback=qa_feedback,
                generation_status=generation_status,
            )

            return WorkerProcessResult(
                cve_id=cve_id,
                success=False,
                skipped=False,
                error=error_message,
                failure_type=failure_type,
                retryable=retryable,
                generation_run_id=generation_run_id,
                context_snapshot_id=context_snapshot_id,
                qa_result=qa_result,
                qa_score=qa_score,
                pipeline_status=pipeline_status
            )

        except Exception as e:
            failure_type, retryable = self.failure_classifier.classify(
                error_message=str(e),
                pipeline_status="worker_exception",
                qa_result=None,
                qa_feedback=None,
                generation_status=None,
            )
            return WorkerProcessResult(
                cve_id=cve_id,
                success=False,
                skipped=False,
                error=str(e),
                failure_type=failure_type,
                retryable=retryable,
                pipeline_status="worker_exception"
            )