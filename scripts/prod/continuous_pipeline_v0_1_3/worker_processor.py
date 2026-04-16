"""
Worker processor bridge
Version: v0.1.3
Timestamp (UTC): 2026-04-15
"""

from .models import WorkerProcessResult
from .production_guard import ProductionPlaybookGuard
from .failure_classifier import FailureClassifier


class WorkerProcessor:
    """
    Bridge into the existing proven direct-CVE processing path.
    This class does not modify original code; it only imports and invokes it.
    """

    def __init__(self):
        self.production_guard = ProductionPlaybookGuard()
        self.failure_classifier = FailureClassifier()

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
            qa_result = results.get("qa_result")

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
                    context_snapshot_id=results.get("context_snapshot_id"),
                    qa_result=qa_result,
                    qa_score=results.get("qa_score"),
                    pipeline_status=pipeline_status
                )

            error_message = (
                f"Pipeline failed: execution_status={execution_status}, "
                f"pipeline_status={pipeline_status}, generation_run_id={generation_run_id}"
            )
            failure_type, retryable = self.failure_classifier.classify(
                error_message=error_message,
                pipeline_status=pipeline_status,
                qa_result=qa_result
            )

            return WorkerProcessResult(
                cve_id=cve_id,
                success=False,
                skipped=False,
                error=error_message,
                failure_type=failure_type,
                retryable=retryable,
                generation_run_id=generation_run_id,
                context_snapshot_id=results.get("context_snapshot_id"),
                qa_result=qa_result,
                qa_score=results.get("qa_score"),
                pipeline_status=pipeline_status
            )

        except Exception as e:
            failure_type, retryable = self.failure_classifier.classify(str(e), pipeline_status="worker_exception", qa_result=None)
            return WorkerProcessResult(
                cve_id=cve_id,
                success=False,
                skipped=False,
                error=str(e),
                failure_type=failure_type,
                retryable=retryable,
                pipeline_status="worker_exception"
            )