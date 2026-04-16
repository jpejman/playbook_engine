"""
Worker processor bridge
Version: v0.1.2
Timestamp (UTC): 2026-04-15
"""

from .models import WorkerProcessResult
from .production_guard import ProductionPlaybookGuard


class WorkerProcessor:
    """
    Bridge into the existing proven direct-CVE processing path.
    This class does not modify original code; it only imports and invokes it.
    """

    def __init__(self):
        self.production_guard = ProductionPlaybookGuard()

    def process(self, cve_id: str) -> WorkerProcessResult:
        try:
            # Re-check production before processing to prevent race-condition duplicates.
            if self.production_guard.exists(cve_id):
                return WorkerProcessResult(
                    cve_id=cve_id,
                    success=True,
                    skipped=True,
                    error=None,
                    pipeline_status="skipped_already_in_production"
                )

            # Bridge to existing proven processor.
            from scripts.prod.phase1_direct_cve_runner import Phase1DirectCVERunner

            runner = Phase1DirectCVERunner(cve_id)
            results = runner.run_pipeline()

            execution_status = results.get("execution_status", "failed")
            pipeline_status = results.get("pipeline_status", "failed")
            generation_run_id = results.get("generation_run_id")

            success = (
                execution_status == "completed"
                and pipeline_status == "success"
                and generation_run_id is not None
            )

            return WorkerProcessResult(
                cve_id=cve_id,
                success=success,
                skipped=False,
                error=None if success else f"Pipeline failed: execution_status={execution_status}, pipeline_status={pipeline_status}, generation_run_id={generation_run_id}",
                generation_run_id=generation_run_id,
                context_snapshot_id=results.get("context_snapshot_id"),
                qa_result=results.get("qa_result"),
                qa_score=results.get("qa_score"),
                pipeline_status=pipeline_status
            )

        except Exception as e:
            return WorkerProcessResult(
                cve_id=cve_id,
                success=False,
                skipped=False,
                error=str(e),
                pipeline_status="worker_exception"
            )