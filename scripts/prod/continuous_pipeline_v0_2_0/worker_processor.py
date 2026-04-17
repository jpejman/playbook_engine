"""
Worker processor bridge
Version: v0.2.0
Timestamp (UTC): 2026-04-16T23:45:00Z
"""

from __future__ import annotations

import logging
import traceback

from .failure_classifier import FailureClassifier
from .generation_guard import GenerationRunGuard
from .models import WorkerProcessResult
from .pipeline_executor import PipelineExecutor
from .production_guard import ProductionPlaybookGuard


class WorkerProcessor:
    def __init__(self):
        self.production_guard = ProductionPlaybookGuard()
        self.generation_guard = GenerationRunGuard()
        self.failure_classifier = FailureClassifier()
        self.executor = PipelineExecutor()
        self.logger = logging.getLogger(__name__)

    def process(self, cve_id: str) -> WorkerProcessResult:
        self.logger.info(f"Processing CVE: {cve_id}")
        try:
            self.logger.info(f"Checking production existence for {cve_id}")
            if self.production_guard.exists(cve_id):
                self.logger.info(f"CVE {cve_id} already in production, skipping")
                return WorkerProcessResult(
                    cve_id=cve_id,
                    success=True,
                    skipped=True,
                    failure_type='ALREADY_IN_PRODUCTION',
                    retryable=False,
                    pipeline_status='skipped_already_in_production',
                    execution_status='completed',
                )
            
            self.logger.info(f"Checking generation existence for {cve_id}")
            if self.generation_guard.exists_completed_nonempty(cve_id):
                self.logger.info(f"CVE {cve_id} already generated, skipping")
                return WorkerProcessResult(
                    cve_id=cve_id,
                    success=True,
                    skipped=True,
                    failure_type='ALREADY_GENERATED',
                    retryable=False,
                    pipeline_status='skipped_already_generated',
                    execution_status='completed',
                )
            
            self.logger.info(f"Starting pipeline execution for {cve_id}")
            results = self.executor.run(cve_id)
            self.logger.info(f"Pipeline execution completed for {cve_id}")
            
            success = (
                results.get('execution_status') == 'completed' and
                results.get('pipeline_status') == 'success' and
                results.get('generation_run_id') is not None
            )
            
            if success:
                self.logger.info(f"Pipeline successful for {cve_id}, generation_run_id={results.get('generation_run_id')}")
                return WorkerProcessResult(
                    cve_id=cve_id,
                    success=True,
                    skipped=False,
                    generation_run_id=results.get('generation_run_id'),
                    context_snapshot_id=results.get('context_snapshot_id'),
                    retrieval_run_id=results.get('retrieval_run_id'),
                    pipeline_status=results.get('pipeline_status'),
                    execution_status=results.get('execution_status'),
                    details=results,
                )
            
            error_message = results.get('error') or 'Pipeline failed without explicit error'
            self.logger.warning(f"Pipeline failed for {cve_id}: {error_message}")
            failure_type, retryable = self.failure_classifier.classify(
                error_message=error_message,
                pipeline_status=results.get('pipeline_status'),
                generation_status=results.get('generation_status'),
            )
            self.logger.info(f"Classified failure as {failure_type}, retryable={retryable}")
            
            return WorkerProcessResult(
                cve_id=cve_id,
                success=False,
                error=error_message,
                failure_type=failure_type,
                retryable=retryable,
                generation_run_id=results.get('generation_run_id'),
                context_snapshot_id=results.get('context_snapshot_id'),
                retrieval_run_id=results.get('retrieval_run_id'),
                pipeline_status=results.get('pipeline_status'),
                execution_status=results.get('execution_status'),
                details=results,
            )
        except Exception as exc:
            self.logger.error(f"Exception processing CVE {cve_id}: {exc}")
            self.logger.error(f"Traceback: {traceback.format_exc()}")
            failure_type, retryable = self.failure_classifier.classify(str(exc), pipeline_status='worker_exception')
            self.logger.info(f"Classified exception as {failure_type}, retryable={retryable}")
            
            return WorkerProcessResult(
                cve_id=cve_id,
                success=False,
                error=str(exc),
                failure_type=failure_type,
                retryable=retryable,
                pipeline_status='worker_exception',
                execution_status='failed',
            )
