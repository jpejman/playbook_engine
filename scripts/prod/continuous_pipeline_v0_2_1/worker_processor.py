"""
Worker processor bridge
Version: v0.2.1
Timestamp (UTC): 2026-04-17T14:36:53Z
"""

from __future__ import annotations

import logging
import traceback

from .failure_classifier import FailureClassifier
from .generation_guard import GenerationRunGuard
from .models import WorkerProcessResult
from .pipeline_executor import PipelineExecutor
from .production_guard import ProductionPlaybookGuard
from .db_clients import PlaybookEngineClient


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
            # Loop-prevention diagnostic logging
            self.logger.info(f"=== LOOP-PREVENTION DIAGNOSTICS for {cve_id} ===")
            
            # Check queue status
            queue_info = self._get_queue_info(cve_id)
            if queue_info:
                self.logger.info(f"Queue info: id={queue_info.get('id')}, status={queue_info.get('status')}, retry_count={queue_info.get('retry_count')}")
            
            # Check generation guard
            generation_exists = self.generation_guard.exists_completed_nonempty(cve_id)
            self.logger.info(f"Generation guard completed_nonempty: {generation_exists}")
            
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
            if generation_exists:
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
            # Enhanced logging for parse vs canonical structure failures
            is_parse_error = 'JSON_PARSE_ERROR' in failure_type
            is_canonical_error = 'SCHEMA_VALIDATION_FAIL' in failure_type
            self.logger.info(f"Classified failure as {failure_type}, retryable={retryable}, "
                           f"parse_error={is_parse_error}, canonical_error={is_canonical_error}")
            self.logger.debug(f"Raw error string: {error_message}")
            
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
            error_str = str(exc)
            self.logger.error(f"Exception processing CVE {cve_id}: {error_str}")
            self.logger.error(f"Traceback: {traceback.format_exc()}")
            failure_type, retryable = self.failure_classifier.classify(error_str, pipeline_status='worker_exception')
            # Enhanced logging for parse vs canonical structure failures
            is_parse_error = 'JSON_PARSE_ERROR' in failure_type
            is_canonical_error = 'SCHEMA_VALIDATION_FAIL' in failure_type
            self.logger.info(f"Classified exception as {failure_type}, retryable={retryable}, "
                           f"parse_error={is_parse_error}, canonical_error={is_canonical_error}")
            self.logger.debug(f"Raw exception string: {error_str}")
            
            return WorkerProcessResult(
                cve_id=cve_id,
                success=False,
                error=str(exc),
                failure_type=failure_type,
                retryable=retryable,
                pipeline_status='worker_exception',
                execution_status='failed',
            )
    
    def _get_queue_info(self, cve_id: str) -> dict:
        """Get queue information for diagnostic logging."""
        try:
            db = PlaybookEngineClient()
            row = db.fetch_one(
                """
                SELECT id, status, retry_count
                FROM public.cve_queue
                WHERE cve_id = %s
                ORDER BY updated_at DESC
                LIMIT 1
                """,
                (cve_id,),
            )
            return row if row else {}
        except Exception as e:
            self.logger.warning(f"Failed to get queue info for {cve_id}: {e}")
            return {}
