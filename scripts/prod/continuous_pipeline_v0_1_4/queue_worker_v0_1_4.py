"""
Queue Worker v0.1.4
Version: v0.1.4
Timestamp (UTC): 2026-04-15
"""

import argparse
import time
from typing import Optional

from .config import ContinuousPipelineWorkerConfig
from .models import WorkerSummary
from .queue_claim import QueueClaimService
from .queue_status import QueueStatusService
from .queue_schema import QueueSchemaService
from .worker_processor import WorkerProcessor
from .run_loop_v0_1_4 import RunLoopV014


class ContinuousPipelineWorkerV014:
    """
    Enhanced queue worker with multiple modes:
    1. SINGLE: Process one item
    2. BATCH: Process N items sequentially
    3. PARALLEL: Simulate multiple workers
    4. LOOP: Continuous execution with sleep intervals
    """
    
    def __init__(
        self,
        max_runs: int = ContinuousPipelineWorkerConfig.DEFAULT_MAX_RUNS,
        wait_seconds: int = ContinuousPipelineWorkerConfig.DEFAULT_WAIT_SECONDS,
        max_retries: Optional[int] = None,
        batch_size: int = ContinuousPipelineWorkerConfig.DEFAULT_BATCH_SIZE,
        workers: int = ContinuousPipelineWorkerConfig.DEFAULT_WORKERS,
        loop: bool = False
    ):
        self.max_runs = max_runs
        self.wait_seconds = wait_seconds
        self.max_retries = max_retries if max_retries is not None else ContinuousPipelineWorkerConfig.DEFAULT_MAX_RETRIES
        self.batch_size = batch_size
        self.workers = workers
        self.loop = loop
        
        self.schema_service = QueueSchemaService()
        self.claim_service = QueueClaimService()
        self.status_service = QueueStatusService()
        self.processor = WorkerProcessor()
        
        self.claimed_count = 0
        self.completed_count = 0
        self.failed_count = 0
        self.skipped_count = 0
        self.requeued_count = 0
    
    def determine_mode(self) -> str:
        """
        Determine the operation mode based on parameters.
        """
        if self.loop:
            return ContinuousPipelineWorkerConfig.MODE_LOOP
        elif self.workers > 1:
            return ContinuousPipelineWorkerConfig.MODE_PARALLEL
        elif self.batch_size > 1:
            return ContinuousPipelineWorkerConfig.MODE_BATCH
        else:
            return ContinuousPipelineWorkerConfig.MODE_SINGLE
    
    def run_once(self) -> bool:
        """
        Process a single queue item.
        Returns True if work was done, False if no items available.
        """
        item = self.claim_service.claim_one_pending()
        
        if not item:
            print("No pending CVEs available to claim.")
            return False
        
        self.claimed_count += 1
        print(f"Claimed queue item: id={item.id}, cve_id={item.cve_id}, status={item.status}, retry_count={item.retry_count}")
        
        result = self.processor.process(item.cve_id)
        
        if result.success:
            self.status_service.mark_completed(item.id)
            self.completed_count += 1
            if result.skipped:
                self.skipped_count += 1
                print(f"Skipped queue item already in production: id={item.id}, cve_id={item.cve_id}")
            else:
                print(
                    f"Completed queue item: id={item.id}, cve_id={item.cve_id}, "
                    f"generation_run_id={result.generation_run_id}, "
                    f"context_snapshot_id={result.context_snapshot_id}, "
                    f"pipeline_status={result.pipeline_status}"
                )
            return True
        
        next_retry_count = item.retry_count + 1
        if result.retryable and next_retry_count <= self.max_retries:
            self.status_service.requeue(item.id, result.error, result.failure_type)
            self.requeued_count += 1
            print(
                f"Re-queued queue item: id={item.id}, cve_id={item.cve_id}, "
                f"failure_type={result.failure_type}, retry_count={next_retry_count}/{self.max_retries}"
            )
        else:
            self.status_service.mark_failed(item.id, result.error, result.failure_type)
            self.failed_count += 1
            print(
                f"Failed queue item permanently: id={item.id}, cve_id={item.cve_id}, "
                f"failure_type={result.failure_type}, error={result.error}"
            )
        
        return True
    
    def run_single_mode(self) -> WorkerSummary:
        """
        Run in SINGLE mode: process one item.
        """
        print("=== SINGLE MODE ===")
        self.run_once()
        return self._create_summary()
    
    def run_batch_mode(self) -> WorkerSummary:
        """
        Run in BATCH mode: process N items sequentially.
        """
        print(f"=== BATCH MODE (batch_size={self.batch_size}) ===")
        
        runs = 0
        while runs < self.batch_size:
            had_work = self.run_once()
            runs += 1
            
            if not had_work:
                break
            
            if runs < self.batch_size and self.wait_seconds > 0:
                time.sleep(self.wait_seconds)
        
        return self._create_summary()
    
    def run_parallel_mode(self) -> WorkerSummary:
        """
        Run in PARALLEL mode: simulate multiple workers.
        """
        print(f"=== PARALLEL MODE (workers={self.workers}, batch_size={self.batch_size}) ===")
        
        # Import locally to avoid circular dependency
        from .batch_orchestrator_v0_1_4 import BatchOrchestratorV014
        
        orchestrator = BatchOrchestratorV014(
            batch_size=self.batch_size,
            workers=self.workers,
            wait_seconds=self.wait_seconds,
            max_retries=self.max_retries
        )
        
        result = orchestrator.run()
        
        # Update counters from orchestrator results
        self.claimed_count = result["claimed"]
        self.completed_count = result["completed"]
        self.failed_count = result["failed"]
        self.requeued_count = result["requeued"]
        
        return self._create_summary()
    
    def run_loop_mode(self) -> WorkerSummary:
        """
        Run in LOOP mode: continuous execution.
        """
        print(f"=== LOOP MODE (workers={self.workers}, batch_size={self.batch_size}, wait_seconds={self.wait_seconds}) ===")
        
        run_loop = RunLoopV014(
            batch_size=self.batch_size,
            workers=self.workers,
            wait_seconds=self.wait_seconds,
            max_cycles=None,  # Run until no work
            max_retries=self.max_retries
        )
        
        result = run_loop.run()
        
        # Update counters from run loop results
        self.claimed_count = result["claimed"]
        self.completed_count = result["completed"]
        self.failed_count = result["failed"]
        self.requeued_count = result["requeued"]
        
        return self._create_summary()
    
    def run(self) -> WorkerSummary:
        """
        Run the worker in the appropriate mode.
        """
        self.schema_service.ensure_columns()
        
        mode = self.determine_mode()
        print(f"Mode: {mode}")
        
        if mode == ContinuousPipelineWorkerConfig.MODE_LOOP:
            return self.run_loop_mode()
        elif mode == ContinuousPipelineWorkerConfig.MODE_PARALLEL:
            return self.run_parallel_mode()
        elif mode == ContinuousPipelineWorkerConfig.MODE_BATCH:
            return self.run_batch_mode()
        else:  # SINGLE mode
            return self.run_single_mode()
    
    def _create_summary(self) -> WorkerSummary:
        """
        Create and print the worker summary.
        """
        summary = WorkerSummary(
            claimed=self.claimed_count,
            completed=self.completed_count,
            failed=self.failed_count,
            skipped=self.skipped_count,
            requeued=self.requeued_count
        )
        
        print("\n=== WORKER SUMMARY ===")
        print(f"Claimed: {summary.claimed}")
        print(f"Completed: {summary.completed}")
        print(f"Failed: {summary.failed}")
        print(f"Skipped: {summary.skipped}")
        print(f"Requeued: {summary.requeued}")
        
        return summary


def main():
    parser = argparse.ArgumentParser(description="Queue Worker v0.1.4")
    parser.add_argument(
        "--max-runs",
        type=int,
        default=ContinuousPipelineWorkerConfig.DEFAULT_MAX_RUNS,
        help="Maximum number of queue items to process (for single/batch mode)"
    )
    parser.add_argument(
        "--wait-seconds",
        type=int,
        default=ContinuousPipelineWorkerConfig.DEFAULT_WAIT_SECONDS,
        help="Seconds to wait between runs"
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=ContinuousPipelineWorkerConfig.DEFAULT_MAX_RETRIES,
        help="Maximum retry count before permanent failure"
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=ContinuousPipelineWorkerConfig.DEFAULT_BATCH_SIZE,
        help="Number of items to process in batch/parallel mode"
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=ContinuousPipelineWorkerConfig.DEFAULT_WORKERS,
        help="Number of workers for parallel mode"
    )
    parser.add_argument(
        "--loop",
        action="store_true",
        help="Run in continuous loop mode"
    )
    
    args = parser.parse_args()
    
    worker = ContinuousPipelineWorkerV014(
        max_runs=args.max_runs,
        wait_seconds=args.wait_seconds,
        max_retries=args.max_retries,
        batch_size=args.batch_size,
        workers=args.workers,
        loop=args.loop
    )
    
    worker.run()


if __name__ == "__main__":
    main()