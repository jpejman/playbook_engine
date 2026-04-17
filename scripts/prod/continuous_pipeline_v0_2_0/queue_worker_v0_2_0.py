"""
Queue Worker v0.2.0
Version: v0.2.0
Timestamp (UTC): 2026-04-16T23:45:00Z
"""

from __future__ import annotations

import argparse
import time
from typing import Optional

from .config import ContinuousPipelineConfig
from .models import WorkerSummary
from .queue_claim import QueueClaimService
from .queue_feeder import QueueFeederService
from .queue_schema import QueueSchemaService
from .queue_status import QueueStatusService
from .worker_processor import WorkerProcessor


class ContinuousPipelineWorkerV020:
    def __init__(
        self,
        wait_seconds: int = ContinuousPipelineConfig.DEFAULT_WAIT_SECONDS,
        max_retries: Optional[int] = None,
        batch_size: int = ContinuousPipelineConfig.DEFAULT_BATCH_SIZE,
        workers: int = ContinuousPipelineConfig.DEFAULT_WORKERS,
        loop: bool = False,
        queue_low_watermark: int = ContinuousPipelineConfig.DEFAULT_QUEUE_LOW_WATERMARK,
        feed_page_size: int = ContinuousPipelineConfig.DEFAULT_FEED_PAGE_SIZE,
        feed_max_scan: int = ContinuousPipelineConfig.DEFAULT_FEED_MAX_SCAN,
        feed_target: int = ContinuousPipelineConfig.DEFAULT_FEED_TARGET,
    ):
        self.wait_seconds = wait_seconds
        self.max_retries = max_retries if max_retries is not None else ContinuousPipelineConfig.DEFAULT_MAX_RETRIES
        self.batch_size = batch_size
        self.workers = workers
        self.loop = loop
        self.queue_low_watermark = queue_low_watermark
        self.feed_page_size = feed_page_size
        self.feed_max_scan = feed_max_scan
        self.feed_target = feed_target

        self.schema_service = QueueSchemaService()
        self.claim_service = QueueClaimService()
        self.status_service = QueueStatusService()
        self.processor = WorkerProcessor()
        self.feeder = QueueFeederService()

        self.claimed_count = 0
        self.completed_count = 0
        self.failed_count = 0
        self.skipped_count = 0
        self.requeued_count = 0
        self.enqueued_count = 0

    def determine_mode(self) -> str:
        if self.loop:
            return ContinuousPipelineConfig.MODE_LOOP
        if self.workers > 1:
            return ContinuousPipelineConfig.MODE_PARALLEL
        if self.batch_size > 1:
            return ContinuousPipelineConfig.MODE_BATCH
        return ContinuousPipelineConfig.MODE_SINGLE

    def ensure_queue_has_work(self):
        pending = self.claim_service.pending_count()
        if pending >= self.queue_low_watermark:
            return
        to_fill = max(self.feed_target, self.queue_low_watermark - pending)
        summary = self.feeder.fill_from_opensearch(
            page_size=self.feed_page_size,
            max_scan=self.feed_max_scan,
            target_enqueue=to_fill,
        )
        self.enqueued_count += summary.enqueued
        print(
            f"Queue fill: scanned={summary.scanned}, enqueued={summary.enqueued}, "
            f"skip_queue={summary.skipped_existing_queue}, skip_generation={summary.skipped_existing_generation}, "
            f"skip_production={summary.skipped_in_production}, stopped_early={summary.stopped_early}"
        )

    def run_once(self) -> bool:
        self.ensure_queue_has_work()
        item = self.claim_service.claim_one_pending()
        if not item:
            print('No pending CVEs available to claim.')
            return False
        self.claimed_count += 1
        print(f"Claimed queue item: id={item.id}, cve_id={item.cve_id}, status={item.status}, retry_count={item.retry_count}")
        result = self.processor.process(item.cve_id)
        if result.success:
            self.status_service.mark_completed(item.id)
            self.completed_count += 1
            if result.skipped:
                self.skipped_count += 1
                print(f"Skipped queue item: id={item.id}, cve_id={item.cve_id}, reason={result.failure_type}")
            else:
                print(
                    f"Completed queue item: id={item.id}, cve_id={item.cve_id}, generation_run_id={result.generation_run_id}, "
                    f"context_snapshot_id={result.context_snapshot_id}, retrieval_run_id={result.retrieval_run_id}, "
                    f"pipeline_status={result.pipeline_status}"
                )
            return True
        next_retry_count = item.retry_count + 1
        if result.retryable and next_retry_count <= self.max_retries:
            self.status_service.requeue(item.id, result.error, result.failure_type)
            self.requeued_count += 1
            print(f"Re-queued queue item: id={item.id}, cve_id={item.cve_id}, failure_type={result.failure_type}, retry_count={next_retry_count}/{self.max_retries}")
        else:
            self.status_service.mark_failed(item.id, result.error, result.failure_type)
            self.failed_count += 1
            print(f"Failed queue item permanently: id={item.id}, cve_id={item.cve_id}, failure_type={result.failure_type}, error={result.error}")
        return True

    def run_single_mode(self) -> WorkerSummary:
        print('=== SINGLE MODE ===')
        self.run_once()
        return self._create_summary()

    def run_batch_mode(self) -> WorkerSummary:
        print(f'=== BATCH MODE (batch_size={self.batch_size}) ===')
        for run_index in range(self.batch_size):
            had_work = self.run_once()
            if not had_work:
                break
            if run_index < self.batch_size - 1 and self.wait_seconds > 0:
                time.sleep(self.wait_seconds)
        return self._create_summary()

    def run_parallel_mode(self) -> WorkerSummary:
        print(f'=== PARALLEL MODE (workers={self.workers}, batch_size={self.batch_size}) ===')
        from .batch_orchestrator_v0_2_0 import BatchOrchestratorV020
        orchestrator = BatchOrchestratorV020(
            batch_size=self.batch_size,
            workers=self.workers,
            wait_seconds=self.wait_seconds,
            max_retries=self.max_retries,
            queue_low_watermark=self.queue_low_watermark,
            feed_page_size=self.feed_page_size,
            feed_max_scan=self.feed_max_scan,
            feed_target=self.feed_target,
        )
        result = orchestrator.run()
        self.claimed_count = result['claimed']
        self.completed_count = result['completed']
        self.failed_count = result['failed']
        self.requeued_count = result['requeued']
        self.enqueued_count = result.get('enqueued', 0)
        return self._create_summary()

    def run_loop_mode(self) -> WorkerSummary:
        print(f'=== LOOP MODE (workers={self.workers}, batch_size={self.batch_size}, wait_seconds={self.wait_seconds}) ===')
        from .run_loop_v0_2_0 import RunLoopV020
        run_loop = RunLoopV020(
            batch_size=self.batch_size,
            workers=self.workers,
            wait_seconds=self.wait_seconds,
            max_cycles=None,
            max_retries=self.max_retries,
            queue_low_watermark=self.queue_low_watermark,
            feed_page_size=self.feed_page_size,
            feed_max_scan=self.feed_max_scan,
            feed_target=self.feed_target,
        )
        result = run_loop.run()
        self.claimed_count = result['claimed']
        self.completed_count = result['completed']
        self.failed_count = result['failed']
        self.requeued_count = result['requeued']
        self.enqueued_count = result.get('enqueued', 0)
        return self._create_summary()

    def run(self) -> WorkerSummary:
        self.schema_service.ensure_columns()
        mode = self.determine_mode()
        print(f'Mode: {mode}')
        if mode == ContinuousPipelineConfig.MODE_LOOP:
            return self.run_loop_mode()
        if mode == ContinuousPipelineConfig.MODE_PARALLEL:
            return self.run_parallel_mode()
        if mode == ContinuousPipelineConfig.MODE_BATCH:
            return self.run_batch_mode()
        return self.run_single_mode()

    def _create_summary(self) -> WorkerSummary:
        summary = WorkerSummary(
            claimed=self.claimed_count,
            completed=self.completed_count,
            failed=self.failed_count,
            skipped=self.skipped_count,
            requeued=self.requeued_count,
        )
        print()
        print('=== WORKER SUMMARY ===')
        print(f'Claimed: {summary.claimed}')
        print(f'Completed: {summary.completed}')
        print(f'Failed: {summary.failed}')
        print(f'Skipped: {summary.skipped}')
        print(f'Requeued: {summary.requeued}')
        print(f'Enqueued: {self.enqueued_count}')
        return summary


def main():
    parser = argparse.ArgumentParser(description='Queue Worker v0.2.0')
    parser.add_argument('--wait-seconds', type=int, default=ContinuousPipelineConfig.DEFAULT_WAIT_SECONDS)
    parser.add_argument('--max-retries', type=int, default=ContinuousPipelineConfig.DEFAULT_MAX_RETRIES)
    parser.add_argument('--batch-size', type=int, default=ContinuousPipelineConfig.DEFAULT_BATCH_SIZE)
    parser.add_argument('--workers', type=int, default=ContinuousPipelineConfig.DEFAULT_WORKERS)
    parser.add_argument('--loop', action='store_true')
    parser.add_argument('--queue-low-watermark', type=int, default=ContinuousPipelineConfig.DEFAULT_QUEUE_LOW_WATERMARK)
    parser.add_argument('--feed-page-size', type=int, default=ContinuousPipelineConfig.DEFAULT_FEED_PAGE_SIZE)
    parser.add_argument('--feed-max-scan', type=int, default=ContinuousPipelineConfig.DEFAULT_FEED_MAX_SCAN)
    parser.add_argument('--feed-target', type=int, default=ContinuousPipelineConfig.DEFAULT_FEED_TARGET)
    args = parser.parse_args()
    worker = ContinuousPipelineWorkerV020(
        wait_seconds=args.wait_seconds,
        max_retries=args.max_retries,
        batch_size=args.batch_size,
        workers=args.workers,
        loop=args.loop,
        queue_low_watermark=args.queue_low_watermark,
        feed_page_size=args.feed_page_size,
        feed_max_scan=args.feed_max_scan,
        feed_target=args.feed_target,
    )
    worker.run()


if __name__ == '__main__':
    main()
