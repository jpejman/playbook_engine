"""
Batch Orchestrator v0.2.0
Version: v0.2.0
Timestamp (UTC): 2026-04-16T23:45:00Z
"""

from __future__ import annotations

import argparse
import time
from typing import Dict, Optional

from .config import ContinuousPipelineConfig


class BatchOrchestratorV020:
    def __init__(
        self,
        batch_size: int = ContinuousPipelineConfig.DEFAULT_BATCH_SIZE,
        workers: int = ContinuousPipelineConfig.DEFAULT_WORKERS,
        wait_seconds: int = ContinuousPipelineConfig.DEFAULT_WAIT_SECONDS,
        max_retries: Optional[int] = None,
        queue_low_watermark: int = ContinuousPipelineConfig.DEFAULT_QUEUE_LOW_WATERMARK,
        feed_page_size: int = ContinuousPipelineConfig.DEFAULT_FEED_PAGE_SIZE,
        feed_max_scan: int = ContinuousPipelineConfig.DEFAULT_FEED_MAX_SCAN,
        feed_target: int = ContinuousPipelineConfig.DEFAULT_FEED_TARGET,
    ):
        self.batch_size = batch_size
        self.workers = workers
        self.wait_seconds = wait_seconds
        self.max_retries = max_retries
        self.queue_low_watermark = queue_low_watermark
        self.feed_page_size = feed_page_size
        self.feed_max_scan = feed_max_scan
        self.feed_target = feed_target
        self.total_claimed = 0
        self.total_completed = 0
        self.total_failed = 0
        self.total_requeued = 0
        self.total_enqueued = 0

    def run_worker(self, worker_id: int) -> Dict:
        print(f'[Worker {worker_id}] Starting with batch_size={self.batch_size}')
        from .queue_worker_v0_2_0 import ContinuousPipelineWorkerV020
        worker = ContinuousPipelineWorkerV020(
            wait_seconds=0,
            max_retries=self.max_retries,
            batch_size=self.batch_size,
            workers=1,
            loop=False,
            queue_low_watermark=self.queue_low_watermark,
            feed_page_size=self.feed_page_size,
            feed_max_scan=self.feed_max_scan,
            feed_target=self.feed_target,
        )
        summary = worker.run_batch_mode()
        print(f'[Worker {worker_id}] Summary: claimed={summary.claimed}, completed={summary.completed}, failed={summary.failed}, requeued={summary.requeued}')
        return {
            'claimed': summary.claimed,
            'completed': summary.completed,
            'failed': summary.failed,
            'requeued': summary.requeued,
            'enqueued': worker.enqueued_count,
        }

    def run(self) -> Dict:
        print('=== BATCH ORCHESTRATOR v0.2.0 ===')
        print(f'Workers: {self.workers}')
        print(f'Batch size per worker: {self.batch_size}')
        print(f'Wait seconds between workers: {self.wait_seconds}')
        print(f'Max retries: {self.max_retries or ContinuousPipelineConfig.DEFAULT_MAX_RETRIES}')
        print()
        for i in range(self.workers):
            worker_summary = self.run_worker(i + 1)
            self.total_claimed += worker_summary['claimed']
            self.total_completed += worker_summary['completed']
            self.total_failed += worker_summary['failed']
            self.total_requeued += worker_summary['requeued']
            self.total_enqueued += worker_summary.get('enqueued', 0)
            if i < self.workers - 1 and self.wait_seconds > 0:
                print(f'Waiting {self.wait_seconds} seconds before next worker...')
                time.sleep(self.wait_seconds)
        print()
        print('=== BATCH ORCHESTRATOR SUMMARY ===')
        print(f'Total Claimed: {self.total_claimed}')
        print(f'Total Completed: {self.total_completed}')
        print(f'Total Failed: {self.total_failed}')
        print(f'Total Requeued: {self.total_requeued}')
        print(f'Total Enqueued: {self.total_enqueued}')
        return {
            'claimed': self.total_claimed,
            'completed': self.total_completed,
            'failed': self.total_failed,
            'requeued': self.total_requeued,
            'enqueued': self.total_enqueued,
            'workers': self.workers,
            'batch_size_per_worker': self.batch_size,
        }


def main():
    parser = argparse.ArgumentParser(description='Batch Orchestrator v0.2.0')
    parser.add_argument('--batch-size', type=int, default=ContinuousPipelineConfig.DEFAULT_BATCH_SIZE)
    parser.add_argument('--workers', type=int, default=ContinuousPipelineConfig.DEFAULT_WORKERS)
    parser.add_argument('--wait-seconds', type=int, default=ContinuousPipelineConfig.DEFAULT_WAIT_SECONDS)
    parser.add_argument('--max-retries', type=int, default=ContinuousPipelineConfig.DEFAULT_MAX_RETRIES)
    parser.add_argument('--queue-low-watermark', type=int, default=ContinuousPipelineConfig.DEFAULT_QUEUE_LOW_WATERMARK)
    parser.add_argument('--feed-page-size', type=int, default=ContinuousPipelineConfig.DEFAULT_FEED_PAGE_SIZE)
    parser.add_argument('--feed-max-scan', type=int, default=ContinuousPipelineConfig.DEFAULT_FEED_MAX_SCAN)
    parser.add_argument('--feed-target', type=int, default=ContinuousPipelineConfig.DEFAULT_FEED_TARGET)
    args = parser.parse_args()
    orchestrator = BatchOrchestratorV020(
        batch_size=args.batch_size,
        workers=args.workers,
        wait_seconds=args.wait_seconds,
        max_retries=args.max_retries,
        queue_low_watermark=args.queue_low_watermark,
        feed_page_size=args.feed_page_size,
        feed_max_scan=args.feed_max_scan,
        feed_target=args.feed_target,
    )
    orchestrator.run()


if __name__ == '__main__':
    main()
