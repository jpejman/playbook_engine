"""
Run Loop v0.2.1
Version: v0.2.1
Timestamp (UTC): 2026-04-17T14:36:53Z
"""

from __future__ import annotations

import argparse
import logging
import time
from typing import Optional

from .config import ContinuousPipelineConfig
from .log_setup import get_logger


class RunLoopV020:
    def __init__(
        self,
        batch_size: int = ContinuousPipelineConfig.DEFAULT_BATCH_SIZE,
        workers: int = ContinuousPipelineConfig.DEFAULT_WORKERS,
        wait_seconds: int = ContinuousPipelineConfig.DEFAULT_WAIT_SECONDS,
        max_cycles: Optional[int] = None,
        max_retries: Optional[int] = None,
        queue_low_watermark: int = ContinuousPipelineConfig.DEFAULT_QUEUE_LOW_WATERMARK,
        feed_page_size: int = ContinuousPipelineConfig.DEFAULT_FEED_PAGE_SIZE,
        feed_max_scan: int = ContinuousPipelineConfig.DEFAULT_FEED_MAX_SCAN,
        feed_target: int = ContinuousPipelineConfig.DEFAULT_FEED_TARGET,
    ):
        self.batch_size = batch_size
        self.workers = workers
        self.wait_seconds = wait_seconds
        self.max_cycles = max_cycles
        self.max_retries = max_retries
        self.queue_low_watermark = queue_low_watermark
        self.feed_page_size = feed_page_size
        self.feed_max_scan = feed_max_scan
        self.feed_target = feed_target
        self.cycle_count = 0
        self.total_claimed = 0
        self.total_completed = 0
        self.total_failed = 0
        self.total_requeued = 0
        self.total_enqueued = 0
        self.logger = get_logger("run_loop_v0_2_1")

    def should_continue(self, last_summary: dict) -> bool:
        if self.max_cycles is not None and self.cycle_count >= self.max_cycles:
            self.logger.info(f'Stopping: Max cycles ({self.max_cycles}) reached')
            return False
        if last_summary['claimed'] == 0 and last_summary.get('enqueued', 0) == 0:
            self.logger.warning('Stopping: No items claimed and no new items enqueued in last cycle (starvation)')
            return False
        return True

    def run_cycle(self) -> dict:
        self.cycle_count += 1
        self.logger.info('')
        self.logger.info(f'=== CYCLE {self.cycle_count} ===')
        orchestrator = BatchOrchestratorV020(
            batch_size=self.batch_size,
            workers=self.workers,
            wait_seconds=0,
            max_retries=self.max_retries,
            queue_low_watermark=self.queue_low_watermark,
            feed_page_size=self.feed_page_size,
            feed_max_scan=self.feed_max_scan,
            feed_target=self.feed_target,
        )
        summary = orchestrator.run()
        self.total_claimed += summary['claimed']
        self.total_completed += summary['completed']
        self.total_failed += summary['failed']
        self.total_requeued += summary['requeued']
        self.total_enqueued += summary.get('enqueued', 0)
        return summary

    def run(self) -> dict:
        self.logger.info('=== RUN LOOP v0.2.1 ===')
        self.logger.info(f'Batch size: {self.batch_size}')
        self.logger.info(f'Workers: {self.workers}')
        self.logger.info(f'Wait seconds between cycles: {self.wait_seconds}')
        self.logger.info(f'Max cycles: {self.max_cycles or "Unlimited"}')
        self.logger.info(f'Max retries: {self.max_retries or ContinuousPipelineConfig.DEFAULT_MAX_RETRIES}')
        self.logger.info('')
        while True:
            cycle_summary = self.run_cycle()
            if not self.should_continue(cycle_summary):
                break
            if self.wait_seconds > 0:
                self.logger.info(f'Waiting {self.wait_seconds} seconds before next cycle...')
                time.sleep(self.wait_seconds)
        self.logger.info('')
        self.logger.info('=== RUN LOOP FINAL SUMMARY ===')
        self.logger.info(f'Total cycles: {self.cycle_count}')
        self.logger.info(f'Total claimed: {self.total_claimed}')
        self.logger.info(f'Total completed: {self.total_completed}')
        self.logger.info(f'Total failed: {self.total_failed}')
        self.logger.info(f'Total requeued: {self.total_requeued}')
        self.logger.info(f'Total enqueued: {self.total_enqueued}')
        return {
            'claimed': self.total_claimed,
            'completed': self.total_completed,
            'failed': self.total_failed,
            'requeued': self.total_requeued,
            'enqueued': self.total_enqueued,
        }


def main():
    parser = argparse.ArgumentParser(description='Run Loop v0.2.1')
    parser.add_argument('--batch-size', type=int, default=ContinuousPipelineConfig.DEFAULT_BATCH_SIZE)
    parser.add_argument('--workers', type=int, default=ContinuousPipelineConfig.DEFAULT_WORKERS)
    parser.add_argument('--wait-seconds', type=int, default=ContinuousPipelineConfig.DEFAULT_WAIT_SECONDS)
    parser.add_argument('--max-cycles', type=int, default=None)
    parser.add_argument('--max-retries', type=int, default=ContinuousPipelineConfig.DEFAULT_MAX_RETRIES)
    parser.add_argument('--queue-low-watermark', type=int, default=ContinuousPipelineConfig.DEFAULT_QUEUE_LOW_WATERMARK)
    parser.add_argument('--feed-page-size', type=int, default=ContinuousPipelineConfig.DEFAULT_FEED_PAGE_SIZE)
    parser.add_argument('--feed-max-scan', type=int, default=ContinuousPipelineConfig.DEFAULT_FEED_MAX_SCAN)
    parser.add_argument('--feed-target', type=int, default=ContinuousPipelineConfig.DEFAULT_FEED_TARGET)
    args = parser.parse_args()
    run_loop = RunLoopV020(
        batch_size=args.batch_size,
        workers=args.workers,
        wait_seconds=args.wait_seconds,
        max_cycles=args.max_cycles,
        max_retries=args.max_retries,
        queue_low_watermark=args.queue_low_watermark,
        feed_page_size=args.feed_page_size,
        feed_max_scan=args.feed_max_scan,
        feed_target=args.feed_target,
    )
    run_loop.run()


if __name__ == '__main__':
    main()
