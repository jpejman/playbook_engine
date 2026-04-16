"""
Queue Worker v0.1.3
Version: v0.1.3
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


class ContinuousPipelineWorkerV013:
    def __init__(self, max_runs: int = 1, wait_seconds: int = 0, max_retries: Optional[int] = None):
        self.max_runs = max_runs
        self.wait_seconds = wait_seconds
        self.max_retries = max_retries if max_retries is not None else ContinuousPipelineWorkerConfig.DEFAULT_MAX_RETRIES

        self.schema_service = QueueSchemaService()
        self.claim_service = QueueClaimService()
        self.status_service = QueueStatusService()
        self.processor = WorkerProcessor()

        self.claimed_count = 0
        self.completed_count = 0
        self.failed_count = 0
        self.skipped_count = 0
        self.requeued_count = 0

    def run_once(self) -> bool:
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

    def run(self) -> WorkerSummary:
        self.schema_service.ensure_columns()

        runs = 0
        while runs < self.max_runs:
            had_work = self.run_once()
            runs += 1

            if not had_work:
                break

            if runs < self.max_runs and self.wait_seconds > 0:
                time.sleep(self.wait_seconds)

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
    parser = argparse.ArgumentParser(description="Continuous Pipeline Queue Worker v0.1.3")
    parser.add_argument(
        "--max-runs",
        type=int,
        default=ContinuousPipelineWorkerConfig.DEFAULT_MAX_RUNS,
        help="Maximum number of queue items to process in this invocation"
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

    args = parser.parse_args()

    worker = ContinuousPipelineWorkerV013(
        max_runs=args.max_runs,
        wait_seconds=args.wait_seconds,
        max_retries=args.max_retries
    )
    worker.run()


if __name__ == "__main__":
    main()