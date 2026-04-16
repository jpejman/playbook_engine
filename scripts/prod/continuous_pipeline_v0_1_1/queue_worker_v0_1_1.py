"""
Queue Worker v0.1.1
Version: v0.1.1
Timestamp (UTC): 2026-04-15
"""

import argparse
import time

from .config import ContinuousPipelineWorkerConfig
from .models import WorkerSummary
from .queue_claim import QueueClaimService
from .queue_status import QueueStatusService
from .worker_processor import WorkerProcessor


class ContinuousPipelineWorkerV011:
    def __init__(self, max_runs: int = 1, wait_seconds: int = 0):
        self.max_runs = max_runs
        self.wait_seconds = wait_seconds

        self.claim_service = QueueClaimService()
        self.status_service = QueueStatusService()
        self.processor = WorkerProcessor()

        self.claimed_count = 0
        self.completed_count = 0
        self.failed_count = 0

    def run_once(self) -> bool:
        item = self.claim_service.claim_one_pending()

        if not item:
            print("No pending CVEs available to claim.")
            return False

        self.claimed_count += 1

        print(f"Claimed queue item: id={item.id}, cve_id={item.cve_id}, status={item.status}")

        result = self.processor.process(item.cve_id)

        if result.success:
            self.status_service.mark_completed(item.id)
            self.completed_count += 1
            print(f"Completed queue item: id={item.id}, cve_id={item.cve_id}")
        else:
            self.status_service.mark_failed(item.id, result.error)
            self.failed_count += 1
            print(f"Failed queue item: id={item.id}, cve_id={item.cve_id}, error={result.error}")

        return True

    def run(self) -> WorkerSummary:
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
            failed=self.failed_count
        )

        print("\n=== WORKER SUMMARY ===")
        print(f"Claimed: {summary.claimed}")
        print(f"Completed: {summary.completed}")
        print(f"Failed: {summary.failed}")

        return summary


def main():
    parser = argparse.ArgumentParser(description="Continuous Pipeline Queue Worker v0.1.1")
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

    args = parser.parse_args()

    worker = ContinuousPipelineWorkerV011(
        max_runs=args.max_runs,
        wait_seconds=args.wait_seconds
    )
    worker.run()


if __name__ == "__main__":
    main()