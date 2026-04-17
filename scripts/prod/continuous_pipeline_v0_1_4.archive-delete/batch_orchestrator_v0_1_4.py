"""
Batch Orchestrator v0.1.4
Version: v0.1.4
Timestamp (UTC): 2026-04-15
"""

import argparse
import time
from typing import Dict, Optional

from .config import ContinuousPipelineWorkerConfig


class BatchOrchestratorV014:
    """
    Multi-worker batch orchestrator for continuous CVE processing.
    Spawns N workers to process items in parallel.
    """
    
    def __init__(
        self,
        batch_size: int = ContinuousPipelineWorkerConfig.DEFAULT_BATCH_SIZE,
        workers: int = ContinuousPipelineWorkerConfig.DEFAULT_WORKERS,
        wait_seconds: int = ContinuousPipelineWorkerConfig.DEFAULT_WAIT_SECONDS,
        max_retries: Optional[int] = None
    ):
        self.batch_size = batch_size
        self.workers = workers
        self.wait_seconds = wait_seconds
        self.max_retries = max_retries
        
        # Initialize counters
        self.total_claimed = 0
        self.total_completed = 0
        self.total_failed = 0
        self.total_requeued = 0
        
    def run_worker(self, worker_id: int) -> Dict:
        """
        Run a single worker instance.
        Returns summary dictionary.
        """
        print(f"[Worker {worker_id}] Starting with batch_size={self.batch_size}")
        
        # Import locally to avoid circular dependency
        from .queue_worker_v0_1_4 import ContinuousPipelineWorkerV014
        
        worker = ContinuousPipelineWorkerV014(
            max_runs=self.batch_size,
            wait_seconds=0,  # No wait between runs within a worker
            max_retries=self.max_retries
        )
        
        summary = worker.run()
        
        print(f"[Worker {worker_id}] Summary: claimed={summary.claimed}, "
              f"completed={summary.completed}, failed={summary.failed}, "
              f"requeued={summary.requeued}")
        
        return {
            "claimed": summary.claimed,
            "completed": summary.completed,
            "failed": summary.failed,
            "requeued": summary.requeued
        }
    
    def run(self) -> Dict:
        """
        Run the batch orchestrator with multiple workers.
        Returns aggregated summary dictionary.
        """
        print(f"=== BATCH ORCHESTRATOR v0.1.4 ===")
        print(f"Workers: {self.workers}")
        print(f"Batch size per worker: {self.batch_size}")
        print(f"Wait seconds between workers: {self.wait_seconds}")
        print(f"Max retries: {self.max_retries or ContinuousPipelineWorkerConfig.DEFAULT_MAX_RETRIES}")
        print()
        
        # Run workers sequentially (for now - can be parallelized later)
        for i in range(self.workers):
            worker_summary = self.run_worker(i + 1)
            
            # Aggregate results
            self.total_claimed += worker_summary["claimed"]
            self.total_completed += worker_summary["completed"]
            self.total_failed += worker_summary["failed"]
            self.total_requeued += worker_summary["requeued"]
            
            # Wait between workers if specified
            if i < self.workers - 1 and self.wait_seconds > 0:
                print(f"Waiting {self.wait_seconds} seconds before next worker...")
                time.sleep(self.wait_seconds)
        
        # Print final summary
        print("\n=== BATCH ORCHESTRATOR SUMMARY ===")
        print(f"Total Claimed: {self.total_claimed}")
        print(f"Total Completed: {self.total_completed}")
        print(f"Total Failed: {self.total_failed}")
        print(f"Total Requeued: {self.total_requeued}")
        
        return {
            "claimed": self.total_claimed,
            "completed": self.total_completed,
            "failed": self.total_failed,
            "requeued": self.total_requeued,
            "workers": self.workers,
            "batch_size_per_worker": self.batch_size
        }


def main():
    parser = argparse.ArgumentParser(description="Batch Orchestrator v0.1.4")
    parser.add_argument(
        "--batch-size",
        type=int,
        default=ContinuousPipelineWorkerConfig.DEFAULT_BATCH_SIZE,
        help="Number of items each worker should process"
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=ContinuousPipelineWorkerConfig.DEFAULT_WORKERS,
        help="Number of workers to spawn"
    )
    parser.add_argument(
        "--wait-seconds",
        type=int,
        default=ContinuousPipelineWorkerConfig.DEFAULT_WAIT_SECONDS,
        help="Seconds to wait between workers"
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=ContinuousPipelineWorkerConfig.DEFAULT_MAX_RETRIES,
        help="Maximum retry count before permanent failure"
    )
    
    args = parser.parse_args()
    
    orchestrator = BatchOrchestratorV014(
        batch_size=args.batch_size,
        workers=args.workers,
        wait_seconds=args.wait_seconds,
        max_retries=args.max_retries
    )
    
    orchestrator.run()


if __name__ == "__main__":
    main()