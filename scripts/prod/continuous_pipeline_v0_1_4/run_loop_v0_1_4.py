"""
Run Loop v0.1.4
Version: v0.1.4
Timestamp (UTC): 2026-04-15
"""

import argparse
import time
from typing import Optional

from .config import ContinuousPipelineWorkerConfig
from .batch_orchestrator_v0_1_4 import BatchOrchestratorV014


class RunLoopV014:
    """
    Continuous execution loop for large-scale CVE processing.
    Runs batch orchestrator repeatedly until conditions are met.
    """
    
    def __init__(
        self,
        batch_size: int = ContinuousPipelineWorkerConfig.DEFAULT_BATCH_SIZE,
        workers: int = ContinuousPipelineWorkerConfig.DEFAULT_WORKERS,
        wait_seconds: int = ContinuousPipelineWorkerConfig.DEFAULT_WAIT_SECONDS,
        max_cycles: Optional[int] = None,
        max_retries: Optional[int] = None
    ):
        self.batch_size = batch_size
        self.workers = workers
        self.wait_seconds = wait_seconds
        self.max_cycles = max_cycles
        self.max_retries = max_retries
        
        # Initialize counters
        self.cycle_count = 0
        self.total_claimed = 0
        self.total_completed = 0
        self.total_failed = 0
        self.total_requeued = 0
        
    def should_continue(self, last_summary: dict) -> bool:
        """
        Determine if the loop should continue.
        Returns False if:
        - max_cycles reached
        - No items were processed in the last cycle
        """
        # Check max cycles
        if self.max_cycles is not None and self.cycle_count >= self.max_cycles:
            print(f"Stopping: Max cycles ({self.max_cycles}) reached")
            return False
        
        # Check if any items were processed in the last cycle
        if last_summary["claimed"] == 0:
            print("Stopping: No items to process in last cycle")
            return False
        
        return True
    
    def run_cycle(self) -> dict:
        """
        Run a single cycle using the batch orchestrator.
        Returns summary dictionary.
        """
        self.cycle_count += 1
        print(f"\n=== CYCLE {self.cycle_count} ===")
        
        orchestrator = BatchOrchestratorV014(
            batch_size=self.batch_size,
            workers=self.workers,
            wait_seconds=0,  # No wait between workers within a cycle
            max_retries=self.max_retries
        )
        
        summary = orchestrator.run()
        
        # Aggregate results
        self.total_claimed += summary["claimed"]
        self.total_completed += summary["completed"]
        self.total_failed += summary["failed"]
        self.total_requeued += summary["requeued"]
        
        return summary
    
    def run(self) -> dict:
        """
        Run the continuous execution loop.
        Returns final summary dictionary.
        """
        print(f"=== RUN LOOP v0.1.4 ===")
        print(f"Batch size: {self.batch_size}")
        print(f"Workers: {self.workers}")
        print(f"Wait seconds between cycles: {self.wait_seconds}")
        print(f"Max cycles: {self.max_cycles or 'Unlimited'}")
        print(f"Max retries: {self.max_retries or ContinuousPipelineWorkerConfig.DEFAULT_MAX_RETRIES}")
        print()
        
        # Run cycles until stopping condition is met
        while True:
            cycle_summary = self.run_cycle()
            
            # Check if we should continue
            if not self.should_continue(cycle_summary):
                break
            
            # Wait between cycles if specified
            if self.wait_seconds > 0:
                print(f"\nWaiting {self.wait_seconds} seconds before next cycle...")
                time.sleep(self.wait_seconds)
        
        # Print final summary
        print("\n=== RUN LOOP FINAL SUMMARY ===")
        print(f"Cycles completed: {self.cycle_count}")
        print(f"Total Claimed: {self.total_claimed}")
        print(f"Total Completed: {self.total_completed}")
        print(f"Total Failed: {self.total_failed}")
        print(f"Total Requeued: {self.total_requeued}")
        
        return {
            "cycles": self.cycle_count,
            "claimed": self.total_claimed,
            "completed": self.total_completed,
            "failed": self.total_failed,
            "requeued": self.total_requeued,
            "workers": self.workers,
            "batch_size": self.batch_size
        }


def main():
    parser = argparse.ArgumentParser(description="Run Loop v0.1.4")
    parser.add_argument(
        "--batch-size",
        type=int,
        default=ContinuousPipelineWorkerConfig.DEFAULT_BATCH_SIZE,
        help="Number of items each worker should process per cycle"
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=ContinuousPipelineWorkerConfig.DEFAULT_WORKERS,
        help="Number of workers per cycle"
    )
    parser.add_argument(
        "--wait-seconds",
        type=int,
        default=ContinuousPipelineWorkerConfig.DEFAULT_WAIT_SECONDS,
        help="Seconds to wait between cycles"
    )
    parser.add_argument(
        "--max-cycles",
        type=int,
        default=None,
        help="Maximum number of cycles to run (default: unlimited)"
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=ContinuousPipelineWorkerConfig.DEFAULT_MAX_RETRIES,
        help="Maximum retry count before permanent failure"
    )
    
    args = parser.parse_args()
    
    run_loop = RunLoopV014(
        batch_size=args.batch_size,
        workers=args.workers,
        wait_seconds=args.wait_seconds,
        max_cycles=args.max_cycles,
        max_retries=args.max_retries
    )
    
    run_loop.run()


if __name__ == "__main__":
    main()