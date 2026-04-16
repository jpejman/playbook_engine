"""
Continuous Intake Pipeline
Version: v0.1.0
Timestamp (UTC): 2026-04-14
"""

from .opensearch_intake import OpenSearchIntakeService
from .production_guard import ProductionPlaybookGuard
from .queue_stage import QueueStageService


class ContinuousPipelineV010:

    def __init__(self):
        self.intake = OpenSearchIntakeService()
        self.guard = ProductionPlaybookGuard()
        self.queue = QueueStageService()

    def run(self):
        candidates = self.intake.fetch_candidates()

        total = len(candidates)
        excluded = 0
        staged = 0

        for c in candidates:
            cve_id = c.get("cve_id")

            if not cve_id:
                continue

            if self.guard.exists(cve_id):
                excluded += 1
                continue

            if self.queue.already_in_queue(cve_id):
                continue

            self.queue.insert(cve_id)
            staged += 1

        print("\n=== INTAKE SUMMARY ===")
        print(f"Fetched: {total}")
        print(f"Excluded (already in production): {excluded}")
        print(f"Staged to queue: {staged}")


def main():
    pipeline = ContinuousPipelineV010()
    pipeline.run()


if __name__ == "__main__":
    main()