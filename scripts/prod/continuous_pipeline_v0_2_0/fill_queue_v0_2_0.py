"""
Queue filler entrypoint
Version: v0.2.0
Timestamp (UTC): 2026-04-16T23:45:00Z
"""

from __future__ import annotations

import argparse

from .config import ContinuousPipelineConfig
from .queue_feeder import QueueFeederService


def main():
    parser = argparse.ArgumentParser(description='Fill cve_queue from OpenSearch NVD')
    parser.add_argument('--page-size', type=int, default=ContinuousPipelineConfig.DEFAULT_FEED_PAGE_SIZE)
    parser.add_argument('--max-scan', type=int, default=ContinuousPipelineConfig.DEFAULT_FEED_MAX_SCAN)
    parser.add_argument('--target-enqueue', type=int, default=ContinuousPipelineConfig.DEFAULT_FEED_TARGET)
    args = parser.parse_args()
    feeder = QueueFeederService()
    summary = feeder.fill_from_opensearch(args.page_size, args.max_scan, args.target_enqueue)
    print('=== QUEUE FILL SUMMARY ===')
    print(f'Scanned: {summary.scanned}')
    print(f'Enqueued: {summary.enqueued}')
    print(f'Skipped existing queue: {summary.skipped_existing_queue}')
    print(f'Skipped existing generation: {summary.skipped_existing_generation}')
    print(f'Skipped in production: {summary.skipped_in_production}')
    print(f'Stopped early: {summary.stopped_early}')


if __name__ == '__main__':
    main()
