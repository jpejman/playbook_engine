"""
Queue filler entrypoint
Version: v0.2.1
Timestamp (UTC): 2026-04-17T14:36:53Z
"""

from __future__ import annotations

import argparse

from .config import ContinuousPipelineConfig
from .queue_feeder import QueueFeederService


def main():
    parser = argparse.ArgumentParser(description='Fill cve_queue from OpenSearch NVD v0.2.1')
    parser.add_argument('--page-size', type=int, default=ContinuousPipelineConfig.DEFAULT_FEED_PAGE_SIZE)
    parser.add_argument('--max-scan', type=int, default=ContinuousPipelineConfig.DEFAULT_FEED_MAX_SCAN)
    parser.add_argument('--target-enqueue', type=int, default=ContinuousPipelineConfig.DEFAULT_FEED_TARGET)
    parser.add_argument('--max-scan-windows', type=int, default=ContinuousPipelineConfig.DEFAULT_FEED_MAX_SCAN_WINDOWS)
    parser.add_argument('--max-total-scan', type=int, default=ContinuousPipelineConfig.DEFAULT_FEED_MAX_TOTAL_SCAN)
    parser.add_argument('--min-enqueue-required', type=int, default=ContinuousPipelineConfig.DEFAULT_FEED_MIN_ENQUEUE_REQUIRED)
    parser.add_argument('--sort-diversification', action='store_true', 
                       help='Use different sort strategies for different windows to avoid scanning same CVEs')
    args = parser.parse_args()
    feeder = QueueFeederService()
    summary = feeder.fill_from_opensearch(
        args.page_size, 
        args.max_scan, 
        args.target_enqueue,
        args.max_scan_windows,
        args.max_total_scan,
        args.min_enqueue_required,
        args.sort_diversification
    )
    print('=== QUEUE FILL SUMMARY ===')
    print(f'Scanned: {summary.scanned}')
    print(f'Enqueued: {summary.enqueued}')
    print(f'Skipped existing queue: {summary.skipped_existing_queue}')
    print(f'Skipped existing generation: {summary.skipped_existing_generation}')
    print(f'Skipped in production: {summary.skipped_in_production}')
    print(f'Stopped early: {summary.stopped_early}')


if __name__ == '__main__':
    main()
