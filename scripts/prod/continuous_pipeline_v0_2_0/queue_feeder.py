"""
OpenSearch-backed queue feeder
Version: v0.2.0
Timestamp (UTC): 2026-04-16T23:45:00Z
"""

from __future__ import annotations

from .db_clients import PlaybookEngineClient
from .generation_guard import GenerationRunGuard
from .models import QueueFillSummary
from .opensearch_client import OpenSearchClient
from .production_guard import ProductionPlaybookGuard
from .queue_schema import QueueSchemaService


class QueueFeederService:
    def __init__(self):
        self.os = OpenSearchClient()
        self.db = PlaybookEngineClient()
        self.production_guard = ProductionPlaybookGuard()
        self.generation_guard = GenerationRunGuard()
        self.schema_service = QueueSchemaService()

    def queue_contains(self, cve_id: str) -> bool:
        row = self.db.fetch_one(
            "SELECT EXISTS (SELECT 1 FROM public.cve_queue WHERE cve_id = %s AND status IN ('pending','processing','completed')) AS exists",
            (cve_id,),
        )
        return bool(row and row.get('exists'))

    def enqueue_cve(self, cve_id: str, source: str = 'opensearch_nvd') -> bool:
        row = self.db.execute_returning_one(
            """
            INSERT INTO public.cve_queue (cve_id, status, created_at, updated_at, retry_count, source)
            SELECT %s, 'pending', NOW(), NOW(), 0, %s
            WHERE NOT EXISTS (
                SELECT 1 FROM public.cve_queue WHERE cve_id = %s AND status IN ('pending','processing')
            )
            RETURNING id
            """,
            (cve_id, source, cve_id),
        )
        return bool(row and row.get('id'))

    def fill_from_opensearch(self, page_size: int, max_scan: int, target_enqueue: int) -> QueueFillSummary:
        self.schema_service.ensure_columns()
        scanned = 0
        enqueued = 0
        skipped_existing_queue = 0
        skipped_existing_generation = 0
        skipped_in_production = 0
        offset = 0
        stopped_early = False

        while scanned < max_scan and enqueued < target_enqueue:
            batch = self.os.search_candidates(from_offset=offset, page_size=page_size)
            if not batch:
                stopped_early = True
                break
            for candidate in batch:
                cve_id = candidate.get('cve_id')
                if not cve_id:
                    continue
                scanned += 1
                if self.queue_contains(cve_id):
                    skipped_existing_queue += 1
                    if scanned >= max_scan or enqueued >= target_enqueue:
                        break
                    continue
                if self.production_guard.exists(cve_id):
                    skipped_in_production += 1
                    if scanned >= max_scan or enqueued >= target_enqueue:
                        break
                    continue
                if self.generation_guard.exists_completed_nonempty(cve_id):
                    skipped_existing_generation += 1
                    if scanned >= max_scan or enqueued >= target_enqueue:
                        break
                    continue
                if self.enqueue_cve(cve_id):
                    enqueued += 1
                if scanned >= max_scan or enqueued >= target_enqueue:
                    break
            offset += page_size

        return QueueFillSummary(
            scanned=scanned,
            enqueued=enqueued,
            skipped_existing_queue=skipped_existing_queue,
            skipped_existing_generation=skipped_existing_generation,
            skipped_in_production=skipped_in_production,
            stopped_early=stopped_early,
        )
