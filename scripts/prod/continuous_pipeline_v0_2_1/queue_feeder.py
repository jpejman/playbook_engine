"""
OpenSearch-backed queue feeder
Version: v0.2.1
Timestamp (UTC): 2026-04-17T14:36:53Z
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
            """
            SELECT EXISTS (
                SELECT 1
                FROM public.cve_queue
                WHERE cve_id = %s
                  AND status IN ('pending', 'processing')
            ) AS exists
            """,
            (cve_id,),
        )
        return bool(row and row.get("exists"))

    def enqueue_cve(self, cve_id: str, source: str = 'opensearch_nvd', force_requeue_completed: bool = False) -> bool:
        try:
            if force_requeue_completed:
                # Force requeue mode: update existing row regardless of status
                row = self.db.execute_returning_one(
                    """
                    INSERT INTO public.cve_queue (cve_id, status, created_at, updated_at, retry_count, source)
                    VALUES (%s, 'pending', NOW(), NOW(), 0, %s)
                    ON CONFLICT (cve_id) DO UPDATE 
                    SET status = EXCLUDED.status,
                        updated_at = NOW(),
                        source = EXCLUDED.source,
                        retry_count = 0
                    RETURNING id
                    """,
                    (cve_id, source),
                )
            else:
                # Default mode: insert only if cve_id does not already exist
                # Do NOT reactivate failed/completed rows automatically
                row = self.db.execute_returning_one(
                    """
                    INSERT INTO public.cve_queue (cve_id, status, created_at, updated_at, retry_count, source)
                    VALUES (%s, 'pending', NOW(), NOW(), 0, %s)
                    ON CONFLICT (cve_id) DO NOTHING
                    RETURNING id
                    """,
                    (cve_id, source),
                )
            return bool(row and row.get('id'))
        except Exception as e:
            # Log the error but don't crash - just return False
            import logging
            logging.getLogger(__name__).warning(f"Failed to enqueue CVE {cve_id}: {e}")
            return False

    def fill_from_opensearch(self, page_size: int, max_scan: int, target_enqueue: int, 
                           max_scan_windows: int = 10, max_total_scan: int = 5000, 
                           min_enqueue_required: int = 5, sort_diversification: bool = True) -> QueueFillSummary:
        self.schema_service.ensure_columns()
        scanned = 0
        enqueued = 0
        skipped_existing_queue = 0
        skipped_existing_generation = 0
        skipped_in_production = 0
        offset = 0
        stopped_early = False
        windows_scanned = 0
        starvation_detected = False
        final_zero_enqueue_reason = None

        import logging
        logger = logging.getLogger(__name__)

        while (scanned < max_total_scan and enqueued < target_enqueue and 
               windows_scanned < max_scan_windows):
            sort_strategy = 'cvss_recent'
            if sort_diversification and windows_scanned > 0:
                if windows_scanned % 3 == 1:
                    sort_strategy = 'recent_only'
                elif windows_scanned % 3 == 2:
                    sort_strategy = 'oldest_first'
                else:
                    sort_strategy = 'cvss_recent'
            
            batch = self.os.search_candidates(from_offset=offset, page_size=page_size, sort_strategy=sort_strategy)
            if not batch:
                stopped_early = True
                final_zero_enqueue_reason = "No more CVEs available in OpenSearch"
                break
            
            window_enqueued = 0
            window_scanned = 0
            window_skipped_queue = 0
            window_skipped_generation = 0
            window_skipped_production = 0
            
            for candidate in batch:
                cve_id = candidate.get('cve_id')
                if not cve_id:
                    continue
                scanned += 1
                window_scanned += 1
                
                if self.queue_contains(cve_id):
                    skipped_existing_queue += 1
                    window_skipped_queue += 1
                    if scanned >= max_total_scan or enqueued >= target_enqueue:
                        break
                    continue
                if self.production_guard.exists(cve_id):
                    skipped_in_production += 1
                    window_skipped_production += 1
                    if scanned >= max_total_scan or enqueued >= target_enqueue:
                        break
                    continue
                if self.generation_guard.exists_completed_nonempty(cve_id):
                    skipped_existing_generation += 1
                    window_skipped_generation += 1
                    if scanned >= max_total_scan or enqueued >= target_enqueue:
                        break
                    continue
                if self.enqueue_cve(cve_id, source='opensearch_nvd', force_requeue_completed=False):
                    enqueued += 1
                    window_enqueued += 1
                if scanned >= max_total_scan or enqueued >= target_enqueue:
                    break
            
            windows_scanned += 1
            offset += page_size
            
            logger.info(f"Window {windows_scanned}: scanned={window_scanned}, enqueued={window_enqueued}, "
                       f"skipped_queue={window_skipped_queue}, skipped_generation={window_skipped_generation}, "
                       f"skipped_production={window_skipped_production}, offset={offset-page_size}")
            
            if window_enqueued == 0 and enqueued == 0 and windows_scanned > 1:
                starvation_detected = True
                logger.warning(f"Starvation detected: scanned {scanned} CVEs across {windows_scanned} windows, "
                             f"enqueued={enqueued}, skipped_generation={skipped_existing_generation}")
            
            if enqueued >= min_enqueue_required and enqueued >= target_enqueue:
                break
        
        if enqueued == 0:
            if skipped_existing_generation > 0:
                final_zero_enqueue_reason = f"All {scanned} scanned CVEs already have completed non-empty generations"
            elif skipped_existing_queue > 0:
                final_zero_enqueue_reason = f"All {scanned} scanned CVEs already in queue (pending/processing)"
            elif skipped_in_production > 0:
                final_zero_enqueue_reason = f"All {scanned} scanned CVEs already in production"
            elif scanned == 0:
                final_zero_enqueue_reason = "No CVEs scanned"
            else:
                final_zero_enqueue_reason = "Unknown reason"
            
            logger.warning(f"Zero enqueue summary: windows_scanned={windows_scanned}, "
                         f"total_scanned={scanned}, skipped_generation={skipped_existing_generation}, "
                         f"skipped_queue={skipped_existing_queue}, skipped_production={skipped_in_production}, "
                         f"reason={final_zero_enqueue_reason}")

        return QueueFillSummary(
            scanned=scanned,
            enqueued=enqueued,
            skipped_existing_queue=skipped_existing_queue,
            skipped_existing_generation=skipped_existing_generation,
            skipped_in_production=skipped_in_production,
            stopped_early=stopped_early,
        )
