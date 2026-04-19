"""
OpenSearch-backed queue feeder
Version: v0.2.1
Timestamp (UTC): 2026-04-17T14:36:53Z
"""

from __future__ import annotations

from .config import ContinuousPipelineConfig
from .db_clients import PlaybookEngineClient
from .feeder_state import FeederStateService
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
        self.feeder_state = FeederStateService()
        self.use_persistent_cursor = ContinuousPipelineConfig.CP_FEED_USE_PERSISTENT_CURSOR
        self.feeder_name = ContinuousPipelineConfig.CP_FEED_CURSOR_FEEDER_NAME
        self.cursor_page_size = ContinuousPipelineConfig.CP_FEED_CURSOR_PAGE_SIZE

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
        
        import logging
        logger = logging.getLogger(__name__)
        
        # Log which mode we're using
        if self.use_persistent_cursor:
            logger.info(f"Using PERSISTENT CURSOR mode (feeder_name={self.feeder_name}, page_size={self.cursor_page_size})")
            return self._fill_with_persistent_cursor(
                page_size=self.cursor_page_size,
                max_scan=max_scan,
                target_enqueue=target_enqueue,
                max_total_scan=max_total_scan,
                min_enqueue_required=min_enqueue_required
            )
        else:
            logger.info(f"Using LEGACY mode (offset-based pagination)")
            return self._fill_with_legacy_pagination(
                page_size=page_size,
                max_scan=max_scan,
                target_enqueue=target_enqueue,
                max_scan_windows=max_scan_windows,
                max_total_scan=max_total_scan,
                min_enqueue_required=min_enqueue_required,
                sort_diversification=sort_diversification
            )
    
    def _fill_with_legacy_pagination(self, page_size: int, max_scan: int, target_enqueue: int,
                                   max_scan_windows: int = 10, max_total_scan: int = 5000,
                                   min_enqueue_required: int = 5, sort_diversification: bool = True) -> QueueFillSummary:
        """Original offset-based pagination implementation."""
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
    
    def _fill_with_persistent_cursor(self, page_size: int, max_scan: int, target_enqueue: int,
                                   max_total_scan: int = 5000, min_enqueue_required: int = 5) -> QueueFillSummary:
        """Persistent cursor-based pagination implementation."""
        scanned = 0
        enqueued = 0
        skipped_existing_queue = 0
        skipped_existing_generation = 0
        skipped_in_production = 0
        stopped_early = False

        import logging
        logger = logging.getLogger(__name__)
        
        # Get current cursor state
        cursor_state = self.feeder_state.get_state(self.feeder_name)
        search_after = None
        
        if cursor_state:
            last_sort_1 = cursor_state.get('last_sort_value_1')
            last_sort_2 = cursor_state.get('last_sort_value_2')
            if last_sort_1 is not None and last_sort_2 is not None:
                search_after = [last_sort_1, last_sort_2]
                logger.info(f"Resuming from cursor: {last_sort_1}, {last_sort_2}")
            else:
                logger.info("No cursor found, starting from beginning")
        else:
            logger.info("No feeder state found, starting from beginning")
        
        # Check if full pass was already completed
        if cursor_state and cursor_state.get('completed_full_pass'):
            logger.warning(f"Full pass already completed for feeder {self.feeder_name}. "
                          f"Use reset_state() to start over or check for new CVEs.")
            stopped_early = True
            return QueueFillSummary(
                scanned=scanned,
                enqueued=enqueued,
                skipped_existing_queue=skipped_existing_queue,
                skipped_existing_generation=skipped_existing_generation,
                skipped_in_production=skipped_in_production,
                stopped_early=stopped_early,
            )
        
        # Process one page at a time
        last_cve_id = None
        last_sort_values = None
        
        while scanned < max_total_scan and enqueued < target_enqueue:
            # Get next page using search_after
            batch, next_cursor, end_of_corpus = self.os.search_candidates_after(
                page_size=page_size,
                search_after=search_after
            )
            
            if not batch:
                stopped_early = True
                logger.info("No more CVEs available in OpenSearch")
                break
            
            window_scanned = 0
            window_enqueued = 0
            window_skipped_queue = 0
            window_skipped_generation = 0
            window_skipped_production = 0
            
            for candidate in batch:
                cve_id = candidate.get('cve_id')
                if not cve_id:
                    continue
                
                scanned += 1
                window_scanned += 1
                last_cve_id = cve_id
                
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
            
            # Update cursor for next iteration
            if next_cursor and len(next_cursor) >= 2:
                last_sort_values = next_cursor
                search_after = next_cursor
            else:
                # No next cursor means we're at the end
                last_sort_values = None
                search_after = None
            
            logger.info(f"Page processed: scanned={window_scanned}, enqueued={window_enqueued}, "
                       f"skipped_queue={window_skipped_queue}, skipped_generation={window_skipped_generation}, "
                       f"skipped_production={window_skipped_production}, total_scanned={scanned}, total_enqueued={enqueued}")
            
            # Save state after processing page
            if last_sort_values and len(last_sort_values) >= 2:
                save_success = self.feeder_state.save_state(
                    feeder_name=self.feeder_name,
                    last_sort_value_1=str(last_sort_values[0]),
                    last_sort_value_2=str(last_sort_values[1]),
                    last_cve_id=last_cve_id,
                    scanned_delta=window_scanned,
                    enqueued_delta=window_enqueued
                )
                if save_success:
                    logger.debug(f"Saved feeder state: {last_sort_values[0]}, {last_sort_values[1]}")
                else:
                    logger.warning("Failed to save feeder state")
            
            # Check if we've reached the end of corpus
            if end_of_corpus:
                logger.info("Reached end of corpus")
                # Mark full pass as complete
                self.feeder_state.mark_full_pass_complete(self.feeder_name)
                logger.info(f"Marked full pass as complete for feeder {self.feeder_name}")
                stopped_early = True
                break
            
            if enqueued >= min_enqueue_required and enqueued >= target_enqueue:
                logger.info(f"Reached target enqueue count: {enqueued}")
                break
        
        # Final summary logging
        if enqueued == 0:
            if skipped_existing_generation > 0:
                logger.warning(f"Zero enqueue: All {scanned} scanned CVEs already have completed non-empty generations")
            elif skipped_existing_queue > 0:
                logger.warning(f"Zero enqueue: All {scanned} scanned CVEs already in queue (pending/processing)")
            elif skipped_in_production > 0:
                logger.warning(f"Zero enqueue: All {scanned} scanned CVEs already in production")
            elif scanned == 0:
                logger.warning("Zero enqueue: No CVEs scanned")
            else:
                logger.warning("Zero enqueue: Unknown reason")
        
        return QueueFillSummary(
            scanned=scanned,
            enqueued=enqueued,
            skipped_existing_queue=skipped_existing_queue,
            skipped_existing_generation=skipped_existing_generation,
            skipped_in_production=skipped_in_production,
            stopped_early=stopped_early,
        )
