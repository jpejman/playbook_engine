"""
Feeder state service for persistent cursor tracking
Version: v0.2.1
Timestamp (UTC): 2026-04-18T23:37:21Z
"""

from __future__ import annotations

from typing import Dict, Any, Optional, Tuple

from .db_clients import PlaybookEngineClient


class FeederStateService:
    """Service for managing persistent feeder state in public.feeder_state table."""
    
    def __init__(self):
        self.db = PlaybookEngineClient()
    
    def get_state(self, feeder_name: str) -> Optional[Dict[str, Any]]:
        """
        Get feeder state for the given feeder name.
        
        Args:
            feeder_name: Name of the feeder
            
        Returns:
            Dictionary with state fields or None if no state exists
        """
        row = self.db.fetch_one(
            """
            SELECT 
                id, feeder_name, 
                last_sort_value_1, last_sort_value_2, last_cve_id,
                total_scanned, total_enqueued,
                completed_full_pass,
                created_at, updated_at
            FROM public.feeder_state
            WHERE feeder_name = %s
            """,
            (feeder_name,)
        )
        return row
    
    def save_state(self, feeder_name: str, 
                   last_sort_value_1: Optional[str] = None,
                   last_sort_value_2: Optional[str] = None,
                   last_cve_id: Optional[str] = None,
                   scanned_delta: int = 0,
                   enqueued_delta: int = 0) -> bool:
        """
        Save or update feeder state.
        
        Args:
            feeder_name: Name of the feeder
            last_sort_value_1: First sort value (published_date)
            last_sort_value_2: Second sort value (cve_id.keyword)
            last_cve_id: Last CVE ID processed
            scanned_delta: Number of CVEs scanned in this run
            enqueued_delta: Number of CVEs enqueued in this run
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # First try to update existing row
            row = self.db.execute_returning_one(
                """
                UPDATE public.feeder_state
                SET 
                    last_sort_value_1 = COALESCE(%s, last_sort_value_1),
                    last_sort_value_2 = COALESCE(%s, last_sort_value_2),
                    last_cve_id = COALESCE(%s, last_cve_id),
                    total_scanned = total_scanned + %s,
                    total_enqueued = total_enqueued + %s,
                    updated_at = NOW()
                WHERE feeder_name = %s
                RETURNING id
                """,
                (last_sort_value_1, last_sort_value_2, last_cve_id, 
                 scanned_delta, enqueued_delta, feeder_name)
            )
            
            # If no row was updated, insert a new one
            if not row or not row.get('id'):
                row = self.db.execute_returning_one(
                    """
                    INSERT INTO public.feeder_state 
                    (feeder_name, last_sort_value_1, last_sort_value_2, last_cve_id,
                     total_scanned, total_enqueued, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s, NOW(), NOW())
                    ON CONFLICT (feeder_name) DO UPDATE SET
                        last_sort_value_1 = EXCLUDED.last_sort_value_1,
                        last_sort_value_2 = EXCLUDED.last_sort_value_2,
                        last_cve_id = EXCLUDED.last_cve_id,
                        total_scanned = public.feeder_state.total_scanned + EXCLUDED.total_scanned,
                        total_enqueued = public.feeder_state.total_enqueued + EXCLUDED.total_enqueued,
                        updated_at = NOW()
                    RETURNING id
                    """,
                    (feeder_name, last_sort_value_1, last_sort_value_2, last_cve_id,
                     scanned_delta, enqueued_delta)
                )
            
            return bool(row and row.get('id'))
        except Exception as e:
            import logging
            logging.getLogger(__name__).error(f"Failed to save feeder state for {feeder_name}: {e}")
            return False
    
    def mark_full_pass_complete(self, feeder_name: str) -> bool:
        """
        Mark that a full pass of the corpus has been completed.
        
        Args:
            feeder_name: Name of the feeder
            
        Returns:
            True if successful, False otherwise
        """
        try:
            row = self.db.execute_returning_one(
                """
                UPDATE public.feeder_state
                SET completed_full_pass = TRUE,
                    updated_at = NOW()
                WHERE feeder_name = %s
                RETURNING id
                """,
                (feeder_name,)
            )
            
            # If no row exists, create one with completed flag
            if not row or not row.get('id'):
                row = self.db.execute_returning_one(
                    """
                    INSERT INTO public.feeder_state 
                    (feeder_name, completed_full_pass, created_at, updated_at)
                    VALUES (%s, TRUE, NOW(), NOW())
                    ON CONFLICT (feeder_name) DO UPDATE SET
                        completed_full_pass = TRUE,
                        updated_at = NOW()
                    RETURNING id
                    """,
                    (feeder_name,)
                )
            
            return bool(row and row.get('id'))
        except Exception as e:
            import logging
            logging.getLogger(__name__).error(f"Failed to mark full pass complete for {feeder_name}: {e}")
            return False
    
    def reset_state(self, feeder_name: str) -> bool:
        """
        Reset feeder state (clear cursor and counters).
        
        Args:
            feeder_name: Name of the feeder
            
        Returns:
            True if successful, False otherwise
        """
        try:
            row = self.db.execute_returning_one(
                """
                UPDATE public.feeder_state
                SET 
                    last_sort_value_1 = NULL,
                    last_sort_value_2 = NULL,
                    last_cve_id = NULL,
                    total_scanned = 0,
                    total_enqueued = 0,
                    completed_full_pass = FALSE,
                    updated_at = NOW()
                WHERE feeder_name = %s
                RETURNING id
                """,
                (feeder_name,)
            )
            
            # If no row exists, create an empty one
            if not row or not row.get('id'):
                row = self.db.execute_returning_one(
                    """
                    INSERT INTO public.feeder_state 
                    (feeder_name, created_at, updated_at)
                    VALUES (%s, NOW(), NOW())
                    RETURNING id
                    """,
                    (feeder_name,)
                )
            
            return bool(row and row.get('id'))
        except Exception as e:
            import logging
            logging.getLogger(__name__).error(f"Failed to reset feeder state for {feeder_name}: {e}")
            return False
    
    def get_cursor_values(self, feeder_name: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Get cursor values for search_after query.
        
        Args:
            feeder_name: Name of the feeder
            
        Returns:
            Tuple of (last_sort_value_1, last_sort_value_2) or (None, None) if no cursor
        """
        state = self.get_state(feeder_name)
        if not state:
            return (None, None)
        
        return (state.get('last_sort_value_1'), state.get('last_sort_value_2'))