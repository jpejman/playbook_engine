"""
Generation run existence guard
Version: v0.2.1
Timestamp (UTC): 2026-04-17T14:36:53Z
"""

from __future__ import annotations

from .db_clients import PlaybookEngineClient


class GenerationRunGuard:
    def __init__(self):
        self.db = PlaybookEngineClient()

    def exists_completed_nonempty(self, cve_id: str, exclude_evaluation: bool = True) -> bool:
        """
        Check if CVE already has a completed generation run.
        
        Args:
            cve_id: CVE ID to check
            exclude_evaluation: Whether to exclude evaluation runs (default: True)
            
        Returns:
            True if completed non-empty generation exists
        """
        if exclude_evaluation:
            query = """
                SELECT EXISTS (
                    SELECT 1
                    FROM public.generation_runs
                    WHERE cve_id = %s
                      AND status = 'completed'
                      AND response IS NOT NULL
                      AND btrim(response) <> ''
                      AND (evaluation_mode = FALSE OR evaluation_mode IS NULL)
                ) AS exists
            """
        else:
            query = """
                SELECT EXISTS (
                    SELECT 1
                    FROM public.generation_runs
                    WHERE cve_id = %s
                      AND status = 'completed'
                      AND response IS NOT NULL
                      AND btrim(response) <> ''
                ) AS exists
            """
        
        row = self.db.fetch_one(query, (cve_id,))
        return bool(row and row.get('exists'))
