"""
Generation run existence guard
Version: v0.2.0
Timestamp (UTC): 2026-04-16T23:45:00Z
"""

from __future__ import annotations

from .db_clients import PlaybookEngineClient


class GenerationRunGuard:
    def __init__(self):
        self.db = PlaybookEngineClient()

    def exists_completed_nonempty(self, cve_id: str) -> bool:
        row = self.db.fetch_one(
            """
            SELECT EXISTS (
                SELECT 1
                FROM public.generation_runs
                WHERE cve_id = %s
                  AND status = 'completed'
                  AND response IS NOT NULL
                  AND btrim(response) <> ''
            ) AS exists
            """,
            (cve_id,),
        )
        return bool(row and row.get('exists'))
