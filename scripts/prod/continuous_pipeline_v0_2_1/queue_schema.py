"""
Queue schema safety helpers
Version: v0.2.1
Timestamp (UTC): 2026-04-17T14:36:53Z
"""

from __future__ import annotations

from .db_clients import PlaybookEngineClient


class QueueSchemaService:
    def __init__(self):
        self.db = PlaybookEngineClient()

    def ensure_columns(self):
        statements = [
            "ALTER TABLE public.cve_queue ADD COLUMN IF NOT EXISTS retry_count INTEGER DEFAULT 0",
            "ALTER TABLE public.cve_queue ADD COLUMN IF NOT EXISTS last_error TEXT",
            "ALTER TABLE public.cve_queue ADD COLUMN IF NOT EXISTS failure_type VARCHAR(64)",
            "ALTER TABLE public.cve_queue ADD COLUMN IF NOT EXISTS source VARCHAR(64)",
        ]
        for statement in statements:
            self.db.execute(statement)

    def recover_stale_processing(self, stale_minutes: int = 30) -> int:
        """
        Reset stale 'processing' rows back to 'pending' with retry increment.
        Clears diagnostics (last_error, failure_type) for fresh retry.
        Returns number of rows recovered.
        """
        result = self.db.fetch_one(
            """
            WITH stale_rows AS (
                SELECT id
                FROM public.cve_queue
                WHERE status = 'processing'
                AND updated_at < NOW() - INTERVAL '%s minutes'
                FOR UPDATE SKIP LOCKED
            )
            UPDATE public.cve_queue q
            SET status = 'pending',
                updated_at = NOW(),
                retry_count = COALESCE(retry_count, 0) + 1,
                last_error = NULL,
                failure_type = NULL
            FROM stale_rows
            WHERE q.id = stale_rows.id
            RETURNING COUNT(*) AS recovered_count
            """,
            (stale_minutes,),
        )
        return int(result['recovered_count']) if result else 0
