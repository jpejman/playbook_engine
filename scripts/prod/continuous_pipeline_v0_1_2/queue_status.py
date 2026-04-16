"""
Queue status transitions
Version: v0.1.2
Timestamp (UTC): 2026-04-15
"""

from .db_clients import PlaybookEngineClient


class QueueStatusService:
    def __init__(self):
        self.db = PlaybookEngineClient()

    def mark_completed(self, queue_id: int):
        self.db.execute(
            """
            UPDATE public.cve_queue
            SET status = 'completed',
                updated_at = NOW()
            WHERE id = %s
            """,
            (queue_id,)
        )

    def mark_failed(self, queue_id: int, error_message: str = None):
        self.db.execute(
            """
            UPDATE public.cve_queue
            SET status = 'failed',
                updated_at = NOW()
            WHERE id = %s
            """,
            (queue_id,)
        )