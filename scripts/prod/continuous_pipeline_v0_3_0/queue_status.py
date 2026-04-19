"""
Queue status transitions
Version: v0.2.1
Timestamp (UTC): 2026-04-17T14:36:53Z
"""

from __future__ import annotations

from typing import Optional

from .db_clients import PlaybookEngineClient


class QueueStatusService:
    def __init__(self):
        self.db = PlaybookEngineClient()

    def mark_completed(self, queue_id: int):
        self.db.execute(
            """
            UPDATE public.cve_queue
            SET status = 'completed', updated_at = NOW()
            WHERE id = %s
            """,
            (queue_id,),
        )

    def mark_failed(self, queue_id: int, error_message: Optional[str] = None, failure_type: Optional[str] = None):
        self.db.execute(
            """
            UPDATE public.cve_queue
            SET status = 'failed', updated_at = NOW(), last_error = %s, failure_type = %s
            WHERE id = %s
            """,
            (error_message or '', failure_type or '', queue_id),
        )

    def mark_dead_letter(self, queue_id: int, error_message: Optional[str] = None, failure_type: Optional[str] = None):
        self.db.execute(
            """
            UPDATE public.cve_queue
            SET status = 'dead_letter', updated_at = NOW(), last_error = %s, failure_type = %s
            WHERE id = %s
            """,
            (error_message or '', failure_type or '', queue_id),
        )

    def requeue(self, queue_id: int, error_message: Optional[str] = None, failure_type: Optional[str] = None):
        self.db.execute(
            """
            UPDATE public.cve_queue
            SET status = 'pending',
                updated_at = NOW(),
                retry_count = COALESCE(retry_count, 0) + 1,
                last_error = %s,
                failure_type = %s
            WHERE id = %s
            """,
            (error_message or '', failure_type or '', queue_id),
        )
