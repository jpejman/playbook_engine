"""
Queue schema safety helpers
Version: v0.1.3
Timestamp (UTC): 2026-04-15
"""

from .db_clients import PlaybookEngineClient


class QueueSchemaService:
    def __init__(self):
        self.db = PlaybookEngineClient()

    def ensure_columns(self):
        self.db.execute(
            """
            ALTER TABLE public.cve_queue
            ADD COLUMN IF NOT EXISTS retry_count INTEGER DEFAULT 0
            """
        )
        self.db.execute(
            """
            ALTER TABLE public.cve_queue
            ADD COLUMN IF NOT EXISTS last_error TEXT
            """
        )
        self.db.execute(
            """
            ALTER TABLE public.cve_queue
            ADD COLUMN IF NOT EXISTS failure_type VARCHAR(64)
            """
        )