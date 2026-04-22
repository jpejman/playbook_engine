"""
Queue schema safety helpers
Version: v0.2.0
Timestamp (UTC): 2026-04-16T23:45:00Z
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
