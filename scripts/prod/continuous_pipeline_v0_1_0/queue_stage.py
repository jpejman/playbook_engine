"""
Queue Staging
Version: v0.1.0
Timestamp (UTC): 2026-04-14
"""

from .db_clients import PlaybookEngineClient


class QueueStageService:

    def __init__(self):
        self.db = PlaybookEngineClient()

    def already_in_queue(self, cve_id: str) -> bool:
        result = self.db.fetch_one(
            """
            SELECT EXISTS (
                SELECT 1 FROM cve_queue WHERE cve_id = %s
            ) AS exists
            """,
            (cve_id,)
        )
        return result and result.get("exists")

    def insert(self, cve_id: str):
        self.db.execute(
            """
            INSERT INTO cve_queue (cve_id, status)
            VALUES (%s, 'pending')
            ON CONFLICT DO NOTHING
            """,
            (cve_id,)
        )