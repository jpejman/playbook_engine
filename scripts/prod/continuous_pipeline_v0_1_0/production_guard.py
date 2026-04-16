"""
Production Guard
Version: v0.1.0
Timestamp (UTC): 2026-04-14
"""

from .db_clients import VulnstrikeProductionClient


class ProductionPlaybookGuard:

    def __init__(self):
        self.db = VulnstrikeProductionClient()

    def exists(self, cve_id: str) -> bool:
        result = self.db.fetch_one(
            """
            SELECT EXISTS (
                SELECT 1 FROM public.playbooks WHERE cve_id = %s
            ) AS exists
            """,
            (cve_id,)
        )
        return result and result.get("exists")