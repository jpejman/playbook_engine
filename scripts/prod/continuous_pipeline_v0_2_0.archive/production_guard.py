"""
Production playbook existence guard
Version: v0.2.0
Timestamp (UTC): 2026-04-16T23:45:00Z
"""

from __future__ import annotations

import logging
from typing import Optional

from .db_clients import VulnstrikeProductionClient


class ProductionPlaybookGuard:
    def __init__(self):
        self.db = VulnstrikeProductionClient()
        self.logger = logging.getLogger(__name__)
        self._production_table: Optional[str] = None
        
    def _resolve_production_table(self) -> str:
        if self._production_table is not None:
            return self._production_table
            
        # Check if public.playbooks exists
        result = self.db.fetch_one(
            """
            SELECT EXISTS (
                SELECT 1 FROM information_schema.tables 
                WHERE table_schema = 'public' AND table_name = 'playbooks'
            ) AS exists
            """
        )
        if result and result.get('exists'):
            self._production_table = 'public.playbooks'
            self.logger.info(f"Using production table: {self._production_table}")
            return self._production_table
            
        # Check if public.approved_playbooks exists
        result = self.db.fetch_one(
            """
            SELECT EXISTS (
                SELECT 1 FROM information_schema.tables 
                WHERE table_schema = 'public' AND table_name = 'approved_playbooks'
            ) AS exists
            """
        )
        if result and result.get('exists'):
            self._production_table = 'public.approved_playbooks'
            self.logger.info(f"Using production table: {self._production_table}")
            return self._production_table
            
        raise RuntimeError("Neither public.playbooks nor public.approved_playbooks exists in vulnstrike database")

    def exists(self, cve_id: str) -> bool:
        table = self._resolve_production_table()
        result = self.db.fetch_one(
            f"""
            SELECT EXISTS (
                SELECT 1 FROM {table} WHERE cve_id = %s
            ) AS exists
            """,
            (cve_id,),
        )
        return bool(result and result.get('exists'))
