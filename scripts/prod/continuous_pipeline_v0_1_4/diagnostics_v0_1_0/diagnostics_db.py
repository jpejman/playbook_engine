"""
Diagnostics DB clients
Version: v0.1.0
Timestamp (UTC): 2026-04-15
"""

import os
from contextlib import contextmanager
from typing import Any, Optional

import psycopg2
import psycopg2.extras


class BaseDBClient:
    def __init__(self, database: str):
        self.host = os.getenv("DB_HOST", "10.0.0.110")
        self.port = os.getenv("DB_PORT", "5432")
        self.database = database
        self.user = os.getenv("DB_USER", "vulnstrike")
        self.password = os.getenv("DB_PASSWORD", "vulnstrike")

    def _connect(self):
        return psycopg2.connect(
            host=self.host,
            port=self.port,
            database=self.database,
            user=self.user,
            password=self.password,
        )

    @contextmanager
    def get_connection(self):
        conn = self._connect()
        try:
            yield conn
        finally:
            conn.close()

    def fetch_one(self, query: str, params: Optional[tuple[Any, ...]] = None):
        with self.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(query, params)
                return cur.fetchone()

    def fetch_all(self, query: str, params: Optional[tuple[Any, ...]] = None):
        with self.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(query, params)
                return cur.fetchall()


class PlaybookEngineDiagnosticsClient(BaseDBClient):
    def __init__(self):
        super().__init__("playbook_engine")


class VulnstrikeDiagnosticsClient(BaseDBClient):
    def __init__(self):
        super().__init__("vulnstrike")