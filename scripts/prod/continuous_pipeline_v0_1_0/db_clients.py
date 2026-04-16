"""
DB Clients
Version: v0.1.0
Timestamp (UTC): 2026-04-14
"""

import os
import psycopg2
import psycopg2.extras


class BaseDBClient:
    def __init__(self, database):
        self.host = os.getenv("DB_HOST", "10.0.0.110")
        self.port = os.getenv("DB_PORT", "5432")
        self.user = os.getenv("DB_USER", "vulnstrike")
        self.password = os.getenv("DB_PASSWORD", "vulnstrike")
        self.database = database

    def fetch_one(self, query, params=None):
        conn = psycopg2.connect(
            host=self.host,
            port=self.port,
            database=self.database,
            user=self.user,
            password=self.password
        )
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(query, params)
                return cur.fetchone()
        finally:
            conn.close()

    def execute(self, query, params=None):
        conn = psycopg2.connect(
            host=self.host,
            port=self.port,
            database=self.database,
            user=self.user,
            password=self.password
        )
        try:
            with conn.cursor() as cur:
                cur.execute(query, params)
                conn.commit()
        finally:
            conn.close()


class PlaybookEngineClient(BaseDBClient):
    def __init__(self):
        super().__init__("playbook_engine")


class VulnstrikeProductionClient(BaseDBClient):
    def __init__(self):
        super().__init__("vulnstrike")