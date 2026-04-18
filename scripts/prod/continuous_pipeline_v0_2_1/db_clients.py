"""
DB clients for continuous_pipeline_v0_2_0
Version: v0.2.1
Timestamp (UTC): 2026-04-17T14:36:53Z
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Any, Iterable, Optional

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

    def fetch_one(self, query: str, params: Optional[Iterable[Any]] = None):
        with self.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(query, params)
                return cur.fetchone()

    def fetch_all(self, query: str, params: Optional[Iterable[Any]] = None):
        with self.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(query, params)
                return cur.fetchall()

    def execute(self, query: str, params: Optional[Iterable[Any]] = None):
        with self.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(query, params)
                conn.commit()

    def execute_returning_one(self, query: str, params: Optional[Iterable[Any]] = None):
        with self.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(query, params)
                row = cur.fetchone()
                conn.commit()
                return row

    def table_columns(self, schema: str, table: str) -> list[str]:
        rows = self.fetch_all(
            """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = %s AND table_name = %s
            ORDER BY ordinal_position
            """,
            (schema, table),
        )
        return [row["column_name"] for row in rows]

    def insert_dynamic(self, fq_table: str, data: dict[str, Any], returning: Optional[str] = None):
        schema, table = fq_table.split('.', 1)
        available = set(self.table_columns(schema, table))
        payload = {k: v for k, v in data.items() if k in available}
        if not payload:
            raise ValueError(f"No matching columns available for {fq_table}")
        cols = list(payload.keys())
        placeholders = ', '.join(['%s'] * len(cols))
        column_sql = ', '.join(cols)
        query = f"INSERT INTO {fq_table} ({column_sql}) VALUES ({placeholders})"
        if returning:
            query += f" RETURNING {returning}"
            row = self.execute_returning_one(query, tuple(payload[c] for c in cols))
            if row and returning in row:
                return row[returning]
            if row and len(row) == 1:
                return next(iter(row.values()))
            return row
        self.execute(query, tuple(payload[c] for c in cols))
        return None


class PlaybookEngineClient(BaseDBClient):
    def __init__(self):
        super().__init__("playbook_engine")


class VulnstrikeProductionClient(BaseDBClient):
    def __init__(self):
        super().__init__("vulnstrike")
