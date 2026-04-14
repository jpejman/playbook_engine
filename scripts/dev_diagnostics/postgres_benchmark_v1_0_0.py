#!/usr/bin/env python3
"""
PostgreSQL Benchmark Script
Version: v1.0.0
Timestamp (UTC): 2026-04-13
"""

from __future__ import annotations

import argparse
import statistics
import time
from dataclasses import dataclass
from typing import List, Optional

import psycopg2
import psycopg2.extras


@dataclass
class QueryResult:
    name: str
    durations_ms: List[float]
    rowcount: Optional[int] = None

    @property
    def avg_ms(self) -> float:
        return statistics.mean(self.durations_ms)

    @property
    def min_ms(self) -> float:
        return min(self.durations_ms)

    @property
    def max_ms(self) -> float:
        return max(self.durations_ms)


def run_query(cur, sql: str, params=None) -> int:
    cur.execute(sql, params or ())
    rows = cur.fetchall()
    return len(rows)


def benchmark_query(conn, name: str, sql: str, iterations: int = 5, params=None) -> QueryResult:
    durations = []
    rowcount = None

    for _ in range(iterations):
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            start = time.perf_counter()
            rowcount = run_query(cur, sql, params)
            end = time.perf_counter()
            durations.append((end - start) * 1000)

    return QueryResult(name=name, durations_ms=durations, rowcount=rowcount)


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark PostgreSQL query latency.")
    parser.add_argument("--host", default="10.0.0.110")
    parser.add_argument("--port", type=int, default=5432)
    parser.add_argument("--dbname", default="playbook_engine")
    parser.add_argument("--user", default="vulnstrike")
    parser.add_argument("--password", default="vulnstrike")
    parser.add_argument("--iterations", type=int, default=5)
    parser.add_argument("--cve", default=None, help="Optional CVE for targeted lookup tests")
    args = parser.parse_args()

    conn = psycopg2.connect(
        host=args.host,
        port=args.port,
        dbname=args.dbname,
        user=args.user,
        password=args.password,
    )
    conn.autocommit = True

    queries = [
        (
            "select_1",
            "SELECT 1 AS ok"
        ),
        (
            "count_generation_runs",
            "SELECT COUNT(*)::int AS cnt FROM generation_runs"
        ),
        (
            "count_context_snapshot",
            "SELECT COUNT(*)::int AS cnt FROM cve_context_snapshot"
        ),
        (
            "latest_generation_runs_10",
            """
            SELECT id, cve_id, status, created_at
            FROM generation_runs
            ORDER BY created_at DESC
            LIMIT 10
            """
        ),
        (
            "latest_context_snapshot_10",
            """
            SELECT id, cve_id, created_at
            FROM cve_context_snapshot
            ORDER BY created_at DESC
            LIMIT 10
            """
        ),
    ]

    if args.cve:
        queries.extend([
            (
                "generation_runs_by_cve",
                """
                SELECT id, cve_id, status, created_at
                FROM generation_runs
                WHERE cve_id = %s
                ORDER BY created_at DESC
                """,
                (args.cve,)
            ),
            (
                "context_snapshot_by_cve",
                """
                SELECT id, cve_id, created_at
                FROM cve_context_snapshot
                WHERE cve_id = %s
                ORDER BY created_at DESC
                """,
                (args.cve,)
            ),
            (
                "approved_playbook_by_cve",
                """
                SELECT ap.id, gr.cve_id
                FROM approved_playbooks ap
                JOIN generation_runs gr ON ap.generation_run_id = gr.id
                WHERE gr.cve_id = %s
                """,
                (args.cve,)
            ),
        ])

    print("=" * 80)
    print("POSTGRESQL BENCHMARK RESULTS")
    print("=" * 80)

    for entry in queries:
        name = entry[0]
        sql = entry[1]
        params = entry[2] if len(entry) > 2 else None

        result = benchmark_query(conn, name, sql, iterations=args.iterations, params=params)
        print(
            f"{result.name:<30} "
            f"avg={result.avg_ms:8.2f} ms  "
            f"min={result.min_ms:8.2f} ms  "
            f"max={result.max_ms:8.2f} ms  "
            f"rows={result.rowcount}"
        )

    print("=" * 80)

    conn.close()


if __name__ == "__main__":
    main()