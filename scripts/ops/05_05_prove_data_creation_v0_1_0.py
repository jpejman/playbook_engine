#!/usr/bin/env python3
"""
Service: VulnStrike Playbook Engine
Script: 05_05_prove_data_creation_v0_1_0.py
Version: v0.1.0
Timestamp (UTC): 2026-04-08

Purpose:
- Prove that data is actually being created for a selected CVE
- Show latest inserted rows across retrieval, generation, QA, approval
- Show timestamps and IDs
- Show clean lineage for the newest run
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import psycopg2
import psycopg2.extras
from dotenv import load_dotenv


ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")

DEFAULT_CVE = os.getenv("TEST_CVE_ID", "CVE-TEST-0001")


def get_conn():
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=os.getenv("DB_PORT", "5432"),
        database=os.getenv("DB_NAME", "playbook_engine"),
        user=os.getenv("DB_USER", "vulnstrike"),
        password=os.getenv("DB_PASSWORD", "vulnstrike"),
    )


def fetch_all(conn, query: str, params: Optional[tuple] = None) -> List[Dict[str, Any]]:
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(query, params)
        return [dict(r) for r in cur.fetchall()]


def fetch_one(conn, query: str, params: Optional[tuple] = None) -> Optional[Dict[str, Any]]:
    rows = fetch_all(conn, query, params)
    return rows[0] if rows else None


def print_header(title: str):
    print("\n" + "=" * 84)
    print(title)
    print("=" * 84)


def print_json(label: str, obj: Any):
    print(f"\n{label}")
    print(json.dumps(obj, indent=2, default=str))


def main():
    cve_id = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_CVE

    with get_conn() as conn:
        # Latest retrieval run for the CVE
        retrieval_run = fetch_one(
            conn,
            """
            SELECT *
            FROM retrieval_runs
            WHERE cve_id = %s
            ORDER BY id DESC
            LIMIT 1
            """,
            (cve_id,),
        )

        if not retrieval_run:
            print_header("DATA CREATION PROOF")
            print(f"No retrieval run found for {cve_id}")
            sys.exit(1)

        retrieval_run_id = retrieval_run["id"]

        retrieval_docs = fetch_all(
            conn,
            """
            SELECT *
            FROM retrieval_documents
            WHERE retrieval_run_id = %s
            ORDER BY id DESC
            LIMIT 10
            """,
            (retrieval_run_id,),
        )

        # Try direct lineage via retrieval_run_id if present in generation_runs
        generation_columns = fetch_all(
            conn,
            """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = 'generation_runs'
            ORDER BY ordinal_position
            """
        )
        generation_col_names = {r["column_name"] for r in generation_columns}

        if "retrieval_run_id" in generation_col_names:
            generation_run = fetch_one(
                conn,
                """
                SELECT *
                FROM generation_runs
                WHERE retrieval_run_id = %s
                ORDER BY id DESC
                LIMIT 1
                """,
                (retrieval_run_id,),
            )
        else:
            generation_run = fetch_one(
                conn,
                """
                SELECT *
                FROM generation_runs
                WHERE cve_id = %s
                ORDER BY id DESC
                LIMIT 1
                """,
                (cve_id,),
            )

        qa_run = None
        approved_playbook = None

        if generation_run:
            generation_run_id = generation_run["id"]

            qa_run = fetch_one(
                conn,
                """
                SELECT *
                FROM qa_runs
                WHERE generation_run_id = %s
                ORDER BY id DESC
                LIMIT 1
                """,
                (generation_run_id,),
            )

            approved_playbook = fetch_one(
                conn,
                """
                SELECT *
                FROM approved_playbooks
                WHERE generation_run_id = %s
                ORDER BY id DESC
                LIMIT 1
                """,
                (generation_run_id,),
            )

        # Counts for proof
        counts = {
            "retrieval_runs_for_cve": fetch_one(
                conn,
                "SELECT COUNT(*) AS count FROM retrieval_runs WHERE cve_id = %s",
                (cve_id,),
            )["count"],
            "retrieval_documents_for_latest_run": len(retrieval_docs),
            "generation_runs_for_cve": fetch_one(
                conn,
                "SELECT COUNT(*) AS count FROM generation_runs WHERE cve_id = %s",
                (cve_id,),
            )["count"],
        }

        # Lineage proof
        if generation_run and qa_run:
            lineage = {
                "cve_id": cve_id,
                "retrieval_run_id": retrieval_run_id,
                "retrieval_document_ids": [r["id"] for r in retrieval_docs],
                "generation_run_id": generation_run["id"],
                "qa_run_id": qa_run["id"],
                "approved_playbook_id": approved_playbook["id"] if approved_playbook else None,
            }
        else:
            lineage = {
                "cve_id": cve_id,
                "retrieval_run_id": retrieval_run_id,
                "retrieval_document_ids": [r["id"] for r in retrieval_docs],
                "generation_run_id": generation_run["id"] if generation_run else None,
                "qa_run_id": qa_run["id"] if qa_run else None,
                "approved_playbook_id": approved_playbook["id"] if approved_playbook else None,
            }

        print_header("DATA CREATION PROOF")
        print(f"CVE: {cve_id}")
        print(f"Timestamp (UTC): {datetime.now(timezone.utc).isoformat()}")

        print_json("LATEST RETRIEVAL RUN", retrieval_run)
        print_json("LATEST RETRIEVAL DOCUMENTS", retrieval_docs)
        print_json("LATEST GENERATION RUN", generation_run)
        print_json("LATEST QA RUN", qa_run)
        print_json("LATEST APPROVED PLAYBOOK", approved_playbook)
        print_json("COUNTS", counts)
        print_json("LINEAGE", lineage)

        # Pass/fail summary
        passed = (
            retrieval_run is not None
            and len(retrieval_docs) > 0
            and generation_run is not None
            and qa_run is not None
        )

        if passed:
            print_header("RESULT")
            print("PASS: Data is being created and persisted.")
            print(f"Latest retrieval_run_id: {retrieval_run_id}")
            print(f"Latest generation_run_id: {generation_run['id']}")
            print(f"Latest qa_run_id: {qa_run['id']}")
            print(f"Latest approved_playbook_id: {approved_playbook['id'] if approved_playbook else 'NONE'}")
            sys.exit(0)
        else:
            print_header("RESULT")
            print("FAIL: Missing one or more required created records.")
            sys.exit(1)


if __name__ == "__main__":
    main()