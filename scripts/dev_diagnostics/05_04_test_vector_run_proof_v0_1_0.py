#!/usr/bin/env python3
"""
Service: VulnStrike Playbook Engine
Script: test_vector_run_proof_v0_1_0.py
Version: v0.1.0
Timestamp (UTC): 2026-04-08

Purpose:
- Connect to PostgreSQL using repo-root .env
- Verify current database target
- Introspect live schema for key pipeline tables
- Dump recent rows from retrieval/generation/approval tables
- Evaluate whether current evidence supports a real vector-backed Run 2

Notes:
- Read-only script
- No schema changes
- No inserts/updates/deletes
"""

import os
import sys
import json
from pathlib import Path
from typing import List, Dict, Any, Optional

import psycopg2
import psycopg2.extras
from dotenv import load_dotenv


# --------------------------------------------------------------------
# Repo-root .env loading
# --------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parents[1]
load_dotenv(REPO_ROOT / ".env")


# --------------------------------------------------------------------
# DB connection helpers
# --------------------------------------------------------------------
def get_conn():
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=os.getenv("DB_PORT", "5432"),
        database=os.getenv("DB_NAME", "playbook_engine"),
        user=os.getenv("DB_USER", "vulnstrike"),
        password=os.getenv("DB_PASSWORD", "vulnstrike"),
    )


def fetch_all_dict(conn, query: str, params: Optional[tuple] = None) -> List[Dict[str, Any]]:
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(query, params)
        rows = cur.fetchall()
        return [dict(r) for r in rows]


def fetch_one_dict(conn, query: str, params: Optional[tuple] = None) -> Optional[Dict[str, Any]]:
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(query, params)
        row = cur.fetchone()
        return dict(row) if row else None


# --------------------------------------------------------------------
# Schema inspection
# --------------------------------------------------------------------
def get_current_database_name(conn) -> str:
    with conn.cursor() as cur:
        cur.execute("SELECT current_database()")
        row = cur.fetchone()
        return row[0]


def get_table_columns(conn, table_name: str) -> List[Dict[str, Any]]:
    query = """
    SELECT
        column_name,
        data_type,
        is_nullable,
        column_default
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = %s
    ORDER BY ordinal_position;
    """
    return fetch_all_dict(conn, query, (table_name,))


def get_table_constraints(conn, table_name: str) -> List[Dict[str, Any]]:
    query = """
    SELECT
        c.conname,
        pg_get_constraintdef(c.oid) AS constraint_def
    FROM pg_constraint c
    WHERE c.conrelid = %s::regclass
    ORDER BY c.conname;
    """
    return fetch_all_dict(conn, query, (table_name,))


# --------------------------------------------------------------------
# Output formatting
# --------------------------------------------------------------------
def print_header(title: str):
    print("\n" + "=" * 80)
    print(title)
    print("=" * 80)


def print_json(obj: Any):
    print(json.dumps(obj, indent=2, default=str))


def print_table_columns(table_name: str, columns: List[Dict[str, Any]]):
    print_header(f"SCHEMA: {table_name}")
    if not columns:
        print("No columns found.")
        return
    for col in columns:
        print(
            f"{col['column_name']:<24} "
            f"{col['data_type']:<30} "
            f"nullable={col['is_nullable']:<3} "
            f"default={str(col['column_default'])}"
        )


def print_constraints(table_name: str, constraints: List[Dict[str, Any]]):
    print_header(f"CONSTRAINTS: {table_name}")
    if not constraints:
        print("No constraints found.")
        return
    for c in constraints:
        print(f"{c['conname']}: {c['constraint_def']}")


def print_rows(title: str, rows: List[Dict[str, Any]]):
    print_header(title)
    if not rows:
        print("No rows found.")
        return
    for idx, row in enumerate(rows, start=1):
        print(f"\nRow {idx}:")
        print_json(row)


# --------------------------------------------------------------------
# Evidence evaluation
# --------------------------------------------------------------------
def has_col(columns: List[Dict[str, Any]], name: str) -> bool:
    return any(c["column_name"] == name for c in columns)


def evaluate_vector_evidence(
    retrieval_run_rows: List[Dict[str, Any]],
    retrieval_doc_rows: List[Dict[str, Any]],
    generation_rows: List[Dict[str, Any]],
    approval_rows: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Heuristic evaluation only.
    This does not prove business correctness, but it highlights whether the DB
    evidence looks like a real vector-backed run versus a placeholder run.
    """
    findings = {
        "retrieval_run_exists": len(retrieval_run_rows) > 0,
        "retrieval_docs_exist": len(retrieval_doc_rows) > 0,
        "generation_exists": len(generation_rows) > 0,
        "approval_exists": len(approval_rows) > 0,
        "retrieved_context_nonempty": False,
        "source_indexes_nonempty": False,
        "doc_content_nonempty": False,
        "metadata_nontrivial": False,
        "overall_assessment": "INSUFFICIENT_EVIDENCE",
        "notes": [],
    }

    # Check retrieval_runs content
    for row in retrieval_run_rows:
        if "retrieved_context" in row and row["retrieved_context"]:
            findings["retrieved_context_nonempty"] = True
        if "source_indexes" in row and row["source_indexes"]:
            findings["source_indexes_nonempty"] = True

    # Check retrieval_documents richness
    for row in retrieval_doc_rows:
        if "content" in row and row["content"]:
            findings["doc_content_nonempty"] = True

        metadata = row.get("metadata") or row.get("document_metadata")
        if metadata:
            # Any non-empty metadata counts; richer metadata is better
            findings["metadata_nontrivial"] = True

    # Assess
    if not findings["retrieval_run_exists"]:
        findings["notes"].append("No retrieval_runs row found.")
    if not findings["retrieval_docs_exist"]:
        findings["notes"].append("No retrieval_documents rows found.")
    if not findings["generation_exists"]:
        findings["notes"].append("No generation_runs row found.")
    if not findings["approval_exists"]:
        findings["notes"].append("No approved_playbooks row found.")

    if findings["retrieval_run_exists"] and findings["retrieval_docs_exist"]:
        if findings["retrieved_context_nonempty"] or findings["source_indexes_nonempty"] or findings["metadata_nontrivial"]:
            findings["overall_assessment"] = "PARTIAL_VECTOR_EVIDENCE"
            findings["notes"].append(
                "Retrieval artifacts exist and contain some non-empty retrieval evidence."
            )
        else:
            findings["overall_assessment"] = "WEAK_EVIDENCE"
            findings["notes"].append(
                "Retrieval rows exist, but retrieval-specific evidence is mostly empty or placeholder-like."
            )

    if (
        findings["retrieval_run_exists"]
        and findings["retrieval_docs_exist"]
        and findings["generation_exists"]
        and findings["approval_exists"]
        and (findings["retrieved_context_nonempty"] or findings["source_indexes_nonempty"] or findings["metadata_nontrivial"])
    ):
        findings["overall_assessment"] = "LIKELY_VECTOR_PATH_USED"
        findings["notes"].append(
            "The DB shows a plausible retrieval → generation → approval chain with non-empty retrieval evidence."
        )

    return findings


# --------------------------------------------------------------------
# Main execution
# --------------------------------------------------------------------
def main():
    target_cve = os.getenv("TEST_CVE_ID", "CVE-TEST-0001")

    tables_to_introspect = [
        "retrieval_runs",
        "retrieval_documents",
        "generation_runs",
        "approved_playbooks",
        "qa_runs",
    ]

    try:
        with get_conn() as conn:
            current_db = get_current_database_name(conn)

            print_header("DATABASE TARGET")
            print(f"CURRENT_DATABASE: {current_db}")
            print(f"EXPECTED_DATABASE_FROM_ENV: {os.getenv('DB_NAME')}")

            # Introspect schema
            schema_map = {}
            for table in tables_to_introspect:
                cols = get_table_columns(conn, table)
                schema_map[table] = cols
                print_table_columns(table, cols)

            # Optional: constraints for QA and approvals
            for table in ["qa_runs", "approved_playbooks", "generation_runs"]:
                constraints = get_table_constraints(conn, table)
                print_constraints(table, constraints)

            # Pull recent data safely using SELECT *
            retrieval_run_rows = fetch_all_dict(
                conn,
                """
                SELECT *
                FROM retrieval_runs
                WHERE cve_id = %s
                ORDER BY id DESC
                LIMIT 5;
                """,
                (target_cve,),
            )

            retrieval_doc_rows = fetch_all_dict(
                conn,
                """
                SELECT rd.*
                FROM retrieval_documents rd
                JOIN retrieval_runs rr
                  ON rd.retrieval_run_id = rr.id
                WHERE rr.cve_id = %s
                ORDER BY rd.id DESC
                LIMIT 10;
                """,
                (target_cve,),
            )

            generation_rows = fetch_all_dict(
                conn,
                """
                SELECT *
                FROM generation_runs
                WHERE cve_id = %s
                ORDER BY id DESC
                LIMIT 5;
                """,
                (target_cve,),
            )

            approval_rows = fetch_all_dict(
                conn,
                """
                SELECT ap.*
                FROM approved_playbooks ap
                LEFT JOIN generation_runs gr
                  ON ap.generation_run_id = gr.id
                WHERE gr.cve_id = %s
                   OR EXISTS (
                        SELECT 1
                        FROM information_schema.columns c
                        WHERE c.table_schema = 'public'
                          AND c.table_name = 'approved_playbooks'
                          AND c.column_name = 'cve_id'
                   )
                ORDER BY ap.id DESC
                LIMIT 5;
                """,
                (target_cve,),
            )

            qa_rows = fetch_all_dict(
                conn,
                """
                SELECT qr.*
                FROM qa_runs qr
                JOIN generation_runs gr
                  ON qr.generation_run_id = gr.id
                WHERE gr.cve_id = %s
                ORDER BY qr.id DESC
                LIMIT 5;
                """,
                (target_cve,),
            )

            print_rows(f"RECENT retrieval_runs FOR {target_cve}", retrieval_run_rows)
            print_rows(f"RECENT retrieval_documents FOR {target_cve}", retrieval_doc_rows)
            print_rows(f"RECENT generation_runs FOR {target_cve}", generation_rows)
            print_rows(f"RECENT qa_runs FOR {target_cve}", qa_rows)
            print_rows(f"RECENT approved_playbooks (targeting {target_cve} where possible)", approval_rows)

            # Best-effort lineage query using only columns we know are stable enough
            print_header("LINEAGE CHECK")
            try:
                lineage_rows = fetch_all_dict(
                    conn,
                    """
                    SELECT
                        rr.cve_id,
                        rr.id AS retrieval_run_id,
                        rd.id AS retrieval_document_id,
                        gr.id AS generation_run_id,
                        qr.id AS qa_run_id,
                        ap.id AS approved_playbook_id
                    FROM retrieval_runs rr
                    LEFT JOIN retrieval_documents rd
                        ON rd.retrieval_run_id = rr.id
                    LEFT JOIN generation_runs gr
                        ON gr.cve_id = rr.cve_id
                    LEFT JOIN qa_runs qr
                        ON qr.generation_run_id = gr.id
                    LEFT JOIN approved_playbooks ap
                        ON ap.generation_run_id = gr.id
                    WHERE rr.cve_id = %s
                    ORDER BY rr.id DESC, rd.id DESC
                    LIMIT 10;
                    """,
                    (target_cve,),
                )
                print_rows("LINEAGE ROWS", lineage_rows)
            except Exception as e:
                print(f"Lineage query failed: {e}")

            # Evaluate evidence strength
            assessment = evaluate_vector_evidence(
                retrieval_run_rows=retrieval_run_rows,
                retrieval_doc_rows=retrieval_doc_rows,
                generation_rows=generation_rows,
                approval_rows=approval_rows,
            )

            print_header("VECTOR PROOF ASSESSMENT")
            print_json(assessment)

    except Exception as e:
        print_header("ERROR")
        print(str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()