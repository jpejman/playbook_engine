#!/usr/bin/env python3
"""
Service: VulnStrike Playbook Engine
Script: validate_playbook_engine_run_v0_1_0.py
Version: v0.1.0
Timestamp (UTC): 2026-04-08

Purpose:
- Run after every task run
- Validate DB target, schema, latest run integrity, retrieval quality, lineage quality
- Emit a compact PASS/WARN/FAIL report plus machine-readable JSON summary

Usage:
    python scripts/validate_playbook_engine_run_v0_1_0.py
    python scripts/validate_playbook_engine_run_v0_1_0.py --cve CVE-TEST-0001 --limit 10
"""

import os
import sys
import json
import argparse
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import psycopg2
import psycopg2.extras
from dotenv import load_dotenv


REPO_ROOT = Path(__file__).resolve().parents[1]
load_dotenv(REPO_ROOT / ".env")


EXPECTED_DB = os.getenv("DB_NAME", "playbook_engine")
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


def get_current_database(conn) -> str:
    with conn.cursor() as cur:
        cur.execute("SELECT current_database()")
        return cur.fetchone()[0]


def get_columns(conn, table_name: str) -> List[str]:
    rows = fetch_all(
        conn,
        """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = %s
        ORDER BY ordinal_position
        """,
        (table_name,),
    )
    return [r["column_name"] for r in rows]


def status_rank(status: str) -> int:
    return {"PASS": 0, "WARN": 1, "FAIL": 2}.get(status, 2)


def add_result(results: List[Dict[str, Any]], name: str, status: str, detail: str, extra: Optional[Dict[str, Any]] = None):
    item = {"check": name, "status": status, "detail": detail}
    if extra:
        item["extra"] = extra
    results.append(item)


def latest_retrieval_run(conn, cve_id: str) -> Optional[Dict[str, Any]]:
    return fetch_one(
        conn,
        "SELECT * FROM retrieval_runs WHERE cve_id = %s ORDER BY id DESC LIMIT 1",
        (cve_id,),
    )


def latest_generation_run(conn, cve_id: str) -> Optional[Dict[str, Any]]:
    return fetch_one(
        conn,
        "SELECT * FROM generation_runs WHERE cve_id = %s ORDER BY id DESC LIMIT 1",
        (cve_id,),
    )


def latest_qa_for_generation(conn, generation_run_id: int) -> Optional[Dict[str, Any]]:
    return fetch_one(
        conn,
        "SELECT * FROM qa_runs WHERE generation_run_id = %s ORDER BY id DESC LIMIT 1",
        (generation_run_id,),
    )


def latest_approval_for_generation(conn, generation_run_id: int) -> Optional[Dict[str, Any]]:
    return fetch_one(
        conn,
        "SELECT * FROM approved_playbooks WHERE generation_run_id = %s ORDER BY id DESC LIMIT 1",
        (generation_run_id,),
    )


def retrieval_docs_for_run(conn, retrieval_run_id: int, limit: int) -> List[Dict[str, Any]]:
    return fetch_all(
        conn,
        "SELECT * FROM retrieval_documents WHERE retrieval_run_id = %s ORDER BY rank NULLS LAST, id DESC LIMIT %s",
        (retrieval_run_id, limit),
    )


def validate_db_target(conn, results: List[Dict[str, Any]]):
    actual = get_current_database(conn)
    if actual == EXPECTED_DB:
        add_result(results, "db_target", "PASS", f"Connected to expected DB '{actual}'")
    else:
        add_result(results, "db_target", "FAIL", f"Connected to '{actual}', expected '{EXPECTED_DB}'", {"actual": actual, "expected": EXPECTED_DB})


def validate_schema(conn, results: List[Dict[str, Any]]):
    required = {
        "retrieval_runs": {"id", "cve_id", "retrieved_context", "source_indexes", "created_at"},
        "retrieval_documents": {"id", "retrieval_run_id", "doc_id", "content", "metadata", "score", "rank", "created_at"},
        "generation_runs": {"id", "cve_id", "prompt", "response", "model", "status", "created_at"},
        "qa_runs": {"id", "generation_run_id", "qa_result", "qa_score", "qa_feedback", "created_at"},
        "approved_playbooks": {"id", "generation_run_id", "playbook", "version", "approved_at", "created_at"},
    }
    for table, expected_cols in required.items():
        cols = set(get_columns(conn, table))
        missing = sorted(expected_cols - cols)
        if not missing:
            add_result(results, f"schema_{table}", "PASS", f"{table} has expected columns", {"columns": sorted(cols)})
        else:
            add_result(results, f"schema_{table}", "FAIL", f"{table} missing columns: {missing}", {"columns": sorted(cols), "missing": missing})


def validate_latest_run(conn, cve_id: str, limit: int, results: List[Dict[str, Any]]):
    rr = latest_retrieval_run(conn, cve_id)
    gr = latest_generation_run(conn, cve_id)

    if not rr:
        add_result(results, "latest_retrieval_run", "FAIL", f"No retrieval_runs row found for {cve_id}")
        return
    add_result(results, "latest_retrieval_run", "PASS", f"Found retrieval_run_id={rr['id']}", {"retrieval_run_id": rr["id"]})

    docs = retrieval_docs_for_run(conn, rr["id"], limit)
    if not docs:
        add_result(results, "retrieval_documents", "FAIL", f"No retrieval_documents found for retrieval_run_id={rr['id']}")
    else:
        add_result(results, "retrieval_documents", "PASS", f"Found {len(docs)} retrieval_documents", {"count": len(docs)})

    retrieved_context = rr.get("retrieved_context")
    source_indexes = rr.get("source_indexes")

    if retrieved_context:
        add_result(results, "retrieved_context", "PASS", "retrieved_context populated")
    else:
        add_result(results, "retrieved_context", "FAIL", "retrieved_context is empty/null")

    if source_indexes:
        add_result(results, "source_indexes", "PASS", "source_indexes populated", {"source_indexes": source_indexes})
    else:
        add_result(results, "source_indexes", "FAIL", "source_indexes is empty/null")

    if gr:
        add_result(results, "latest_generation_run", "PASS", f"Found generation_run_id={gr['id']}", {"generation_run_id": gr["id"], "status": gr.get("status")})
    else:
        add_result(results, "latest_generation_run", "FAIL", f"No generation_runs row found for {cve_id}")
        return

    qa = latest_qa_for_generation(conn, gr["id"])
    ap = latest_approval_for_generation(conn, gr["id"])

    if qa:
        add_result(results, "qa_for_latest_generation", "PASS", f"Found qa_run_id={qa['id']}", {"qa_result": qa.get("qa_result"), "qa_score": str(qa.get("qa_score"))})
    else:
        add_result(results, "qa_for_latest_generation", "FAIL", f"No qa_runs row found for generation_run_id={gr['id']}")

    if ap:
        add_result(results, "approval_for_latest_generation", "PASS", f"Found approved_playbook_id={ap['id']}")
    else:
        add_result(results, "approval_for_latest_generation", "FAIL", f"No approved_playbooks row found for generation_run_id={gr['id']}")

    validate_prompt_quality(gr, results)
    validate_retrieval_quality(rr, docs, results)
    validate_lineage_isolation(conn, cve_id, rr["id"], gr["id"], results)


def validate_prompt_quality(gr: Dict[str, Any], results: List[Dict[str, Any]]):
    prompt = gr.get("prompt") or ""
    response = gr.get("response") or ""

    prompt_checks = {
        "contains_cve_context": "CVE Context" in prompt or "CVE Context Data" in prompt,
        "contains_retrieved_evidence": "Retrieved Evidence" in prompt,
        "contains_output_schema": "Output Schema" in prompt,
        "contains_source_section": "Sources:" in prompt or "Source:" in prompt,
    }
    missing = [k for k, v in prompt_checks.items() if not v]
    if not missing:
        add_result(results, "prompt_quality", "PASS", "Prompt contains core sections", {"length": len(prompt)})
    else:
        add_result(results, "prompt_quality", "WARN", f"Prompt missing sections: {missing}", {"length": len(prompt), "missing": missing})

    if response.strip():
        add_result(results, "response_nonempty", "PASS", "Generation response is non-empty", {"length": len(response)})
    else:
        add_result(results, "response_nonempty", "FAIL", "Generation response is empty")


def validate_retrieval_quality(rr: Dict[str, Any], docs: List[Dict[str, Any]], results: List[Dict[str, Any]]):
    duplicates = 0
    contents_seen = set()
    non_placeholder = 0
    opensearch_docs = 0
    vulnstrike_docs = 0

    for d in docs:
        content = (d.get("content") or "").strip()
        metadata = d.get("metadata") or {}
        source = metadata.get("source_index") or metadata.get("retrieval_source") or ""

        if content in contents_seen and content:
            duplicates += 1
        contents_seen.add(content)

        if content and content != "Test vulnerability context":
            non_placeholder += 1

        if metadata.get("retrieval_source") == "opensearch" or "spring-ai-document-index" in str(source):
            opensearch_docs += 1
        if metadata.get("retrieval_source") == "vulnstrike" or str(source).startswith("vulnstrike."):
            vulnstrike_docs += 1

    decision = None
    if isinstance(rr.get("retrieved_context"), dict):
        decision = rr["retrieved_context"].get("decision")

    dup_ratio = duplicates / len(docs) if docs else 0.0
    detail = {
        "decision": decision,
        "doc_count": len(docs),
        "duplicates": duplicates,
        "duplicate_ratio": round(dup_ratio, 3),
        "non_placeholder_docs": non_placeholder,
        "opensearch_docs": opensearch_docs,
        "vulnstrike_docs": vulnstrike_docs,
    }

    if non_placeholder == 0:
        add_result(results, "retrieval_quality", "FAIL", "All retrieval docs appear placeholder or empty", detail)
    elif dup_ratio > 0.6:
        add_result(results, "retrieval_quality", "WARN", "Retrieval quality is weak due to high duplication", detail)
    elif decision == "weak":
        add_result(results, "retrieval_quality", "WARN", "Retrieval decision is weak", detail)
    else:
        add_result(results, "retrieval_quality", "PASS", "Retrieval quality looks usable", detail)


def validate_lineage_isolation(conn, cve_id: str, retrieval_run_id: int, generation_run_id: int, results: List[Dict[str, Any]]):
    # First check if generation_runs has retrieval_run_id column
    columns = get_columns(conn, "generation_runs")
    has_retrieval_run_id = "retrieval_run_id" in columns
    
    if has_retrieval_run_id:
        # Use direct foreign key relationship
        rows = fetch_all(
            conn,
            """
            SELECT
                rr.id AS retrieval_run_id,
                rd.id AS retrieval_document_id,
                gr.id AS generation_run_id,
                qr.id AS qa_run_id,
                ap.id AS approved_playbook_id
            FROM retrieval_runs rr
            LEFT JOIN retrieval_documents rd
                ON rd.retrieval_run_id = rr.id
            LEFT JOIN generation_runs gr
                ON gr.retrieval_run_id = rr.id
            LEFT JOIN qa_runs qr
                ON qr.generation_run_id = gr.id
            LEFT JOIN approved_playbooks ap
                ON ap.generation_run_id = gr.id
            WHERE rr.cve_id = %s
              AND rr.id = %s
            ORDER BY rd.id DESC, gr.id DESC
            LIMIT 100
            """,
            (cve_id, retrieval_run_id),
        )
    else:
        # Fallback to CVE-based linking (old behavior)
        rows = fetch_all(
            conn,
            """
            SELECT
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
              AND rr.id = %s
            ORDER BY rd.id DESC, gr.id DESC
            LIMIT 100
            """,
            (cve_id, retrieval_run_id),
        )
    
    linked_generation_ids = sorted({r["generation_run_id"] for r in rows if r.get("generation_run_id") is not None})
    
    if has_retrieval_run_id:
        # With retrieval_run_id, we should have clean 1:1 mapping
        if linked_generation_ids == [generation_run_id]:
            add_result(results, "lineage_isolation", "PASS", "Retrieval run maps cleanly to generation run via retrieval_run_id", 
                      {"generation_ids": linked_generation_ids, "has_retrieval_run_id": True})
        elif not linked_generation_ids:
            add_result(results, "lineage_isolation", "WARN", "No generation run linked to this retrieval run via retrieval_run_id", 
                      {"generation_ids": linked_generation_ids, "has_retrieval_run_id": True})
        else:
            add_result(results, "lineage_isolation", "WARN", "Multiple generation runs linked to this retrieval run", 
                      {"generation_ids": linked_generation_ids, "has_retrieval_run_id": True})
    else:
        # Old behavior - CVE-based linking
        if linked_generation_ids == [generation_run_id]:
            add_result(results, "lineage_isolation", "PASS", "Latest retrieval run maps cleanly to latest generation run", 
                      {"generation_ids": linked_generation_ids, "has_retrieval_run_id": False})
        else:
            add_result(results, "lineage_isolation", "WARN", "Latest retrieval run links to multiple generation runs for the same CVE", 
                      {"generation_ids": linked_generation_ids, "has_retrieval_run_id": False})


def summarize(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    overall = "PASS"
    for r in results:
        if r["status"] == "FAIL":
            overall = "FAIL"
            break
        if r["status"] == "WARN" and overall != "FAIL":
            overall = "WARN"
    return {
        "overall_status": overall,
        "checks": results,
        "pass_count": sum(1 for r in results if r["status"] == "PASS"),
        "warn_count": sum(1 for r in results if r["status"] == "WARN"),
        "fail_count": sum(1 for r in results if r["status"] == "FAIL"),
    }


def print_report(summary: Dict[str, Any], cve_id: str):
    print("\n" + "=" * 84)
    print("PLAYBOOK ENGINE RUN VALIDATION")
    print("=" * 84)
    print(f"CVE: {cve_id}")
    print(f"OVERALL STATUS: {summary['overall_status']}")
    print("-" * 84)

    for r in summary["checks"]:
        print(f"[{r['status']:<4}] {r['check']}: {r['detail']}")
        if "extra" in r:
            print(f"       extra={json.dumps(r['extra'], default=str)}")

    print("-" * 84)
    print(
        f"PASS={summary['pass_count']}  WARN={summary['warn_count']}  FAIL={summary['fail_count']}"
    )
    print("=" * 84)
    print("\nJSON_SUMMARY:")
    print(json.dumps(summary, indent=2, default=str))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cve", default=DEFAULT_CVE, help="CVE ID to validate")
    parser.add_argument("--limit", type=int, default=20, help="Max retrieval docs to inspect")
    args = parser.parse_args()

    results: List[Dict[str, Any]] = []

    try:
        with get_conn() as conn:
            validate_db_target(conn, results)
            validate_schema(conn, results)
            validate_latest_run(conn, args.cve, args.limit, results)

        summary = summarize(results)
        print_report(summary, args.cve)
        sys.exit(0 if summary["overall_status"] != "FAIL" else 1)

    except Exception as e:
        failure = {
            "overall_status": "FAIL",
            "checks": [{"check": "runtime_exception", "status": "FAIL", "detail": str(e)}],
            "pass_count": 0,
            "warn_count": 0,
            "fail_count": 1,
        }
        print_report(failure, args.cve)
        sys.exit(1)


if __name__ == "__main__":
    main()
