"""
Service: Playbook Engine DB Test
Version: v0.1.1
Timestamp: 2026-04-07 UTC

Purpose:
- Validate sidecar PostgreSQL database connectivity
- Confirm required tables, columns, indexes, and foreign keys
- Run transactional smoke tests without persisting data
"""

import os
import sys
import psycopg2
from psycopg2.extras import Json
from dotenv import load_dotenv

load_dotenv()

DB_HOST = os.getenv("DB_HOST", "10.0.0.110")
DB_PORT = int(os.getenv("DB_PORT", "5432"))
DB_NAME = os.getenv("DB_NAME", "playbook_engine")
DB_USER = os.getenv("DB_USER", "vulnstrike")
DB_PASSWORD = os.getenv("DB_PASSWORD", "vulnstrike")

REQUIRED_TABLES = {
    "cve_queue": [
        "id", "cve_id", "status", "priority", "retry_count", "source", "created_at", "updated_at"
    ],
    "cve_context_snapshot": [
        "id", "cve_id", "source", "snapshot_json", "snapshot_hash", "created_at"
    ],
    "retrieval_runs": [
        "id", "cve_id", "queue_id", "retrieval_type", "keyword_query",
        "vector_query_metadata", "retrieval_metadata", "created_at"
    ],
    "retrieval_documents": [
        "id", "retrieval_run_id", "source_index", "document_id", "score",
        "rank", "document_metadata", "created_at"
    ],
    "prompt_templates": [
        "id", "name", "description", "is_active", "created_at"
    ],
    "prompt_template_versions": [
        "id", "template_id", "version", "system_block", "instruction_block",
        "workflow_block", "output_schema_block", "created_at"
    ],
    "generation_runs": [
        "id", "cve_id", "queue_id", "prompt_template_version_id", "rendered_prompt",
        "prompt_inputs", "model_name", "raw_response", "parsed_response", "status", "created_at"
    ],
    "qa_runs": [
        "id", "generation_run_id", "qa_result", "qa_score", "qa_feedback", "created_at"
    ],
    "approved_playbooks": [
        "id", "cve_id", "generation_run_id", "playbook", "version", "approved_at"
    ],
}

REQUIRED_INDEXES = [
    "idx_cve_queue_status",
    "idx_cve_queue_priority",
    "idx_cve_queue_created_at",
    "idx_cve_context_snapshot_cve_id",
    "idx_retrieval_runs_cve_id",
    "idx_retrieval_runs_queue_id",
    "idx_retrieval_documents_run_id",
    "idx_prompt_templates_name",
    "idx_prompt_template_versions_template_id",
    "idx_generation_runs_cve_id",
    "idx_generation_runs_queue_id",
    "idx_generation_runs_status",
    "idx_qa_runs_generation_run_id",
    "idx_approved_playbooks_cve_id",
]

REQUIRED_FKS = [
    ("retrieval_runs", "queue_id", "cve_queue"),
    ("retrieval_documents", "retrieval_run_id", "retrieval_runs"),
    ("prompt_template_versions", "template_id", "prompt_templates"),
    ("generation_runs", "queue_id", "cve_queue"),
    ("generation_runs", "prompt_template_version_id", "prompt_template_versions"),
    ("qa_runs", "generation_run_id", "generation_runs"),
    ("approved_playbooks", "generation_run_id", "generation_runs"),
]


def connect():
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
    )


def print_header(title: str):
    print("\n" + "=" * 80)
    print(title)
    print("=" * 80)


def pass_fail(label: str, ok: bool, detail: str = ""):
    prefix = "[PASS]" if ok else "[FAIL]"
    print(f"{prefix} {label}" + (f" :: {detail}" if detail else ""))


def warn(label: str, detail: str = ""):
    print(f"[WARN] {label}" + (f" :: {detail}" if detail else ""))


def get_current_identity(cur):
    cur.execute("SELECT current_database(), current_user, version()")
    return cur.fetchone()


def check_tables(cur):
    print_header("TABLE CHECK")
    cur.execute("""
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = 'public'
        ORDER BY table_name
    """)
    existing = {row[0] for row in cur.fetchall()}

    all_ok = True
    for table in REQUIRED_TABLES:
        ok = table in existing
        pass_fail(f"table {table}", ok)
        if not ok:
            all_ok = False
    return all_ok


def check_columns(cur):
    print_header("COLUMN CHECK")
    all_ok = True
    for table, expected_cols in REQUIRED_TABLES.items():
        cur.execute("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = %s
            ORDER BY ordinal_position
        """, (table,))
        actual_cols = {row[0] for row in cur.fetchall()}
        for col in expected_cols:
            ok = col in actual_cols
            pass_fail(f"{table}.{col}", ok)
            if not ok:
                all_ok = False
    return all_ok


def check_indexes(cur):
    print_header("INDEX CHECK")
    cur.execute("""
        SELECT indexname
        FROM pg_indexes
        WHERE schemaname = 'public'
        ORDER BY indexname
    """)
    actual = {row[0] for row in cur.fetchall()}

    all_ok = True
    for idx in REQUIRED_INDEXES:
        ok = idx in actual
        pass_fail(f"index {idx}", ok)
        if not ok:
            all_ok = False
    return all_ok


def check_foreign_keys(cur):
    print_header("FOREIGN KEY CHECK")
    cur.execute("""
        SELECT
            tc.table_name,
            kcu.column_name,
            ccu.table_name AS foreign_table_name
        FROM information_schema.table_constraints AS tc
        JOIN information_schema.key_column_usage AS kcu
          ON tc.constraint_name = kcu.constraint_name
         AND tc.table_schema = kcu.table_schema
        JOIN information_schema.constraint_column_usage AS ccu
          ON ccu.constraint_name = tc.constraint_name
         AND ccu.table_schema = tc.table_schema
        WHERE tc.constraint_type = 'FOREIGN KEY'
          AND tc.table_schema = 'public'
        ORDER BY tc.table_name, kcu.column_name
    """)
    actual = {(row[0], row[1], row[2]) for row in cur.fetchall()}

    all_ok = True
    for fk in REQUIRED_FKS:
        ok = fk in actual
        pass_fail(f"fk {fk[0]}.{fk[1]} -> {fk[2]}", ok)
        if not ok:
            all_ok = False
    return all_ok


def smoke_test(conn):
    print_header("TRANSACTIONAL SMOKE TEST")
    ok = True

    # run inside transaction and roll back
    conn.autocommit = False
    cur = conn.cursor()

    try:
        # cve_queue
        cur.execute("""
            INSERT INTO cve_queue (cve_id, status, priority, retry_count, source)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id
        """, ("CVE-TEST-0001", "pending", 5, 0, "test_script"))
        queue_id = cur.fetchone()[0]
        pass_fail("insert cve_queue", True, f"id={queue_id}")

        # cve_context_snapshot
        cur.execute("""
            INSERT INTO cve_context_snapshot (cve_id, source, snapshot_json, snapshot_hash)
            VALUES (%s, %s, %s, %s)
            RETURNING id
        """, (
            "CVE-TEST-0001",
            "test_script",
            Json({"id": "CVE-TEST-0001", "description": "test snapshot"}),
            "hash-test-0001",
        ))
        snapshot_id = cur.fetchone()[0]
        pass_fail("insert cve_context_snapshot", True, f"id={snapshot_id}")

        # prompt_templates
        cur.execute("""
            INSERT INTO prompt_templates (name, description, is_active)
            VALUES (%s, %s, %s)
            RETURNING id
        """, ("test_template", "test template", True))
        template_id = cur.fetchone()[0]
        pass_fail("insert prompt_templates", True, f"id={template_id}")

        # prompt_template_versions
        cur.execute("""
            INSERT INTO prompt_template_versions
            (template_id, version, system_block, instruction_block, workflow_block, output_schema_block)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (
            template_id,
            "v-test",
            "system",
            "instruction",
            "workflow",
            "output schema",
        ))
        template_version_id = cur.fetchone()[0]
        pass_fail("insert prompt_template_versions", True, f"id={template_version_id}")

        # retrieval_runs
        cur.execute("""
            INSERT INTO retrieval_runs
            (cve_id, queue_id, retrieval_type, keyword_query, vector_query_metadata, retrieval_metadata)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (
            "CVE-TEST-0001",
            queue_id,
            "hybrid",
            "test query",
            Json({"vector": "meta"}),
            Json({"info": "retrieval"}),
        ))
        retrieval_run_id = cur.fetchone()[0]
        pass_fail("insert retrieval_runs", True, f"id={retrieval_run_id}")

        # retrieval_documents
        cur.execute("""
            INSERT INTO retrieval_documents
            (retrieval_run_id, source_index, document_id, score, rank, document_metadata)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (
            retrieval_run_id,
            "cve",
            "doc-1",
            0.99,
            1,
            Json({"title": "test doc"}),
        ))
        retrieval_doc_id = cur.fetchone()[0]
        pass_fail("insert retrieval_documents", True, f"id={retrieval_doc_id}")

        # generation_runs
        cur.execute("""
            INSERT INTO generation_runs
            (cve_id, queue_id, prompt_template_version_id, rendered_prompt, prompt_inputs,
             model_name, raw_response, parsed_response, status)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (
            "CVE-TEST-0001",
            queue_id,
            template_version_id,
            "rendered prompt",
            Json({"inputs": "test"}),
            "test-model",
            "raw response",
            Json({"parsed": "response"}),
            "created",
        ))
        generation_run_id = cur.fetchone()[0]
        pass_fail("insert generation_runs", True, f"id={generation_run_id}")

        # qa_runs
        cur.execute("""
            INSERT INTO qa_runs
            (generation_run_id, qa_result, qa_score, qa_feedback)
            VALUES (%s, %s, %s, %s)
            RETURNING id
        """, (
            generation_run_id,
            "pass",
            9.5,
            Json({"notes": "good"}),
        ))
        qa_run_id = cur.fetchone()[0]
        pass_fail("insert qa_runs", True, f"id={qa_run_id}")

        # approved_playbooks
        cur.execute("""
            INSERT INTO approved_playbooks
            (cve_id, generation_run_id, playbook, version)
            VALUES (%s, %s, %s, %s)
            RETURNING id
        """, (
            "CVE-TEST-0001",
            generation_run_id,
            Json({"playbook": "content"}),
            "v-test",
        ))
        approved_id = cur.fetchone()[0]
        pass_fail("insert approved_playbooks", True, f"id={approved_id}")

        # update cve_queue
        cur.execute("""
            UPDATE cve_queue
            SET status = %s, retry_count = %s, updated_at = NOW()
            WHERE id = %s
        """, ("retrieval_complete", 1, queue_id))
        pass_fail("update cve_queue", cur.rowcount == 1)

        # select joins
        cur.execute("""
            SELECT
                q.cve_id,
                rr.id,
                gr.id,
                qr.id,
                ap.id
            FROM cve_queue q
            LEFT JOIN retrieval_runs rr ON rr.queue_id = q.id
            LEFT JOIN generation_runs gr ON gr.queue_id = q.id
            LEFT JOIN qa_runs qr ON qr.generation_run_id = gr.id
            LEFT JOIN approved_playbooks ap ON ap.generation_run_id = gr.id
            WHERE q.id = %s
        """, (queue_id,))
        row = cur.fetchone()
        pass_fail("join path queue -> retrieval -> generation -> qa -> approved", row is not None)

        # uniqueness test
        uniqueness_ok = False
        try:
            cur.execute("""
                INSERT INTO cve_queue (cve_id, status, priority, retry_count, source)
                VALUES (%s, %s, %s, %s, %s)
            """, ("CVE-TEST-0001", "pending", 5, 0, "test_script"))
        except psycopg2.Error:
            uniqueness_ok = True
            conn.rollback()
            cur = conn.cursor()
            # recreate transaction state after rollback for final cleanup check
        pass_fail("unique constraint cve_queue.cve_id", uniqueness_ok)
        ok = ok and uniqueness_ok

        # rollback everything
        conn.rollback()
        pass_fail("transaction rollback", True, "all smoke-test data rolled back")

    except Exception as e:
        conn.rollback()
        pass_fail("transactional smoke test", False, str(e))
        ok = False
    finally:
        cur.close()
        conn.autocommit = False

    return ok


def main():
    print_header("PLAYBOOK ENGINE DB FULL TEST")
    print(f"Target host: {DB_HOST}:{DB_PORT}")
    print(f"Target db:   {DB_NAME}")
    print(f"Target user: {DB_USER}")

    try:
        conn = connect()
    except Exception as e:
        print(f"[FAIL] DB connection :: {e}")
        sys.exit(1)

    cur = conn.cursor()
    db_name, db_user, db_version = get_current_identity(cur)
    pass_fail("connected", True, f"database={db_name}, user={db_user}")
    print(f"PostgreSQL version: {db_version}")

    overall_ok = True
    overall_ok &= check_tables(cur)
    overall_ok &= check_columns(cur)
    overall_ok &= check_indexes(cur)
    overall_ok &= check_foreign_keys(cur)

    cur.close()

    overall_ok &= smoke_test(conn)

    conn.close()

    print_header("FINAL RESULT")
    if overall_ok:
        print("[PASS] All DB checks passed.")
        sys.exit(0)
    else:
        print("[FAIL] One or more DB checks failed.")
        sys.exit(2)


if __name__ == "__main__":
    main()