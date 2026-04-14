"""
Service: Playbook Engine DB Initialization
Version: v0.1.0
Timestamp: 2026-04-07 UTC

Purpose:
- Create PostgreSQL database (if not exists)
- Create core tables, indexes, and constraints
- Idempotent execution (safe to rerun)
"""

import os
import psycopg2
from psycopg2 import sql

DB_NAME = os.getenv("DB_NAME", "playbook_engine")
DB_USER = os.getenv("DB_USER", "vulnstrike")
DB_PASSWORD = os.getenv("DB_PASSWORD", "vulnstrike")
DB_HOST = os.getenv("DB_HOST", "10.0.0.110")
DB_PORT = os.getenv("DB_PORT", "5432")


def create_database():
    """Create database if it does not exist."""
    conn = psycopg2.connect(
        dbname="postgres",
        user=DB_USER,
        password=DB_PASSWORD,
        host=DB_HOST,
        port=DB_PORT
    )
    conn.autocommit = True
    cur = conn.cursor()

    cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (DB_NAME,))
    exists = cur.fetchone()

    if not exists:
        print(f"[+] Creating database: {DB_NAME}")
        cur.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(DB_NAME)))
    else:
        print(f"[=] Database already exists: {DB_NAME}")

    cur.close()
    conn.close()


def connect_db():
    """Connect to target database."""
    return psycopg2.connect(
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        host=DB_HOST,
        port=DB_PORT
    )


def create_tables(conn):
    """Create all core tables."""
    cur = conn.cursor()

    print("[+] Creating tables...")

    # CVE Queue
    cur.execute("""
    CREATE TABLE IF NOT EXISTS cve_queue (
        id SERIAL PRIMARY KEY,
        cve_id TEXT UNIQUE NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        priority INTEGER DEFAULT 5,
        retry_count INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # Generation Runs
    cur.execute("""
    CREATE TABLE IF NOT EXISTS generation_runs (
        id SERIAL PRIMARY KEY,
        cve_id TEXT NOT NULL,
        prompt TEXT,
        response TEXT,
        model TEXT,
        status TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # Retrieval Runs
    cur.execute("""
    CREATE TABLE IF NOT EXISTS retrieval_runs (
        id SERIAL PRIMARY KEY,
        cve_id TEXT NOT NULL,
        retrieved_context JSONB,
        source_indexes TEXT[],
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # Prompt Templates
    cur.execute("""
    CREATE TABLE IF NOT EXISTS prompt_templates (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        version TEXT NOT NULL,
        template TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # QA Results
    cur.execute("""
    CREATE TABLE IF NOT EXISTS qa_results (
        id SERIAL PRIMARY KEY,
        generation_run_id INTEGER,
        score NUMERIC,
        feedback TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    conn.commit()
    cur.close()


def create_indexes(conn):
    """Create indexes for performance."""
    cur = conn.cursor()

    print("[+] Creating indexes...")

    cur.execute("CREATE INDEX IF NOT EXISTS idx_cve_queue_status ON cve_queue(status);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_generation_cve ON generation_runs(cve_id);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_retrieval_cve ON retrieval_runs(cve_id);")

    conn.commit()
    cur.close()


def verify(conn):
    """Verify tables exist."""
    cur = conn.cursor()

    cur.execute("""
    SELECT table_name FROM information_schema.tables
    WHERE table_schema = 'public';
    """)

    tables = cur.fetchall()

    print("\n[✓] Tables in database:")
    for t in tables:
        print(f" - {t[0]}")

    cur.close()


def main():
    print("=== Playbook Engine DB Initialization ===")

    create_database()

    conn = connect_db()

    create_tables(conn)
    create_indexes(conn)
    verify(conn)

    conn.close()

    print("\n[✓] DB setup complete.")


if __name__ == "__main__":
    main()