"""
Audit table catalog
Version: v0.1.0
Timestamp (UTC): 2026-04-15
"""

TABLE_CATALOG = [
    {
        "database": "playbook_engine",
        "schema": "public",
        "table": "cve_queue",
        "role": "primary runtime queue for claim/retry/failure state",
        "expected_columns": ["id", "cve_id", "status", "retry_count", "failure_type", "created_at", "updated_at"],
        "timestamp_candidates": ["updated_at", "created_at"],
    },
    {
        "database": "playbook_engine",
        "schema": "public",
        "table": "cve_context_snapshot",
        "role": "context snapshot created before generation",
        "expected_columns": ["id", "cve_id"],
        "timestamp_candidates": ["created_at", "updated_at", "captured_at"],
    },
    {
        "database": "playbook_engine",
        "schema": "public",
        "table": "generation_runs",
        "role": "raw generation output and execution history",
        "expected_columns": ["id", "cve_id", "status", "response", "created_at", "retrieval_run_id"],
        "timestamp_candidates": ["created_at", "updated_at"],
    },
    {
        "database": "playbook_engine",
        "schema": "public",
        "table": "qa_runs",
        "role": "QA decisions and feedback tied to generation runs",
        "expected_columns": ["id", "generation_run_id", "qa_result", "qa_score", "created_at"],
        "timestamp_candidates": ["created_at", "updated_at"],
    },
    {
        "database": "playbook_engine",
        "schema": "public",
        "table": "approved_playbooks",
        "role": "approved playbooks in playbook_engine control plane",
        "expected_columns": ["id", "cve_id", "generation_run_id", "playbook", "version", "approved_at"],
        "timestamp_candidates": ["approved_at", "created_at", "updated_at"],
    },
    {
        "database": "playbook_engine",
        "schema": "public",
        "table": "retrieval_runs",
        "role": "retrieval execution history linked to generation runs",
        "expected_columns": ["id"],
        "timestamp_candidates": ["created_at", "updated_at"],
    },
    {
        "database": "playbook_engine",
        "schema": "public",
        "table": "retrieval_documents",
        "role": "documents/evidence linked to retrieval runs",
        "expected_columns": ["id", "retrieval_run_id"],
        "timestamp_candidates": ["created_at", "updated_at"],
    },
    {
        "database": "playbook_engine",
        "schema": "public",
        "table": "prompt_templates",
        "role": "prompt template control-plane table",
        "expected_columns": ["id", "name"],
        "timestamp_candidates": ["created_at", "updated_at"],
    },
    {
        "database": "playbook_engine",
        "schema": "public",
        "table": "prompt_template_versions",
        "role": "versioned prompt templates used by generation",
        "expected_columns": ["id", "template_id"],
        "timestamp_candidates": ["created_at", "updated_at"],
    },
    {
        "database": "playbook_engine",
        "schema": "public",
        "table": "continuous_execution_locks",
        "role": "optional lock table used by older runner path",
        "expected_columns": ["cve_id", "status"],
        "timestamp_candidates": ["lock_acquired_at", "lock_released_at", "created_at", "updated_at"],
    },
    {
        "database": "vulnstrike",
        "schema": "public",
        "table": "playbooks",
        "role": "production playbook table used by production guard",
        "expected_columns": ["id", "cve_id", "created_at", "updated_at"],
        "timestamp_candidates": ["updated_at", "created_at"],
    },
]