"""
Service: Playbook Engine
Script: phase1_finalize_playbook_v0_1_0.py
Version: v0.1.0
Timestamp: 2026-04-16 UTC
"""

INSERT_SQL = """
INSERT INTO approved_playbooks (cve_id, generation_run_id, playbook, version, approved_at, created_at)
SELECT
    gr.cve_id,
    gr.id,
    gr.response,
    'v1',
    NOW(),
    NOW()
FROM generation_runs gr
JOIN qa_runs qr ON qr.generation_run_id = gr.id
LEFT JOIN approved_playbooks ap ON ap.generation_run_id = gr.id
WHERE qr.qa_result = 'PASS'
AND ap.id IS NULL;
"""