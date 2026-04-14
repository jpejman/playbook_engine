-- SQL Proof for Queue Integration + Idempotent Single-CVE Processing
-- Shows the current state of queue integration implementation

-- 1. Show queue table schema and current data
SELECT '1. Queue Table Schema and Current Data' as section;
SELECT 
    column_name, 
    data_type,
    is_nullable,
    column_default
FROM information_schema.columns 
WHERE table_name = 'cve_queue'
ORDER BY ordinal_position;

SELECT 'Current queue items:' as note;
SELECT 
    id,
    cve_id,
    status,
    priority,
    retry_count,
    created_at,
    updated_at
FROM cve_queue
ORDER BY id;

-- 2. Show approved playbooks and their CVEs
SELECT '2. Approved Playbooks and CVEs' as section;
SELECT 
    ap.id as approved_id,
    gr.cve_id,
    gr.id as generation_run_id,
    ap.created_at as approved_at
FROM approved_playbooks ap
JOIN generation_runs gr ON ap.generation_run_id = gr.id
ORDER BY ap.created_at DESC
LIMIT 5;

-- 3. Show CVEs with context snapshots
SELECT '3. CVEs with Context Snapshots' as section;
SELECT 
    cve_id,
    created_at
FROM cve_context_snapshot
ORDER BY created_at DESC;

-- 4. Show idempotency check: CVEs that would be skipped
SELECT '4. Idempotency Check - CVEs to Skip' as section;
SELECT 
    gr.cve_id,
    'Has approved playbook' as reason
FROM approved_playbooks ap
JOIN generation_runs gr ON ap.generation_run_id = gr.id
UNION
SELECT 
    cve_id,
    'Queue status: ' || status as reason
FROM cve_queue
WHERE status IN ('completed', 'processing')
ORDER BY cve_id;

-- 5. Show eligible CVEs for processing
SELECT '5. Eligible CVEs for Processing' as section;
SELECT 
    cs.cve_id,
    'Has context snapshot, no approved playbook' as eligibility
FROM cve_context_snapshot cs
LEFT JOIN (
    SELECT DISTINCT gr.cve_id
    FROM approved_playbooks ap
    JOIN generation_runs gr ON ap.generation_run_id = gr.id
) ap ON cs.cve_id = ap.cve_id
LEFT JOIN cve_queue cq ON cs.cve_id = cq.cve_id
WHERE ap.cve_id IS NULL
AND (cq.cve_id IS NULL OR cq.status NOT IN ('completed', 'processing'))
ORDER BY cs.created_at DESC;

-- 6. Show queue status transition proof
SELECT '6. Queue Status Transition Proof' as section;
SELECT 
    cve_id,
    status,
    CASE 
        WHEN status = 'pending' THEN 'Ready for processing'
        WHEN status = 'processing' THEN 'Currently being processed'
        WHEN status = 'completed' THEN 'Successfully processed'
        WHEN status = 'failed' THEN 'Processing failed, can be retried'
        WHEN status = 'skipped' THEN 'Skipped (e.g., has approved playbook)'
        ELSE 'Unknown status'
    END as status_meaning,
    retry_count,
    updated_at
FROM cve_queue
ORDER BY updated_at DESC;

-- 7. Summary statistics
SELECT '7. Queue Integration Summary' as section;
SELECT 
    (SELECT COUNT(*) FROM cve_queue) as total_queue_items,
    (SELECT COUNT(*) FROM cve_queue WHERE status = 'pending') as pending_items,
    (SELECT COUNT(*) FROM cve_queue WHERE status = 'processing') as processing_items,
    (SELECT COUNT(*) FROM cve_queue WHERE status = 'completed') as completed_items,
    (SELECT COUNT(*) FROM cve_queue WHERE status = 'failed') as failed_items,
    (SELECT COUNT(*) FROM approved_playbooks) as total_approved_playbooks,
    (SELECT COUNT(DISTINCT gr.cve_id) FROM approved_playbooks ap JOIN generation_runs gr ON ap.generation_run_id = gr.id) as unique_cves_with_playbooks;