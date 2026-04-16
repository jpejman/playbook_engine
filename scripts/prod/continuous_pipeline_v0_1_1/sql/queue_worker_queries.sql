-- Atomic claim of one pending row
WITH next_item AS (
    SELECT id
    FROM public.cve_queue
    WHERE status = 'pending'
    ORDER BY created_at ASC
    FOR UPDATE SKIP LOCKED
    LIMIT 1
)
UPDATE public.cve_queue q
SET status = 'processing',
    updated_at = NOW()
FROM next_item
WHERE q.id = next_item.id
RETURNING q.id, q.cve_id, q.status, q.created_at, q.updated_at;

-- Mark completed
UPDATE public.cve_queue
SET status = 'completed',
    updated_at = NOW()
WHERE id = $1;

-- Mark failed
UPDATE public.cve_queue
SET status = 'failed',
    updated_at = NOW()
WHERE id = $1;