-- Ensure queue columns exist
ALTER TABLE public.cve_queue ADD COLUMN IF NOT EXISTS retry_count INTEGER DEFAULT 0;
ALTER TABLE public.cve_queue ADD COLUMN IF NOT EXISTS last_error TEXT;
ALTER TABLE public.cve_queue ADD COLUMN IF NOT EXISTS failure_type VARCHAR(64);

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
RETURNING q.id, q.cve_id, q.status, q.created_at, q.updated_at, COALESCE(q.retry_count, 0) AS retry_count;

-- Mark completed
UPDATE public.cve_queue
SET status = 'completed',
    updated_at = NOW()
WHERE id = $1;

-- Mark failed
UPDATE public.cve_queue
SET status = 'failed',
    updated_at = NOW(),
    last_error = $2,
    failure_type = $3
WHERE id = $1;

-- Requeue retryable
UPDATE public.cve_queue
SET status = 'pending',
    updated_at = NOW(),
    retry_count = COALESCE(retry_count, 0) + 1,
    last_error = $2,
    failure_type = $3
WHERE id = $1;