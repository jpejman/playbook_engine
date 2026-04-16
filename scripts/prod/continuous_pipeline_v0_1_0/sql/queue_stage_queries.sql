-- Queue existence check
SELECT EXISTS (
    SELECT 1 FROM cve_queue WHERE cve_id = $1
);

-- Insert into queue
INSERT INTO cve_queue (cve_id, status)
VALUES ($1, 'pending')
ON CONFLICT DO NOTHING;