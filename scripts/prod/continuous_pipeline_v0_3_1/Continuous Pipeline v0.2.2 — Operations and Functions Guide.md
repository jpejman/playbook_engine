# Continuous Pipeline v0.2.2 — Operations and Functions Guide
## Version: v0.2.2
## Timestamp (ET): 2026-04-18

---

# 1. Purpose

The continuous pipeline is a queue-driven CVE processing system that:

1. pulls eligible CVEs from OpenSearch  
2. enqueues them into `playbook_engine.public.cve_queue`  
3. processes queued CVEs through the canonical pipeline  
4. stores outputs in `generation_runs`  
5. records metadata for each run:
   - `model`
   - `run_duration_seconds`
   - `creator_script`

---

# 2. Core Runtime Components

## 2.1 Feeder
Script:

scripts.prod.continuous_pipeline_v0_2_1.fill_queue_v0_2_1


Purpose:
- Finds fresh CVEs
- Applies dedupe rules
- Inserts into queue

Key behavior:
- Uses persistent cursor when enabled
- Avoids reprocessing completed CVEs
- Traverses full NVD corpus over time

---

## 2.2 Worker
Script:

scripts.prod.continuous_pipeline_v0_2_1.queue_worker_v0_2_1


Purpose:
- Claims pending CVEs
- Runs generation
- Validates output
- Updates queue + DB

Key behavior:
- Batch processing supported
- Retry logic for transient failures
- Writes metadata to `generation_runs`

---

## 2.3 Diagnostics
Script:

scripts.prod.continuous_pipeline_v0_2_1.diagnostics_v0_2_1


Purpose:
- Verify system health
- Show queue state
- Show feeder cursor state
- Show recent runs

---

## 2.4 Debug Runner
Script:

scripts.prod.continuous_pipeline_v0_2_1.debug_run_cve_v0_2_1


Purpose:
- Run single CVE
- Troubleshoot output
- Validate generation path

---

# 3. v0.2.2 Metadata Enhancements

## generation_runs fields

### model
Stores model used

### run_duration_seconds
Tracks execution time

### creator_script
Tracks which script generated the output

---

# 4. Environment / Config Behavior

## 4.1 LLM Model Selection

```python
DEFAULT_LLM_MODEL = "qwen3.5:4b"
LLM_MODEL = os.getenv("LLM_MODEL", DEFAULT_LLM_MODEL)
4.2 Persistent Cursor

Enable:

$env:CP_FEED_USE_PERSISTENT_CURSOR="true"

Effect:

Full dataset traversal
No repeated shallow scanning
5. Standard Workflows
5.1 Health Check
python -m scripts.prod.continuous_pipeline_v0_2_1.diagnostics_v0_2_1
5.2 Fill Queue
python -m scripts.prod.continuous_pipeline_v0_2_1.fill_queue_v0_2_1 --target-enqueue 20
5.3 Single Worker
python -m scripts.prod.continuous_pipeline_v0_2_1.queue_worker_v0_2_1
5.4 Batch Worker
python -m scripts.prod.continuous_pipeline_v0_2_1.queue_worker_v0_2_1 --batch-size 10
5.5 Debug CVE
python -m scripts.prod.continuous_pipeline_v0_2_1.debug_run_cve_v0_2_1 --cve-id CVE-XXXX
5.6 Full Cycle
diagnostics → fill_queue → worker → diagnostics
6. Command Reference
Diagnostics
python -m scripts.prod.continuous_pipeline_v0_2_1.diagnostics_v0_2_1
Fill Queue
--target-enqueue 5
--target-enqueue 20
--target-enqueue 100

Extended:

--page-size
--max-scan
--max-scan-windows
--max-total-scan
--min-enqueue-required
Worker
--batch-size 5
--batch-size 10
--batch-size 50
--batch-size 100
Debug Runner
--cve-id
--verify-only
--generation-run-id
7. Model Testing
Default
python -m scripts.prod.continuous_pipeline_v0_2_1.queue_worker_v0_2_1 --batch-size 5
Override
$env:LLM_MODEL="qwen3:8b"
8. Persistent Cursor Commands
$env:CP_FEED_USE_PERSISTENT_CURSOR="true"

Run:

fill_queue --target-enqueue 20
9. Operator Guidance
Run Feeder When
queue is low
Do NOT Run Feeder When
backlog already large
Run Worker When
queue has pending items
10. SQL Validation
Queue Counts
SELECT status, COUNT(*) FROM public.cve_queue GROUP BY status;
Recent Runs
SELECT id, cve_id, model, run_duration_seconds
FROM public.generation_runs
ORDER BY id DESC
LIMIT 20;
11. Full Runbook
Step 1
.\.venv\Scripts\Activate
$env:CP_FEED_USE_PERSISTENT_CURSOR="true"
Step 2
diagnostics
Step 3
fill_queue --target-enqueue 20
Step 4
queue_worker --batch-size 10
Step 5
diagnostics