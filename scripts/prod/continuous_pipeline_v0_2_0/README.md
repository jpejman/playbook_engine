# Continuous Pipeline v0.2.0

## Purpose
Self-contained CVE intake and processing service.

## What changed from v0.1.4
- Removes the external `scripts.prod.phase1_direct_cve_runner` dependency.
- Adds internal OpenSearch/NVD intake and queue population.
- Keeps queue claiming, retries, and worker orchestration inside the package.
- Uses `vulnstrike.public.playbooks` as a production skip guard and `playbook_engine.public.generation_runs` as a generated-output skip guard.

## Internal flow
1. Pull candidate CVEs from OpenSearch/NVD.
2. Filter out CVEs already in production or already generated.
3. Insert eligible CVEs into `playbook_engine.public.cve_queue` as `pending`.
4. Atomically claim pending items with `FOR UPDATE SKIP LOCKED`.
5. Fetch the CVE context from OpenSearch.
6. Build a remediation prompt.
7. Call the configured LLM endpoint.
8. Persist context, retrieval, and generation records in `playbook_engine`.
9. Mark queue item `completed`, `failed`, or `pending` again.

## Run commands

### Fill queue only
```bash
python -m scripts.prod.continuous_pipeline_v0_2_0.fill_queue_v0_2_0 --target-enqueue 25
```

### Single worker
```bash
python -m scripts.prod.continuous_pipeline_v0_2_0.queue_worker_v0_2_0
```

### Batch mode
```bash
python -m scripts.prod.continuous_pipeline_v0_2_0.queue_worker_v0_2_0 --batch-size 10
```

### Multi-worker orchestrator shape
```bash
python -m scripts.prod.continuous_pipeline_v0_2_0.queue_worker_v0_2_0 --workers 4 --batch-size 10
```

### Continuous loop
```bash
python -m scripts.prod.continuous_pipeline_v0_2_0.queue_worker_v0_2_0 --loop --workers 2 --batch-size 5 --wait-seconds 5
```

## Required environment
- `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`
- `OPENSEARCH_URL`, optionally `OPENSEARCH_INDEX`, `OPENSEARCH_USERNAME`, `OPENSEARCH_PASSWORD`
- `LLM_BASE_URL`, optionally `LLM_GENERATE_PATH`, `LLM_MODEL`, `LLM_TIMEOUT_SECONDS`

## Validation order
1. Queue fill with `--target-enqueue 5`
2. Single worker
3. Batch 5
4. Batch 25
5. Loop or orchestrator

## Commit timing
Do not commit this version until:
- queue fill succeeds against OpenSearch
- worker writes a non-empty completed `generation_runs` record
- queue items transition correctly through `pending -> processing -> completed/failed`
- at least one batch run completes cleanly without crashing
