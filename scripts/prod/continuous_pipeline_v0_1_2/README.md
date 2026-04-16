# Continuous Pipeline v0.1.2

## Purpose
Isolated queue worker that produces a real playbook result by bridging into the existing proven CVE processing path.

## Responsibilities
- Claim one CVE atomically from `playbook_engine.public.cve_queue`
- Re-check whether the CVE already exists in `vulnstrike.public.playbooks`
- Run the existing direct-CVE processing path for the claimed CVE
- Mark the queue row `completed` only on success
- Mark the queue row `failed` on failure

## Non-Goals
- No OpenSearch intake
- No mutation of original Gen-3 code
- No new QA redesign
- No new promotion redesign

## Run Command
python -m scripts.prod.continuous_pipeline_v0_1_2.queue_worker_v0_1_2

## Status Lifecycle
- `pending`
- `processing`
- `completed`
- `failed`

## Success Criteria
- Two concurrent workers do not claim the same row
- Worker produces a real processing result
- Already-produced CVEs are skipped before processing
- Clean worker summary output