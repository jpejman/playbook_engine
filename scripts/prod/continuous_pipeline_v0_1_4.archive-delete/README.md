# Continuous Pipeline v0.1.4

## Purpose
Large-scale continuous CVE processing system with multi-worker batch orchestration.

## Features
- Multi-worker batch orchestration
- Continuous execution loop
- Safe queue draining
- Retry-aware processing
- Production-safe completion gating

## Run Commands

### Single Worker Mode
```bash
python -m scripts.prod.continuous_pipeline_v0_1_4.queue_worker_v0_1_4
```

### Batch Mode
```bash
python -m scripts.prod.continuous_pipeline_v0_1_4.queue_worker_v0_1_4 --batch-size 10
```

### Multi-Worker Mode
```bash
python -m scripts.prod.continuous_pipeline_v0_1_4.queue_worker_v0_1_4 --workers 4 --batch-size 5
```

### Loop Mode
```bash
python -m scripts.prod.continuous_pipeline_v0_1_4.queue_worker_v0_1_4 --loop --workers 2 --batch-size 3 --wait-seconds 10
```

### Direct Run Loop
```bash
python -m scripts.prod.continuous_pipeline_v0_1_4.run_loop_v0_1_4 --workers 3 --batch-size 4 --wait-seconds 15
```

### Batch Orchestrator
```bash
python -m scripts.prod.continuous_pipeline_v0_1_4.batch_orchestrator_v0_1_4 --workers 5 --batch-size 2
```

## Modes

1. **SINGLE**: Process one item
2. **BATCH**: Process N items sequentially
3. **PARALLEL**: Simulate multiple workers
4. **LOOP**: Continuous execution with sleep intervals

## Completion Rule
Items are marked COMPLETE only when:
- `execution_status == "completed"`
- `pipeline_status == "success"`
- `generation_run_id is not None`

Otherwise, failures are classified and either retried or marked as failed.

## Output Format
```
=== WORKER SUMMARY ===
Claimed: X
Completed: Y
Failed: Z
Requeued: W
```

## Guarantees
- No duplicate CVEs processed
- Atomic queue handling
- Safe parallel execution
- No modification to existing pipeline code