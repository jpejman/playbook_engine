# Phase 1 Single-CVE Continuous Runner

## Overview

The `phase1_single_cve_continuous_runner.py` script implements a repeatable production run that selects and processes exactly one fresh CVE per execution using Phase 1 selection rules.

## Phase 1 Selection Rules

### Source of candidates:
- OpenSearch cve index only

### Filter:
- severity present
- CVSS score present
- not already approved in PostgreSQL
- not already processed in PostgreSQL

### Sort:
1. severity descending (CRITICAL > HIGH > MEDIUM > LOW)
2. CVSS descending (higher scores first)
3. published descending (newer CVEs first)

## Processing Rule

Each execution must:
1. Select exactly one fresh CVE
2. Build context
3. Run generation
4. Persist generation_runs row
5. Run QA
6. Stop

**Do not select multiple CVEs in one execution.**
**Do not batch.**
**Do not require manual CVE input.**

## Output For Each Run

Returns:
- timestamp_utc
- selected_cve
- source_of_selection = OpenSearch cve
- context_snapshot_id
- generation_run_id
- status
- generation_source
- llm_error_info
- qa_result
- qa_score
- approved_playbook_id if any

## Definition of Complete for Phase 1

A CVE is considered completed for this phase when it has:
- been selected from OpenSearch cve
- had context built
- had generation attempted
- had a generation_runs row persisted
- had QA executed

**APPROVAL is not required for Phase 1 completion** because parser/contract issue is a separate downstream blocker.

## Goal

Allow repeated execution of the same runner so that each run processes one fresh CVE and then moves to the next one on the following run.

## Usage

### Basic usage:
```bash
python phase1_single_cve_continuous_runner.py
```

### With options:
```bash
# Limit OpenSearch query to 50 CVEs
python phase1_single_cve_continuous_runner.py --limit 50

# Output JSON format
python phase1_single_cve_continuous_runner.py --json

# Enable verbose logging
python phase1_single_cve_continuous_runner.py --verbose

# Combine options
python phase1_single_cve_continuous_runner.py --limit 100 --json --verbose
```

### Exit codes:
- `0`: Phase 1 completed successfully
- `1`: Phase 1 failed (no CVE selected or errors occurred)

## Implementation Details

### Key Components:

1. **Phase1CVESelector**: Implements Phase 1 selection logic
   - Queries OpenSearch cve index with Phase 1 filters
   - Filters candidates against PostgreSQL with Phase 1 rules
   - Selects CVE using Phase 1 sorting criteria

2. **Phase1ContinuousRunner**: Orchestrates the complete Phase 1 pipeline
   - Runs selection → context snapshot → generation → QA
   - Returns required output with all metrics
   - Handles errors and tracks completion status

### Selection Algorithm:

1. Query OpenSearch for CVEs with:
   - `metrics` field present (CVSS score)
   - `published` field present
   - Sorted by `published` descending

2. For each candidate:
   - Extract severity from CVSS score
   - Skip if no CVSS score or severity
   - Skip test CVEs (CVE-TEST-, TEST-, DEMO-, etc.)

3. Filter against PostgreSQL:
   - Skip if already has approved playbook
   - Skip if already processed in generation_runs
   - Skip test CVEs

4. Sort eligible candidates by:
   - Severity descending (CRITICAL > HIGH > MEDIUM > LOW)
   - CVSS score descending
   - Published date descending

5. Select the top candidate

## Integration with Existing Pipeline

The runner integrates with existing scripts:
- Context snapshot: `scripts/02_85_build_context_snapshot_v0_1_0.py`
- Generation: `scripts/03_01_run_playbook_generation_v0_1_1_real_retrieval.py`
- QA: `scripts/06_08_qa_enforcement_gate_canonical_v0_2_0.py`

## Testing

To test the runner without executing the full pipeline, use the `--verbose` flag to see detailed logs. The runner will still execute all steps but provides visibility into each stage.

## Example Output

```
================================================================================
PHASE 1 SINGLE-CVE CONTINUOUS RUNNER RESULTS
================================================================================
Timestamp (UTC): 2026-04-10T17:06:56.068202
Source of Selection: OpenSearch cve

SELECTED CVE: CVE-2025-50735
----------------------------------------

Context Snapshot ID: 19
Generation Run ID: 12345
Generation Source: real_retrieval
Status: success
LLM Error Info: None
QA Result: PASS
QA Score: 0.85

Phase 1 Complete: True
================================================================================
```

## Notes

- The runner is designed to be executed repeatedly (e.g., via cron job)
- Each run processes exactly one fresh CVE
- The runner automatically skips CVEs that have already been processed
- Phase 1 completion does not require approval (separate downstream process)
- Errors are captured and reported in the output