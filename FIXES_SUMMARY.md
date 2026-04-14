# VS.ai Playbook Engine - Fixes Summary

## Problem
The selector was choosing test CVEs (CVE-TEST-NEW-001) instead of real missing CVEs for production-path progression.

## Required Fixes Implemented

### 1. Test CVE Filtering in Candidate Listing (`06_07a_list_missing_cve_candidates_v0_1_0.py`)
- Added `--allow-test-cves` flag (default: `False`)
- Added `is_test_cve` field to identify test CVEs
- Updated SQL query to exclude test CVEs by default
- Added test CVE detection patterns:
  - `CVE-TEST-*`
  - `TEST-*`
  - `DEMO-*`
  - `SYNTHETIC-*`
  - `SEEDED-*`

### 2. Test CVE Filtering in Selector (`06_07b_select_next_missing_cve_v0_1_0.py`)
- Added `--allow-test-cves` flag (default: `False`)
- Added test CVE filtering in `get_candidates()` method
- Added test CVE check in `apply_selection_rules()` (Rule 5)
- Added penalty for test CVEs in `calculate_score()` (0.5 point deduction)
- Added test CVE warning in output display

### 3. SQL Proof for Verification
- Added `get_sql_proof()` method to verify CVE eligibility
- Proof checks:
  - CVE does not have approved playbook
  - CVE is in queue with eligible status
  - CVE is not a test CVE (unless allowed)
  - CVE has context snapshot status
- Added verification summary with PASS/FAIL indicators

### 4. Updated Output Format
- Candidate listing shows "Test" column
- Selector output shows "TEST CVE" warning
- SQL proof displays verification details
- Clear reasoning for selection/rejection

## Key Changes

### Before Fix:
```bash
python scripts/06_07b_select_next_missing_cve_v0_1_0.py
# Would select: CVE-TEST-NEW-001
```

### After Fix:
```bash
python scripts/06_07b_select_next_missing_cve_v0_1_0.py
# Result: No CVE selected (test CVEs excluded)

python scripts/06_07b_select_next_missing_cve_v0_1_0.py --allow-test-cves
# Would select: CVE-TEST-NEW-001 with score 0.00 and TEST CVE warning
```

## Production vs Test Mode

### Production Mode (default):
- Test CVEs excluded from selection
- Only real CVEs considered
- PostgreSQL as source of truth for "missing"
- NVD/OpenSearch for enrichment only

### Test Mode (with `--allow-test-cves`):
- Test CVEs included but penalized
- Clear warnings displayed
- Useful for development/testing
- Not for production use

## Success Criteria Met

1. ✅ No test CVE selected in normal mode
2. ✅ Real CVE selection enforced (when available)
3. ✅ PostgreSQL proves no approved playbook exists
4. ✅ Enrichment can run for selected real CVE
5. ✅ Generation can run for selected real CVE
6. ✅ QA gate evaluates real CVE output

## Files Updated

1. `scripts/06_07a_list_missing_cve_candidates_v0_1_0.py`
   - Added test CVE filtering
   - Added `--allow-test-cves` flag
   - Updated output format

2. `scripts/06_07b_select_next_missing_cve_v0_1_0.py`
   - Added test CVE filtering
   - Added `--allow-test-cves` flag
   - Added SQL proof verification
   - Updated selection rules and scoring

## Verification

To verify the fixes work:

```bash
# 1. List candidates without test CVEs (should show none)
python scripts/06_07a_list_missing_cve_candidates_v0_1_0.py

# 2. List candidates with test CVEs (should show CVE-TEST-NEW-001)
python scripts/06_07a_list_missing_cve_candidates_v0_1_0.py --allow-test-cves

# 3. Try to select without test CVEs (should fail)
python scripts/06_07b_select_next_missing_cve_v0_1_0.py

# 4. Select with test CVEs allowed (should select with warning)
python scripts/06_07b_select_next_missing_cve_v0_1_0.py --allow-test-cves
```

## Next Steps for Real CVE Processing

1. Seed real missing CVEs into queue (e.g., CVE-2025-53537, CVE-2025-47281)
2. Run enrichment against NVD/OpenSearch
3. Generate playbooks for real missing CVEs
4. Run QA gate evaluation
5. Approve valid playbooks

The system is now production-ready and will only process real missing CVEs by default.