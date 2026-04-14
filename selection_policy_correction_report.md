# VS.ai — Playbook Engine Gen-3
## Selection Policy Correction Directive Report
**Timestamp (UTC):** 2026-04-13  
**Analysis Complete:** 2026-04-13T18:18:56-04:00

---

## 1. OLD EXCLUSION LOGIC

### Current Problem Identified:
The Phase 1 selector (`phase1_single_cve_continuous_runner.py:262-326`) excludes **ANY CVE that has ANY entry in the `generation_runs` table**, regardless of whether the prior run was successful or not.

### Old SQL Query (Line 294-307):
```sql
SELECT EXISTS (
    SELECT 1 
    FROM generation_runs 
    WHERE cve_id = %s
) as has_processed
```

### Old Exclusion Criteria:
1. **approved_playbook exists** ✓ (correct)
2. **ANY generation_runs entry exists** ✗ (INCORRECT - too broad)
3. Test/excluded CVE pattern ✓ (correct)

### Result:
- **99 out of 100 candidates** were excluded with reason: "Already processed in generation_runs (Phase 1 filter)"
- This mapped to `excluded_successful_generation_exists` in the directive taxonomy
- **Only 1 candidate** passed filters

---

## 2. NEW EXCLUSION LOGIC

### Required Policy (Per Directive):
A CVE must be excluded **only if at least one** of the following is true:

1. ✅ `approved_playbook` exists for that CVE
2. ✅ `generation_run` exists with **true terminal success state**, defined as:
   - generation status = 'completed'
   - response IS NOT NULL AND response != '' (has content)
   - QA returned a valid success result (`qa_result = 'approved'`)
3. ✅ active lock exists
4. ✅ in-progress queue state exists
5. ✅ already processed in current session

A CVE must **NOT** be excluded solely because:
- ❌ it exists in `generation_runs`
- ❌ it has failed generation history
- ❌ it has partial pipeline history
- ❌ QA result was None or not 'approved'
- ❌ parser previously failed

### New SQL Query for Success Check:
```sql
SELECT EXISTS (
    SELECT 1 
    FROM generation_runs gr
    LEFT JOIN qa_runs qa ON gr.id = qa.generation_run_id
    WHERE gr.cve_id = %s
    AND gr.status = 'completed'
    AND gr.response IS NOT NULL
    AND gr.response != ''
    AND qa.qa_result = 'approved'
) as has_successful_generation
```

### Implementation:
- File: `phase1_selector_corrected.py`
- Method: `_check_postgresql_state_corrected()`
- Maps to directive exclusion categories:
  - `excluded_already_approved`
  - `excluded_successful_generation_exists` (now correctly defined)
  - `excluded_in_progress_queue`
  - `excluded_active_lock`
  - `excluded_session_dedup`
  - `excluded_other`

---

## 3. TEST AGAINST RECENT 100-CANDIDATE SET

### Test Data:
- **Source:** `logs/runs/556732eb-e36e-4371-8f5b-a1dc78c53343-run-0010/metadata.json`
- **Timestamp:** 2026-04-13T19:56:44.151801+00:00
- **Candidates:** 100 CVEs from OpenSearch cve index

### Results Comparison:

| Metric | Old Policy | New (Corrected) Policy | Change |
|--------|------------|------------------------|---------|
| **Total Candidates** | 100 | 100 | 0 |
| **Filtered Out** | 99 | 0 | **-99** |
| **Eligible** | 1 | 100 | **+99** |
| **Exclusion Rate** | 99% | 0% | **-99%** |

### New Exclusion Counts by Reason:
1. **excluded_already_approved**: 0
2. **excluded_successful_generation_exists**: 0
3. **excluded_in_progress_queue**: 0
4. **excluded_active_lock**: 0
5. **excluded_session_dedup**: 0
6. **excluded_other**: 0

**Total Excluded:** 0 (all 100 candidates are eligible)

---

## 4. CONFIRMATION: PREVIOUSLY FAILED/PARTIAL CVEs ARE NOW ELIGIBLE

### Sample Verification (5 CVEs from test set):

| CVE ID | Old Status | New Status | Reason |
|--------|------------|------------|---------|
| CVE-2025-63293 | ❌ Excluded | ✅ Eligible | Has 1 failed generation, QA: needs_revision |
| CVE-2025-12657 | ❌ Excluded | ✅ Eligible | Has 1 completed generation, QA: rejected |
| CVE-2025-50735 | ❌ Excluded | ✅ Eligible | Has 1 failed generation, QA: needs_revision |
| CVE-2025-12463 | ❌ Excluded | ✅ Eligible | Has 1 failed generation, QA: needs_revision |
| CVE-2025-11953 | ❌ Excluded | ✅ Eligible | Has 1 failed generation, QA: needs_revision |

### Key Findings:
- **0 CVEs** have approved playbooks
- **0 CVEs** have truly successful generations (completed + has response + QA approved)
- **All CVEs** have either:
  - Failed generations (`status = 'failed'`)
  - Completed generations with QA results other than 'approved' (rejected/needs_revision)
- **Therefore:** All 100 CVEs are correctly eligible under the new policy

---

## 5. SUCCESS CONDITION MET

✅ **The selector excludes only truly completed CVEs**  
- No CVEs are excluded under the new policy because none meet the strict success criteria

✅ **Does not starve the batch because of historical failed or partial attempts**  
- 100% of previously excluded CVEs (99) are now eligible
- Batch starvation issue is resolved

---

## 6. IMPLEMENTATION DETAILS

### Files Modified/Created:
1. **`phase1_selector_corrected.py`** - New implementation with corrected policy
   - Complete replacement of exclusion logic
   - Proper mapping to directive exclusion categories
   - Testing framework included

### Key Changes:
1. **Success Definition Updated:** From "any generation_runs entry" to "completed + has response + QA approved"
2. **Exclusion Categories Mapped:** Direct alignment with directive requirements
3. **Backward Compatibility:** Maintains all other Phase 1 requirements (severity, CVSS, etc.)
4. **Testing Included:** Validates against real 100-candidate dataset

### No Changes Required:
- ✅ No prompt changes
- ✅ No model changes  
- ✅ No schema changes (uses existing tables/columns)
- ✅ Minimal policy correction only

---

## 7. RECOMMENDATIONS

### Immediate Action:
1. **Replace** `phase1_single_cve_continuous_runner.py` with corrected logic
2. **Update** `phase1_continuous_execution_system_v0_2_0.py` to use corrected selector
3. **Verify** in production with monitoring of exclusion rates

### Monitoring Metrics:
- Track `excluded_successful_generation_exists` count (should be very low)
- Monitor eligible candidate count (should increase significantly)
- Watch for actual successful completion rates

### Expected Impact:
- **Increased throughput:** More CVEs available for processing
- **Better resource utilization:** No starvation due to historical failures
- **Accurate tracking:** Proper distinction between failed vs. successful attempts

---

**END OF REPORT**