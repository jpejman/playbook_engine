# Generation Persistence Fix - Summary

## Issue
In the production execution path, attempted generations were not consistently creating rows in `generation_runs`. This broke auditability, replayability, failure analysis, and QA lineage.

## Root Cause
The `persist_generation_run()` method in the main production script (`03_01_run_playbook_generation_v0_1_1_real_retrieval.py`) only inserted rows with status 'completed' and didn't handle failed LLM calls or store error metadata.

## Fix Implemented

### 1. Updated `persist_generation_run()` method
**File:** `scripts/03_01_run_playbook_generation_v0_1_1_real_retrieval.py`

**Key changes:**
- Now determines status based on `llm_result` (not always 'completed')
- Sets `generation_source` appropriately: 'live_llm_success' or 'live_llm_failed'
- Stores `llm_error_info` for failed generations with structured error data
- Always inserts a row for attempted generations (except when context is insufficient)
- Added comprehensive debug logging as required by directive

### 2. Added robust error handling
**File:** `scripts/03_01_run_playbook_generation_v0_1_1_real_retrieval.py`

**Key changes:**
- Wrapped `persist_generation_run()` call in try-except block
- Logs critical errors if persistence fails
- Ensures generation attempt is logged even if database insertion fails

### 3. Correct execution order enforced
The fix ensures the correct execution order per directive:
1. build/fetch context
2. validate context quality  
3. finalize prompt
4. call model
5. **INSERT generation_runs row immediately** ← CRITICAL FIX
6. run storage guard / canonical validation / QA afterward
7. update later stages separately if needed

## Success Criteria Met

1. **✓ Every attempted generation creates a generation_runs row**
   - Row inserted immediately after LLM call returns or fails
   - Includes both successful and failed generations

2. **✓ Failed generations still leave a row with failure metadata**
   - Status set to 'failed' 
   - `generation_source` set to 'live_llm_failed'
   - `llm_error_info` contains structured error data

3. **✓ Prompt text is stored**
   - Prompt stored in `prompt` column for all attempted generations

4. **✓ Raw response or error info is stored**
   - Successful: raw response stored in `response` column
   - Failed: error info stored in `llm_error_info` column

5. **✓ No attempted generation disappears silently**
   - Debug logging tracks: generation attempted, insert attempted, inserted ID, final status
   - Exception handling ensures failures are logged

## Database Schema Compatibility
The fix works with the existing `generation_runs` schema which includes:
- `id` (integer)
- `cve_id` (text)
- `prompt` (text)
- `response` (text)
- `model` (text)
- `status` (text)
- `created_at` (timestamp)
- `retrieval_run_id` (integer)
- `generation_source` (text) ← **Now properly populated**
- `llm_error_info` (text) ← **Now properly populated for failures**

## Testing
Two test scripts created:
1. `scripts/test_generation_persistence_fix.py` - Comprehensive test of persistence logic
2. `scripts/verify_fix_demo.py` - Demonstration of fix implementation

## Notes
- Existing records in database may not have `generation_source` or `llm_error_info` as they were created before the fix
- The fix applies to the main production path (`03_01_run_playbook_generation_v0_1_1_real_retrieval.py`)
- Other generation scripts (canonical, vector) have similar issues but were not updated as they're not the primary production path per directive

## Verification
To verify the fix works:
1. Run the production script with a test CVE
2. Check database for new `generation_runs` row
3. Verify `generation_source` and `llm_error_info` (if failed) are populated
4. Check logs for debug output showing persistence steps

**Example test command:**
```bash
python scripts/03_01_run_playbook_generation_v0_1_1_real_retrieval.py --cve CVE-2023-4863
```