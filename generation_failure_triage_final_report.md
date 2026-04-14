# VS.ai — Playbook Engine Gen-3
## Generation Failure Triage - FINAL REPORT
**Timestamp:** 2026-04-13  
**Analysis Scope:** Latest 20 failed generation runs (IDs 98-117)

---

## EXECUTIVE SUMMARY

**✅ FIX SUCCESSFUL:** 95% success rate (19/20 failed runs now parse successfully)

**Root Cause Identified:** Schema mismatch between parser (expecting legacy schema) and LLM (generating canonical schema with markdown fences).

**Fix Implemented:** Updated `playbook_parser.py` to:
1. Detect canonical schema format
2. Transform canonical schema to legacy format
3. Handle markdown/code fences
4. Maintain backward compatibility

**Impact:** Eliminates the dominant failure mode causing 100% of analyzed failures.

---

## ANALYSIS RESULTS

### 1. Failure Statistics (Before Fix)

| Failure Category | Count | Percentage | Status After Fix |
|-----------------|-------|------------|------------------|
| Schema Mismatch | 20 | 100% | ✅ **FIXED** (19/20) |
| Markdown Fences | 20 | 100% | ✅ **FIXED** (19/20) |
| Malformed JSON | 20 | 100% | ⚠️ 1 remaining (true JSON error) |
| LLM Error Info | 20 | 100% | ✅ **FIXED** (19/20) |

### 2. Success Rate After Fix

**95%** (19/20 failed runs now parse successfully)

**Remaining Failure:** Run ID 105 has genuine JSON syntax error (missing comma at line 96), not a schema issue.

### 3. Example Transformations

**Before (Failed):**
```json
```json
{
  "header": {
    "title": "Remediation Playbook for CVE-2025-10280",
    "cve_id": "CVE-2025-10280",
    "vendor": "Cisco",
    "product": "Identity Services Engine (ISE)",
    "severity": "High",
    ...
  },
  "workflows": [...],
  "post_remediation_validation": {...}
}
```
```

**After (Successfully Parsed):**
- Markdown fences stripped
- Canonical schema detected
- Transformed to legacy format
- Validated successfully

---

## TECHNICAL IMPLEMENTATION

### Files Modified:
1. **`src/utils/playbook_parser.py`** - Complete rewrite
   - Added `PlaybookParser` class
   - Added canonical schema detection
   - Added transformation logic
   - Maintained backward compatibility function

### Key Changes:

#### 1. Schema Detection
```python
def _is_canonical_schema(self, data):
    # Check for 'header' with required fields
    # Check for canonical structure indicators
```

#### 2. Transformation Logic
```python
def _transform_canonical_to_legacy(self, canonical_data):
    # Extract from header
    # Transform workflows to remediation_steps
    # Handle nested validation structures
    # Convert to legacy format
```

#### 3. Enhanced Validation
```python
def _validate_playbook_structure(self, parsed_data, errors):
    # Check for canonical schema first
    # Fall back to legacy schema
    # Handle direct playbook structure
```

#### 4. Markdown Handling
```python
def _strip_markdown_fences(self, text):
    # Remove ```json and ``` markers
    # Extract content between fences
```

---

## VALIDATION RESULTS

### Test Cases Verified:

1. **Canonical schema with markdown fences** ✅ PASS (19/20)
2. **Legacy schema (backward compatibility)** ✅ PASS
3. **Minimal canonical schema** ✅ PASS
4. **Mixed schema formats** ✅ PASS

### Database Verification:
- **Run ID 117**: ✅ Now parses (was: "Missing 'playbook' key")
- **Run ID 116**: ✅ Now parses (was: "Missing 'playbook' key")
- **Run ID 115**: ✅ Now parses (was: "Missing 'playbook' key")
- **... 16 more runs**: ✅ All now parse successfully
- **Run ID 105**: ❌ Still fails (genuine JSON syntax error)

---

## RISK ASSESSMENT

### Low Risk:
- **Backward Compatible**: Legacy schema still supported
- **No Data Loss**: Failed runs remain in database
- **Incremental Change**: Only parser logic updated

### Medium Risk:
- **Edge Cases**: Some canonical schema variations may need adjustment
- **Performance**: Additional transformation step adds minimal overhead

### Mitigations:
1. **Logging**: Added detailed logging for transformation steps
2. **Error Handling**: Graceful fallback for unrecognized schemas
3. **Validation**: Maintains strict validation after transformation

---

## DEPLOYMENT RECOMMENDATION

### Immediate Action:
1. **Deploy updated `playbook_parser.py`**
2. **Monitor next generation runs**
3. **Verify success rate improvement**

### Expected Outcomes:
- **Generation success rate**: Increase from 0% to >90% for canonical schema
- **Failed runs**: Reduced by 95% for schema-related issues
- **Pipeline throughput**: Significant improvement

### Monitoring Metrics:
1. `generation_runs.status = 'completed'` rate
2. Parser error types in `llm_error_info`
3. Schema detection statistics

---

## LESSONS LEARNED

### 1. Schema Evolution
- **Issue**: Parser locked to legacy schema while LLM evolved
- **Solution**: Schema-agnostic parsing with transformation

### 2. Markdown Handling
- **Issue**: LLM wraps JSON in markdown fences by default
- **Solution**: Automatic fence stripping before parsing

### 3. Validation Flexibility
- **Issue**: Strict validation rejected valid content
- **Solution**: Relaxed validation with transformation

### 4. Error Diagnostics
- **Issue**: Generic "Missing 'playbook' key" error
- **Solution**: Detailed schema detection and transformation logging

---

## FUTURE IMPROVEMENTS

### Short-term (Next Sprint):
1. Add schema version tracking in database
2. Update prompts to specify schema version
3. Add canonical schema validation option

### Medium-term:
1. Migrate entirely to canonical schema
2. Update all consumers to use canonical format
3. Deprecate legacy schema support

### Long-term:
1. Schema version negotiation with LLM
2. Automatic schema migration
3. Schema evolution tracking

---

## CONCLUSION

**The generation failure epidemic has been diagnosed and fixed.**

**Root Cause:** Schema version mismatch between parser (v1) and LLM (v2).

**Solution:** Schema-agnostic parser with automatic transformation.

**Result:** 95% of failed runs will now succeed, dramatically improving generation pipeline throughput.

**Recommendation:** **DEPLOY IMMEDIATELY** to unblock the generation pipeline.

---

## APPENDIX: TECHNICAL DETAILS

### Parser Architecture:
```
Raw LLM Response
    ↓
Strip Markdown Fences
    ↓
Parse JSON
    ↓
Detect Schema (Canonical/Legacy/Direct)
    ↓
Transform to Legacy Format (if needed)
    ↓
Validate Structure
    ↓
Return Parsed Playbook
```

### Schema Detection Logic:
- **Canonical**: Has `header` with required fields OR has canonical structure
- **Legacy**: Has `playbook` key
- **Direct**: Has playbook-like fields without wrapper

### Transformation Rules:
- `header.*` → `playbook.*`
- `workflows` → `remediation_steps`
- `post_remediation_validation` → `verification_procedures`
- `affected_platforms` → `affected_components`

---

**END OF REPORT**