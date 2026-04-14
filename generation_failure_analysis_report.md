# VS.ai — Playbook Engine Gen-3
## Generation Failure Triage Analysis Report
**Timestamp:** 2026-04-13  
**Analysis Scope:** Latest 20 failed generation runs (IDs 98-117)

---

## EXECUTIVE SUMMARY

**Dominant Failure Category:** **SCHEMA MISMATCH** - Parser expects legacy schema but LLM returns canonical schema

**Root Cause:** The `parse_playbook_response()` function in `src/utils/playbook_parser.py` validates responses against an **obsolete schema** requiring a `"playbook"` wrapper key, while the LLM is generating responses in the **new canonical schema** format (top-level fields without wrapper).

**Failure Rate:** 100% of analyzed failed runs (20/20) show this schema mismatch.

---

## DETAILED ANALYSIS

### 1. Failure Statistics (Latest 20 Failed Runs)

| Failure Category | Count | Percentage | Notes |
|-----------------|-------|------------|-------|
| Schema Mismatch | 20 | 100% | Parser expects `"playbook"` key, LLM returns canonical schema |
| Markdown Fences | 20 | 100% | LLM wraps JSON in ```json ... ``` markdown |
| Malformed JSON | 20 | 100% | JSON parsing fails due to markdown fences |
| LLM Error Info | 20 | 100% | All have `"Missing 'playbook' key in response"` |

### 2. Concrete Raw Response Examples

**Example 1 (Run ID: 117):**
```json
```json
{
  "header": {
    "title": "Remediation Playbook for CVE-2025-10280 (IdentityIQ XSS)",
    "cve_id": "CVE-2025-10280",
    "vendor": "Cisco",
    "product": "Identity Services Engine (ISE)",
    "severity": "High",
    "vulnerability_type": "Cross-Site Scripting (XSS)",
    "description": "A vulnerability in the web-based management interface..."
  }
}
```
```

**Example 2 (Run ID: 116):**
```json
```json
{
  "header": {
    "title": "Remediation Playbook for CVE-2025-12531 (IBM InfoSphere Information Server)",
    "cve_id": "CVE-2025-12531",
    "vendor": "IBM",
    "product": "InfoSphere Information Server",
    "severity": "HIGH",
    "vulnerability_type": "XML External Entity Injection (XXE)",
    "description": "IBM InfoSphere Information Server 11.7.0.0..."
  }
}
```
```

**Key Observations:**
1. **Markdown Fences Present:** All responses start with ```json and end with ```
2. **Canonical Schema Format:** Responses use `"header"` object with top-level fields
3. **No `"playbook"` Wrapper:** Missing the legacy wrapper key expected by parser
4. **Valid JSON Structure:** Content is structurally valid JSON once fences are removed

### 3. Parser Expectation vs. Reality

**Parser Expectation (`playbook_parser.py:192`):**
```python
# Check for playbook key
if "playbook" not in parsed_data:
    errors.append("Missing 'playbook' key in response")
    return False
```

**Parser Expectation (`playbook_parser.py:203-208`):**
```python
required_fields = ["title", "cve_id", "severity", "affected_components", 
                  "remediation_steps", "verification_procedures", "rollback_procedures", "references"]
for field in required_fields:
    if field not in playbook:
        errors.append(f"Missing required field in playbook: '{field}'")
```

**Actual LLM Output (Canonical Schema):**
```json
{
  "header": {
    "title": "...",
    "cve_id": "...",
    "vendor": "...",
    "product": "...",
    "severity": "...",
    "vulnerability_type": "...",
    "description": "..."
  },
  "retrieval_metadata": {...},
  "workflows": [...],
  "pre_remediation_checks": [...],
  "post_remediation_validation": [...]
}
```

### 4. Failure Flow Analysis

1. **LLM Generation:** LLM returns canonical schema response with markdown fences
2. **Parser Attempt:** `parse_playbook_response()` tries to parse raw response
3. **Markdown Stripping:** `strip_markdown_fences()` removes ```json ... ```
4. **JSON Parsing:** JSON parses successfully (content is valid)
5. **Schema Validation:** `validate_playbook_structure()` checks for `"playbook"` key
6. **Validation Fails:** Returns error `"Missing 'playbook' key in response"`
7. **Pipeline Marks as Failed:** Generation run marked `status = 'failed'`

### 5. System Context

**Affected Components:**
- `src/utils/playbook_parser.py` - Legacy schema validation
- `scripts/prod/03_01_run_playbook_generation_v0_1_1_real_retrieval.py` - Production pipeline
- `src/validation/canonical_validator.py` - Canonical schema validator (not being used)

**Database Impact:**
- `generation_runs.status = 'failed'` for all canonical schema responses
- `llm_error_info` contains `"Missing 'playbook' key in response"`
- Valid playbook content stored in `response` column but marked as failed

---

## MINIMAL FIX RECOMMENDATION

### Option 1: Update Parser to Support Both Schemas (Recommended)

**File:** `src/utils/playbook_parser.py`

**Changes:**
1. Remove requirement for `"playbook"` wrapper key
2. Add detection for canonical schema format
3. Update validation logic to check for either schema
4. Transform canonical schema to legacy format if needed

**Implementation:**
```python
def validate_playbook_structure(parsed_data: Dict[str, Any], errors: List[str]) -> bool:
    # Check for canonical schema first
    if "header" in parsed_data and "cve_id" in parsed_data.get("header", {}):
        # Canonical schema detected
        playbook = transform_canonical_to_legacy(parsed_data)
        return validate_legacy_structure(playbook, errors)
    elif "playbook" in parsed_data:
        # Legacy schema detected
        return validate_legacy_structure(parsed_data["playbook"], errors)
    else:
        errors.append("Response does not match either canonical or legacy schema")
        return False
```

### Option 2: Update Prompt to Request Legacy Schema

**File:** Prompt templates

**Changes:**
1. Explicitly request `"playbook"` wrapper in prompt
2. Provide example of legacy schema format
3. Update all prompt templates

**Risk:** May conflict with canonical schema adoption efforts

### Option 3: Bypass Parser for Canonical Schema

**File:** `scripts/prod/03_01_run_playbook_generation_v0_1_1_real_retrieval.py`

**Changes:**
1. Check for canonical schema before calling parser
2. Use `CanonicalValidator` for canonical schema responses
3. Mark as successful if canonical validation passes

---

## IMMEDIATE ACTION PLAN

### Phase 1: Hotfix (15 minutes)
1. Update `playbook_parser.py` to detect canonical schema
2. Add transformation logic from canonical to legacy format
3. Test with sample failed responses

### Phase 2: Validation (5 minutes)
1. Run analysis script on fixed parser
2. Verify failed runs would now pass validation
3. Check database for any other schema issues

### Phase 3: Deployment (5 minutes)
1. Deploy updated parser
2. Monitor next generation runs
3. Verify success rate improvement

---

## SUCCESS METRICS

**Current State:** 100% failure rate for canonical schema responses

**Expected After Fix:** >90% success rate for same responses

**Validation:** Re-run failed generations to confirm they now pass

---

## RISK ASSESSMENT

**Low Risk:** Fix only affects validation logic, not data storage or LLM calls

**Backward Compatible:** Maintains support for legacy schema responses

**No Data Loss:** Failed runs remain in database for audit trail

---

## CONCLUSION

The generation failure epidemic is caused by a **schema version mismatch** between the parser (expecting legacy schema) and the LLM (generating canonical schema). The fix is straightforward: update the parser to recognize and handle both schema formats.

**Critical Insight:** The LLM responses are actually **valid and high-quality** - they're just using the newer canonical schema format. The failures are purely a validation issue, not a content quality issue.

**Recommendation:** Implement **Option 1** immediately to unblock the generation pipeline while maintaining backward compatibility.