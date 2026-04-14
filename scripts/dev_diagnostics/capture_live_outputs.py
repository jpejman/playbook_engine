#!/usr/bin/env python3
"""
Capture raw live LLM outputs for analysis.
Step 1 of Prompt/Model Alignment Directive.
"""

import os
import sys
import json
import time
from datetime import datetime
from typing import Dict, Any, Optional
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add src to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.utils.llm_client import LLMClient
from src.utils.db import DatabaseClient
from src.qa.enforcement_engine import EnforcementEngine


def get_cve_context(cve_id: str) -> Optional[Dict[str, Any]]:
    """Get CVE context from database."""
    db = DatabaseClient()
    query = """
    SELECT context_data 
    FROM cve_context_snapshot 
    WHERE cve_id = %s 
    ORDER BY created_at DESC 
    LIMIT 1
    """
    result = db.fetch_one(query, (cve_id,))
    if result and result.get('context_data'):
        return result['context_data']
    return None


def create_prompt(cve_id: str, context_data: Dict[str, Any]) -> str:
    """Create generation prompt (current version)."""
    context_json = json.dumps(context_data, indent=2)
    
    prompt = f"""Generate a canonical remediation playbook for CVE {cve_id}.

## CVE Context Data
{context_json}

## Instructions
Generate a comprehensive remediation playbook in canonical JSON format with:
1. Title including CVE ID
2. Accurate vendor and product information
3. Specific remediation steps with real commands (not echo statements)
4. Pre-remediation checks
5. Post-remediation validation
6. Evidence-based recommendations

## Output Schema
The playbook must be valid JSON matching the canonical schema with workflows, steps, commands, etc.

Generate only the JSON playbook, no additional text."""
    
    return prompt


def validate_canonical_schema(playbook_json: Dict[str, Any]) -> tuple[bool, list[str]]:
    """Validate against canonical schema."""
    errors = []
    
    # Required top-level fields
    required_fields = [
        'title', 'cve_id', 'vendor', 'product', 'severity', 'description',
        'vulnerability_type', 'affected_versions', 'fixed_versions',
        'affected_platforms', 'references', 'retrieval_metadata',
        'workflows', 'additional_recommendations'
    ]
    
    for field in required_fields:
        if field not in playbook_json:
            errors.append(f"Missing required field: '{field}'")
    
    # Check for obsolete keys
    obsolete_keys = ['remediation_steps', 'playbook']
    for key in obsolete_keys:
        if key in playbook_json:
            errors.append(f"Contains obsolete key: '{key}'")
    
    # Check workflows structure
    if 'workflows' in playbook_json:
        workflows = playbook_json['workflows']
        if not isinstance(workflows, list) or len(workflows) == 0:
            errors.append("'workflows' must be a non-empty list")
        else:
            for i, workflow in enumerate(workflows):
                if not isinstance(workflow, dict):
                    errors.append(f"workflows[{i}] must be a dictionary")
                else:
                    if 'workflow_id' not in workflow:
                        errors.append(f"workflows[{i}] missing 'workflow_id'")
                    if 'workflow_name' not in workflow:
                        errors.append(f"workflows[{i}] missing 'workflow_name'")
                    if 'workflow_type' not in workflow:
                        errors.append(f"workflows[{i}] missing 'workflow_type'")
                    if 'steps' not in workflow:
                        errors.append(f"workflows[{i}] missing 'steps'")
                    elif not isinstance(workflow['steps'], list) or len(workflow['steps']) == 0:
                        errors.append(f"workflows[{i}].'steps' must be a non-empty list")
    
    return len(errors) == 0, errors


def capture_live_output(cve_id: str, attempt: int) -> Dict[str, Any]:
    """Capture one live LLM generation with full diagnostics."""
    print(f"\n{'='*60}")
    print(f"CAPTURE ATTEMPT {attempt}: {cve_id}")
    print(f"{'='*60}")
    
    # Get context
    context_data = get_cve_context(cve_id)
    if not context_data:
        print(f"ERROR: No context data for {cve_id}")
        return {
            "cve_id": cve_id,
            "attempt": attempt,
            "error": "No context data",
            "timestamp": datetime.utcnow().isoformat()
        }
    
    # Create prompt
    prompt = create_prompt(cve_id, context_data)
    
    # Call LLM
    llm = LLMClient()
    print(f"Calling LLM (model: {llm.model})...")
    start_time = time.time()
    llm_result = llm.generate(prompt)
    elapsed = time.time() - start_time
    
    # Parse result
    raw_response = llm_result.get('raw_text', '')
    parsed_json = None
    json_error = None
    validation_errors = []
    validation_passed = False
    
    # Try to parse JSON
    if raw_response:
        try:
            # Clean response - remove markdown code blocks if present
            clean_response = raw_response.strip()
            if clean_response.startswith('```json'):
                clean_response = clean_response[7:]
            if clean_response.startswith('```'):
                clean_response = clean_response[3:]
            if clean_response.endswith('```'):
                clean_response = clean_response[:-3]
            clean_response = clean_response.strip()
            
            parsed_json = json.loads(clean_response)
            print(f"[OK] JSON parsed successfully ({len(clean_response)} chars)")
            
            # Validate canonical schema
            validation_passed, validation_errors = validate_canonical_schema(parsed_json)
            if validation_passed:
                print("[OK] Canonical schema validation PASSED")
            else:
                print(f"[FAIL] Canonical schema validation FAILED: {len(validation_errors)} errors")
                
        except json.JSONDecodeError as e:
            json_error = str(e)
            print(f"[FAIL] JSON parse failed: {json_error}")
        except Exception as e:
            json_error = f"Unexpected error: {str(e)}"
            print(f"[FAIL] Error: {json_error}")
    else:
        json_error = "Empty response from LLM"
        print(f"[FAIL] {json_error}")
    
    # Run QA if validation passed
    qa_result = None
    if validation_passed and parsed_json:
        print("Running QA evaluation...")
        qa_engine = EnforcementEngine()
        qa_result = qa_engine.evaluate_playbook(parsed_json)
        print(f"QA result: {qa_result.get('status', 'UNKNOWN')}")
    
    # Build capture result
    result = {
        "cve_id": cve_id,
        "attempt": attempt,
        "timestamp": datetime.utcnow().isoformat(),
        "model": llm.model,
        "elapsed_seconds": round(elapsed, 2),
        "llm_status": llm_result.get('status', 'unknown'),
        "prompt_excerpt": prompt[:500] + "..." if len(prompt) > 500 else prompt,
        "raw_response_excerpt": raw_response[:1000] + "..." if len(raw_response) > 1000 else raw_response,
        "response_length": len(raw_response),
        "json_parse_success": parsed_json is not None,
        "json_error": json_error,
        "validation_passed": validation_passed,
        "validation_errors": validation_errors,
        "qa_result": qa_result
    }
    
    return result


def main():
    """Main capture function."""
    print("VS.ai — Playbook Engine Gen-3")
    print("Prompt/Model Alignment Directive - Step 1")
    print("Capture Raw Live Outputs")
    print(f"Timestamp: {datetime.utcnow().isoformat()}")
    print("="*60)
    
    # Use CVE-2023-4863 for all captures
    cve_id = "CVE-2023-4863"
    
    # Capture 3 live outputs
    captures = []
    for i in range(1, 4):
        capture = capture_live_output(cve_id, i)
        captures.append(capture)
        
        # Save after each capture
        import os
        os.makedirs("logs/live_capture", exist_ok=True)
        output_file = f"logs/live_capture/live_capture_{cve_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w') as f:
            json.dump(captures, f, indent=2, default=str)
        print(f"Saved capture to: {output_file}")
        
        # Brief pause between attempts
        if i < 3:
            print(f"\nWaiting 5 seconds before next attempt...")
            time.sleep(5)
    
    # Analyze results
    print(f"\n{'='*60}")
    print("CAPTURE ANALYSIS")
    print(f"{'='*60}")
    
    total = len(captures)
    json_success = sum(1 for c in captures if c.get('json_parse_success', False))
    validation_success = sum(1 for c in captures if c.get('validation_passed', False))
    
    print(f"Total captures: {total}")
    print(f"JSON parse success: {json_success}/{total}")
    print(f"Canonical validation success: {validation_success}/{total}")
    
    # Show failure modes
    print("\nFAILURE MODES:")
    for i, capture in enumerate(captures, 1):
        if not capture.get('json_parse_success', False):
            print(f"  Attempt {i}: JSON parse error - {capture.get('json_error', 'Unknown')}")
        elif not capture.get('validation_passed', False):
            errors = capture.get('validation_errors', [])
            print(f"  Attempt {i}: Schema validation failed - {len(errors)} errors")
            for err in errors[:3]:  # Show first 3 errors
                print(f"    - {err}")
            if len(errors) > 3:
                print(f"    - ... and {len(errors) - 3} more")
    
    # Save final analysis
    import os
    os.makedirs("logs/live_capture", exist_ok=True)
    analysis_file = f"logs/live_capture/live_capture_analysis_{cve_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    with open(analysis_file, 'w') as f:
        json.dump({
            "summary": {
                "total_captures": total,
                "json_success": json_success,
                "validation_success": validation_success,
                "timestamp": datetime.utcnow().isoformat()
            },
            "captures": captures
        }, f, indent=2, default=str)
    
    print(f"\nAnalysis saved to: {analysis_file}")
    print("Step 1 complete. Proceed to Step 2: Tighten prompt for canonical output.")


if __name__ == "__main__":
    main()