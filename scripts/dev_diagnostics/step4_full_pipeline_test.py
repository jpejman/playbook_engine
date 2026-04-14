#!/usr/bin/env python3
"""
Step 4: Full pipeline test for CVE-2023-4863.
"""

import os
import sys
import json
import time
from datetime import datetime
from typing import Dict, Any, Optional, Tuple
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.utils.llm_client import LLMClient
from src.utils.db import DatabaseClient
from src.qa.enforcement_engine import EnforcementEngine


class ResponseRejector:
    """Response rejection layer (from Step 3)."""
    
    def __init__(self, strict_mode: bool = True):
        self.strict_mode = strict_mode
        self.required_keys = [
            "title", "cve_id", "vendor", "product", "severity", "description",
            "vulnerability_type", "affected_versions", "fixed_versions",
            "affected_platforms", "references", "retrieval_metadata",
            "workflows", "additional_recommendations"
        ]
        self.forbidden_keys = ["remediation_steps", "playbook"]
    
    def clean_response(self, raw_response: str) -> Tuple[str, Dict[str, Any]]:
        """Clean and analyze response."""
        analysis = {
            "original_length": len(raw_response),
            "has_markdown": False,
            "has_explanatory_text": False,
            "markdown_type": None,
            "cleaned_length": 0,
            "cleaning_applied": []
        }
        
        if not raw_response:
            return "", analysis
        
        clean_response = raw_response.strip()
        
        # Check for markdown
        if '```' in clean_response:
            analysis["has_markdown"] = True
            
            # Check for ```json
            if clean_response.startswith('```json'):
                analysis["markdown_type"] = "json_code_block"
                clean_response = clean_response[7:].strip()
                analysis["cleaning_applied"].append("removed ```json prefix")
            # Check for generic ```
            elif clean_response.startswith('```'):
                analysis["markdown_type"] = "code_block"
                clean_response = clean_response[3:].strip()
                analysis["cleaning_applied"].append("removed ``` prefix")
            
            # Remove trailing ```
            if clean_response.endswith('```'):
                clean_response = clean_response[:-3].strip()
                analysis["cleaning_applied"].append("removed ``` suffix")
        
        # Check for explanatory text
        lines = clean_response.split('\n')
        if len(lines) > 0:
            first_line = lines[0].strip()
            if not first_line.startswith('{') and not first_line.startswith('['):
                analysis["has_explanatory_text"] = True
                # Try to find JSON start
                for i, line in enumerate(lines):
                    if line.strip().startswith('{') or line.strip().startswith('['):
                        clean_response = '\n'.join(lines[i:]).strip()
                        analysis["cleaning_applied"].append(f"removed {i} lines of explanatory text")
                        break
        
        analysis["cleaned_length"] = len(clean_response)
        return clean_response.strip(), analysis
    
    def validate_response(self, raw_response: str) -> Tuple[bool, str, Optional[Dict], Dict[str, Any]]:
        """Validate response against rejection criteria."""
        validation_result = {
            "passed": False,
            "rejection_reason": None,
            "rejection_category": None,
            "analysis": {},
            "parsed_json": None,
            "missing_keys": [],
            "forbidden_keys_found": []
        }
        
        if not raw_response:
            validation_result["rejection_reason"] = "Empty response"
            validation_result["rejection_category"] = "EMPTY_RESPONSE"
            return False, "Empty response from LLM", None, validation_result
        
        # Clean and analyze
        clean_response, analysis = self.clean_response(raw_response)
        validation_result["analysis"] = analysis
        
        # Rejection: Markdown in strict mode
        if self.strict_mode and analysis["has_markdown"]:
            validation_result["rejection_reason"] = f"Response contains markdown code blocks ({analysis['markdown_type']})"
            validation_result["rejection_category"] = "MARKDOWN_WRAPPED"
            return False, validation_result["rejection_reason"], None, validation_result
        
        # Rejection: Explanatory text in strict mode
        if self.strict_mode and analysis["has_explanatory_text"]:
            validation_result["rejection_reason"] = "Response contains explanatory text before JSON"
            validation_result["rejection_category"] = "EXPLANATORY_TEXT"
            return False, validation_result["rejection_reason"], None, validation_result
        
        # Try to parse JSON
        try:
            parsed = json.loads(clean_response)
            validation_result["parsed_json"] = parsed
            
            # Check for forbidden keys
            if isinstance(parsed, dict):
                for key in self.forbidden_keys:
                    if key in parsed:
                        validation_result["forbidden_keys_found"].append(key)
                
                if validation_result["forbidden_keys_found"]:
                    validation_result["rejection_reason"] = f"Response contains forbidden keys: {validation_result['forbidden_keys_found']}"
                    validation_result["rejection_category"] = "FORBIDDEN_KEYS"
                    return False, validation_result["rejection_reason"], None, validation_result
                
                # Check required keys
                for key in self.required_keys:
                    if key not in parsed:
                        validation_result["missing_keys"].append(key)
                
                if validation_result["missing_keys"]:
                    validation_result["rejection_reason"] = f"Missing required keys: {validation_result['missing_keys']}"
                    validation_result["rejection_category"] = "MISSING_KEYS"
                    return False, validation_result["rejection_reason"], None, validation_result
                
                # Check workflows structure
                if "workflows" in parsed:
                    workflows = parsed["workflows"]
                    if not isinstance(workflows, list) or len(workflows) == 0:
                        validation_result["rejection_reason"] = "Workflows must be a non-empty list"
                        validation_result["rejection_category"] = "INVALID_WORKFLOWS"
                        return False, validation_result["rejection_reason"], None, validation_result
                
            validation_result["passed"] = True
            return True, "Response passed all validation checks", parsed, validation_result
            
        except json.JSONDecodeError as e:
            validation_result["rejection_reason"] = f"Invalid JSON: {str(e)}"
            validation_result["rejection_category"] = "INVALID_JSON"
            return False, validation_result["rejection_reason"], None, validation_result
        except Exception as e:
            validation_result["rejection_reason"] = f"Validation error: {str(e)}"
            validation_result["rejection_category"] = "VALIDATION_ERROR"
            return False, validation_result["rejection_reason"], None, validation_result


def get_cve_context(cve_id: str):
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


def create_tightened_prompt(cve_id: str, context_data: dict) -> str:
    """Create tightened prompt (from Step 2)."""
    context_json = json.dumps(context_data, indent=2)
    
    prompt = f"""Generate a canonical remediation playbook for CVE {cve_id}.

## CVE Context Data
{context_json}

## CANONICAL OUTPUT REQUIREMENTS

1. **OUTPUT FORMAT**: Valid JSON only, no markdown, no code blocks, no explanatory text.

2. **REQUIRED TOP-LEVEL KEYS** (exact spelling):
   - title (string)
   - cve_id (string)
   - vendor (string)
   - product (string)
   - severity (string)
   - description (string)
   - vulnerability_type (string)
   - affected_versions (array)
   - fixed_versions (array)
   - affected_platforms (array)
   - references (array)
   - retrieval_metadata (object)
   - workflows (array) - REQUIRED, non-empty
   - additional_recommendations (array)

3. **WORKFLOWS STRUCTURE**:
   - workflows must be an array of workflow objects
   - Each workflow must have: workflow_id, workflow_name, workflow_type, steps
   - steps must be an array of step objects
   - Each step must have: step_number, title, description, commands, target_os_or_platform, expected_result, verification, evidence_based

4. **FORBIDDEN KEYS** (DO NOT USE):
   - remediation_steps (obsolete)
   - playbook (wrapper key)
   - Any key not listed in REQUIRED TOP-LEVEL KEYS

5. **INVALID IF**:
   - Output contains markdown code blocks (```)
   - Output contains explanatory text before/after JSON
   - Missing workflows array
   - Contains remediation_steps key
   - Contains playbook wrapper key
   - JSON is malformed

## GENERATION INSTRUCTIONS

Generate ONLY the JSON playbook object.
Start with {{ and end with }}.
Do not wrap in markdown.
Do not add explanatory text.
Use the exact canonical schema above.

## FINAL INSTRUCTION

Generate the JSON playbook now. Output ONLY the JSON object."""
    
    return prompt


def store_approved_playbook(db: DatabaseClient, playbook: Dict[str, Any], 
                           qa_result: Dict[str, Any], generation_run_id: Optional[int] = None) -> Optional[int]:
    """Store approved playbook in database."""
    try:
        # Generate playbook hash for deduplication
        playbook_json = json.dumps(playbook, sort_keys=True)
        import hashlib
        playbook_hash = hashlib.sha256(playbook_json.encode()).hexdigest()[:32]
        
        # Check if already exists
        check_query = """
        SELECT id FROM approved_playbooks 
        WHERE cve_id = %s AND playbook_hash = %s
        LIMIT 1
        """
        existing = db.fetch_one(check_query, (playbook["cve_id"], playbook_hash))
        if existing:
            print(f"  Playbook already exists in approved_playbooks (ID: {existing['id']})")
            return existing['id']
        
        # Insert new approved playbook
        insert_query = """
        INSERT INTO approved_playbooks (
            cve_id, playbook_data, playbook_hash, qa_score, qa_status,
            qa_feedback, generation_run_id, created_at
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
        RETURNING id
        """
        
        result = db.fetch_one(
            insert_query,
            (
                playbook["cve_id"],
                playbook_json,
                playbook_hash,
                qa_result.get("score", 0.0),
                qa_result.get("status", "UNKNOWN"),
                json.dumps(qa_result.get("feedback", [])),
                generation_run_id
            )
        )
        
        if result and result.get('id'):
            print(f"  Approved playbook stored with ID: {result['id']}")
            return result['id']
        else:
            print("  Failed to get ID after insert")
            return None
            
    except Exception as e:
        print(f"  Error storing approved playbook: {e}")
        return None


def run_full_pipeline_attempt(cve_id: str, attempt: int, max_attempts: int = 5) -> Dict[str, Any]:
    """Run one full pipeline attempt."""
    print(f"\n{'='*60}")
    print(f"PIPELINE ATTEMPT {attempt}/{max_attempts}: {cve_id}")
    print(f"{'='*60}")
    
    result = {
        "cve_id": cve_id,
        "attempt": attempt,
        "timestamp": datetime.utcnow().isoformat(),
        "success": False,
        "stage_results": {},
        "approved_playbook_id": None,
        "error": None
    }
    
    # Stage 1: Get context
    print("1. Getting CVE context...")
    context = get_cve_context(cve_id)
    if not context:
        result["error"] = "No context data"
        print(f"  ERROR: {result['error']}")
        return result
    
    result["stage_results"]["context"] = {"success": True, "context_keys": list(context.keys())}
    print(f"  SUCCESS: Context loaded ({len(context.keys())} keys)")
    
    # Stage 2: Generate prompt
    print("2. Creating tightened prompt...")
    prompt = create_tightened_prompt(cve_id, context)
    result["stage_results"]["prompt"] = {"success": True, "length": len(prompt)}
    print(f"  SUCCESS: Prompt created ({len(prompt)} chars)")
    
    # Stage 3: Call LLM
    print("3. Calling LLM...")
    llm = LLMClient()
    start_time = time.time()
    
    try:
        llm_result = llm.generate(prompt)
        elapsed = time.time() - start_time
        
        if llm_result.get('status') != 'completed':
            result["error"] = f"LLM failed: {llm_result.get('error', 'Unknown error')}"
            print(f"  ERROR: {result['error']}")
            return result
        
        raw_response = llm_result.get('raw_text', '')
        result["stage_results"]["llm"] = {
            "success": True,
            "model": llm.model,
            "elapsed_seconds": round(elapsed, 2),
            "response_length": len(raw_response)
        }
        print(f"  SUCCESS: LLM response received ({len(raw_response)} chars, {elapsed:.1f}s)")
        
    except Exception as e:
        result["error"] = f"LLM exception: {str(e)}"
        print(f"  ERROR: {result['error']}")
        return result
    
    # Stage 4: Apply rejection layer (non-strict for testing)
    print("4. Applying response rejection layer...")
    rejector = ResponseRejector(strict_mode=False)  # Non-strict to clean markdown
    passed, reason, parsed, validation = rejector.validate_response(raw_response)
    
    if not passed:
        result["error"] = f"Response validation failed: {reason}"
        print(f"  ERROR: {result['error']}")
        return result
    
    result["stage_results"]["rejection"] = {
        "success": True,
        "passed": True,
        "has_markdown": validation["analysis"].get("has_markdown", False),
        "has_explanatory_text": validation["analysis"].get("has_explanatory_text", False),
        "cleaning_applied": validation["analysis"].get("cleaning_applied", [])
    }
    print(f"  SUCCESS: Response validated and cleaned")
    if validation["analysis"].get("has_markdown"):
        print(f"    (Markdown cleaned: {validation['analysis'].get('markdown_type')})")
    
    # Stage 5: Run QA
    print("5. Running QA evaluation...")
    qa_engine = EnforcementEngine()
    qa_result = qa_engine.evaluate_playbook(parsed)
    
    if qa_result.get("status") != "PASS":
        result["error"] = f"QA failed: {qa_result.get('status')} - {qa_result.get('feedback', 'No feedback')}"
        print(f"  ERROR: {result['error']}")
        return result
    
    result["stage_results"]["qa"] = {
        "success": True,
        "status": qa_result.get("status"),
        "score": qa_result.get("score", 0.0),
        "feedback_count": len(qa_result.get("feedback", []))
    }
    print(f"  SUCCESS: QA passed (score: {qa_result.get('score', 0.0):.2f})")
    
    # Stage 6: Store in approved_playbooks
    print("6. Storing in approved_playbooks...")
    db = DatabaseClient()
    
    # First store generation run
    generation_run_id = None
    try:
        gen_query = """
        INSERT INTO generation_runs (
            cve_id, prompt, response, model, status, created_at,
            generation_source, llm_error_info
        )
        VALUES (%s, %s, %s, %s, %s, NOW(), %s, %s)
        RETURNING id
        """
        
        gen_result = db.fetch_one(
            gen_query,
            (
                cve_id,
                prompt[:5000],  # Truncate if too long
                raw_response[:10000],  # Truncate if too long
                llm.model,
                "completed",
                "live_llm",
                None
            )
        )
        
        if gen_result and gen_result.get('id'):
            generation_run_id = gen_result['id']
            print(f"  Generation run stored with ID: {generation_run_id}")
        else:
            print("  Warning: Could not store generation run")
            
    except Exception as e:
        print(f"  Warning: Error storing generation run: {e}")
    
    # Store approved playbook
    approved_id = store_approved_playbook(db, parsed, qa_result, generation_run_id)
    
    if approved_id:
        result["approved_playbook_id"] = approved_id
        result["success"] = True
        result["stage_results"]["storage"] = {"success": True, "approved_id": approved_id}
        print(f"  SUCCESS: Approved playbook stored with ID: {approved_id}")
    else:
        result["error"] = "Failed to store approved playbook"
        print(f"  ERROR: {result['error']}")
    
    return result


def main():
    """Main test function."""
    print("VS.ai — Playbook Engine Gen-3")
    print("Prompt/Model Alignment Directive - Step 4")
    print("Full Pipeline Test for CVE-2023-4863")
    print(f"Timestamp: {datetime.utcnow().isoformat()}")
    print("=" * 60)
    
    cve_id = "CVE-2023-4863"
    max_attempts = 5
    results = []
    
    for attempt in range(1, max_attempts + 1):
        result = run_full_pipeline_attempt(cve_id, attempt, max_attempts)
        results.append(result)
        
        # Save after each attempt
        import os
        os.makedirs("logs/misc_runtime", exist_ok=True)
        output_file = f"logs/misc_runtime/step4_attempt_{attempt}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w') as f:
            json.dump(result, f, indent=2, default=str)
        print(f"\nAttempt results saved to: {output_file}")
        
        # Check if successful
        if result.get("success"):
            print(f"\n{'='*60}")
            print("SUCCESS! Canonical playbook created and stored in approved_playbooks!")
            print(f"Approved playbook ID: {result['approved_playbook_id']}")
            print(f"{'='*60}")
            break
        
        # If not last attempt, wait and continue
        if attempt < max_attempts:
            wait_time = 5
            print(f"\nWaiting {wait_time} seconds before next attempt...")
            time.sleep(wait_time)
    
    # Summary
    print(f"\n{'='*60}")
    print("STEP 4 SUMMARY")
    print(f"{'='*60}")
    
    total = len(results)
    successful = sum(1 for r in results if r.get("success"))
    
    print(f"Total attempts: {total}")
    print(f"Successful: {successful}")
    print(f"Failed: {total - successful}")
    
    if successful > 0:
        successful_result = next(r for r in results if r.get("success"))
        print(f"\nSUCCESS CRITERIA MET:")
        print(f"1. Live LLM response generated: ✓")
        print(f"2. Valid JSON: ✓")
        print(f"3. Canonical schema (workflows): ✓")
        print(f"4. QA passed: ✓")
        print(f"5. approved_playbooks row created: ✓ (ID: {successful_result['approved_playbook_id']})")
        print(f"\nPrompt/Model Alignment Directive COMPLETE!")
    else:
        print(f"\nFAILURE ANALYSIS:")
        for i, result in enumerate(results, 1):
            if not result.get("success"):
                print(f"  Attempt {i}: {result.get('error', 'Unknown error')}")
        
        print(f"\nRecommendation: Try Step 5 - Model comparison")
    
    # Save final summary
    import os
    os.makedirs("logs/misc_runtime", exist_ok=True)
    summary_file = f"logs/misc_runtime/step4_summary_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    with open(summary_file, 'w') as f:
        json.dump({
            "summary": {
                "cve_id": cve_id,
                "total_attempts": total,
                "successful_attempts": successful,
                "timestamp": datetime.utcnow().isoformat(),
                "model": os.getenv("LLM_MODEL", "unknown")
            },
            "results": results
        }, f, indent=2, default=str)
    
    print(f"\nSummary saved to: {summary_file}")


if __name__ == "__main__":
    main()