#!/usr/bin/env python3
"""
QA Evaluator for Playbook Generation
Version: v0.1.0
Timestamp: 2026-04-08

Purpose:
- Deterministic QA evaluation for generated playbooks
- Apply approval rules consistently
- Provide clear feedback for rejected playbooks
"""

import logging
from typing import Dict, Any, List, Optional, Tuple

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def evaluate_playbook_qa(
    raw_response: str,
    parsed_playbook: Optional[Dict[str, Any]],
    parse_errors: List[str],
    has_retrieval_backing: bool = False
) -> Dict[str, Any]:
    """
    Evaluate playbook quality and determine QA result.
    
    Args:
        raw_response: Raw LLM response text
        parsed_playbook: Parsed playbook dictionary (from parser)
        parse_errors: List of parse errors from parser
        has_retrieval_backing: Whether this is a retrieval-backed run
        
    Returns:
        Dictionary with structure:
        {
            "qa_result": "approved" | "rejected" | "needs_revision",
            "qa_score": float (0.0-1.0),
            "qa_feedback": {
                "errors": list[str],
                "warnings": list[str],
                "strengths": list[str]
            }
        }
    """
    qa_result = "needs_revision"
    qa_score = 0.0
    qa_feedback = {
        "errors": [],
        "warnings": [],
        "strengths": []
    }
    
    # Rule 1: Raw response exists
    if not raw_response or not raw_response.strip():
        qa_feedback["errors"].append("Empty raw response - failure reason: no_output")
        qa_result = "rejected"
        return format_qa_result(qa_result, qa_score, qa_feedback)
    
    # Rule 2: Parse succeeded
    if parse_errors:
        qa_feedback["errors"].extend([f"Parse error: {err} - failure reason: parse_failure" for err in parse_errors])
        qa_result = "needs_revision"
        return format_qa_result(qa_result, qa_score, qa_feedback)
    
    if parsed_playbook is None:
        qa_feedback["errors"].append("No parsed playbook despite no parse errors - failure reason: schema_mismatch")
        qa_result = "rejected"
        return format_qa_result(qa_result, qa_score, qa_feedback)
    
    # Rule 3: Parsed playbook exists
    if "playbook" not in parsed_playbook:
        qa_feedback["errors"].append("Missing 'playbook' key in parsed response")
        qa_result = "rejected"
        return format_qa_result(qa_result, qa_score, qa_feedback)
    
    playbook = parsed_playbook["playbook"]
    
    # Rule 4: Playbook has a title
    if "title" not in playbook or not playbook["title"] or not str(playbook["title"]).strip():
        qa_feedback["errors"].append("Playbook missing or empty title")
        qa_result = "needs_revision"
    
    # Rule 5: Playbook has non-empty remediation steps with required structure
    if "remediation_steps" not in playbook:
        qa_feedback["errors"].append("Missing 'remediation_steps' in playbook")
        qa_result = "rejected"
    elif not isinstance(playbook["remediation_steps"], list):
        qa_feedback["errors"].append("'remediation_steps' is not a list")
        qa_result = "rejected"
    elif len(playbook["remediation_steps"]) == 0:
        qa_feedback["errors"].append("'remediation_steps' list is empty")
        qa_result = "needs_revision"
    else:
        # Check step structure
        valid_steps = 0
        fully_compliant_steps = 0
        for i, step in enumerate(playbook["remediation_steps"]):
            step_valid = True
            step_compliant = True
            
            if not isinstance(step, dict):
                qa_feedback["warnings"].append(f"Step {i+1} is not a dictionary")
                step_valid = False
                step_compliant = False
            else:
                # Check required fields
                required_fields = ["step_number", "description", "commands", "verification", "evidence_based"]
                for field in required_fields:
                    if field not in step:
                        qa_feedback["warnings"].append(f"Step {i+1} missing required field: '{field}'")
                        step_compliant = False
                
                # Check field types
                if "description" in step and (not step["description"] or not str(step["description"]).strip()):
                    qa_feedback["warnings"].append(f"Step {i+1} has empty description")
                    step_compliant = False
                
                if "commands" in step and (not isinstance(step["commands"], list) or len(step["commands"]) == 0):
                    qa_feedback["warnings"].append(f"Step {i+1} 'commands' field is empty or not a list")
                    step_compliant = False
                
                if "verification" in step and (not step["verification"] or not str(step["verification"]).strip()):
                    qa_feedback["warnings"].append(f"Step {i+1} has empty verification")
                    step_compliant = False
                
                if "evidence_based" in step and not isinstance(step["evidence_based"], bool):
                    qa_feedback["warnings"].append(f"Step {i+1} 'evidence_based' field is not a boolean")
                    step_compliant = False
            
            if step_valid:
                valid_steps += 1
            if step_compliant:
                fully_compliant_steps += 1
        
        if valid_steps > 0:
            qa_feedback["strengths"].append(f"Has {valid_steps} valid remediation steps ({fully_compliant_steps} fully compliant)")
            qa_score += 0.3  # Base score for having steps
            if fully_compliant_steps == len(playbook["remediation_steps"]):
                qa_score += 0.2  # Bonus for all steps being fully compliant
    
    # Rule 6: Retrieval-backed metadata exists for retrieval-backed runs
    if has_retrieval_backing:
        if "retrieval_metadata" not in playbook:
            qa_feedback["errors"].append("Missing retrieval metadata for retrieval-backed run")
            qa_score -= 0.3
            # This is a critical error for retrieval-backed runs
        else:
            # Validate retrieval_metadata structure
            rm = playbook["retrieval_metadata"]
            if not isinstance(rm, dict):
                qa_feedback["errors"].append("retrieval_metadata must be an object")
                qa_score -= 0.2
            else:
                # Check required fields
                required_rm_fields = ["decision", "evidence_count", "source_indexes"]
                for rm_field in required_rm_fields:
                    if rm_field not in rm:
                        qa_feedback["errors"].append(f"retrieval_metadata missing required field: {rm_field}")
                        qa_score -= 0.1
                    elif rm_field == "source_indexes" and (not isinstance(rm[rm_field], list) or len(rm[rm_field]) == 0):
                        qa_feedback["errors"].append("retrieval_metadata.source_indexes must be a non-empty array")
                        qa_score -= 0.1
                    elif rm_field == "evidence_count" and (not isinstance(rm[rm_field], int) or rm[rm_field] <= 0):
                        qa_feedback["errors"].append("retrieval_metadata.evidence_count must be a positive integer")
                        qa_score -= 0.1
                    elif rm_field == "decision" and rm[rm_field] not in ["weak", "sufficient", "empty"]:
                        qa_feedback["errors"].append("retrieval_metadata.decision must be 'weak', 'sufficient', or 'empty'")
                        qa_score -= 0.1
                
                # If all checks passed
                if not any("retrieval_metadata" in err for err in qa_feedback.get("errors", [])):
                    qa_feedback["strengths"].append("Includes valid retrieval metadata")
                    qa_score += 0.3
    
    # Additional quality checks for required fields
    required_fields = ["title", "cve_id", "severity", "affected_components", 
                      "verification_procedures", "rollback_procedures", "references"]
    
    # For retrieval-backed runs, retrieval_metadata is also required
    if has_retrieval_backing:
        required_fields.append("retrieval_metadata")
    
    for field in required_fields:
        if field in playbook:
            if field == "title" and playbook[field] and str(playbook[field]).strip():
                qa_feedback["strengths"].append(f"Has title: {playbook[field][:50]}...")
                qa_score += 0.1
            elif field == "cve_id" and playbook[field]:
                qa_feedback["strengths"].append(f"References CVE: {playbook[field]}")
                qa_score += 0.1
            elif field == "severity" and playbook[field]:
                qa_feedback["strengths"].append(f"Specifies severity: {playbook[field]}")
                qa_score += 0.1
            elif field == "affected_components" and isinstance(playbook[field], list) and len(playbook[field]) > 0:
                qa_feedback["strengths"].append(f"Lists {len(playbook[field])} affected components")
                qa_score += 0.1
            elif field == "verification_procedures" and isinstance(playbook[field], list) and len(playbook[field]) > 0:
                qa_feedback["strengths"].append(f"Provides {len(playbook[field])} verification procedures")
                qa_score += 0.15
            elif field == "rollback_procedures" and isinstance(playbook[field], list) and len(playbook[field]) > 0:
                qa_feedback["strengths"].append(f"Provides {len(playbook[field])} rollback procedures")
                qa_score += 0.15
            elif field == "references" and isinstance(playbook[field], list) and len(playbook[field]) > 0:
                qa_feedback["strengths"].append(f"Provides {len(playbook[field])} references")
                qa_score += 0.1
        else:
            qa_feedback["errors"].append(f"Missing required field: '{field}'")
            qa_result = "needs_revision"
    
    # Determine final result
    if qa_result != "rejected":
        if len(qa_feedback["errors"]) == 0:
            # No errors, check if we should approve
            if qa_score >= 0.5:  # Threshold for approval
                qa_result = "approved"
            else:
                qa_result = "needs_revision"
                qa_feedback["warnings"].append(f"Quality score too low: {qa_score:.2f} - failure reason: validation_reject")
        else:
            # Has errors but not rejected (needs_revision)
            qa_result = "needs_revision"
            # Add validation_reject reason if not already specified
            if not any("failure reason:" in error for error in qa_feedback["errors"]):
                qa_feedback["errors"].append("Validation failed - failure reason: validation_reject")
    
    # Cap score at 1.0
    qa_score = min(max(qa_score, 0.0), 1.0)
    
    return format_qa_result(qa_result, qa_score, qa_feedback)


def format_qa_result(
    qa_result: str,
    qa_score: float,
    qa_feedback: Dict[str, List[str]]
) -> Dict[str, Any]:
    """
    Format QA result consistently.
    
    Args:
        qa_result: "approved", "rejected", or "needs_revision"
        qa_score: Quality score (0.0-1.0)
        qa_feedback: Feedback dictionary
        
    Returns:
        Formatted QA result dictionary
    """
    return {
        "qa_result": qa_result,
        "qa_score": round(qa_score, 3),
        "qa_feedback": qa_feedback
    }


def test_qa_evaluator():
    """Test the QA evaluator with sample playbooks."""
    print("=" * 60)
    print("QA EVALUATOR TEST")
    print("=" * 60)
    
    # Test 1: Valid playbook
    print("\n1. Testing valid playbook:")
    valid_playbook = {
        "playbook": {
            "title": "Test Playbook",
            "cve_id": "CVE-TEST-0001",
            "severity": "High",
            "affected_components": ["test-product"],
            "remediation_steps": [
                {
                    "step_number": 1,
                    "description": "Test step 1 description",
                    "commands": ["command1", "command2"],
                    "verification": "Check logs for step 1 success",
                    "evidence_based": True
                },
                {
                    "step_number": 2,
                    "description": "Test step 2 description",
                    "commands": ["command3"],
                    "verification": "Verify step 2 completion",
                    "evidence_based": False
                }
            ],
            "verification_procedures": ["Verify system logs", "Check monitoring"],
            "rollback_procedures": ["Restore from backup", "Revert configuration"],
            "references": ["https://example.com"],
            "retrieval_metadata": {"decision": "sufficient", "evidence_count": 5}
        }
    }
    
    result = evaluate_playbook_qa(
        raw_response="{}",
        parsed_playbook=valid_playbook,
        parse_errors=[],
        has_retrieval_backing=True
    )
    
    print(f"QA Result: {result['qa_result']}")
    print(f"QA Score: {result['qa_score']:.3f}")
    print(f"Errors: {result['qa_feedback']['errors']}")
    print(f"Warnings: {result['qa_feedback']['warnings']}")
    print(f"Strengths: {result['qa_feedback']['strengths']}")
    
    # Test 2: Playbook with empty steps
    print("\n2. Testing playbook with empty steps:")
    empty_steps_playbook = {
        "playbook": {
            "title": "Empty Steps Playbook",
            "cve_id": "CVE-TEST-0002",
            "remediation_steps": []
        }
    }
    
    result = evaluate_playbook_qa(
        raw_response="{}",
        parsed_playbook=empty_steps_playbook,
        parse_errors=[],
        has_retrieval_backing=False
    )
    
    print(f"QA Result: {result['qa_result']}")
    print(f"QA Score: {result['qa_score']:.3f}")
    print(f"Errors: {result['qa_feedback']['errors']}")
    
    # Test 3: Playbook with parse errors
    print("\n3. Testing playbook with parse errors:")
    result = evaluate_playbook_qa(
        raw_response="{}",
        parsed_playbook=None,
        parse_errors=["JSON parse error: Expecting value"],
        has_retrieval_backing=True
    )
    
    print(f"QA Result: {result['qa_result']}")
    print(f"QA Score: {result['qa_score']:.3f}")
    print(f"Errors: {result['qa_feedback']['errors']}")
    
    # Test 4: Empty response
    print("\n4. Testing empty response:")
    result = evaluate_playbook_qa(
        raw_response="",
        parsed_playbook=None,
        parse_errors=[],
        has_retrieval_backing=False
    )
    
    print(f"QA Result: {result['qa_result']}")
    print(f"QA Score: {result['qa_score']:.3f}")
    print(f"Errors: {result['qa_feedback']['errors']}")
    
    # Test 5: Minimal valid playbook
    print("\n5. Testing minimal valid playbook:")
    minimal_playbook = {
        "playbook": {
            "title": "Minimal Playbook",
            "cve_id": "CVE-TEST-0003",
            "remediation_steps": [
                {"description": "Do something"}
            ]
        }
    }
    
    result = evaluate_playbook_qa(
        raw_response="{}",
        parsed_playbook=minimal_playbook,
        parse_errors=[],
        has_retrieval_backing=False
    )
    
    print(f"QA Result: {result['qa_result']}")
    print(f"QA Score: {result['qa_score']:.3f}")
    print(f"Errors: {result['qa_feedback']['errors']}")
    print(f"Warnings: {result['qa_feedback']['warnings']}")
    print(f"Strengths: {result['qa_feedback']['strengths']}")
    
    print("\n" + "=" * 60)
    print("QA EVALUATOR TEST COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    test_qa_evaluator()