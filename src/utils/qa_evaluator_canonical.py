#!/usr/bin/env python3
"""
Canonical QA Evaluator for Playbook Generation
Version: v0.2.0
Timestamp: 2026-04-09

Purpose:
- Native QA evaluation for canonical playbook schema
- Operates directly on canonical structure (workflows[], steps[])
- No legacy schema dependencies
- Provides clear feedback for canonical playbooks
"""

import logging
import hashlib
import json
from typing import Dict, Any, List, Optional, Tuple

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def evaluate_canonical_playbook_qa(
    raw_response: str,
    parsed_playbook: Optional[Dict[str, Any]],
    parse_errors: List[str],
    has_retrieval_backing: bool = False
) -> Dict[str, Any]:
    """
    Evaluate canonical playbook quality and determine QA result.
    
    Args:
        raw_response: Raw LLM response text
        parsed_playbook: Parsed playbook dictionary (canonical schema)
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
        qa_feedback["errors"].append("Empty raw response")
        qa_result = "rejected"
        return format_qa_result(qa_result, qa_score, qa_feedback)
    
    # Rule 2: Parse succeeded
    if parse_errors:
        qa_feedback["errors"].extend([f"Parse error: {err}" for err in parse_errors])
        qa_result = "needs_revision"
        return format_qa_result(qa_result, qa_score, qa_feedback)
    
    if parsed_playbook is None:
        qa_feedback["errors"].append("No parsed playbook despite no parse errors")
        qa_result = "rejected"
        return format_qa_result(qa_result, qa_score, qa_feedback)
    
    # Rule 3: Playbook has required canonical header fields
    required_header_fields = ["title", "cve_id", "vendor", "product", "severity", "description"]
    for field in required_header_fields:
        if field not in parsed_playbook:
            qa_feedback["errors"].append(f"Missing required canonical field: '{field}'")
            qa_result = "rejected"
        elif not parsed_playbook[field] or not str(parsed_playbook[field]).strip():
            qa_feedback["errors"].append(f"Empty required canonical field: '{field}'")
            qa_result = "needs_revision"
    
    if qa_result == "rejected":
        return format_qa_result(qa_result, qa_score, qa_feedback)
    
    # Rule 4: Playbook has workflows array
    if "workflows" not in parsed_playbook:
        qa_feedback["errors"].append("Missing 'workflows' array in canonical playbook")
        qa_result = "rejected"
        return format_qa_result(qa_result, qa_score, qa_feedback)
    
    workflows = parsed_playbook["workflows"]
    
    if not isinstance(workflows, list):
        qa_feedback["errors"].append("'workflows' must be an array")
        qa_result = "rejected"
        return format_qa_result(qa_result, qa_score, qa_feedback)
    
    if len(workflows) == 0:
        qa_feedback["errors"].append("'workflows' array is empty")
        qa_result = "needs_revision"
        return format_qa_result(qa_result, qa_score, qa_feedback)
    
    # Rule 5: Validate workflow structure
    valid_workflows = 0
    total_steps = 0
    valid_steps = 0
    fully_compliant_steps = 0
    
    for wf_idx, workflow in enumerate(workflows):
        if not isinstance(workflow, dict):
            qa_feedback["errors"].append(f"Workflow {wf_idx+1} is not a dictionary")
            continue
        
        # Check required workflow fields
        workflow_required = ["workflow_id", "workflow_name", "workflow_type", "steps"]
        missing_workflow_fields = [f for f in workflow_required if f not in workflow]
        
        if missing_workflow_fields:
            qa_feedback["errors"].append(f"Workflow {wf_idx+1} missing required fields: {missing_workflow_fields}")
            continue
        
        # Check steps array
        steps = workflow["steps"]
        if not isinstance(steps, list):
            qa_feedback["errors"].append(f"Workflow {wf_idx+1} 'steps' must be an array")
            continue
        
        if len(steps) == 0:
            qa_feedback["errors"].append(f"Workflow {wf_idx+1} 'steps' array is empty")
            continue
        
        valid_workflows += 1
        total_steps += len(steps)
        
        # Validate step structure
        for step_idx, step in enumerate(steps):
            if not isinstance(step, dict):
                qa_feedback["warnings"].append(f"Workflow {wf_idx+1}, Step {step_idx+1} is not a dictionary")
                continue
            
            step_valid = True
            step_compliant = True
            
            # Check required step fields (canonical schema)
            step_required = ["step_number", "title", "description", "commands", "target_os_or_platform", 
                           "expected_result", "verification"]
            
            for field in step_required:
                if field not in step:
                    qa_feedback["warnings"].append(f"Workflow {wf_idx+1}, Step {step_idx+1} missing required field: '{field}'")
                    step_compliant = False
            
            # Check field types and content
            if "description" in step and (not step["description"] or not str(step["description"]).strip()):
                qa_feedback["warnings"].append(f"Workflow {wf_idx+1}, Step {step_idx+1} has empty description")
                step_compliant = False
            
            if "commands" in step:
                if not isinstance(step["commands"], list):
                    qa_feedback["warnings"].append(f"Workflow {wf_idx+1}, Step {step_idx+1} 'commands' field is not a list")
                    step_compliant = False
                elif len(step["commands"]) == 0:
                    qa_feedback["warnings"].append(f"Workflow {wf_idx+1}, Step {step_idx+1} 'commands' list is empty")
                    step_compliant = False
            
            if "verification" in step and (not step["verification"] or not str(step["verification"]).strip()):
                qa_feedback["warnings"].append(f"Workflow {wf_idx+1}, Step {step_idx+1} has empty verification")
                step_compliant = False
            
            if "target_os_or_platform" in step and (not step["target_os_or_platform"] or not str(step["target_os_or_platform"]).strip()):
                qa_feedback["warnings"].append(f"Workflow {wf_idx+1}, Step {step_idx+1} has empty target_os_or_platform")
                step_compliant = False
            
            # Check evidence_based flag if present
            if "evidence_based" in step and not isinstance(step.get("evidence_based"), bool):
                qa_feedback["warnings"].append(f"Workflow {wf_idx+1}, Step {step_idx+1} 'evidence_based' field is not a boolean")
                step_compliant = False
            
            if step_valid:
                valid_steps += 1
            if step_compliant:
                fully_compliant_steps += 1
    
    # Calculate score based on workflow and step quality
    if valid_workflows > 0:
        qa_feedback["strengths"].append(f"Has {valid_workflows} valid workflows with {valid_steps} steps")
        qa_score += 0.3  # Base score for having workflows
        
        if valid_steps > 0:
            qa_score += 0.2  # Bonus for having steps
            
            step_compliance_ratio = fully_compliant_steps / valid_steps if valid_steps > 0 else 0
            qa_score += step_compliance_ratio * 0.3  # Up to 0.3 for step compliance
            
            # Bonus for multiple workflows
            if valid_workflows > 1:
                qa_score += 0.1
    
    # Rule 6: Check for other canonical sections
    if "pre_remediation_checks" in parsed_playbook:
        checks = parsed_playbook["pre_remediation_checks"]
        if isinstance(checks, dict):
            if "required_checks" in checks and isinstance(checks["required_checks"], list) and len(checks["required_checks"]) > 0:
                qa_feedback["strengths"].append("Includes pre-remediation checks")
                qa_score += 0.1
    
    if "post_remediation_validation" in parsed_playbook:
        validation = parsed_playbook["post_remediation_validation"]
        if isinstance(validation, dict):
            if "validation_steps" in validation and isinstance(validation["validation_steps"], list) and len(validation["validation_steps"]) > 0:
                qa_feedback["strengths"].append("Includes post-remediation validation")
                qa_score += 0.1
    
    if "additional_recommendations" in parsed_playbook:
        recommendations = parsed_playbook["additional_recommendations"]
        if isinstance(recommendations, list) and len(recommendations) > 0:
            qa_feedback["strengths"].append("Includes additional recommendations")
            qa_score += 0.1
    
    # Rule 7: Check retrieval_metadata for retrieval-backed runs
    if has_retrieval_backing:
        if "retrieval_metadata" not in parsed_playbook:
            qa_feedback["errors"].append("Missing retrieval_metadata for retrieval-backed run")
            qa_score -= 0.3
        else:
            rm = parsed_playbook["retrieval_metadata"]
            if not isinstance(rm, dict):
                qa_feedback["errors"].append("retrieval_metadata must be an object")
                qa_score -= 0.2
            else:
                rm_required = ["decision", "evidence_count", "source_indexes", "generation_timestamp"]
                for rm_field in rm_required:
                    if rm_field not in rm:
                        qa_feedback["errors"].append(f"retrieval_metadata missing required field: {rm_field}")
                        qa_score -= 0.1
                
                # If all checks passed
                if not any("retrieval_metadata" in err for err in qa_feedback.get("errors", [])):
                    qa_feedback["strengths"].append("Includes valid retrieval metadata")
                    qa_score += 0.3
    
    # Rule 8: Check for version arrays
    version_fields = ["affected_versions", "fixed_versions", "affected_platforms", "references"]
    for field in version_fields:
        if field in parsed_playbook:
            value = parsed_playbook[field]
            if isinstance(value, list) and len(value) > 0:
                qa_feedback["strengths"].append(f"Provides {field.replace('_', ' ')}")
                qa_score += 0.05
            elif not value or (isinstance(value, list) and len(value) == 0):
                qa_feedback["warnings"].append(f"Empty {field.replace('_', ' ')}")
    
    # Determine final result
    if qa_result != "rejected":
        if len(qa_feedback["errors"]) == 0:
            # No errors, check if we should approve
            if qa_score >= 0.5:  # Threshold for approval
                qa_result = "approved"
            else:
                qa_result = "needs_revision"
                qa_feedback["warnings"].append(f"Quality score too low: {qa_score:.2f}")
        else:
            # Has errors - check if score is high enough to approve despite errors
            if qa_score >= 0.9:  # Very high score can override minor errors
                qa_result = "approved"
                qa_feedback["warnings"].append(f"Approved despite errors due to high score ({qa_score:.2f})")
            else:
                qa_result = "needs_revision"
    
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


def verify_payload_integrity(stored_payload: Dict[str, Any], evaluated_payload: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Verify that the payload evaluated by QA matches the stored payload.
    
    Args:
        stored_payload: Payload stored in database
        evaluated_payload: Payload evaluated by QA
        
    Returns:
        Tuple of (is_valid, hash_string)
    """
    # Normalize both payloads for comparison
    stored_json = json.dumps(stored_payload, sort_keys=True)
    evaluated_json = json.dumps(evaluated_payload, sort_keys=True)
    
    stored_hash = hashlib.sha256(stored_json.encode()).hexdigest()
    evaluated_hash = hashlib.sha256(evaluated_json.encode()).hexdigest()
    
    is_valid = stored_hash == evaluated_hash
    
    return is_valid, stored_hash


def test_canonical_qa_evaluator():
    """Test the canonical QA evaluator with sample playbooks."""
    print("=" * 60)
    print("CANONICAL QA EVALUATOR TEST")
    print("=" * 60)
    
    # Test 1: Valid canonical playbook
    print("\n1. Testing valid canonical playbook:")
    valid_canonical_playbook = {
        "title": "Canonical Remediation Playbook for CVE-2023-4863",
        "cve_id": "CVE-2023-4863",
        "vendor": "Google",
        "product": "WebP",
        "severity": "HIGH",
        "description": "Heap buffer overflow vulnerability",
        "affected_versions": ["< 1.3.2"],
        "fixed_versions": ["1.3.2"],
        "affected_platforms": ["Linux", "Windows"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-4863"],
        "retrieval_metadata": {
            "decision": "strong",
            "evidence_count": 5,
            "source_indexes": ["spring-ai-document-index"],
            "generation_timestamp": "2026-04-09T16:05:12.366955"
        },
        "pre_remediation_checks": {
            "required_checks": [
                {
                    "check_id": "check_1",
                    "description": "Check WebP version",
                    "commands": ["libwebp --version"],
                    "expected_result": "Version information"
                }
            ]
        },
        "workflows": [
            {
                "workflow_id": "workflow_1",
                "workflow_name": "Repository Update Workflow",
                "workflow_type": "repository_update",
                "steps": [
                    {
                        "step_number": 1,
                        "title": "Update repositories",
                        "description": "Refresh package repositories",
                        "commands": ["apt-get update", "yum check-update"],
                        "target_os_or_platform": "Linux",
                        "expected_result": "Package lists updated",
                        "verification": "Check exit code",
                        "rollback_hint": "No rollback needed",
                        "evidence_based": True
                    },
                    {
                        "step_number": 2,
                        "title": "Install update",
                        "description": "Install security update",
                        "commands": ["apt-get install --only-upgrade libwebp"],
                        "target_os_or_platform": "Linux/Ubuntu",
                        "expected_result": "Package updated",
                        "verification": "Verify version",
                        "rollback_hint": "Downgrade if needed",
                        "evidence_based": True
                    }
                ]
            }
        ],
        "post_remediation_validation": {
            "validation_steps": [
                {
                    "step_id": "validation_1",
                    "description": "Verify patch",
                    "commands": ["libwebp --version"],
                    "expected_outcomes": ["Version 1.3.2 or higher"]
                }
            ]
        },
        "additional_recommendations": [
            {
                "recommendation_id": "rec_1",
                "category": "security_hardening",
                "description": "Implement image validation",
                "priority": "high",
                "implementation_guidance": "Add server-side validation"
            }
        ]
    }
    
    result = evaluate_canonical_playbook_qa(
        raw_response=json.dumps(valid_canonical_playbook),
        parsed_playbook=valid_canonical_playbook,
        parse_errors=[],
        has_retrieval_backing=True
    )
    
    print(f"QA Result: {result['qa_result']}")
    print(f"QA Score: {result['qa_score']:.3f}")
    print(f"Errors: {result['qa_feedback']['errors']}")
    print(f"Warnings: {result['qa_feedback']['warnings']}")
    print(f"Strengths: {result['qa_feedback']['strengths']}")
    
    # Test 2: Playbook missing workflows
    print("\n2. Testing playbook missing workflows:")
    no_workflows_playbook = {
        "title": "Invalid Playbook",
        "cve_id": "CVE-TEST-0001",
        "vendor": "Test",
        "product": "Test",
        "severity": "High",
        "description": "Test"
    }
    
    result = evaluate_canonical_playbook_qa(
        raw_response=json.dumps(no_workflows_playbook),
        parsed_playbook=no_workflows_playbook,
        parse_errors=[],
        has_retrieval_backing=False
    )
    
    print(f"QA Result: {result['qa_result']}")
    print(f"QA Score: {result['qa_score']:.3f}")
    print(f"Errors: {result['qa_feedback']['errors']}")
    
    # Test 3: Playbook with empty workflows
    print("\n3. Testing playbook with empty workflows:")
    empty_workflows_playbook = {
        "title": "Empty Workflows Playbook",
        "cve_id": "CVE-TEST-0002",
        "vendor": "Test",
        "product": "Test",
        "severity": "High",
        "description": "Test",
        "workflows": []
    }
    
    result = evaluate_canonical_playbook_qa(
        raw_response=json.dumps(empty_workflows_playbook),
        parsed_playbook=empty_workflows_playbook,
        parse_errors=[],
        has_retrieval_backing=False
    )
    
    print(f"QA Result: {result['qa_result']}")
    print(f"QA Score: {result['qa_score']:.3f}")
    print(f"Errors: {result['qa_feedback']['errors']}")
    
    # Test 4: Test payload integrity
    print("\n4. Testing payload integrity verification:")
    is_valid, payload_hash = verify_payload_integrity(valid_canonical_playbook, valid_canonical_playbook)
    print(f"Payload integrity: {is_valid}")
    print(f"Payload hash: {payload_hash[:16]}...")
    
    modified_playbook = valid_canonical_playbook.copy()
    modified_playbook["title"] = "Modified Title"
    is_valid, modified_hash = verify_payload_integrity(valid_canonical_playbook, modified_playbook)
    print(f"Modified payload integrity: {is_valid}")
    print(f"Modified hash: {modified_hash[:16]}...")
    
    print("\n" + "=" * 60)
    print("CANONICAL QA EVALUATOR TEST COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    test_canonical_qa_evaluator()