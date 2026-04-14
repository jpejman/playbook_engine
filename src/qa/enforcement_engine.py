#!/usr/bin/env python3
"""
QA Enforcement Engine (Canonical)
Version: v0.2.0
Timestamp: 2026-04-09

Purpose:
- Enforce QA rules on canonical playbooks
- Provide PASS/FAIL decisions with structured feedback
- Integrate with canonical QA evaluator
- Support enforcement versioning
- No legacy schema dependencies
"""

import json
import logging
import hashlib
from typing import Dict, Any, List, Optional
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import canonical QA evaluator
from src.utils.qa_evaluator_canonical import evaluate_canonical_playbook_qa, verify_payload_integrity


class EnforcementEngine:
    """QA enforcement engine for playbook validation."""
    
    def __init__(self, enforcement_version: str = "v0.2.0"):
        self.enforcement_version = enforcement_version
        self.rules = self._load_rules()
        
    def _load_rules(self) -> Dict[str, Any]:
        """Load enforcement rules for canonical schema."""
        return {
            "version": self.enforcement_version,
            "rules": {
                "required_canonical_fields": ["title", "cve_id", "vendor", "product", "severity", "description", "workflows"],
                "min_workflows": 1,
                "min_steps_per_workflow": 1,
                "max_errors": 0,
                "min_score": 0.5,
                "allow_needs_revision": False,
                "cve_must_match": True,
                "require_evidence_based": False,  # Can be enabled later
                "require_verification": True,
                "require_target_platform": True,
                "require_rollback_hint": False,  # Can be enabled later
                "require_references": False  # Can be enabled later
            }
        }
    
    def evaluate_playbook(self, playbook: Dict[str, Any], expected_cve_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Evaluate canonical playbook against enforcement rules.
        
        Args:
            playbook: Parsed canonical playbook dictionary
            expected_cve_id: Expected CVE ID for validation
            
        Returns:
            Dictionary with enforcement result:
            {
                "status": "PASS" | "FAIL",
                "failure_type": str | None,
                "score": float,
                "decision": "approved" | "rejected" | "needs_revision",
                "enforcement_version": str,
                "feedback": Dict[str, List[str]],
                "rule_violations": List[str],
                "timestamp": str,
                "payload_hash": str
            }
        """
        logger.info(f"Canonical enforcement engine evaluating playbook (version: {self.enforcement_version})")
        
        # Initialize result structure
        result = {
            "status": "PASS",
            "failure_type": None,
            "score": 0.0,
            "decision": "approved",
            "enforcement_version": self.enforcement_version,
            "feedback": {
                "errors": [],
                "warnings": [],
                "strengths": []
            },
            "rule_violations": [],
            "timestamp": datetime.utcnow().isoformat(),
            "payload_hash": hashlib.sha256(json.dumps(playbook, sort_keys=True).encode()).hexdigest()[:16]
        }
        
        # Step 1: Basic validation
        if not playbook:
            result["status"] = "FAIL"
            result["failure_type"] = "empty_playbook"
            result["decision"] = "rejected"
            result["feedback"]["errors"].append("Playbook is empty or None")
            return result
        
        # Step 2: Check for legacy schema (should not exist in canonical flow)
        if "playbook" in playbook:
            result["feedback"]["warnings"].append("Playbook contains legacy 'playbook' key - may be legacy schema")
        
        # Step 3: Check CVE ID match if expected
        if expected_cve_id and "cve_id" in playbook:
            if playbook["cve_id"] != expected_cve_id:
                result["status"] = "FAIL"
                result["failure_type"] = "cve_mismatch"
                result["rule_violations"].append(f"CVE mismatch: expected {expected_cve_id}, got {playbook.get('cve_id')}")
                result["feedback"]["errors"].append(f"CVE ID mismatch: expected '{expected_cve_id}', got '{playbook.get('cve_id')}'")
        
        # Step 4: Run canonical QA evaluation
        raw_response = json.dumps(playbook)
        parse_errors = []
        
        qa_result = evaluate_canonical_playbook_qa(
            raw_response=raw_response,
            parsed_playbook=playbook,
            parse_errors=parse_errors,
            has_retrieval_backing=False  # Default for now
        )
        
        # Map QA result to enforcement result
        result["score"] = qa_result.get("qa_score", 0.0)
        result["decision"] = qa_result.get("qa_result", "needs_revision")
        
        # Merge feedback
        if "qa_feedback" in qa_result:
            result["feedback"]["errors"].extend(qa_result["qa_feedback"].get("errors", []))
            result["feedback"]["warnings"].extend(qa_result["qa_feedback"].get("warnings", []))
            result["feedback"]["strengths"].extend(qa_result["qa_feedback"].get("strengths", []))
        
        # Step 5: Apply canonical enforcement rules
        self._apply_enforcement_rules(playbook, result)
        
        # Step 6: Final decision
        if result["status"] == "PASS":
            # Check if QA result is approved
            if result["decision"] != "approved":
                result["status"] = "FAIL"
                result["failure_type"] = "qa_rejected"
                result["feedback"]["errors"].append(f"QA result: {result['decision']}")
            elif result["score"] < self.rules["rules"]["min_score"]:
                result["status"] = "FAIL"
                result["failure_type"] = "score_too_low"
                result["feedback"]["errors"].append(f"Score {result['score']:.2f} below minimum {self.rules['rules']['min_score']}")
        
        # Step 7: Check error count
        if len(result["feedback"]["errors"]) > self.rules["rules"]["max_errors"]:
            result["status"] = "FAIL"
            if not result["failure_type"]:
                result["failure_type"] = "too_many_errors"
        
        # Step 8: Check rule violations
        if result["rule_violations"]:
            result["status"] = "FAIL"
            if not result["failure_type"]:
                result["failure_type"] = "rule_violation"
        
        logger.info(f"Canonical enforcement result: {result['status']} (score: {result['score']:.2f}, hash: {result['payload_hash']})")
        return result
    
    def _apply_enforcement_rules(self, playbook: Dict[str, Any], result: Dict[str, Any]):
        """Apply canonical enforcement rules to playbook."""
        rules = self.rules["rules"]
        
        # Rule 1: Required canonical fields
        for field in rules["required_canonical_fields"]:
            if field not in playbook:
                result["rule_violations"].append(f"Missing required canonical field: {field}")
                result["feedback"]["errors"].append(f"Missing required canonical field: '{field}'")
            elif not playbook[field] or (isinstance(playbook[field], list) and len(playbook[field]) == 0):
                result["rule_violations"].append(f"Empty required canonical field: {field}")
                result["feedback"]["errors"].append(f"Empty required canonical field: '{field}'")
        
        # Rule 2: Minimum workflows and steps
        if "workflows" in playbook and isinstance(playbook["workflows"], list):
            if len(playbook["workflows"]) < rules["min_workflows"]:
                result["rule_violations"].append(f"Insufficient workflows: {len(playbook['workflows'])} < {rules['min_workflows']}")
                result["feedback"]["errors"].append(f"Need at least {rules['min_workflows']} workflows, got {len(playbook['workflows'])}")
            
            # Check each workflow for minimum steps
            for wf_idx, workflow in enumerate(playbook["workflows"]):
                if isinstance(workflow, dict) and "steps" in workflow:
                    steps = workflow["steps"]
                    if isinstance(steps, list) and len(steps) < rules["min_steps_per_workflow"]:
                        wf_name = workflow.get("workflow_name", f"Workflow {wf_idx+1}")
                        result["rule_violations"].append(f"{wf_name} has insufficient steps: {len(steps)} < {rules['min_steps_per_workflow']}")
                        result["feedback"]["errors"].append(f"{wf_name} needs at least {rules['min_steps_per_workflow']} steps, got {len(steps)}")
        
        # Rule 3: Step structure validation (canonical)
        if "workflows" in playbook and isinstance(playbook["workflows"], list):
            for wf_idx, workflow in enumerate(playbook["workflows"]):
                if isinstance(workflow, dict) and "steps" in workflow:
                    steps = workflow["steps"]
                    if isinstance(steps, list):
                        for step_idx, step in enumerate(steps):
                            if not isinstance(step, dict):
                                result["rule_violations"].append(f"Workflow {wf_idx+1}, Step {step_idx+1} is not a dictionary")
                                result["feedback"]["errors"].append(f"Workflow {wf_idx+1}, Step {step_idx+1} must be a dictionary")
                                continue
                            
                            # Check for required canonical step fields
                            step_required = ["description", "commands", "verification"]
                            if rules["require_target_platform"]:
                                step_required.append("target_os_or_platform")
                            
                            for field in step_required:
                                if field not in step:
                                    result["rule_violations"].append(f"Workflow {wf_idx+1}, Step {step_idx+1} missing required field: {field}")
                                    result["feedback"]["errors"].append(f"Workflow {wf_idx+1}, Step {step_idx+1} missing required field: '{field}'")
                                elif field == "commands" and (not isinstance(step[field], list) or len(step[field]) == 0):
                                    result["rule_violations"].append(f"Workflow {wf_idx+1}, Step {step_idx+1} commands must be non-empty list")
                                    result["feedback"]["errors"].append(f"Workflow {wf_idx+1}, Step {step_idx+1} 'commands' must be a non-empty list")
                                elif field in ["description", "verification", "target_os_or_platform"] and (not step[field] or not str(step[field]).strip()):
                                    result["rule_violations"].append(f"Workflow {wf_idx+1}, Step {step_idx+1} {field} cannot be empty")
                                    result["feedback"]["errors"].append(f"Workflow {wf_idx+1}, Step {step_idx+1} '{field}' cannot be empty")
                            
                            # Check rollback hint if required
                            if rules["require_rollback_hint"] and "rollback_hint" not in step:
                                result["rule_violations"].append(f"Workflow {wf_idx+1}, Step {step_idx+1} missing rollback_hint")
                                result["feedback"]["warnings"].append(f"Workflow {wf_idx+1}, Step {step_idx+1} missing rollback hint (required by rules)")
        
        # Rule 4: Check for evidence-based steps if required
        if rules["require_evidence_based"]:
            has_evidence_based = False
            if "workflows" in playbook and isinstance(playbook["workflows"], list):
                for workflow in playbook["workflows"]:
                    if isinstance(workflow, dict) and "steps" in workflow:
                        steps = workflow["steps"]
                        if isinstance(steps, list):
                            for step in steps:
                                if isinstance(step, dict) and step.get("evidence_based") is True:
                                    has_evidence_based = True
                                    break
                    if has_evidence_based:
                        break
            
            if not has_evidence_based:
                result["rule_violations"].append("No evidence-based steps found")
                result["feedback"]["warnings"].append("No evidence-based steps found (required by rules)")
        
        # Rule 5: Check references if required
        if rules["require_references"]:
            if "references" not in playbook:
                result["rule_violations"].append("Missing references")
                result["feedback"]["warnings"].append("Missing references (required by rules)")
            elif "references" in playbook and isinstance(playbook["references"], list) and len(playbook["references"]) == 0:
                result["rule_violations"].append("Empty references array")
                result["feedback"]["warnings"].append("References array is empty")
        # If require_references is False, don't check references at all


def evaluate_playbook(playbook: Dict[str, Any], expected_cve_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Convenience function for evaluating playbooks.
    
    Args:
        playbook: Parsed playbook dictionary
        expected_cve_id: Expected CVE ID for validation
        
    Returns:
        Enforcement result dictionary
    """
    engine = EnforcementEngine()
    return engine.evaluate_playbook(playbook, expected_cve_id)


def test_enforcement_engine():
    """Test the canonical enforcement engine with sample playbooks."""
    print("=" * 60)
    print("CANONICAL ENFORCEMENT ENGINE TEST")
    print("=" * 60)
    
    engine = EnforcementEngine()
    
    # Test 1: Valid canonical playbook
    print("\n1. Testing valid canonical playbook:")
    valid_canonical_playbook = {
        "title": "Canonical Test Playbook",
        "cve_id": "CVE-TEST-0001",
        "vendor": "Test Vendor",
        "product": "Test Product",
        "severity": "High",
        "description": "Test vulnerability description",
        "affected_versions": ["< 1.0.0"],
        "fixed_versions": ["1.0.0"],
        "affected_platforms": ["Linux"],
        "references": ["https://example.com"],
        "workflows": [
            {
                "workflow_id": "workflow_1",
                "workflow_name": "Test Workflow",
                "workflow_type": "repository_update",
                "steps": [
                    {
                        "step_number": 1,
                        "title": "Test Step",
                        "description": "Test step description",
                        "commands": ["command1", "command2"],
                        "target_os_or_platform": "Linux",
                        "expected_result": "Step completes successfully",
                        "verification": "Check logs for success",
                        "rollback_hint": "No rollback needed",
                        "evidence_based": True
                    }
                ]
            }
        ]
    }
    
    result = engine.evaluate_playbook(valid_canonical_playbook, "CVE-TEST-0001")
    print(f"Status: {result['status']}")
    print(f"Score: {result['score']:.2f}")
    print(f"Decision: {result['decision']}")
    print(f"Payload Hash: {result['payload_hash']}")
    print(f"Errors: {result['feedback']['errors']}")
    
    # Test 2: Playbook with CVE mismatch
    print("\n2. Testing playbook with CVE mismatch:")
    result = engine.evaluate_playbook(valid_canonical_playbook, "CVE-DIFFERENT-0001")
    print(f"Status: {result['status']}")
    print(f"Failure Type: {result['failure_type']}")
    print(f"Errors: {result['feedback']['errors']}")
    
    # Test 3: Playbook missing required canonical fields
    print("\n3. Testing playbook missing required canonical fields:")
    invalid_canonical_playbook = {
        "title": "Incomplete Canonical Playbook"
        # Missing cve_id, vendor, product, workflows, etc.
    }
    
    result = engine.evaluate_playbook(invalid_canonical_playbook)
    print(f"Status: {result['status']}")
    print(f"Rule Violations: {result['rule_violations']}")
    print(f"Errors: {result['feedback']['errors']}")
    
    # Test 4: Playbook with empty workflows
    print("\n4. Testing playbook with empty workflows:")
    empty_workflows_playbook = {
        "title": "Empty Workflows Playbook",
        "cve_id": "CVE-TEST-0002",
        "vendor": "Test",
        "product": "Test",
        "severity": "High",
        "description": "Test",
        "workflows": []
    }
    
    result = engine.evaluate_playbook(empty_workflows_playbook)
    print(f"Status: {result['status']}")
    print(f"Errors: {result['feedback']['errors']}")
    
    # Test 5: Legacy schema (should work but with warning)
    print("\n5. Testing legacy schema (with warning):")
    legacy_playbook = {
        "playbook": {
            "title": "Legacy Playbook",
            "cve_id": "CVE-LEGACY-0001",
            "remediation_steps": [
                {
                    "step_number": 1,
                    "description": "Legacy step",
                    "commands": ["cmd1"],
                    "verification": "Check"
                }
            ]
        }
    }
    
    result = engine.evaluate_playbook(legacy_playbook)
    print(f"Status: {result['status']}")
    print(f"Warnings: {result['feedback']['warnings']}")
    
    print("\n" + "=" * 60)
    print("CANONICAL ENFORCEMENT ENGINE TEST COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    test_enforcement_engine()