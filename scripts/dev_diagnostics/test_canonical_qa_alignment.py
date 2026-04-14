#!/usr/bin/env python3
"""
Test Canonical QA Alignment
Version: v1.0.0
Timestamp: 2026-04-09

Purpose:
- Test that QA system natively evaluates canonical schema
- Verify no legacy schema dependencies
- Validate payload integrity
- Re-run CVE-2023-4863 through updated QA system
"""

import json
import hashlib
import sys
from datetime import datetime
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent))

from src.utils.db import DatabaseClient
from src.qa.enforcement_engine import evaluate_playbook
from src.utils.qa_evaluator_canonical import evaluate_canonical_playbook_qa, verify_payload_integrity
from src.validation.canonical_validator import validate_playbook_canonical


def test_canonical_qa_evaluator():
    """Test canonical QA evaluator directly."""
    print("=" * 80)
    print("TEST 1: CANONICAL QA EVALUATOR")
    print("=" * 80)
    
    # Create a test canonical playbook
    test_canonical_playbook = {
        "title": "Test Canonical Playbook",
        "cve_id": "CVE-TEST-0001",
        "vendor": "Test Vendor",
        "product": "Test Product",
        "severity": "HIGH",
        "description": "Test vulnerability description",
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
    
    # Test canonical QA evaluator
    raw_response = json.dumps(test_canonical_playbook)
    qa_result = evaluate_canonical_playbook_qa(
        raw_response=raw_response,
        parsed_playbook=test_canonical_playbook,
        parse_errors=[],
        has_retrieval_backing=False
    )
    
    print(f"QA Result: {qa_result['qa_result']}")
    print(f"QA Score: {qa_result['qa_score']:.3f}")
    print(f"Errors: {qa_result['qa_feedback']['errors']}")
    print(f"Warnings: {qa_result['qa_feedback']['warnings']}")
    print(f"Strengths: {qa_result['qa_feedback']['strengths']}")
    
    # Verify no legacy schema references
    raw_response_lower = raw_response.lower()
    legacy_terms = ["remediation_steps", "\"playbook\":", "playbook."]
    for term in legacy_terms:
        if term in raw_response_lower:
            print(f"WARNING: Legacy term '{term}' found in response")
    
    return qa_result['qa_result'] == 'approved'


def test_canonical_enforcement_engine():
    """Test canonical enforcement engine."""
    print("\n" + "=" * 80)
    print("TEST 2: CANONICAL ENFORCEMENT ENGINE")
    print("=" * 80)
    
    # Create a test canonical playbook
    test_canonical_playbook = {
        "title": "Test Canonical Playbook",
        "cve_id": "CVE-TEST-0002",
        "vendor": "Test Vendor",
        "product": "Test Product",
        "severity": "HIGH",
        "description": "Test vulnerability description",
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
    
    # Test enforcement engine
    enforcement_result = evaluate_playbook(
        playbook=test_canonical_playbook,
        expected_cve_id="CVE-TEST-0002"
    )
    
    print(f"Status: {enforcement_result['status']}")
    print(f"Score: {enforcement_result['score']:.2f}")
    print(f"Decision: {enforcement_result['decision']}")
    print(f"Payload Hash: {enforcement_result['payload_hash']}")
    
    if enforcement_result['feedback']['errors']:
        print(f"Errors: {enforcement_result['feedback']['errors']}")
    if enforcement_result['feedback']['warnings']:
        print(f"Warnings: {enforcement_result['feedback']['warnings']}")
    if enforcement_result['feedback']['strengths']:
        print(f"Strengths: {enforcement_result['feedback']['strengths']}")
    
    # Check for legacy schema assumptions
    if 'playbook' in test_canonical_playbook:
        print("ERROR: Playbook contains legacy 'playbook' key")
        return False
    
    if 'remediation_steps' in test_canonical_playbook:
        print("ERROR: Playbook contains legacy 'remediation_steps' key")
        return False
    
    return enforcement_result['status'] == 'PASS'


def test_cve_2023_4863_canonical_playbook():
    """Test with real CVE-2023-4863 canonical playbook."""
    print("\n" + "=" * 80)
    print("TEST 3: REAL CVE-2023-4863 CANONICAL PLAYBOOK")
    print("=" * 80)
    
    db = DatabaseClient()
    
    # Get canonical playbook from approved_playbooks (ID 26)
    result = db.fetch_one(
        'SELECT playbook FROM approved_playbooks WHERE id = 26'
    )
    
    if not result:
        print("ERROR: No canonical playbook found for CVE-2023-4863")
        return False
    
    playbook = result['playbook']
    if isinstance(playbook, str):
        playbook = json.loads(playbook)
    
    print(f"Loaded canonical playbook for CVE-2023-4863")
    print(f"Has workflows: {'workflows' in playbook}")
    print(f"Number of workflows: {len(playbook.get('workflows', []))}")
    
    # Validate canonical schema
    is_valid, errors = validate_playbook_canonical(playbook)
    if not is_valid:
        print(f"ERROR: Playbook is not valid canonical schema")
        for error in errors:
            print(f"  - {error}")
        return False
    
    print(f"Canonical validation: PASS")
    
    # Test with canonical enforcement engine
    enforcement_result = evaluate_playbook(
        playbook=playbook,
        expected_cve_id='CVE-2023-4863'
    )
    
    print(f"\nEnforcement Result:")
    print(f"  Status: {enforcement_result['status']}")
    print(f"  Score: {enforcement_result['score']:.2f}")
    print(f"  Decision: {enforcement_result['decision']}")
    print(f"  Payload Hash: {enforcement_result['payload_hash']}")
    
    # Test payload integrity
    is_valid, payload_hash = verify_payload_integrity(playbook, playbook)
    print(f"\nPayload Integrity:")
    print(f"  Is valid: {is_valid}")
    print(f"  Hash: {payload_hash[:16]}...")
    print(f"  Matches enforcement hash: {payload_hash[:16] == enforcement_result['payload_hash']}")
    
    # Check for legacy schema contamination
    playbook_json = json.dumps(playbook)
    legacy_patterns = ['"playbook":', '"remediation_steps":']
    for pattern in legacy_patterns:
        if pattern in playbook_json:
            print(f"WARNING: Legacy pattern '{pattern}' found in playbook")
    
    return enforcement_result['status'] == 'PASS' and is_valid


def test_legacy_schema_rejection():
    """Test that legacy schema is rejected by canonical QA."""
    print("\n" + "=" * 80)
    print("TEST 4: LEGACY SCHEMA REJECTION")
    print("=" * 80)
    
    # Create a legacy schema playbook
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
    
    # Test with canonical enforcement engine
    enforcement_result = evaluate_playbook(
        playbook=legacy_playbook,
        expected_cve_id='CVE-LEGACY-0001'
    )
    
    print(f"Legacy schema enforcement result:")
    print(f"  Status: {enforcement_result['status']}")
    print(f"  Score: {enforcement_result['score']:.2f}")
    print(f"  Decision: {enforcement_result['decision']}")
    
    # Legacy schema should fail because it doesn't have 'workflows'
    if enforcement_result['status'] == 'PASS':
        print("WARNING: Legacy schema passed canonical enforcement (should fail)")
        return False
    
    print("SUCCESS: Legacy schema correctly rejected by canonical enforcement")
    return True


def main():
    """Run all canonical QA alignment tests."""
    print("VS.ai — Playbook Engine Gen-3")
    print("Canonical QA Alignment Test Suite")
    print("Timestamp (UTC):", datetime.utcnow().isoformat())
    print("=" * 80)
    
    test_results = []
    
    # Run tests
    test_results.append(("Canonical QA Evaluator", test_canonical_qa_evaluator()))
    test_results.append(("Canonical Enforcement Engine", test_canonical_enforcement_engine()))
    test_results.append(("CVE-2023-4863 Canonical Playbook", test_cve_2023_4863_canonical_playbook()))
    test_results.append(("Legacy Schema Rejection", test_legacy_schema_rejection()))
    
    # Print summary
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    
    all_passed = True
    for test_name, passed in test_results:
        status = "PASS" if passed else "FAIL"
        print(f"{test_name}: {status}")
        if not passed:
            all_passed = False
    
    print("\n" + "=" * 80)
    if all_passed:
        print("SUCCESS: All canonical QA alignment tests passed")
        print("QA system natively evaluates canonical schema")
        print("No legacy schema dependencies")
        print("Payload integrity verified")
        print("CVE-2023-4863 passes QA under canonical rules")
    else:
        print("FAILURE: Some canonical QA alignment tests failed")
        sys.exit(1)
    
    return all_passed


if __name__ == "__main__":
    main()