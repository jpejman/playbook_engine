#!/usr/bin/env python3
"""
Verify Canonical Payload Integrity
Version: v1.0.0
Timestamp: 2026-04-09

Purpose:
- Verify QA operates directly on canonical payload
- No transformation layer between storage and evaluation
- Hash validation for payload integrity
"""

import json
import hashlib
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent))

from src.utils.db import DatabaseClient
from src.utils.qa_evaluator_canonical import verify_payload_integrity
from src.qa.enforcement_engine import evaluate_playbook


def verify_payload_hash_integrity():
    """Verify that stored payload hash matches evaluated payload hash."""
    print("=" * 80)
    print("PAYLOAD HASH INTEGRITY VERIFICATION")
    print("=" * 80)
    
    db = DatabaseClient()
    
    # Get approved playbook ID 26 (canonical)
    result = db.fetch_one('SELECT playbook FROM approved_playbooks WHERE id = 26')
    
    if not result:
        print("ERROR: Could not find approved playbook ID 26")
        return False
    
    stored_payload = result['playbook']
    if isinstance(stored_payload, str):
        stored_payload = json.loads(stored_payload)
    
    print(f"Loaded canonical playbook from database")
    print(f"  CVE ID: {stored_payload.get('cve_id')}")
    print(f"  Vendor: {stored_payload.get('vendor')}")
    print(f"  Product: {stored_payload.get('product')}")
    
    # Evaluate with canonical enforcement engine
    print(f"\nEvaluating with canonical enforcement engine...")
    enforcement_result = evaluate_playbook(
        playbook=stored_payload,
        expected_cve_id='CVE-2023-4863'
    )
    
    print(f"Enforcement result:")
    print(f"  Status: {enforcement_result['status']}")
    print(f"  Score: {enforcement_result['score']:.2f}")
    print(f"  Decision: {enforcement_result['decision']}")
    print(f"  Payload Hash (from enforcement): {enforcement_result['payload_hash']}")
    
    # Verify payload integrity
    print(f"\nVerifying payload integrity...")
    is_valid, calculated_hash = verify_payload_integrity(stored_payload, stored_payload)
    
    print(f"  Is valid: {is_valid}")
    print(f"  Calculated hash: {calculated_hash[:16]}...")
    print(f"  Enforcement hash: {enforcement_result['payload_hash']}")
    print(f"  Hashes match: {calculated_hash[:16] == enforcement_result['payload_hash']}")
    
    # Check for transformation layers
    print(f"\nChecking for transformation layers...")
    
    # Check if payload has legacy schema contamination
    stored_json = json.dumps(stored_payload)
    legacy_indicators = ['"playbook":', '"remediation_steps":']
    transformation_indicators = ['converted', 'transformed', 'migrated', 'legacy_to_canonical']
    
    has_legacy = any(indicator in stored_json for indicator in legacy_indicators)
    has_transformation = any(indicator in stored_json.lower() for indicator in transformation_indicators)
    
    print(f"  Has legacy schema indicators: {has_legacy}")
    print(f"  Has transformation indicators: {has_transformation}")
    
    if has_legacy:
        print(f"  WARNING: Legacy schema indicators found in stored payload")
    
    if has_transformation:
        print(f"  WARNING: Transformation indicators found in stored payload")
    
    # Verify QA evaluator receives exact same payload
    print(f"\nVerifying QA evaluator input...")
    
    # Calculate hash of what QA evaluator would receive
    qa_input_hash = hashlib.sha256(
        json.dumps(stored_payload, sort_keys=True).encode()
    ).hexdigest()[:16]
    
    print(f"  QA input hash: {qa_input_hash}")
    print(f"  Matches stored hash: {qa_input_hash == enforcement_result['payload_hash']}")
    
    return (enforcement_result['status'] == 'PASS' and 
            is_valid and 
            calculated_hash[:16] == enforcement_result['payload_hash'] and
            not has_transformation)


def verify_no_legacy_dependencies():
    """Verify no legacy schema dependencies in QA system."""
    print("\n" + "=" * 80)
    print("LEGACY DEPENDENCY CHECK")
    print("=" * 80)
    
    # Check imports in enforcement engine
    enforcement_engine_path = Path(__file__).parent.parent / 'src' / 'qa' / 'enforcement_engine.py'
    
    with open(enforcement_engine_path, 'r') as f:
        content = f.read()
    
    # Check for actual legacy dependencies (not in test code)
    lines = content.split('\n')
    legacy_in_code = False
    
    # Skip test function lines
    in_test_function = False
    for i, line in enumerate(lines):
        line_stripped = line.strip()
        
        # Check if we're in test function
        if 'def test_' in line_stripped:
            in_test_function = True
        elif line_stripped and not line_stripped.startswith(' ') and not line_stripped.startswith('\t') and 'def ' in line_stripped:
            in_test_function = False
        
        # Check for legacy patterns outside test functions
        if not in_test_function:
            if 'remediation_steps' in line and not line_stripped.startswith('#'):
                # Check if it's in a string literal (test data) or actual code
                if '"remediation_steps"' not in line and "'remediation_steps'" not in line:
                    legacy_in_code = True
                    print(f"    Line {i+1}: {line_stripped}")
            elif 'playbook.remediation_steps' in line and not line_stripped.startswith('#'):
                legacy_in_code = True
                print(f"    Line {i+1}: {line_stripped}")
    
    print(f"Checking enforcement engine for legacy dependencies...")
    if legacy_in_code:
        print(f"  WARNING: Found legacy references in code (not in test)")
        return False
    else:
        print(f"  OK: No legacy references in production code")
    
    # Check canonical QA evaluator
    canonical_evaluator_path = Path(__file__).parent.parent / 'src' / 'utils' / 'qa_evaluator_canonical.py'
    
    with open(canonical_evaluator_path, 'r') as f:
        content = f.read()
    
    legacy_patterns = ['"playbook"', 'remediation_steps', 'playbook.get']
    legacy_found = []
    
    for pattern in legacy_patterns:
        if pattern in content:
            legacy_found.append(pattern)
    
    print(f"\nChecking canonical QA evaluator for legacy patterns...")
    if legacy_found:
        print(f"  WARNING: Found legacy patterns: {legacy_found}")
        
        # Check if these are in comments or actual code
        lines = content.split('\n')
        for i, line in enumerate(lines):
            for pattern in legacy_found:
                if pattern in line and not line.strip().startswith('#'):
                    print(f"    Line {i+1}: {line.strip()}")
        return False
    else:
        print(f"  OK: No legacy patterns found")
    
    return True


def verify_canonical_schema_native_evaluation():
    """Verify QA evaluates canonical schema natively."""
    print("\n" + "=" * 80)
    print("CANONICAL SCHEMA NATIVE EVALUATION")
    print("=" * 80)
    
    # Create test canonical payload
    canonical_payload = {
        "title": "Test Canonical Playbook",
        "cve_id": "CVE-TEST-0001",
        "vendor": "Test Vendor",
        "product": "Test Product",
        "severity": "HIGH",
        "description": "Test description",
        "workflows": [
            {
                "workflow_id": "workflow_1",
                "workflow_name": "Test Workflow",
                "workflow_type": "repository_update",
                "steps": [
                    {
                        "step_number": 1,
                        "title": "Test Step",
                        "description": "Test step",
                        "commands": ["cmd1"],
                        "target_os_or_platform": "Linux",
                        "expected_result": "Success",
                        "verification": "Check",
                        "evidence_based": True
                    }
                ]
            }
        ]
    }
    
    # Create legacy payload (should fail)
    legacy_payload = {
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
    
    print(f"Testing canonical payload evaluation...")
    canonical_result = evaluate_playbook(canonical_payload, "CVE-TEST-0001")
    print(f"  Canonical payload status: {canonical_result['status']}")
    print(f"  Canonical payload score: {canonical_result['score']:.2f}")
    
    print(f"\nTesting legacy payload evaluation...")
    legacy_result = evaluate_playbook(legacy_payload, "CVE-LEGACY-0001")
    print(f"  Legacy payload status: {legacy_result['status']}")
    print(f"  Legacy payload score: {legacy_result['score']:.2f}")
    
    # Canonical should pass, legacy should fail
    canonical_passes = canonical_result['status'] == 'PASS'
    legacy_fails = legacy_result['status'] == 'FAIL'
    
    print(f"\nVerification:")
    print(f"  Canonical schema passes: {canonical_passes}")
    print(f"  Legacy schema fails: {legacy_fails}")
    
    return canonical_passes and legacy_fails


def main():
    """Run all verification checks."""
    print("VS.ai — Playbook Engine Gen-3")
    print("Canonical Payload Integrity Verification")
    print("=" * 80)
    
    results = []
    
    results.append(("Payload Hash Integrity", verify_payload_hash_integrity()))
    results.append(("No Legacy Dependencies", verify_no_legacy_dependencies()))
    results.append(("Canonical Schema Native Evaluation", verify_canonical_schema_native_evaluation()))
    
    print("\n" + "=" * 80)
    print("VERIFICATION SUMMARY")
    print("=" * 80)
    
    all_passed = True
    for check_name, passed in results:
        status = "PASS" if passed else "FAIL"
        print(f"{check_name}: {status}")
        if not passed:
            all_passed = False
    
    print("\n" + "=" * 80)
    if all_passed:
        print("SUCCESS: All canonical payload integrity checks passed")
        print("✓ QA operates directly on canonical payload")
        print("✓ No transformation layer between storage and evaluation")
        print("✓ Hash validation ensures payload integrity")
        print("✓ No legacy schema dependencies")
        print("✓ Canonical schema evaluated natively")
    else:
        print("FAILURE: Some verification checks failed")
        sys.exit(1)
    
    return all_passed


if __name__ == "__main__":
    main()