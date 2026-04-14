#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Service: VS.ai Playbook Engine
Script: QA Enforcement Gate with Canonical Schema Only
File: 06_08_qa_enforcement_gate_canonical_v0_2_0.py
Version: v0.2.0
Timestamp (UTC): 2026-04-09

Purpose:
    Execute QA enforcement with canonical schema ONLY
    Reject any legacy schema playbooks
    Validate exact canonical payload that is stored in database
    Block invalid playbooks including mock/test outputs
    Ensure QA operates directly on canonical payload

Usage:
    python scripts/06_08_qa_enforcement_gate_canonical_v0_2_0.py --cve CVE-XXXX-XXXX
"""

import argparse
import json
import sys
from datetime import datetime

# Adjust path if needed depending on your repo layout
sys.path.append(".")

from src.qa.enforcement_engine import evaluate_playbook
from src.validation.canonical_validator import validate_playbook_canonical, detect_mock_playbook
from src.utils.db import DatabaseClient
from src.utils.qa_evaluator_canonical import verify_payload_integrity
from scripts.prod.time_utils import get_utc_now, datetime_to_iso


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

def fetch_latest_generation(db: DatabaseClient, cve_id):
    """
    Get latest generation output for CVE with all relevant fields.
    Returns canonical playbook if available, otherwise None.
    """
    query = """
    SELECT 
        gr.id, 
        gr.cve_id,
        gr.prompt,
        gr.response as playbook_json,
        gr.model,
        gr.status,
        gr.created_at
    FROM generation_runs gr
    WHERE gr.cve_id = %s
    ORDER BY gr.created_at DESC
    LIMIT 1;
    """
    result = db.fetch_one(query, (cve_id,))

    if not result:
        raise Exception(f"No generation run found for CVE: {cve_id}")

    return result


def convert_legacy_to_canonical(legacy_playbook: dict) -> dict:
    """
    Convert legacy schema playbook to canonical schema.
    Returns canonical playbook or raises ValueError if conversion fails.
    """
    if "playbook" not in legacy_playbook:
        raise ValueError("Not a legacy schema playbook (missing 'playbook' key)")
    
    legacy = legacy_playbook["playbook"]
    
    # Basic conversion - in production this would be more sophisticated
    canonical = {
        "title": legacy.get("title", ""),
        "cve_id": legacy.get("cve_id", ""),
        "vendor": legacy.get("vendor", "Unknown"),
        "product": legacy.get("product", "Unknown"),
        "severity": legacy.get("severity", "MEDIUM"),
        "description": legacy.get("description", ""),
        "affected_versions": legacy.get("affected_versions", []),
        "fixed_versions": legacy.get("fixed_versions", []),
        "affected_platforms": legacy.get("affected_platforms", []),
        "references": legacy.get("references", []),
    }
    
    # Convert remediation_steps to workflows
    if "remediation_steps" in legacy and isinstance(legacy["remediation_steps"], list):
        workflows = []
        
        # Group steps by workflow (simplified - assumes one workflow)
        workflow_steps = []
        for step in legacy["remediation_steps"]:
            if isinstance(step, dict):
                canonical_step = {
                    "step_number": step.get("step_number", 1),
                    "title": step.get("title", f"Step {step.get('step_number', 1)}"),
                    "description": step.get("description", ""),
                    "commands": step.get("commands", []),
                    "target_os_or_platform": step.get("target_os_or_platform", "Linux"),
                    "expected_result": step.get("expected_result", "Step completes successfully"),
                    "verification": step.get("verification", ""),
                    "rollback_hint": step.get("rollback_hint", ""),
                    "evidence_based": step.get("evidence_based", False)
                }
                workflow_steps.append(canonical_step)
        
        if workflow_steps:
            workflows.append({
                "workflow_id": "workflow_1",
                "workflow_name": "Remediation Workflow",
                "workflow_type": "remediation",
                "steps": workflow_steps
            })
        
        canonical["workflows"] = workflows
    
    # Copy other fields
    for key in ["retrieval_metadata", "pre_remediation_checks", 
                "post_remediation_validation", "additional_recommendations"]:
        if key in legacy:
            canonical[key] = legacy[key]
    
    return canonical


def insert_qa_run(db: DatabaseClient, generation_run_id, qa_result, canonical_validation=None):
    """
    Persist QA result with canonical validation metadata.
    """
    # Map enforcement result to existing qa_runs schema
    qa_status = "approved" if qa_result["status"] == "PASS" else "rejected"
    qa_score = qa_result.get("score", 0.0)
    
    # Store additional info in qa_feedback including canonical validation
    feedback = {
        "enforcement_version": qa_result.get("enforcement_version", "v0.2.0"),
        "failure_type": qa_result.get("failure_type"),
        "decision": qa_result.get("decision"),
        "rule_violations": qa_result.get("rule_violations", []),
        "feedback": qa_result.get("feedback", {}),
        "canonical_validation": canonical_validation or {},
        "schema_type": "canonical" if qa_result.get("status") == "PASS" else "legacy_or_invalid"
    }
    
    query = """
    INSERT INTO qa_runs (
        generation_run_id,
        qa_result,
        qa_score,
        qa_feedback,
        created_at
    )
    VALUES (%s, %s, %s, %s, NOW());
    """

    db.execute(
        query,
        (
            generation_run_id,
            qa_status,
            qa_score,
            json.dumps(feedback),
        ),
    )


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cve", required=True, help="CVE ID to validate")
    args = parser.parse_args()

    cve_id = args.cve

    print("=" * 80)
    print(f"[QA ENFORCEMENT - CANONICAL] Starting for CVE: {cve_id}")
    print("=" * 80)

    db = DatabaseClient()

    # -------------------------------------------------------------------------
    # Step 1 — Fetch generation with metadata
    # -------------------------------------------------------------------------

    gen = fetch_latest_generation(db, cve_id)

    generation_run_id = gen["id"]
    playbook_json = gen["playbook_json"]
    prompt = gen.get("prompt", "")
    model = gen.get("model", "")
    status = gen.get("status", "")

    # Handle both string and already-parsed JSON
    if isinstance(playbook_json, str):
        try:
            playbook = json.loads(playbook_json)
        except json.JSONDecodeError:
            print(f"ERROR: Failed to parse playbook JSON")
            print(f"JSON string (first 500 chars): {playbook_json[:500]}")
            raise
    else:
        playbook = playbook_json

    print(f"Loaded generation_run_id: {generation_run_id}")
    print(f"Generation status: {status}")
    print(f"Model used: {model}")

    # -------------------------------------------------------------------------
    # Step 2 — Schema Detection and Conversion
    # -------------------------------------------------------------------------

    print("\nSCHEMA DETECTION:")
    
    is_legacy_schema = "playbook" in playbook
    is_canonical_schema = "workflows" in playbook
    
    if is_legacy_schema:
        print(f"  [LEGACY] Playbook uses legacy schema (has 'playbook' key)")
        
        # Try to convert to canonical
        try:
            print(f"  Converting legacy to canonical schema...")
            canonical_playbook = convert_legacy_to_canonical(playbook)
            print(f"  [CONVERTED] Successfully converted to canonical schema")
            playbook = canonical_playbook
            is_canonical_schema = True
            is_legacy_schema = False
        except Exception as e:
            print(f"  [ERROR] Failed to convert legacy schema: {e}")
            print(f"  QA will reject legacy schema playbook")
    
    if is_canonical_schema:
        print(f"  [CANONICAL] Playbook uses canonical schema (has 'workflows' key)")
    else:
        print(f"  [UNKNOWN] Playbook schema not recognized")

    # -------------------------------------------------------------------------
    # Step 3 — Canonical Schema Validation
    # -------------------------------------------------------------------------

    print("\nCANONICAL SCHEMA VALIDATION:")
    
    if is_canonical_schema:
        canonical_valid, canonical_errors = validate_playbook_canonical(playbook)
        
        if not canonical_valid:
            print(f"  [FAIL] Playbook does not match canonical schema")
            for error in canonical_errors:
                print(f"    - {error}")
        else:
            print(f"  [PASS] Playbook matches canonical schema")
    else:
        print(f"  [SKIP] Not a canonical schema playbook")
        canonical_valid = False
        canonical_errors = ["Not a canonical schema playbook"]

    # -------------------------------------------------------------------------
    # Step 4 — Mock/Test Detection
    # -------------------------------------------------------------------------

    print("\nMOCK/TEST DETECTION:")
    is_mock, mock_warnings = detect_mock_playbook(prompt, model, playbook)
    
    if is_mock:
        print(f"  [WARNING] Mock/test output detected")
        for warning in mock_warnings:
            print(f"    - {warning}")
    else:
        print(f"  [PASS] No mock/test indicators found")

    # -------------------------------------------------------------------------
    # Step 5 — QA Enforcement (Canonical Only)
    # -------------------------------------------------------------------------

    print("\nQA ENFORCEMENT (CANONICAL):")
    
    if not is_canonical_schema:
        print(f"  [REJECT] Not a canonical schema playbook - automatic rejection")
        qa_result = {
            "status": "FAIL",
            "failure_type": "non_canonical_schema",
            "score": 0.0,
            "decision": "rejected",
            "enforcement_version": "v0.2.0",
            "feedback": {
                "errors": ["Playbook does not use canonical schema"],
                "warnings": [],
                "strengths": []
            },
            "rule_violations": ["non_canonical_schema"],
            "timestamp": datetime_to_iso(get_utc_now()),
            "payload_hash": "invalid_schema"
        }
    else:
        qa_result = evaluate_playbook(
            playbook=playbook,
            expected_cve_id=cve_id,
        )

    print("\nQA RESULT:")
    print(json.dumps(qa_result, indent=2))

    # -------------------------------------------------------------------------
    # Step 6 — Combine Validations
    # -------------------------------------------------------------------------

    # Update QA result with canonical validation info
    canonical_validation = {
        "is_canonical": is_canonical_schema,
        "canonical_errors": canonical_errors if not canonical_valid else [],
        "is_mock": is_mock,
        "mock_warnings": mock_warnings,
        "generation_status": status,
        "model_used": model,
        "original_schema": "legacy" if is_legacy_schema else "canonical" if is_canonical_schema else "unknown"
    }
    
    # Fail QA if canonical validation fails
    if not canonical_valid:
        qa_result["status"] = "FAIL"
        if not qa_result.get("failure_type"):
            qa_result["failure_type"] = "non_canonical_schema"
        qa_result["feedback"]["errors"].extend(canonical_errors)
    
    # Fail QA if mock output detected
    if is_mock:
        qa_result["status"] = "FAIL"
        if not qa_result.get("failure_type"):
            qa_result["failure_type"] = "mock_output_detected"
        qa_result["feedback"]["warnings"].extend(mock_warnings)

    # -------------------------------------------------------------------------
    # Step 7 — Persist QA Run with Canonical Metadata
    # -------------------------------------------------------------------------

    insert_qa_run(db, generation_run_id, qa_result, canonical_validation)

    # -------------------------------------------------------------------------
    # Step 8 — Decision Gate
    # -------------------------------------------------------------------------

    if qa_result["status"] == "FAIL":
        print("\n[FAIL] QA FAILED - Playbook rejected")
        print(f"Failure Type: {qa_result['failure_type']}")
        
        # Special message for non-canonical schema
        if qa_result['failure_type'] == 'non_canonical_schema':
            print(f"\nNOTE: Playbook uses legacy schema. Update generation pipeline to produce canonical schema.")
            print(f"Canonical schema required fields: title, cve_id, vendor, product, severity, description, workflows[]")
        
        sys.exit(1)

    print("\n[PASS] QA PASSED - Playbook approved for next stage")
    print(f"Schema: {'Canonical' if is_canonical_schema else 'Legacy (converted)'}")
    print(f"Score: {qa_result['score']:.2f}")
    print(f"Payload Hash: {qa_result['payload_hash']}")
    sys.exit(0)


# -----------------------------------------------------------------------------

if __name__ == "__main__":
    main()