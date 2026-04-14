#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Service: VS.ai Playbook Engine
Script: QA Enforcement Gate with Canonical Validation
File: 06_07_qa_enforcement_gate_v0_1_0.py
Version: v0.2.0
Timestamp (UTC): 2026-04-09

Purpose:
    Execute QA enforcement with canonical schema validation
    Validate exact payload that is stored in database
    Block invalid playbooks including mock/test outputs
    Prepare for retry system (next phase)

Usage:
    python scripts/06_07_qa_enforcement_gate_v0_1_0.py --cve CVE-XXXX-XXXX
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


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

def fetch_latest_generation(db: DatabaseClient, cve_id):
    """
    Get latest generation output for CVE with all relevant fields.
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
        "canonical_validation": canonical_validation or {}
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
    print(f"[QA ENFORCEMENT] Starting for CVE: {cve_id}")
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
    # Step 2 — Canonical Schema Validation
    # -------------------------------------------------------------------------

    print("\nCANONICAL SCHEMA VALIDATION:")
    canonical_valid, canonical_errors = validate_playbook_canonical(playbook)
    
    if not canonical_valid:
        print(f"  [FAIL] Playbook does not match canonical schema")
        for error in canonical_errors:
            print(f"    - {error}")
    else:
        print(f"  [PASS] Playbook matches canonical schema")

    # -------------------------------------------------------------------------
    # Step 3 — Mock/Test Detection
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
    # Step 4 — QA Enforcement
    # -------------------------------------------------------------------------

    print("\nQA ENFORCEMENT:")
    qa_result = evaluate_playbook(
        playbook=playbook,
        expected_cve_id=cve_id,
    )

    print("\nQA RESULT:")
    print(json.dumps(qa_result, indent=2))

    # -------------------------------------------------------------------------
    # Step 5 — Combine Validations
    # -------------------------------------------------------------------------

    # Update QA result with canonical validation info
    canonical_validation = {
        "is_canonical": canonical_valid,
        "canonical_errors": canonical_errors,
        "is_mock": is_mock,
        "mock_warnings": mock_warnings,
        "generation_status": status,
        "model_used": model
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
    # Step 6 — Persist QA Run with Canonical Metadata
    # -------------------------------------------------------------------------

    insert_qa_run(db, generation_run_id, qa_result, canonical_validation)

    # -------------------------------------------------------------------------
    # Step 4 — Decision Gate
    # -------------------------------------------------------------------------

    if qa_result["status"] == "FAIL":
        print("\n[FAIL] QA FAILED - Playbook rejected")
        print(f"Failure Type: {qa_result['failure_type']}")
        sys.exit(1)

    print("\n[PASS] QA PASSED - Playbook approved for next stage")
    sys.exit(0)


# -----------------------------------------------------------------------------

if __name__ == "__main__":
    main()