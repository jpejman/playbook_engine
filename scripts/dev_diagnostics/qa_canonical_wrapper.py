#!/usr/bin/env python3
"""
QA wrapper for canonical playbooks to make them compatible with existing QA system.
"""

import json
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent))

from src.utils.db import DatabaseClient
from src.validation.canonical_validator import validate_playbook_canonical, detect_mock_playbook

def canonical_to_legacy(canonical_playbook: dict) -> dict:
    """Convert canonical playbook to legacy schema for QA compatibility."""
    
    legacy_playbook = {
        "playbook": {
            "title": canonical_playbook.get("title", ""),
            "cve_id": canonical_playbook.get("cve_id", ""),
            "severity": canonical_playbook.get("severity", ""),
            "vendor": canonical_playbook.get("vendor", ""),
            "product": canonical_playbook.get("product", ""),
            "description": canonical_playbook.get("description", ""),
            "affected_components": canonical_playbook.get("affected_platforms", []),
            "references": canonical_playbook.get("references", []),
            "retrieval_metadata": canonical_playbook.get("retrieval_metadata", {})
        }
    }
    
    # Convert workflows to remediation_steps
    remediation_steps = []
    workflows = canonical_playbook.get("workflows", [])
    
    for workflow in workflows:
        if isinstance(workflow, dict) and "steps" in workflow:
            steps = workflow["steps"]
            if isinstance(steps, list):
                for step in steps:
                    if isinstance(step, dict):
                        legacy_step = {
                            "step_number": step.get("step_number", 0),
                            "description": step.get("description", ""),
                            "commands": step.get("commands", []),
                            "verification": step.get("verification", ""),
                            "evidence_based": step.get("evidence_based", False),
                            "workflow_id": workflow.get("workflow_id", ""),
                            "workflow_name": workflow.get("workflow_name", ""),
                            "target_os_or_platform": step.get("target_os_or_platform", "")
                        }
                        remediation_steps.append(legacy_step)
    
    legacy_playbook["playbook"]["remediation_steps"] = remediation_steps
    
    # Add other sections
    if "pre_remediation_checks" in canonical_playbook:
        checks = canonical_playbook["pre_remediation_checks"]
        if isinstance(checks, dict):
            verification_procedures = []
            for check_list in ["required_checks", "backup_steps"]:
                if check_list in checks and isinstance(checks[check_list], list):
                    for check in checks[check_list]:
                        if isinstance(check, dict) and "description" in check:
                            verification_procedures.append(check["description"])
            
            if verification_procedures:
                legacy_playbook["playbook"]["verification_procedures"] = verification_procedures
    
    if "post_remediation_validation" in canonical_playbook:
        validation = canonical_playbook["post_remediation_validation"]
        if isinstance(validation, dict):
            rollback_procedures = []
            for val_list in ["validation_steps", "testing_procedures"]:
                if val_list in validation and isinstance(validation[val_list], list):
                    for val_step in validation[val_list]:
                        if isinstance(val_step, dict) and "description" in val_step:
                            rollback_procedures.append(val_step["description"])
            
            if rollback_procedures:
                legacy_playbook["playbook"]["rollback_procedures"] = rollback_procedures
    
    return legacy_playbook

def update_generation_run_for_qa(generation_run_id: int):
    """Update generation run with legacy-compatible playbook for QA."""
    db = DatabaseClient()
    
    # Get the generation run
    gen_run = db.fetch_one(
        "SELECT * FROM generation_runs WHERE id = %s",
        (generation_run_id,)
    )
    
    if not gen_run:
        print(f"Generation run {generation_run_id} not found")
        return False
    
    response = gen_run.get("response")
    if not response:
        print(f"Generation run {generation_run_id} has no response")
        return False
    
    # Parse the response
    if isinstance(response, str):
        try:
            playbook = json.loads(response)
        except json.JSONDecodeError:
            print(f"Failed to parse JSON response")
            return False
    else:
        playbook = response
    
    # Check if it's already in legacy format
    if "playbook" in playbook and "remediation_steps" in playbook.get("playbook", {}):
        print(f"Generation run {generation_run_id} already in legacy format")
        return True
    
    # Convert canonical to legacy
    legacy_playbook = canonical_to_legacy(playbook)
    legacy_json = json.dumps(legacy_playbook)
    
    # Update the generation run
    db.execute(
        "UPDATE generation_runs SET response = %s WHERE id = %s",
        (legacy_json, generation_run_id)
    )
    
    print(f"Updated generation run {generation_run_id} with legacy-compatible playbook")
    return True

def main():
    """Main execution function."""
    if len(sys.argv) != 2:
        print("Usage: python qa_canonical_wrapper.py <generation_run_id>")
        sys.exit(1)
    
    try:
        generation_run_id = int(sys.argv[1])
    except ValueError:
        print("Error: generation_run_id must be an integer")
        sys.exit(1)
    
    success = update_generation_run_for_qa(generation_run_id)
    
    if success:
        print(f"Successfully updated generation run {generation_run_id} for QA compatibility")
        sys.exit(0)
    else:
        print(f"Failed to update generation run {generation_run_id}")
        sys.exit(1)

if __name__ == "__main__":
    main()