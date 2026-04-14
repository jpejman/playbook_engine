#!/usr/bin/env python3
"""
Audit Generation Run 30 for CVE-2023-4863
Version: v0.1.0
Timestamp: 2026-04-09

Purpose:
- Audit generation_run_id 30 for CVE-2023-4863
- Identify which script created it
- Identify why mock prompt was used
- Identify why QA gate passed it
- Identify whether QA was run against raw output or transformed data
"""

import sys
import json
sys.path.append(".")

from src.utils.db import DatabaseClient
from src.validation.canonical_validator import CanonicalValidator


def audit_generation_run_30():
    """Audit generation run 30."""
    db = DatabaseClient()
    
    print("=" * 80)
    print("AUDIT: GENERATION RUN 30 FOR CVE-2023-4863")
    print("=" * 80)
    
    # 1. Get generation run details
    print("\n1. GENERATION RUN DETAILS:")
    print("-" * 80)
    
    gen_run = db.fetch_one(
        "SELECT * FROM generation_runs WHERE id = 30"
    )
    
    if not gen_run:
        print("Generation run 30 not found")
        return
    
    print(f"ID: {gen_run['id']}")
    print(f"CVE ID: {gen_run['cve_id']}")
    print(f"Model: {gen_run.get('model')}")
    print(f"Status: {gen_run['status']}")
    print(f"Created: {gen_run['created_at']}")
    
    # 2. Analyze prompt
    print("\n2. PROMPT ANALYSIS:")
    print("-" * 80)
    
    prompt = gen_run.get('prompt', '')
    if prompt:
        print(f"Prompt length: {len(prompt)} chars")
        print(f"Prompt preview: {prompt[:200]}...")
        
        if 'Mock prompt' in prompt:
            print("  [ISSUE] Contains 'Mock prompt' text")
        if 'test' in prompt.lower():
            print("  [ISSUE] Contains 'test' indicator")
    else:
        print("No prompt found")
    
    # 3. Analyze response
    print("\n3. RESPONSE ANALYSIS:")
    print("-" * 80)
    
    response = gen_run.get('response')
    if response:
        if isinstance(response, str):
            try:
                parsed = json.loads(response)
                print(f"Response parsed successfully")
                print(f"Response type: {type(parsed)}")
                
                # Check structure
                if isinstance(parsed, dict):
                    print(f"Response keys: {list(parsed.keys())}")
                    
                    if 'playbook' in parsed:
                        print("  [ISSUE] Response nested under 'playbook' key (obsolete schema)")
                        playbook = parsed['playbook']
                        print(f"  Playbook keys: {list(playbook.keys())}")
                        
                        # Check for obsolete keys
                        obsolete_keys = ['affected_components', 'remediation_steps', 
                                       'verification_procedures', 'rollback_procedures']
                        for key in obsolete_keys:
                            if key in playbook:
                                print(f"  [ISSUE] Contains obsolete key: '{key}'")
            except Exception as e:
                print(f"Error parsing response: {e}")
        else:
            print(f"Response type: {type(response)}")
    else:
        print("No response found")
    
    # 4. Check QA runs for this generation
    print("\n4. QA RUNS ANALYSIS:")
    print("-" * 80)
    
    qa_runs = db.fetch_all(
        "SELECT * FROM qa_runs WHERE generation_run_id = 30 ORDER BY created_at DESC"
    )
    
    if qa_runs:
        print(f"Found {len(qa_runs)} QA runs for generation run 30")
        
        for i, qa_run in enumerate(qa_runs):
            print(f"\n  QA Run {i+1}:")
            print(f"    ID: {qa_run['id']}")
            print(f"    Result: {qa_run['qa_result']}")
            print(f"    Score: {qa_run['qa_score']}")
            print(f"    Created: {qa_run['created_at']}")
            
            # Analyze QA feedback
            feedback = qa_run.get('qa_feedback')
            if feedback:
                if isinstance(feedback, str):
                    try:
                        feedback_data = json.loads(feedback)
                        print(f"    Feedback keys: {list(feedback_data.keys())}")
                        
                        # Check if canonical validation was performed
                        if 'canonical_validation' in feedback_data:
                            print("    [NOTE] Contains canonical validation data")
                        else:
                            print("    [ISSUE] No canonical validation data in QA feedback")
                    except:
                        print(f"    Feedback: {feedback[:100]}...")
                else:
                    print(f"    Feedback type: {type(feedback)}")
    else:
        print("No QA runs found for generation run 30")
    
    # 5. Check approved playbooks
    print("\n5. APPROVED PLAYBOOKS ANALYSIS:")
    print("-" * 80)
    
    approved = db.fetch_one(
        "SELECT * FROM approved_playbooks WHERE generation_run_id = 30"
    )
    
    if approved:
        print(f"Approved playbook found: ID {approved['id']}")
        print(f"Version: {approved.get('version')}")
        print(f"Approved at: {approved.get('approved_at')}")
        
        # Check playbook structure
        playbook = approved.get('playbook')
        if playbook:
            if isinstance(playbook, str):
                try:
                    playbook_data = json.loads(playbook)
                    print(f"Playbook parsed successfully")
                    
                    # Validate canonical schema
                    validator = CanonicalValidator()
                    is_canonical, errors = validator.validate_canonical_schema(playbook_data)
                    
                    if is_canonical:
                        print("  [OK] Approved playbook matches canonical schema")
                    else:
                        print("  [ISSUE] Approved playbook does not match canonical schema")
                        for error in errors:
                            print(f"    - {error}")
                except Exception as e:
                    print(f"Error parsing approved playbook: {e}")
            else:
                print(f"Playbook type: {type(playbook)}")
    else:
        print("No approved playbook found for generation run 30")
    
    # 6. Check prompt template used
    print("\n6. PROMPT TEMPLATE ANALYSIS:")
    print("-" * 80)
    
    # Try to find which template might have been used
    templates = db.fetch_all(
        "SELECT id, name, created_at FROM prompt_templates ORDER BY created_at DESC LIMIT 5"
    )
    
    print(f"Recent prompt templates:")
    for template in templates:
        print(f"  ID: {template['id']}, Name: {template['name']}, Created: {template['created_at']}")
    
    # 7. Identify likely script that created this
    print("\n7. SCRIPT IDENTIFICATION:")
    print("-" * 80)
    
    print("Based on analysis:")
    print("  - Prompt contains 'Mock prompt for testing'")
    print("  - Model is 'test-model'")
    print("  - Response uses obsolete nested schema")
    print("\n  [LIKELY SOURCE] scripts/create_test_generation_run.py")
    print("    This script creates mock generation runs with:")
    print("    - prompt: 'Mock prompt for testing'")
    print("    - model: 'test-model'")
    print("    - response: nested playbook structure")
    
    # 8. Summary of issues
    print("\n8. SUMMARY OF ISSUES:")
    print("-" * 80)
    
    issues = []
    
    if prompt and 'Mock prompt' in prompt:
        issues.append("Uses mock prompt: 'Mock prompt for testing'")
    
    if gen_run.get('model') == 'test-model':
        issues.append("Uses test model: 'test-model'")
    
    if response and isinstance(response, str) and 'playbook' in response:
        issues.append("Uses obsolete nested schema (playbook key)")
    
    if qa_runs and len(qa_runs) > 0:
        # Check if QA passed despite issues
        latest_qa = qa_runs[0]
        if latest_qa['qa_result'] == 'approved':
            issues.append("QA passed despite mock/test indicators")
    
    if approved:
        issues.append("Playbook was approved and stored despite issues")
    
    if issues:
        print(f"Found {len(issues)} issues:")
        for i, issue in enumerate(issues, 1):
            print(f"  {i}. {issue}")
    else:
        print("No issues found (unlikely)")
    
    print("\n" + "=" * 80)
    print("AUDIT COMPLETE")
    print("=" * 80)


def main():
    """Main function."""
    try:
        audit_generation_run_30()
    except Exception as e:
        print(f"Error during audit: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()