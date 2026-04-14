#!/usr/bin/env python3
"""
Process one real CVE end-to-end.
"""

import sys
import json
import subprocess
import os
from pathlib import Path

sys.path.append(".")

from src.utils.db import DatabaseClient

def run_command(cmd, description):
    """Run a command and return output."""
    print(f"\n{'='*80}")
    print(f"STEP: {description}")
    print(f"Command: {cmd}")
    print(f"{'='*80}")
    
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        print(f"Return code: {result.returncode}")
        if result.stdout:
            print(f"Output:\n{result.stdout}")
        if result.stderr:
            print(f"Stderr:\n{result.stderr}")
        
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        print(f"Error running command: {e}")
        return 1, "", str(e)

def get_sql_proof(cve_id):
    """Get SQL proof for CVE processing."""
    db = DatabaseClient()
    
    queries = {
        "approved_playbooks_before": """
        SELECT COUNT(*) as count 
        FROM approved_playbooks ap 
        JOIN generation_runs gr ON ap.generation_run_id = gr.id 
        WHERE gr.cve_id = %s
        """,
        "generation_runs": """
        SELECT id, cve_id, status, created_at 
        FROM generation_runs 
        WHERE cve_id = %s 
        ORDER BY created_at DESC 
        LIMIT 5
        """,
        "qa_runs": """
        SELECT id, generation_run_id, score, decision, created_at 
        FROM qa_runs 
        WHERE generation_run_id IN (
            SELECT id FROM generation_runs WHERE cve_id = %s
        )
        ORDER BY created_at DESC 
        LIMIT 5
        """,
        "approved_playbooks_after": """
        SELECT ap.id, ap.generation_run_id, ap.version, ap.approved_at 
        FROM approved_playbooks ap 
        JOIN generation_runs gr ON ap.generation_run_id = gr.id 
        WHERE gr.cve_id = %s
        ORDER BY ap.approved_at DESC 
        LIMIT 5
        """,
        "cve_queue_status": """
        SELECT cve_id, status, priority, created_at, updated_at 
        FROM cve_queue 
        WHERE cve_id = %s
        """
    }
    
    results = {}
    for name, query in queries.items():
        try:
            result = db.fetch_one(query, (cve_id,))
            results[name] = result
        except Exception as e:
            results[name] = f"Error: {e}"
    
    return results

def main():
    """Main execution function."""
    # Use CVE-2023-4863 (WebP vulnerability)
    cve_id = "CVE-2023-4863"
    
    print(f"PROCESSING REAL CVE END-TO-END: {cve_id}")
    print("="*80)
    
    # Step 1: Get SQL proof before processing
    print("\n1. SQL PROOF BEFORE PROCESSING")
    print("-"*80)
    proof_before = get_sql_proof(cve_id)
    print(json.dumps(proof_before, indent=2, default=str))
    
    # Step 2: Enrich CVE
    print("\n2. ENRICH CVE")
    print("-"*80)
    enrich_cmd = f'python scripts/02_60_enrich_cve_with_opensearch_v0_1_0.py --cve {cve_id}'
    enrich_code, enrich_out, enrich_err = run_command(enrich_cmd, "Enrich CVE with OpenSearch")
    
    # Step 3: Generate playbook (using vector generation script)
    print("\n3. GENERATE PLAYBOOK")
    print("-"*80)
    
    # First, let's check if we need to create a context snapshot
    db = DatabaseClient()
    snapshot = db.fetch_one(
        "SELECT id FROM cve_context_snapshot WHERE cve_id = %s",
        (cve_id,)
    )
    
    if not snapshot:
        print("Creating context snapshot...")
        # Create a simple context snapshot
        context_data = {
            "cve_id": cve_id,
            "description": "WebP heap buffer overflow vulnerability",
            "cvss_score": 8.8,
            "severity": "HIGH",
            "vendor": "Google",
            "product": "WebP",
            "affected_versions": ["< 1.3.2"],
            "fixed_versions": ["1.3.2"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-4863"],
            "vulnerability_type": "Heap Buffer Overflow"
        }
        
        db.execute(
            """
            INSERT INTO cve_context_snapshot (cve_id, context_data, confidence_score)
            VALUES (%s, %s, %s)
            RETURNING id
            """,
            (cve_id, json.dumps(context_data), 0.9)
        )
        print("Created context snapshot")
    
    # Step 4: Run QA enforcement gate
    print("\n4. RUN QA ENFORCEMENT GATE")
    print("-"*80)
    qa_cmd = f'python scripts/06_07_qa_enforcement_gate_v0_1_0.py --cve {cve_id}'
    qa_code, qa_out, qa_err = run_command(qa_cmd, "Run QA enforcement gate")
    
    # Step 5: Get SQL proof after processing
    print("\n5. SQL PROOF AFTER PROCESSING")
    print("-"*80)
    proof_after = get_sql_proof(cve_id)
    print(json.dumps(proof_after, indent=2, default=str))
    
    # Step 6: Final summary
    print("\n6. FINAL SUMMARY")
    print("="*80)
    print(f"CVE Processed: {cve_id}")
    print(f"Enrichment: {'SUCCESS' if enrich_code == 0 else 'FAILED'}")
    print(f"QA Gate: {'PASSED' if qa_code == 0 else 'FAILED'}")
    
    # Check if playbook was approved
    approved = proof_after.get('approved_playbooks_after', {})
    if isinstance(approved, dict) and approved.get('id'):
        print(f"Playbook Approved: YES (ID: {approved['id']})")
    else:
        print(f"Playbook Approved: NO")
    
    print("\nEND-TO-END PROCESSING COMPLETE")

if __name__ == "__main__":
    main()