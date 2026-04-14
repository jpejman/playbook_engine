#!/usr/bin/env python3
"""
Create a test generation run for a real CVE.
"""

import sys
import json
sys.path.append(".")

from src.utils.db import DatabaseClient
from datetime import datetime

def create_generation_run(cve_id):
    """Create a test generation run for a CVE."""
    db = DatabaseClient()
    
    # Check if generation run already exists
    existing = db.fetch_one(
        "SELECT id FROM generation_runs WHERE cve_id = %s",
        (cve_id,)
    )
    
    if existing:
        print(f"Generation run already exists for {cve_id} (ID: {existing['id']})")
        return existing['id']
    
    # Create a mock playbook response
    mock_playbook = {
        "playbook": {
            "title": f"Remediation Playbook for {cve_id}",
            "cve_id": cve_id,
            "severity": "HIGH",
            "affected_components": ["WebP library"],
            "steps": [
                {
                    "step_number": 1,
                    "action": "Update WebP library to version 1.3.2 or later",
                    "description": "Apply security patch for heap buffer overflow vulnerability",
                    "expected_outcome": "WebP library updated to secure version"
                },
                {
                    "step_number": 2,
                    "action": "Verify WebP version",
                    "description": "Check that WebP library is at version 1.3.2 or higher",
                    "expected_outcome": "Version verification successful"
                }
            ],
            "verification": ["Check WebP version with 'webpinfo --version'"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-4863"]
        }
    }
    
    # Create generation run
    result = db.execute(
        """
        INSERT INTO generation_runs (
            cve_id, prompt, response, model, status, created_at
        )
        VALUES (%s, %s, %s, %s, %s, NOW())
        RETURNING id
        """,
        (
            cve_id,
            "Mock prompt for testing",
            json.dumps(mock_playbook),
            "test-model",
            "completed"
        ),
        fetch=True
    )
    
    if result:
        print(f"Created generation run for {cve_id} (ID: {result})")
        return result
    else:
        print(f"Failed to create generation run for {cve_id}")
        return None

def main():
    """Main function."""
    cve_id = "CVE-2023-4863"
    
    print(f"Creating test generation run for {cve_id}")
    print("="*80)
    
    gen_id = create_generation_run(cve_id)
    
    if gen_id:
        print(f"\nSuccessfully created generation run ID: {gen_id}")
        
        # Verify it was created
        db = DatabaseClient()
        gen_run = db.fetch_one(
            "SELECT id, cve_id, status, created_at FROM generation_runs WHERE id = %s",
            (gen_id,)
        )
        
        if gen_run:
            print(f"\nVerification:")
            print(f"  ID: {gen_run['id']}")
            print(f"  CVE: {gen_run['cve_id']}")
            print(f"  Status: {gen_run['status']}")
            print(f"  Created: {gen_run['created_at']}")
    else:
        print("\nFailed to create generation run")

if __name__ == "__main__":
    main()