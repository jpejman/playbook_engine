#!/usr/bin/env python3
"""
Test idempotency check logic.
"""

import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.db import get_database_client

def check_cve_has_approved_playbook(cve_id: str) -> bool:
    """Check if CVE already has an approved playbook."""
    db = get_database_client()
    
    # Method 1: Join through generation_runs (more reliable)
    query = """
    SELECT ap.id
    FROM approved_playbooks ap
    JOIN generation_runs gr ON ap.generation_run_id = gr.id
    WHERE gr.cve_id = %s
    LIMIT 1
    """
    
    result = db.fetch_one(query, (cve_id,))
    return result is not None

def check_cve_queue_status(cve_id: str) -> str:
    """Check current status of CVE in queue."""
    db = get_database_client()
    
    query = "SELECT status FROM cve_queue WHERE cve_id = %s"
    result = db.fetch_one(query, (cve_id,))
    
    return result['status'] if result else None

def is_cve_eligible_for_processing(cve_id: str) -> dict:
    """
    Check if CVE is eligible for processing.
    
    Returns:
        dict with keys: eligible, reason, queue_id, current_status
    """
    db = get_database_client()
    
    # Check if CVE already has approved playbook
    if check_cve_has_approved_playbook(cve_id):
        return {
            "eligible": False,
            "reason": "CVE already has an approved playbook",
            "queue_id": None,
            "current_status": None
        }
    
    # Check if CVE is in queue
    query = "SELECT id, status FROM cve_queue WHERE cve_id = %s"
    queue_item = db.fetch_one(query, (cve_id,))
    
    if not queue_item:
        # CVE not in queue - eligible for insertion
        return {
            "eligible": True,
            "reason": "CVE not in queue, can be added",
            "queue_id": None,
            "current_status": None
        }
    
    queue_id = queue_item['id']
    status = queue_item['status']
    
    # Check queue status
    if status == 'completed':
        return {
            "eligible": False,
            "reason": f"CVE already processed (status: {status})",
            "queue_id": queue_id,
            "current_status": status
        }
    elif status == 'processing':
        return {
            "eligible": False,
            "reason": f"CVE currently being processed (status: {status})",
            "queue_id": queue_id,
            "current_status": status
        }
    elif status in ['pending', 'failed', 'retry']:
        return {
            "eligible": True,
            "reason": f"CVE in queue with processable status: {status}",
            "queue_id": queue_id,
            "current_status": status
        }
    else:
        # Unknown status
        return {
            "eligible": False,
            "reason": f"CVE has unknown queue status: {status}",
            "queue_id": queue_id,
            "current_status": status
        }

def main():
    """Test idempotency check with example CVEs."""
    test_cves = [
        'CVE-2025-54377',  # Has approved playbook
        'CVE-2025-54365',  # No approved playbook, not in queue
        'CVE-TEST-0001',   # In queue with status 'completed'
    ]
    
    for cve_id in test_cves:
        print(f"\n=== Testing CVE: {cve_id} ===")
        
        # Check if has approved playbook
        has_playbook = check_cve_has_approved_playbook(cve_id)
        print(f"Has approved playbook: {has_playbook}")
        
        # Check queue status
        queue_status = check_cve_queue_status(cve_id)
        print(f"Queue status: {queue_status}")
        
        # Check eligibility
        eligibility = is_cve_eligible_for_processing(cve_id)
        print(f"Eligible for processing: {eligibility['eligible']}")
        print(f"Reason: {eligibility['reason']}")
        if eligibility['queue_id']:
            print(f"Queue ID: {eligibility['queue_id']}")

if __name__ == "__main__":
    main()