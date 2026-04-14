#!/usr/bin/env python3
"""
Add selected CVEs to queue for production verification.
"""

import sys
from pathlib import Path

# Add src to path
sys.path.append(str(Path(__file__).parent))

from src.utils.db import DatabaseClient

def add_cve_to_queue(cve_id, priority=5):
    """Add CVE to queue if not already present."""
    db = DatabaseClient()
    
    # Check if already in queue
    existing = db.fetch_one(
        "SELECT id, status FROM cve_queue WHERE cve_id = %s",
        (cve_id,)
    )
    
    if existing:
        print(f"CVE {cve_id} already in queue (ID: {existing['id']}, status: {existing['status']})")
        # Update to pending if not already
        if existing['status'] != 'pending':
            db.execute(
                "UPDATE cve_queue SET status = 'pending', updated_at = NOW() WHERE id = %s",
                (existing['id'],)
            )
            print(f"Updated status to 'pending'")
        return existing['id']
    else:
        # Insert new queue item
        query = """
        INSERT INTO cve_queue (cve_id, status, priority, created_at, updated_at)
        VALUES (%s, 'pending', %s, NOW(), NOW())
        RETURNING id
        """
        
        try:
            result = db.fetch_one(query, (cve_id, priority))
            if result and 'id' in result:
                queue_id = result['id']
                print(f"Inserted CVE {cve_id} into queue (ID: {queue_id})")
                return queue_id
            else:
                print(f"Failed to insert CVE {cve_id}")
                return None
        except Exception as e:
            print(f"Error inserting CVE {cve_id}: {e}")
            return None

def main():
    """Add selected CVEs to queue."""
    selected_cves = [
        "CVE-2025-32019",  # Harbor vulnerability
        "CVE-2025-47187",  # Mitel SIP Phones vulnerability
        "CVE-2025-4700",   # GitLab vulnerability
        "CVE-2025-8069",   # AWS Client VPN vulnerability
        "CVE-2025-46171",  # vBulletin vulnerability
    ]
    
    print("Adding selected CVEs to queue for production verification...")
    print("=" * 80)
    
    queue_ids = {}
    for cve_id in selected_cves:
        print(f"\nProcessing {cve_id}:")
        queue_id = add_cve_to_queue(cve_id)
        if queue_id:
            queue_ids[cve_id] = queue_id
    
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Total CVEs selected: {len(selected_cves)}")
    print(f"Successfully added/updated in queue: {len(queue_ids)}")
    
    if queue_ids:
        print("\nQueue IDs:")
        for cve_id, qid in queue_ids.items():
            print(f"  {cve_id}: Queue ID {qid}")
    
    # Verify they are in queue
    print("\nVerifying queue status...")
    db = DatabaseClient()
    for cve_id in selected_cves:
        result = db.fetch_one(
            "SELECT id, status FROM cve_queue WHERE cve_id = %s",
            (cve_id,)
        )
        if result:
            print(f"  {cve_id}: Queue ID {result['id']}, Status: {result['status']}")
        else:
            print(f"  {cve_id}: NOT FOUND IN QUEUE")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())