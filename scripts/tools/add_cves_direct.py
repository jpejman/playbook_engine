#!/usr/bin/env python3
"""Add CVEs directly to queue."""

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent))

from src.utils.db import DatabaseClient

def add_cve_direct(cve_id, priority=5):
    """Add CVE directly to queue."""
    db = DatabaseClient()
    
    try:
        # First check if exists
        existing = db.fetch_one(
            "SELECT id, status FROM cve_queue WHERE cve_id = %s",
            (cve_id,)
        )
        
        if existing:
            print(f"{cve_id}: Already exists - ID {existing['id']}, Status: {existing['status']}")
            # Update to pending if not already
            if existing['status'] != 'pending':
                db.execute(
                    "UPDATE cve_queue SET status = 'pending', updated_at = NOW() WHERE id = %s",
                    (existing['id'],)
                )
                print(f"  Updated status to 'pending'")
            return existing['id']
        else:
            # Insert new
            result = db.fetch_one(
                """INSERT INTO cve_queue (cve_id, status, priority, created_at, updated_at)
                VALUES (%s, 'pending', %s, NOW(), NOW())
                RETURNING id""",
                (cve_id, priority)
            )
            if result and 'id' in result:
                print(f"{cve_id}: Inserted - ID {result['id']}")
                return result['id']
            else:
                print(f"{cve_id}: Failed to insert")
                return None
    except Exception as e:
        print(f"{cve_id}: Error - {e}")
        return None

def main():
    """Add all selected CVEs."""
    selected_cves = [
        "CVE-2025-32019",  # Harbor vulnerability
        "CVE-2025-47187",  # Mitel SIP Phones vulnerability
        "CVE-2025-4700",   # GitLab vulnerability
        "CVE-2025-8069",   # AWS Client VPN vulnerability
        "CVE-2025-46171",  # vBulletin vulnerability
    ]
    
    print("Adding selected CVEs to queue...")
    print("=" * 80)
    
    queue_ids = {}
    for cve_id in selected_cves:
        qid = add_cve_direct(cve_id)
        if qid:
            queue_ids[cve_id] = qid
    
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Total CVEs: {len(selected_cves)}")
    print(f"Successfully added/updated: {len(queue_ids)}")
    
    # Verify
    print("\nVerification:")
    db = DatabaseClient()
    for cve_id in selected_cves:
        result = db.fetch_one(
            "SELECT id, status FROM cve_queue WHERE cve_id = %s",
            (cve_id,)
        )
        if result:
            print(f"  {cve_id}: ✓ Found - ID {result['id']}, Status: {result['status']}")
        else:
            print(f"  {cve_id}: ✗ NOT FOUND")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())