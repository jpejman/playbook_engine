#!/usr/bin/env python3
"""Add CVEs to queue with proper transaction handling."""

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent))

from src.utils.db import DatabaseClient

def add_cve_with_transaction(cve_id, priority=5):
    """Add CVE to queue with proper transaction handling."""
    db = DatabaseClient()
    
    try:
        # Use get_connection context manager which handles commit/rollback
        with db.get_connection() as conn:
            with conn.cursor() as cursor:
                # Check if exists
                cursor.execute(
                    "SELECT id, status FROM cve_queue WHERE cve_id = %s",
                    (cve_id,)
                )
                existing = cursor.fetchone()
                
                if existing:
                    print(f"{cve_id}: Already exists - ID {existing[0]}, Status: {existing[1]}")
                    # Update to pending if not already
                    if existing[1] != 'pending':
                        cursor.execute(
                            "UPDATE cve_queue SET status = 'pending', updated_at = NOW() WHERE id = %s",
                            (existing[0],)
                        )
                        print(f"  Updated status to 'pending'")
                    return existing[0]
                else:
                    # Insert new
                    cursor.execute(
                        """INSERT INTO cve_queue (cve_id, status, priority, created_at, updated_at)
                        VALUES (%s, 'pending', %s, NOW(), NOW())
                        RETURNING id""",
                        (cve_id, priority)
                    )
                    result = cursor.fetchone()
                    if result:
                        queue_id = result[0]
                        print(f"{cve_id}: Inserted - ID {queue_id}")
                        return queue_id
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
    
    print("Adding selected CVEs to queue with proper transactions...")
    print("=" * 80)
    
    queue_ids = {}
    for cve_id in selected_cves:
        qid = add_cve_with_transaction(cve_id)
        if qid:
            queue_ids[cve_id] = qid
    
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Total CVEs: {len(selected_cves)}")
    print(f"Successfully added/updated: {len(queue_ids)}")
    
    # Verify using a separate connection
    print("\nVerification (separate connection):")
    db = DatabaseClient()
    for cve_id in selected_cves:
        result = db.fetch_one(
            "SELECT id, status FROM cve_queue WHERE cve_id = %s",
            (cve_id,)
        )
        if result:
            print(f"  {cve_id}: Found - ID {result['id']}, Status: {result['status']}")
        else:
            print(f"  {cve_id}: NOT FOUND")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())