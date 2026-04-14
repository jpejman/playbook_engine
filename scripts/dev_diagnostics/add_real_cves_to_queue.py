#!/usr/bin/env python3
"""
Add real CVEs to cve_queue for processing.
"""

import sys
sys.path.append(".")

from src.utils.db import DatabaseClient

def add_real_cves_to_queue():
    """Add real CVEs to the queue for processing."""
    db = DatabaseClient()
    
    # Real CVEs to add (using examples from the directive)
    real_cves = [
        "CVE-2025-53537",
        "CVE-2025-47281",
        "CVE-2024-9313",  # Another real CVE
        "CVE-2024-6387",  # regreSSHion CVE
        "CVE-2023-4863"   # WebP vulnerability
    ]
    
    added_cves = []
    
    for cve_id in real_cves:
        # Check if CVE already in queue
        existing = db.fetch_one(
            "SELECT id FROM cve_queue WHERE cve_id = %s",
            (cve_id,)
        )
        
        if existing:
            print(f"CVE {cve_id} already in queue (ID: {existing['id']})")
            continue
        
        # Insert into queue with medium priority
        result = db.execute(
            """
            INSERT INTO cve_queue (cve_id, status, priority, retry_count)
            VALUES (%s, 'pending', 3, 0)
            RETURNING id
            """,
            (cve_id,)
        )
        
        if result:
            print(f"Added CVE {cve_id} to queue (ID: {result})")
            added_cves.append(cve_id)
        else:
            print(f"Failed to add CVE {cve_id} to queue")
    
    return added_cves

def verify_real_cves_in_queue():
    """Verify real CVEs are in queue and not test CVEs."""
    db = DatabaseClient()
    
    query = """
    SELECT cve_id, status, priority, created_at
    FROM cve_queue
    WHERE cve_id NOT LIKE 'CVE-TEST-%'
    AND cve_id NOT LIKE 'TEST-%'
    AND cve_id NOT LIKE 'DEMO-%'
    AND cve_id NOT LIKE 'SYNTHETIC-%'
    AND cve_id NOT LIKE 'SEEDED-%'
    ORDER BY created_at DESC
    """
    
    real_cves = db.fetch_all(query)
    
    print("\nReal CVEs in queue:")
    print("-" * 80)
    for cve in real_cves:
        print(f"{cve['cve_id']:20} | Status: {cve['status']:10} | Priority: {cve['priority']}")
    
    return real_cves

if __name__ == "__main__":
    print("Adding real CVEs to queue...")
    print("=" * 80)
    
    added = add_real_cves_to_queue()
    
    if added:
        print(f"\nSuccessfully added {len(added)} real CVEs: {', '.join(added)}")
    else:
        print("\nNo new CVEs added (may already exist)")
    
    print("\n" + "=" * 80)
    print("Verifying real CVEs in queue...")
    print("=" * 80)
    
    real_cves = verify_real_cves_in_queue()
    
    if real_cves:
        print(f"\nTotal real CVEs in queue: {len(real_cves)}")
    else:
        print("\nNo real CVEs found in queue")