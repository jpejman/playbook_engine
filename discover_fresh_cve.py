#!/usr/bin/env python3
"""
Simple script to discover a fresh CVE for end-to-end testing.
"""

import sys
import json
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from src.utils.db import DatabaseClient
from src.retrieval.vulnstrike_db_client import VulnstrikeDBClient

def discover_fresh_cve():
    """Discover a fresh CVE not already processed."""
    print("Discovering fresh CVE for end-to-end testing...")
    
    # Get database clients
    playbook_db = DatabaseClient()
    vulnstrike_db = VulnstrikeDBClient()
    
    # Get CVEs that already have generation runs
    existing_cves = playbook_db.fetch_all(
        "SELECT DISTINCT cve_id FROM generation_runs"
    )
    existing_cve_ids = {row['cve_id'] for row in existing_cves}
    
    print(f"Found {len(existing_cve_ids)} CVEs already in generation_runs")
    
    # Get recent CVEs from vulnstrike database
    with vulnstrike_db._create_connection() as conn:
        with conn.cursor() as cur:
            # Get recent CVEs with CVSS scores
            cur.execute("""
                SELECT cve_id, published, description, metrics
                FROM nvd_cve_data 
                WHERE description IS NOT NULL 
                  AND description NOT LIKE 'Rejected reason:%%'
                  AND metrics IS NOT NULL
                ORDER BY published DESC 
                LIMIT 50
            """)
            recent_cves = cur.fetchall()
    
    print(f"Found {len(recent_cves)} recent CVEs from NVD")
    
    # Find a fresh CVE not already processed
    fresh_cve = None
    for row in recent_cves:
        cve_id = row[0]
        if cve_id not in existing_cve_ids:
            fresh_cve = cve_id
            break
    
    if fresh_cve:
        print(f"\nDiscovered fresh CVE: {fresh_cve}")
        print("Source: NVD/vulnstrike database (recent, not previously processed)")
        return fresh_cve
    else:
        print("\nNo fresh CVEs found (all recent CVEs already processed)")
        return None

if __name__ == "__main__":
    cve = discover_fresh_cve()
    if cve:
        print(f"\nSelected CVE for end-to-end testing: {cve}")
        sys.exit(0)
    else:
        sys.exit(1)