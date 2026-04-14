#!/usr/bin/env python3
"""Verify queue status."""

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent))

from src.utils.db import DatabaseClient

def main():
    db = DatabaseClient()
    
    # Check all queue items
    print("All queue items:")
    print("-" * 80)
    result = db.fetch_all("SELECT id, cve_id, status, created_at FROM cve_queue ORDER BY id")
    for r in result:
        print(f"ID: {r['id']:3} | CVE: {r['cve_id']:20} | Status: {r['status']:20} | Created: {r['created_at']}")
    
    print("\n" + "=" * 80)
    
    # Check specific CVEs
    selected_cves = ["CVE-2025-32019", "CVE-2025-47187", "CVE-2025-4700", "CVE-2025-8069", "CVE-2025-46171"]
    print("Checking selected CVEs:")
    for cve in selected_cves:
        result = db.fetch_one("SELECT id, status FROM cve_queue WHERE cve_id = %s", (cve,))
        if result:
            print(f"  {cve}: Found - ID {result['id']}, Status: {result['status']}")
        else:
            print(f"  {cve}: NOT FOUND")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())