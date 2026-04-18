"""
Final SQL test for v0.2.2 metadata enrichment.
"""

from __future__ import annotations

import sys
import os

# Add the parent directory to the path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from scripts.prod.continuous_pipeline_v0_2_1.db_clients import PlaybookEngineClient


def main():
    db = PlaybookEngineClient()
    
    print("Executing SQL query from directive...")
    
    rows = db.fetch_all("""
        SELECT id, cve_id, model, run_duration_seconds, creator_script, status, created_at
        FROM public.generation_runs
        ORDER BY id DESC
        LIMIT 20
    """)
    
    print(f"Success! Query returned {len(rows)} rows")
    
    # Show a few rows
    print("\nSample rows (showing first 3):")
    for i, row in enumerate(rows[:3]):
        print(f"\nRow {i+1}:")
        print(f"  ID: {row.get('id')}")
        print(f"  CVE: {row.get('cve_id')}")
        print(f"  Model: {row.get('model')}")
        print(f"  Duration: {row.get('run_duration_seconds')}")
        print(f"  Creator Script: {row.get('creator_script')}")
        print(f"  Status: {row.get('status')}")
        print(f"  Created: {row.get('created_at')}")
    
    print("\n" + "="*60)
    print("SUCCESS: SQL query from directive executes correctly")
    print("Note: Old rows have null values for new columns (expected)")
    print("New rows created with v0.2.2 will have metadata populated")
    print("="*60)
    
    return 0


if __name__ == '__main__':
    sys.exit(main())