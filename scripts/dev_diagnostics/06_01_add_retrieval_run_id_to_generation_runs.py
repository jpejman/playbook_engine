#!/usr/bin/env python3
"""
Add retrieval_run_id to generation_runs table for lineage isolation.
Version: v0.2.1-fix
Timestamp: 2026-04-08
"""

import os
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.db import get_database_client

def add_retrieval_run_id_column():
    """Add retrieval_run_id column to generation_runs table."""
    db = get_database_client()
    
    print("Checking if retrieval_run_id column exists in generation_runs...")
    
    # Check if column already exists
    result = db.fetch_one(
        """
        SELECT column_name 
        FROM information_schema.columns 
        WHERE table_schema = 'public' 
          AND table_name = 'generation_runs' 
          AND column_name = 'retrieval_run_id'
        """
    )
    
    if result:
        print("Column 'retrieval_run_id' already exists in generation_runs table.")
        return True
    
    print("Adding retrieval_run_id column to generation_runs table...")
    
    try:
        # Add the column
        db.execute(
            """
            ALTER TABLE generation_runs 
            ADD COLUMN retrieval_run_id INTEGER REFERENCES retrieval_runs(id)
            """
        )
        print("Successfully added retrieval_run_id column to generation_runs table.")
        
        # Update existing rows to link to latest retrieval run for each CVE
        print("Updating existing generation_runs to link to retrieval_runs...")
        
        db.execute(
            """
            WITH latest_retrieval AS (
                SELECT 
                    cve_id,
                    MAX(id) as latest_retrieval_id
                FROM retrieval_runs
                GROUP BY cve_id
            )
            UPDATE generation_runs gr
            SET retrieval_run_id = lr.latest_retrieval_id
            FROM latest_retrieval lr
            WHERE gr.cve_id = lr.cve_id
            """
        )
        
        print("Successfully updated existing generation_runs with retrieval_run_id links.")
        return True
        
    except Exception as e:
        print(f"Error adding column: {e}")
        return False

def main():
    """Main execution function."""
    print("=" * 80)
    print("ADD RETRIEVAL_RUN_ID TO GENERATION_RUNS - LINEAGE ISOLATION FIX")
    print("=" * 80)
    
    success = add_retrieval_run_id_column()
    
    if success:
        print("\nMigration completed successfully.")
        print("Lineage isolation fix applied.")
    else:
        print("\nMigration failed.")
        sys.exit(1)

if __name__ == "__main__":
    main()