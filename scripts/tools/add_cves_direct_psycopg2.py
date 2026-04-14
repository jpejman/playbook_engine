#!/usr/bin/env python3
"""Add CVEs to queue using direct psycopg2 with proper commits."""

import os
import sys
import psycopg2
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
repo_root = Path(__file__).resolve().parent
env_path = repo_root / '.env'
load_dotenv(env_path)

def get_db_connection():
    """Get direct database connection."""
    host = os.getenv('DB_HOST', 'localhost')
    port = os.getenv('DB_PORT', '5432')
    database = os.getenv('DB_NAME', 'vulnstrike')
    user = os.getenv('DB_USER', 'vulnstrike')
    password = os.getenv('DB_PASSWORD', 'vulnstrike')
    
    print(f"Connecting to {host}:{port}/{database}...")
    conn = psycopg2.connect(
        host=host,
        port=port,
        database=database,
        user=user,
        password=password
    )
    conn.autocommit = False  # Ensure we control transactions
    return conn

def add_cve_direct(cve_id, priority=5):
    """Add CVE directly with proper transaction handling."""
    conn = get_db_connection()
    try:
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
                conn.commit()
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
                conn.commit()  # COMMIT THE TRANSACTION
                if result:
                    queue_id = result[0]
                    print(f"{cve_id}: Inserted - ID {queue_id}")
                    return queue_id
                else:
                    print(f"{cve_id}: Failed to insert")
                    return None
    except Exception as e:
        conn.rollback()
        print(f"{cve_id}: Error - {e}")
        return None
    finally:
        conn.close()

def verify_cves(cve_list):
    """Verify CVEs are in queue using a new connection."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            print("\nVerification:")
            for cve_id in cve_list:
                cursor.execute(
                    "SELECT id, status FROM cve_queue WHERE cve_id = %s",
                    (cve_id,)
                )
                result = cursor.fetchone()
                if result:
                    print(f"  {cve_id}: ✓ Found - ID {result[0]}, Status: {result[1]}")
                else:
                    print(f"  {cve_id}: ✗ NOT FOUND")
    finally:
        conn.close()

def main():
    """Add all selected CVEs."""
    selected_cves = [
        "CVE-2025-32019",  # Harbor vulnerability
        "CVE-2025-47187",  # Mitel SIP Phones vulnerability
        "CVE-2025-4700",   # GitLab vulnerability
        "CVE-2025-8069",   # AWS Client VPN vulnerability
        "CVE-2025-46171",  # vBulletin vulnerability
    ]
    
    print("Adding selected CVEs to queue with direct psycopg2...")
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
    verify_cves(selected_cves)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())