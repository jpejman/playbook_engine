#!/usr/bin/env python3
"""
Debug lock mechanism.
"""

import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from src.utils.db import DatabaseClient
from scripts.prod.phase1_continuous_execution_system_v0_2_0 import ParallelSafetyLock, ExecutionStatus

def debug_lock_table():
    """Debug the lock table structure and data."""
    db = DatabaseClient()
    
    # Check if table exists
    table_check = db.fetch_one("""
    SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_schema = 'public' 
        AND table_name = 'continuous_execution_locks'
    ) as table_exists
    """)
    
    print(f"Table exists: {table_check['table_exists']}")
    
    if table_check['table_exists']:
        # Show table structure
        columns = db.fetch_all("""
        SELECT column_name, data_type, is_nullable
        FROM information_schema.columns
        WHERE table_schema = 'public' 
        AND table_name = 'continuous_execution_locks'
        ORDER BY ordinal_position
        """)
        
        print("\nTable structure:")
        for col in columns:
            print(f"  {col['column_name']}: {col['data_type']} (nullable: {col['is_nullable']})")
        
        # Show current data
        data = db.fetch_all("SELECT * FROM continuous_execution_locks ORDER BY created_at")
        print(f"\nCurrent rows: {len(data)}")
        for row in data:
            print(f"  ID: {row['id']}, Session: {row['session_id']}, Run: {row['run_id']}, CVE: {row['cve_id']}, Status: {row['status']}, Acquired: {row['lock_acquired_at']}, Released: {row['lock_released_at']}")

def test_lock_mechanism():
    """Test the lock mechanism directly."""
    print("\n" + "=" * 60)
    print("Testing Lock Mechanism")
    print("=" * 60)
    
    db = DatabaseClient()
    lock_manager = ParallelSafetyLock(db)
    
    # Clean up any existing locks
    db.execute("DELETE FROM continuous_execution_locks")
    
    test_session = "debug-session"
    
    # Test 1: Acquire first lock
    print("\nTest 1: Acquire first lock")
    acquired1 = lock_manager.acquire_lock(test_session, "debug-run-1", "CVE-DEBUG-001")
    print(f"  Acquired: {acquired1}")
    
    # Show current locks
    locks = db.fetch_all("SELECT * FROM continuous_execution_locks")
    print(f"  Current locks in DB: {len(locks)}")
    for lock in locks:
        print(f"    - ID: {lock['id']}, Status: {lock['status']}, Released: {lock['lock_released_at']}")
    
    # Test 2: Try to acquire second lock (should fail)
    print("\nTest 2: Try to acquire second lock (should fail)")
    acquired2 = lock_manager.acquire_lock(test_session, "debug-run-2", "CVE-DEBUG-002")
    print(f"  Acquired: {acquired2}")
    
    # Show current locks
    locks = db.fetch_all("SELECT * FROM continuous_execution_locks")
    print(f"  Current locks in DB: {len(locks)}")
    for lock in locks:
        print(f"    - ID: {lock['id']}, Status: {lock['status']}, Released: {lock['lock_released_at']}")
    
    # Test 3: Release first lock
    print("\nTest 3: Release first lock")
    lock_manager.release_lock(test_session, "debug-run-1", ExecutionStatus.COMPLETED)
    
    # Show current locks
    locks = db.fetch_all("SELECT * FROM continuous_execution_locks")
    print(f"  Current locks in DB: {len(locks)}")
    for lock in locks:
        print(f"    - ID: {lock['id']}, Status: {lock['status']}, Released: {lock['lock_released_at']}")
    
    # Test 4: Now should be able to acquire lock
    print("\nTest 4: Now should be able to acquire lock")
    acquired3 = lock_manager.acquire_lock(test_session, "debug-run-3", "CVE-DEBUG-003")
    print(f"  Acquired: {acquired3}")
    
    # Clean up
    lock_manager.release_lock(test_session, "debug-run-3", ExecutionStatus.COMPLETED)
    
    return acquired1 and not acquired2 and acquired3

def main():
    """Run debug tests."""
    print("DEBUG LOCK MECHANISM")
    print("=" * 60)
    
    debug_lock_table()
    
    success = test_lock_mechanism()
    
    print("\n" + "=" * 60)
    if success:
        print("[OK] Lock mechanism working correctly")
    else:
        print("[ERROR] Lock mechanism has issues")
    
    return success

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)