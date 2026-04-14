#!/usr/bin/env python3
"""
Test Real CVE Selection
Tests the fixes for excluding test CVEs and selecting real missing CVEs.
"""

import sys
import json
from pathlib import Path

# Add src to path
sys.path.append(str(Path(__file__).parent.parent))

from src.utils.db import DatabaseClient

def test_candidate_listing():
    """Test candidate listing with and without test CVEs."""
    print("=" * 80)
    print("TEST 1: Candidate Listing")
    print("=" * 80)
    
    # Import and run the candidate listing script
    import importlib.util
    spec = importlib.util.spec_from_file_location("listing_script", "scripts/06_07a_list_missing_cve_candidates_v0_1_0.py")
    listing_script = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(listing_script)
    
    db = DatabaseClient()
    
    # Test without test CVEs (default)
    print("\n1. Listing WITHOUT test CVEs (default):")
    candidates = listing_script.get_missing_cve_candidates(db, exclude_recent=False, allow_test_cves=False)
    print(f"   Found {len(candidates)} candidates")
    for c in candidates:
        print(f"   - {c['cve_id']} (test: {c.get('is_test_cve', False)}, eligible: {c['eligible_for_selection']})")
    
    # Test with test CVEs allowed
    print("\n2. Listing WITH test CVEs (--allow-test-cves):")
    candidates = listing_script.get_missing_cve_candidates(db, exclude_recent=False, allow_test_cves=True)
    print(f"   Found {len(candidates)} candidates")
    for c in candidates:
        print(f"   - {c['cve_id']} (test: {c.get('is_test_cve', False)}, eligible: {c['eligible_for_selection']})")
    
    return len(candidates)

def test_selector():
    """Test selector with and without test CVEs."""
    print("\n" + "=" * 80)
    print("TEST 2: Selector Behavior")
    print("=" * 80)
    
    # Import and run the selector script
    import scripts.06_07b_select_next_missing_cve_v0_1_0 as selector_script
    
    db = DatabaseClient()
    
    # Test without test CVEs (default)
    print("\n1. Selector WITHOUT test CVEs (default):")
    selector = selector_script.CVESelector(db, allow_test_cves=False)
    selected = selector.select_next_cve(force=False)
    if selected:
        print(f"   Selected: {selected['cve_id']} (test: {selected.get('is_test_cve', False)})")
        print(f"   Score: {selected.get('selection_score', 0.0):.2f}")
    else:
        print("   No CVE selected (correct - test CVEs excluded)")
    
    # Test with test CVEs allowed
    print("\n2. Selector WITH test CVEs (--allow-test-cves):")
    selector = selector_script.CVESelector(db, allow_test_cves=True)
    selected = selector.select_next_cve(force=False)
    if selected:
        print(f"   Selected: {selected['cve_id']} (test: {selected.get('is_test_cve', False)})")
        print(f"   Score: {selected.get('selection_score', 0.0):.2f}")
        
        # Get SQL proof
        sql_proof = selector.get_sql_proof(selected['cve_id'])
        print(f"\n   SQL Proof:")
        print(f"   - Has approved playbook: {sql_proof.get('has_approved_playbook', 'N/A')}")
        print(f"   - Queue status: {sql_proof.get('queue_status', 'N/A')}")
        print(f"   - Is test CVE: {sql_proof.get('is_test', 'N/A')}")
    else:
        print("   No CVE selected")
    
    return selected is not None

def seed_real_cve_for_test():
    """Seed a real CVE into queue for testing."""
    print("\n" + "=" * 80)
    print("TEST 3: Seeding Real CVE for Testing")
    print("=" * 80)
    
    db = DatabaseClient()
    
    # Check for real CVEs without approved playbooks
    real_cve = "CVE-2025-53537"  # From earlier check
    
    # Check if already in queue
    existing = db.fetch_one("SELECT id, status FROM cve_queue WHERE cve_id = %s", (real_cve,))
    
    if existing:
        print(f"CVE {real_cve} already in queue (ID: {existing['id']}, status: {existing['status']})")
        # Update to pending if not already
        if existing['status'] != 'pending':
            db.execute("UPDATE cve_queue SET status = 'pending', updated_at = NOW() WHERE id = %s", (existing['id'],))
            print(f"Updated status to 'pending'")
        return real_cve, existing['id']
    else:
        # Insert new queue item
        query = """
        INSERT INTO cve_queue (cve_id, status, priority, created_at, updated_at)
        VALUES (%s, 'pending', 5, NOW(), NOW())
        RETURNING id
        """
        
        try:
            conn = db.begin_transaction()
            with conn.cursor() as cursor:
                cursor.execute(query, (real_cve,))
                result = cursor.fetchone()
                conn.commit()
            
            if result and len(result) > 0:
                queue_id = result[0]
                print(f"Inserted real CVE {real_cve} into queue (ID: {queue_id})")
                return real_cve, queue_id
            else:
                print(f"Failed to insert CVE {real_cve}")
                return None, None
        except Exception as e:
            print(f"Error inserting CVE {real_cve}: {e}")
            return None, None

def test_real_cve_selection():
    """Test selection with a real CVE in queue."""
    print("\n" + "=" * 80)
    print("TEST 4: Real CVE Selection Test")
    print("=" * 80)
    
    # First seed a real CVE
    cve_id, queue_id = seed_real_cve_for_test()
    if not cve_id:
        print("Failed to seed real CVE for testing")
        return False
    
    # Now test the selector
    import scripts.06_07b_select_next_missing_cve_v0_1_0 as selector_script
    
    db = DatabaseClient()
    selector = selector_script.CVESelector(db, allow_test_cves=False)
    selected = selector.select_next_cve(force=False)
    
    if selected:
        print(f"\nSelected CVE: {selected['cve_id']}")
        print(f"Is test CVE: {selected.get('is_test_cve', False)}")
        
        # Verify it's not a test CVE
        if selected.get('is_test_cve', False):
            print("❌ FAIL: Selected CVE is a test CVE (should be real)")
            return False
        else:
            print("✓ PASS: Selected CVE is not a test CVE")
            
            # Get SQL proof
            sql_proof = selector.get_sql_proof(selected['cve_id'])
            print(f"\nSQL Proof Verification:")
            print(f"  - Has approved playbook: {sql_proof.get('has_approved_playbook', 'N/A')} (should be False)")
            print(f"  - Queue status: {sql_proof.get('queue_status', 'N/A')} (should be 'pending')")
            print(f"  - Is test CVE: {sql_proof.get('is_test', 'N/A')} (should be False)")
            
            # Verify all conditions
            if (not sql_proof.get('has_approved_playbook', True) and 
                sql_proof.get('queue_status') == 'pending' and
                not sql_proof.get('is_test', True)):
                print("\n✓✓✓ ALL CHECKS PASSED: Real missing CVE correctly selected")
                return True
            else:
                print("\n❌ FAIL: SQL proof shows issues")
                return False
    else:
        print("No CVE selected")
        return False

def cleanup_test_cve(cve_id):
    """Clean up test CVE from queue."""
    if cve_id and cve_id.startswith('CVE-2025-'):
        db = DatabaseClient()
        db.execute("DELETE FROM cve_queue WHERE cve_id = %s", (cve_id,))
        print(f"\nCleaned up test CVE {cve_id} from queue")

def main():
    """Run all tests."""
    print("VS.ai Playbook Engine - Real CVE Selection Test")
    print("Testing fixes for excluding test CVEs and enforcing real missing-CVE processing")
    print("=" * 80)
    
    test_results = []
    
    # Run tests
    test_results.append(("Candidate Listing", test_candidate_listing()))
    test_results.append(("Selector Behavior", test_selector()))
    
    # Test with real CVE
    real_cve_test_passed = test_real_cve_selection()
    test_results.append(("Real CVE Selection", real_cve_test_passed))
    
    # Get the real CVE ID for cleanup
    real_cve_id = "CVE-2025-53537"
    
    # Summary
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    
    all_passed = True
    for test_name, result in test_results:
        status = "PASS" if result else "FAIL"
        if not result:
            all_passed = False
        print(f"{test_name:30} {status}")
    
    print("\n" + "=" * 80)
    if all_passed:
        print("✓ ALL TESTS PASSED")
        print("The fixes successfully:")
        print("  1. Exclude test CVEs from normal selection")
        print("  2. Enforce real missing-CVE processing")
        print("  3. Provide SQL proof for verification")
        print("  4. Allow test CVEs only with --allow-test-cves flag")
    else:
        print("❌ SOME TESTS FAILED")
    
    # Cleanup
    cleanup_test_cve(real_cve_id)
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())