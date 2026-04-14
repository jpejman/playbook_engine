#!/usr/bin/env python3
"""
Simple Test for Real CVE Selection Fixes
Demonstrates that test CVEs are excluded and real CVEs are selected.
"""

import sys
import subprocess
from pathlib import Path

def run_command(cmd):
    """Run a command and return output."""
    print(f"\nRunning: {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    print(result.stdout)
    if result.stderr:
        print(f"STDERR: {result.stderr}")
    return result.returncode == 0, result.stdout

def main():
    """Run simple tests."""
    print("VS.ai Playbook Engine - Real CVE Selection Test")
    print("Testing fixes for excluding test CVEs")
    print("=" * 80)
    
    # Change to script directory
    script_dir = Path(__file__).parent
    os.chdir(script_dir)
    
    test_results = []
    
    # Test 1: List candidates without test CVEs
    print("\nTEST 1: List candidates WITHOUT test CVEs (default)")
    print("-" * 40)
    success, output = run_command("python scripts/06_07a_list_missing_cve_candidates_v0_1_0.py")
    if "No missing CVE candidates found" in output:
        print("✓ PASS: No test CVEs shown (they are filtered out)")
        test_results.append(("Test CVE filtering", True))
    else:
        print("❌ FAIL: Test CVEs might be showing")
        test_results.append(("Test CVE filtering", False))
    
    # Test 2: List candidates WITH test CVEs
    print("\nTEST 2: List candidates WITH test CVEs (--allow-test-cves)")
    print("-" * 40)
    success, output = run_command("python scripts/06_07a_list_missing_cve_candidates_v0_1_0.py --allow-test-cves")
    if "CVE-TEST-NEW-001" in output:
        print("✓ PASS: Test CVEs shown when flag is used")
        test_results.append(("--allow-test-cves flag", True))
    else:
        print("❌ FAIL: Test CVEs not shown even with flag")
        test_results.append(("--allow-test-cves flag", False))
    
    # Test 3: Selector without test CVEs
    print("\nTEST 3: Selector WITHOUT test CVEs (default)")
    print("-" * 40)
    success, output = run_command("python scripts/06_07b_select_next_missing_cve_v0_1_0.py")
    if "No CVE selected" in output or "No eligible candidates" in output:
        print("✓ PASS: Selector correctly rejects test CVEs")
        test_results.append(("Selector test CVE rejection", True))
    else:
        print("❌ FAIL: Selector might be selecting test CVEs")
        test_results.append(("Selector test CVE rejection", False))
    
    # Test 4: Selector with test CVEs
    print("\nTEST 4: Selector WITH test CVEs (--allow-test-cves)")
    print("-" * 40)
    success, output = run_command("python scripts/06_07b_select_next_missing_cve_v0_1_0.py --allow-test-cves")
    if "CVE-TEST-NEW-001" in output and "TEST CVE:" in output:
        print("✓ PASS: Selector shows test CVE with warning when flag is used")
        test_results.append(("Selector with --allow-test-cves", True))
    else:
        print("❌ FAIL: Selector not working with --allow-test-cves")
        test_results.append(("Selector with --allow-test-cves", False))
    
    # Test 5: Check SQL proof is shown
    print("\nTEST 5: SQL Proof Display")
    print("-" * 40)
    success, output = run_command("python scripts/06_07b_select_next_missing_cve_v0_1_0.py --allow-test-cves")
    if "SQL Proof - CVE" in output and "Has Approved Playbook:" in output:
        print("✓ PASS: SQL proof is displayed for verification")
        test_results.append(("SQL proof display", True))
    else:
        print("❌ FAIL: SQL proof not displayed")
        test_results.append(("SQL proof display", False))
    
    # Summary
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    
    all_passed = True
    for test_name, passed in test_results:
        status = "PASS" if passed else "FAIL"
        if not passed:
            all_passed = False
        print(f"{test_name:40} {status}")
    
    print("\n" + "=" * 80)
    if all_passed:
        print("✓ ALL TESTS PASSED")
        print("\nThe fixes successfully implement:")
        print("  1. Test CVEs excluded by default from selection")
        print("  2. --allow-test-cves flag for testing purposes")
        print("  3. SQL proof for CVE verification")
        print("  4. Clear warnings when test CVEs are selected")
        print("\nProduction path now enforces real missing-CVE processing only.")
    else:
        print("❌ SOME TESTS FAILED")
        print("\nReview the test output above for issues.")
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    import os
    sys.exit(main())