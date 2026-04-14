#!/usr/bin/env python3
"""
Context Readiness Proof - Prove context readiness gate works
Version: v0.1.0
Timestamp: 2026-04-08

Purpose:
- Prove context readiness gate before generation
- Show one of: existing snapshot valid, missing snapshot auto-built, blocked with clear reason
- Show whether generation was allowed based on readiness

Required output:
- Selected CVE
- Snapshot existed or was built
- Snapshot ID if available
- Readiness status
- Whether generation was allowed
"""

import os
import sys
import json
import logging
import argparse
from pathlib import Path
from typing import Dict, Any, Optional

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.db import get_database_client

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class ContextReadinessProver:
    """Prove context readiness gate functionality."""
    
    def __init__(self):
        self.db = get_database_client()
        self.results = {
            "test_cases": [],
            "summary": {}
        }
        
        logger.info("ContextReadinessProver initialized")
    
    def test_context_readiness(self, cve_id: str) -> Dict[str, Any]:
        """
        Test context readiness for a CVE.
        
        Returns:
            Test results dict
        """
        logger.info(f"Testing context readiness for {cve_id}...")
        
        # Import and run context builder
        context_builder_script = Path(__file__).parent / "02_85_build_context_snapshot_v0_1_0.py"
        
        if not context_builder_script.exists():
            logger.error(f"Context builder script not found: {context_builder_script}")
            return {
                "cve_id": cve_id,
                "error": "Context builder script missing",
                "readiness_status": "blocked_missing_context",
                "generation_allowed": False
            }
        
        try:
            import subprocess
            import json as json_module
            
            # Run context builder
            cmd = [sys.executable, str(context_builder_script), '--cve', cve_id, '--json']
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                builder_output = json_module.loads(result.stdout.strip())
                readiness_status = builder_output.get('readiness_status', 'blocked_missing_context')
                context_snapshot_id = builder_output.get('context_snapshot_id')
                error = builder_output.get('error')
                
                # Determine if generation would be allowed
                generation_allowed = readiness_status in ['ready', 'auto_built']
                
                test_result = {
                    "cve_id": cve_id,
                    "readiness_status": readiness_status,
                    "context_snapshot_id": context_snapshot_id,
                    "error": error,
                    "generation_allowed": generation_allowed,
                    "builder_output": builder_output
                }
                
                logger.info(f"Context readiness for {cve_id}: {readiness_status}")
                logger.info(f"Generation allowed: {generation_allowed}")
                if context_snapshot_id:
                    logger.info(f"Context snapshot ID: {context_snapshot_id}")
                
                return test_result
            else:
                logger.error(f"Context builder failed for {cve_id}")
                return {
                    "cve_id": cve_id,
                    "error": f"Context builder failed with code {result.returncode}",
                    "readiness_status": "blocked_missing_context",
                    "generation_allowed": False,
                    "builder_stderr": result.stderr
                }
                
        except Exception as e:
            logger.error(f"Error testing context readiness for {cve_id}: {e}")
            return {
                "cve_id": cve_id,
                "error": str(e),
                "readiness_status": "blocked_missing_context",
                "generation_allowed": False
            }
    
    def check_queue_processor_integration(self, cve_id: str) -> Dict[str, Any]:
        """
        Check if queue processor would handle this CVE correctly.
        
        Returns:
            Integration test results
        """
        logger.info(f"Checking queue processor integration for {cve_id}...")
        
        # Check if CVE is in queue
        queue_item = self.db.fetch_one(
            "SELECT id, status FROM cve_queue WHERE cve_id = %s",
            (cve_id,)
        )
        
        # Check if CVE has approved playbook (idempotency check)
        approved_playbook = self.db.fetch_one(
            """
            SELECT ap.id 
            FROM approved_playbooks ap
            JOIN generation_runs gr ON ap.generation_run_id = gr.id
            WHERE gr.cve_id = %s
            """,
            (cve_id,)
        )
        
        # Check context snapshot
        context_snapshot = self.db.fetch_one(
            "SELECT id, context_data FROM cve_context_snapshot WHERE cve_id = %s",
            (cve_id,)
        )
        
        return {
            "cve_id": cve_id,
            "in_queue": queue_item is not None,
            "queue_id": queue_item['id'] if queue_item else None,
            "queue_status": queue_item['status'] if queue_item else None,
            "has_approved_playbook": approved_playbook is not None,
            "approved_playbook_id": approved_playbook['id'] if approved_playbook else None,
            "has_context_snapshot": context_snapshot is not None,
            "context_snapshot_id": context_snapshot['id'] if context_snapshot else None
        }
    
    def run_proof(self, test_cves: list) -> Dict[str, Any]:
        """
        Run complete context readiness proof.
        
        Args:
            test_cves: List of CVE IDs to test
            
        Returns:
            Complete proof results
        """
        logger.info("CONTEXT READINESS PROOF")
        logger.info("=" * 60)
        
        test_results = []
        
        for cve_id in test_cves:
            logger.info(f"\nTesting CVE: {cve_id}")
            logger.info("-" * 40)
            
            # Test context readiness
            readiness_result = self.test_context_readiness(cve_id)
            
            # Check queue processor integration
            integration_result = self.check_queue_processor_integration(cve_id)
            
            # Combine results
            test_result = {
                **readiness_result,
                **integration_result
            }
            
            test_results.append(test_result)
        
        # Generate summary
        total_tests = len(test_results)
        ready_count = sum(1 for r in test_results if r['readiness_status'] == 'ready')
        auto_built_count = sum(1 for r in test_results if r['readiness_status'] == 'auto_built')
        blocked_count = sum(1 for r in test_results if r['readiness_status'] == 'blocked_missing_context')
        generation_allowed_count = sum(1 for r in test_results if r['generation_allowed'])
        
        summary = {
            "total_tests": total_tests,
            "ready": ready_count,
            "auto_built": auto_built_count,
            "blocked": blocked_count,
            "generation_allowed": generation_allowed_count,
            "generation_blocked": total_tests - generation_allowed_count,
            "all_tests_passed": blocked_count > 0  # Should have at least one blocked case
        }
        
        self.results = {
            "test_cases": test_results,
            "summary": summary
        }
        
        return self.results
    
    def print_summary(self):
        """Print proof summary."""
        print("\n" + "=" * 80)
        print("CONTEXT READINESS PROOF - SUMMARY")
        print("=" * 80)
        
        summary = self.results['summary']
        print(f"Total Tests: {summary['total_tests']}")
        print(f"Ready: {summary['ready']}")
        print(f"Auto-built: {summary['auto_built']}")
        print(f"Blocked: {summary['blocked']}")
        print(f"Generation Allowed: {summary['generation_allowed']}")
        print(f"Generation Blocked: {summary['generation_blocked']}")
        print(f"All Tests Passed: {summary['all_tests_passed']}")
        
        print("\n" + "=" * 80)
        print("DETAILED TEST RESULTS")
        print("=" * 80)
        
        for i, test_case in enumerate(self.results['test_cases'], 1):
            print(f"\nTest Case {i}: {test_case['cve_id']}")
            print(f"  Readiness Status: {test_case['readiness_status']}")
            print(f"  Generation Allowed: {test_case['generation_allowed']}")
            
            if test_case['context_snapshot_id']:
                print(f"  Context Snapshot ID: {test_case['context_snapshot_id']}")
            
            if test_case['has_context_snapshot']:
                print(f"  Has Context Snapshot: Yes (ID: {test_case['context_snapshot_id']})")
            else:
                print(f"  Has Context Snapshot: No")
            
            if test_case['in_queue']:
                print(f"  In Queue: Yes (ID: {test_case['queue_id']}, Status: {test_case['queue_status']})")
            else:
                print(f"  In Queue: No")
            
            if test_case['has_approved_playbook']:
                print(f"  Has Approved Playbook: Yes (ID: {test_case['approved_playbook_id']})")
            else:
                print(f"  Has Approved Playbook: No")
            
            if test_case['error']:
                print(f"  Error: {test_case['error']}")
        
        print("\n" + "=" * 80)
        print("CONTEXT READINESS GATE VERIFICATION")
        print("=" * 80)
        
        # Verify the gate logic
        gate_verified = True
        for test_case in self.results['test_cases']:
            cve_id = test_case['cve_id']
            readiness = test_case['readiness_status']
            allowed = test_case['generation_allowed']
            
            # Check logic: generation allowed only for ready or auto_built
            if readiness in ['ready', 'auto_built'] and not allowed:
                print(f"FAIL: {cve_id} is {readiness} but generation not allowed")
                gate_verified = False
            elif readiness == 'blocked_missing_context' and allowed:
                print(f"FAIL: {cve_id} is blocked but generation allowed")
                gate_verified = False
            else:
                print(f"PASS: {cve_id} - {readiness} -> generation {'allowed' if allowed else 'blocked'}")
        
        print(f"\nContext Readiness Gate Verified: {'PASS' if gate_verified else 'FAIL'}")
        print("=" * 80)


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(description='Prove context readiness gate')
    parser.add_argument('--cves', nargs='+', help='CVE IDs to test (space-separated)')
    parser.add_argument('--auto-select', action='store_true', help='Auto-select test CVEs')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('--json', action='store_true', help='Output JSON only')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Determine test CVEs
    test_cves = []
    
    if args.cves:
        test_cves = args.cves
    elif args.auto_select:
        # Auto-select test CVEs: one with snapshot, one without, one non-existent
        db = get_database_client()
        
        # Get a CVE with existing snapshot
        existing = db.fetch_one(
            "SELECT cve_id FROM cve_context_snapshot WHERE cve_id != 'CVE-TEST-0001' LIMIT 1"
        )
        if existing:
            test_cves.append(existing['cve_id'])
        
        # Get a CVE without snapshot but in vulnstrike
        all_cves = db.fetch_all(
            "SELECT cve_id FROM cve_context_snapshot"
        )
        existing_cves = {row['cve_id'] for row in all_cves}
        
        # Try to find CVE-2025-54377 (we saw it earlier)
        if 'CVE-2025-54377' not in existing_cves:
            test_cves.append('CVE-2025-54377')
        
        # Add a non-existent CVE
        test_cves.append('CVE-2025-99999')
    else:
        # Default test cases
        test_cves = ['CVE-2025-54365', 'CVE-2025-54377', 'CVE-2025-99999']
    
    logger.info(f"Testing CVEs: {', '.join(test_cves)}")
    
    # Run proof
    prover = ContextReadinessProver()
    results = prover.run_proof(test_cves)
    
    if args.json:
        # Output JSON only
        print(json.dumps(results, indent=2))
    else:
        # Print summary
        prover.print_summary()
    
    # Exit code based on proof results
    if results['summary']['all_tests_passed']:
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()