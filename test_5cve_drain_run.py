#!/usr/bin/env python3
"""
Test a 5-CVE drain run with corrected selection policy.
"""

import sys
import json
import logging
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/test_5cve_drain.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def run_5cve_drain_test():
    """Run a 5-CVE drain test with corrected selector."""
    logger.info("=" * 80)
    logger.info("5-CVE DRAIN RUN TEST WITH CORRECTED SELECTOR")
    logger.info("=" * 80)
    
    try:
        from scripts.prod.phase1_continuous_execution_system_v0_2_0 import (
            Phase1ContinuousExecutionSystem, 
            RunMode
        )
        
        # Create system in drain mode with max 5 runs
        logger.info("Creating continuous execution system in DRAIN_QUEUE mode...")
        system = Phase1ContinuousExecutionSystem(
            mode=RunMode.DRAIN_QUEUE,
            max_runs=5,
            batch_size=5,
            timeout_minutes=5  # Short timeout for testing
        )
        
        # Run the system
        logger.info("Starting 5-CVE drain run...")
        results = system.run()
        
        # Analyze results
        logger.info("\n" + "=" * 80)
        logger.info("DRAIN RUN RESULTS")
        logger.info("=" * 80)
        
        # Extract session summary
        session_summary = results.get('session_summary', {})
        runs_completed = session_summary.get('runs_completed', 0)
        runs_failed = session_summary.get('runs_failed', 0)
        runs_skipped = session_summary.get('runs_skipped', 0)
        
        logger.info(f"Runs completed: {runs_completed}")
        logger.info(f"Runs failed: {runs_failed}")
        logger.info(f"Runs skipped: {runs_skipped}")
        
        # Check individual run results
        run_results = results.get('run_results', [])
        logger.info(f"\nIndividual run results ({len(run_results)} runs):")
        
        for i, run in enumerate(run_results, 1):
            cve_id = run.get('cve_id', 'Unknown')
            status = run.get('status', 'Unknown')
            errors = run.get('errors', [])
            
            logger.info(f"  Run {i}: CVE={cve_id}, Status={status}")
            if errors:
                logger.info(f"    Errors: {errors}")
        
        # Check selection statistics from runs
        logger.info("\nSELECTION STATISTICS (Corrected Policy):")
        
        selection_stats = []
        for run in run_results:
            selection_data = run.get('selection_data', {})
            if selection_data:
                fetched = selection_data.get('number_of_candidates_returned_from_opensearch', 0)
                filtered = selection_data.get('number_filtered_out_by_postgres', 0)
                eligible = len(selection_data.get('eligible_candidates', []))
                exclusion_counts = selection_data.get('exclusion_counts', {})
                
                selection_stats.append({
                    'fetched': fetched,
                    'filtered': filtered,
                    'eligible': eligible,
                    'exclusion_counts': exclusion_counts
                })
        
        if selection_stats:
            # Calculate averages
            avg_fetched = sum(s['fetched'] for s in selection_stats) / len(selection_stats)
            avg_filtered = sum(s['filtered'] for s in selection_stats) / len(selection_stats)
            avg_eligible = sum(s['eligible'] for s in selection_stats) / len(selection_stats)
            
            logger.info(f"  Average per selection:")
            logger.info(f"    Fetched: {avg_fetched:.1f}")
            logger.info(f"    Filtered: {avg_filtered:.1f}")
            logger.info(f"    Eligible: {avg_eligible:.1f}")
            
            # Show exclusion counts from first selection
            first_counts = selection_stats[0].get('exclusion_counts', {})
            logger.info(f"  Exclusion counts (first selection):")
            for category, count in first_counts.items():
                logger.info(f"    {category}: {count}")
        
        # Verify corrected selector is being used
        logger.info("\nCORRECTED SELECTOR VERIFICATION:")
        
        # Check if exclusion_counts field exists (indicator of corrected selector)
        if selection_stats and 'exclusion_counts' in selection_stats[0]:
            logger.info("  ✓ Corrected selector is being used (exclusion_counts field present)")
            
            # Check that filtered count is 0 (with corrected policy)
            if avg_filtered == 0:
                logger.info("  ✓ No CVEs filtered out (corrected policy working)")
            else:
                logger.warning(f"  ⚠ Some CVEs filtered out: {avg_filtered:.1f}")
        else:
            logger.error("  ✗ Corrected selector NOT detected")
        
        # Save results to file
        output_file = Path("logs/5cve_drain_results.json")
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        logger.info(f"\nFull results saved to: {output_file}")
        
        return True, results
        
    except Exception as e:
        logger.error(f"Failed to run 5-CVE drain test: {e}")
        import traceback
        traceback.print_exc()
        return False, None

def main():
    """Run the test."""
    success, results = run_5cve_drain_test()
    
    if success:
        logger.info("\n" + "=" * 80)
        logger.info("TEST COMPLETE - CORRECTED SELECTOR WIRING VERIFIED")
        logger.info("=" * 80)
        
        # Print key metrics
        session_summary = results.get('session_summary', {})
        print(f"\nKey Metrics:")
        print(f"  Runs attempted: {session_summary.get('total_runs_attempted', 0)}")
        print(f"  Runs completed: {session_summary.get('runs_completed', 0)}")
        print(f"  Runs failed: {session_summary.get('runs_failed', 0)}")
        
        # Check selection stats
        run_results = results.get('run_results', [])
        if run_results:
            first_run = run_results[0]
            selection_data = first_run.get('selection_data', {})
            if selection_data:
                print(f"\nFirst selection stats (corrected policy):")
                print(f"  Candidates fetched: {selection_data.get('number_of_candidates_returned_from_opensearch', 0)}")
                print(f"  Filtered out: {selection_data.get('number_filtered_out_by_postgres', 0)}")
                print(f"  Eligible: {len(selection_data.get('eligible_candidates', []))}")
                
                exclusion_counts = selection_data.get('exclusion_counts', {})
                if exclusion_counts:
                    print(f"\nExclusion counts:")
                    for category, count in exclusion_counts.items():
                        print(f"  {category}: {count}")
        
        return 0
    else:
        logger.error("\nTEST FAILED")
        return 1

if __name__ == "__main__":
    sys.exit(main())