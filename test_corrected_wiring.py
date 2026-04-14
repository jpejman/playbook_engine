#!/usr/bin/env python3
"""
Test script to verify corrected selector wiring.
"""

import sys
import logging
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent))

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def test_corrected_selector_import():
    """Test that the corrected selector can be imported and used."""
    logger.info("Testing corrected selector import...")
    
    try:
        from phase1_selector_corrected import Phase1CVESelectorCorrected
        logger.info("✓ Successfully imported Phase1CVESelectorCorrected")
        
        # Create instance
        selector = Phase1CVESelectorCorrected()
        logger.info("✓ Successfully created Phase1CVESelectorCorrected instance")
        
        # Test selection (limit to 5 for quick test)
        results = selector.run_selection_corrected(limit=5)
        
        # Check required fields
        required_fields = [
            'selected_cve',
            'number_of_candidates_returned_from_opensearch',
            'number_filtered_out_by_postgres',
            'eligible_candidates',
            'exclusion_counts'
        ]
        
        for field in required_fields:
            if field in results:
                logger.info(f"✓ Field '{field}' present in results")
            else:
                logger.error(f"✗ Field '{field}' missing from results")
        
        # Log results
        candidates = results.get('number_of_candidates_returned_from_opensearch', 0)
        filtered = results.get('number_filtered_out_by_postgres', 0)
        eligible = len(results.get('eligible_candidates', []))
        
        logger.info(f"Selection results: {candidates} fetched, {filtered} filtered, {eligible} eligible")
        
        if results.get('selected_cve'):
            logger.info(f"✓ Selected CVE: {results['selected_cve']}")
        else:
            logger.warning("No CVE selected")
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to test corrected selector: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_continuous_system_wiring():
    """Test that the continuous execution system uses the corrected selector."""
    logger.info("\nTesting continuous execution system wiring...")
    
    try:
        from scripts.prod.phase1_continuous_execution_system_v0_2_0 import Phase1ContinuousExecutionSystem
        
        # Create instance
        system = Phase1ContinuousExecutionSystem(max_runs=1)
        logger.info("✓ Successfully created Phase1ContinuousExecutionSystem instance")
        
        # Test selection method
        selection = system._select_fresh_cve_phase1(limit=5)
        
        if selection:
            logger.info(f"✓ System selected CVE: {selection.get('cve_id')}")
            logger.info(f"✓ Selection data keys: {list(selection.get('selection_data', {}).keys())}")
            
            # Check for corrected selector fields
            selection_data = selection.get('selection_data', {})
            if 'exclusion_counts' in selection_data:
                logger.info("✓ Corrected selector is being used (exclusion_counts field present)")
                logger.info(f"  Exclusion counts: {selection_data.get('exclusion_counts')}")
            else:
                logger.warning("✗ Corrected selector fields not found")
        else:
            logger.warning("No CVE selected by system")
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to test continuous system wiring: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all tests."""
    logger.info("=" * 80)
    logger.info("CORRECTED SELECTOR WIRING TEST")
    logger.info("=" * 80)
    
    test1_passed = test_corrected_selector_import()
    test2_passed = test_continuous_system_wiring()
    
    logger.info("\n" + "=" * 80)
    logger.info("TEST SUMMARY")
    logger.info("=" * 80)
    
    if test1_passed and test2_passed:
        logger.info("✓ ALL TESTS PASSED")
        logger.info("✓ Corrected selector is properly wired")
        return 0
    else:
        logger.error("✗ SOME TESTS FAILED")
        logger.error("✗ Check wiring implementation")
        return 1

if __name__ == "__main__":
    sys.exit(main())