#!/usr/bin/env python3
"""
Test session deduplication fix.
"""

import sys
import logging
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def test_session_dedup():
    """Test that session deduplication works correctly."""
    logger.info("Testing session deduplication fix...")
    
    try:
        from scripts.prod.phase1_continuous_execution_system_v0_2_0 import (
            Phase1ContinuousExecutionSystem, 
            RunMode
        )
        
        # Create system in drain mode with max 3 runs
        logger.info("Creating system in DRAIN_QUEUE mode (max 3 runs)...")
        system = Phase1ContinuousExecutionSystem(
            mode=RunMode.DRAIN_QUEUE,
            max_runs=3,
            batch_size=3,
            timeout_minutes=2,  # Short timeout for testing
            wait_seconds=1  # Short wait between runs
        )
        
        # Mock the _process_single_cve method to avoid actual processing
        original_process = system._process_single_cve
        
        processed_cves = []
        def mock_process(cve_selection):
            cve_id = cve_selection['cve_id']
            logger.info(f"Mock processing CVE: {cve_id}")
            processed_cves.append(cve_id)
            return True
        
        system._process_single_cve = mock_process
        
        # Run the system
        logger.info("Starting drain run...")
        result = system.run_drain_queue(batch_size=3)
        
        logger.info(f"\nResults:")
        logger.info(f"  Processed count: {result}")
        logger.info(f"  Processed CVEs: {processed_cves}")
        
        # Check for duplicates
        unique_cves = set(processed_cves)
        if len(processed_cves) == len(unique_cves):
            logger.info("✓ No duplicate CVEs processed (session deduplication working)")
        else:
            logger.error(f"✗ Duplicate CVEs found! Processed: {processed_cves}")
            
        return len(processed_cves) == len(unique_cves)
        
    except Exception as e:
        logger.error(f"Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_session_dedup()
    sys.exit(0 if success else 1)