#!/usr/bin/env python3
"""
Queue Integration - Process One Queued CVE
Version: v0.1.0
Timestamp: 2026-04-08

Purpose:
- Process exactly one CVE from the queue with idempotent single-CVE processing
- Move from manual single-CVE execution to safe queue-driven pilot
- Automatically select one eligible CVE from queue or discovery set
- Prevent duplicate playbook generation
- Process exactly one CVE per execution
- Persist queue status transitions (pending → processing → completed/failed/skipped)
- Create real approved playbook quickly
- Preserve validator/proof discipline while keeping pipeline idempotent

Queue selection priority:
1. Existing pending queue items missing playbooks
2. Seed from discovery if queue empty

Idempotency check:
- Skip CVEs that already have approved playbooks
- Skip CVEs with queue status 'completed' or 'processing'

Required flow:
1. Import and run queue selector (02_80_select_next_cve_from_queue_v0_1_0.py)
2. If selector returns CVE, check idempotency
3. Update queue status to 'processing'
4. Run canonical generation script (03_01_run_playbook_generation_v0_1_1_real_retrieval.py)
5. Handle generation result and update queue status accordingly
6. If no CVE from selector, seed queue from discovery and retry
"""

import os
import sys
import json
import logging
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional, Tuple

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.db import get_database_client

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class QueueProcessor:
    """Process one queued CVE with idempotent single-CVE processing."""
    
    def __init__(self):
        self.db = get_database_client()
        self.cve_id = None
        self.queue_id = None
        self.results = {}
        
        logger.info("QueueProcessor initialized for single-CVE processing")
    
    def assert_database_target(self):
        """Assert connected to correct database."""
        logger.info("Verifying database target...")
        from src.utils.db import assert_expected_database
        assert_expected_database('playbook_engine')
        logger.info("Connected to playbook_engine")
    
    def run_queue_selector(self) -> Optional[Dict]:
        """
        Run the queue selector script to get next CVE.
        
        Returns:
            Dictionary with cve_id and queue_id, or None if no eligible CVE
        """
        logger.info("Running queue selector...")
        
        # Import and run the selector
        selector_path = Path(__file__).parent / "02_80_select_next_cve_from_queue_v0_1_0.py"
        
        if not selector_path.exists():
            logger.error(f"Queue selector not found: {selector_path}")
            return None
        
        try:
            # Run selector as subprocess to get JSON output
            import subprocess
            import json
            
            cmd = [sys.executable, str(selector_path), '--json']
            logger.info(f"Executing selector: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                try:
                    json_output = json.loads(result.stdout.strip())
                    if json_output.get('eligible', False):
                        return {
                            'cve_id': json_output['cve_id'],
                            'queue_id': json_output['queue_id']
                        }
                    else:
                        logger.info(f"Selector returned but not eligible: {json_output.get('reason')}")
                        return None
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse selector JSON output: {e}")
                    return None
            else:
                logger.error(f"Selector failed with return code: {result.returncode}")
                if result.stderr:
                    logger.error(f"Selector stderr: {result.stderr}")
                return None
                
        except Exception as e:
            logger.error(f"Error running queue selector: {e}")
            return None
    
    def check_idempotency(self, cve_id: str) -> bool:
        """
        Check if CVE is eligible for processing (idempotency check).
        
        Returns:
            True if CVE can be processed (no approved playbook, not processing/completed)
        """
        logger.info(f"Checking idempotency for {cve_id}...")
        
        # Check if CVE already has approved playbook
        approved_playbook = self.db.fetch_one(
            """
            SELECT ap.id 
            FROM approved_playbooks ap
            JOIN generation_runs gr ON ap.generation_run_id = gr.id
            WHERE gr.cve_id = %s
            """,
            (cve_id,)
        )
        
        if approved_playbook:
            logger.warning(f"CVE {cve_id} already has approved playbook ID: {approved_playbook['id']}")
            return False
        
        # Check queue status if CVE is in queue
        queue_item = self.db.fetch_one(
            "SELECT id, status FROM cve_queue WHERE cve_id = %s",
            (cve_id,)
        )
        
        if queue_item:
            status = queue_item['status']
            if status in ['processing', 'completed']:
                logger.warning(f"CVE {cve_id} has queue status '{status}' - skipping")
                return False
        
        logger.info(f"CVE {cve_id} passed idempotency check")
        return True
    
    def update_queue_status(self, queue_id: Optional[int], status: str, cve_id: Optional[str] = None):
        """
        Update queue item status.
        
        If queue_id is None but cve_id is provided, create new queue item.
        """
        if not queue_id and not cve_id:
            logger.warning("Cannot update queue status: no queue_id or cve_id provided")
            return
        
        if queue_id:
            # Update existing queue item
            logger.info(f"Updating queue item {queue_id} status to '{status}'...")
            self.db.execute(
                "UPDATE cve_queue SET status = %s WHERE id = %s",
                (status, queue_id)
            )
            logger.info(f"Queue item {queue_id} updated to '{status}'")
        elif cve_id:
            # Create new queue item
            logger.info(f"Creating new queue item for {cve_id} with status '{status}'...")
            result = self.db.execute(
                """
                INSERT INTO cve_queue (cve_id, status, priority, retry_count)
                VALUES (%s, %s, %s, %s)
                RETURNING id
                """,
                (cve_id, status, 5, 0)
            )
            queue_id = result[0]['id'] if result else None
            logger.info(f"Created queue item ID: {queue_id}")
    
    def seed_queue_from_discovery(self) -> Optional[Dict]:
        """
        Seed queue from discovery if empty.
        
        Returns:
            Dictionary with cve_id for newly queued CVE, or None if no eligible CVE
        """
        logger.info("Seeding queue from discovery...")
        
        # Get CVEs from discovery that don't have approved playbooks
        eligible_cves = self.db.fetch_all(
            """
            SELECT cs.cve_id, cs.created_at
            FROM cve_context_snapshot cs
            LEFT JOIN (
                SELECT gr.cve_id
                FROM approved_playbooks ap
                JOIN generation_runs gr ON ap.generation_run_id = gr.id
            ) ap ON cs.cve_id = ap.cve_id
            LEFT JOIN cve_queue cq ON cs.cve_id = cq.cve_id
            WHERE ap.cve_id IS NULL  -- No approved playbook
            AND (cq.cve_id IS NULL OR cq.status NOT IN ('processing', 'completed'))
            ORDER BY cs.created_at DESC
            LIMIT 5
            """
        )
        
        if not eligible_cves:
            logger.warning("No eligible CVEs found in discovery")
            return None
        
        # Take the first eligible CVE
        cve_id = eligible_cves[0]['cve_id']
        logger.info(f"Selected CVE from discovery: {cve_id}")
        
        # Create queue item
        result = self.db.execute(
            """
            INSERT INTO cve_queue (cve_id, status, priority, retry_count)
            VALUES (%s, %s, %s, %s)
            RETURNING id
            """,
            (cve_id, 'pending', 5, 0)
        )
        
        queue_id = result[0]['id'] if result else None
        logger.info(f"Created queue item ID: {queue_id} for {cve_id}")
        
        return {'cve_id': cve_id, 'queue_id': queue_id}
    
    def check_context_readiness(self, cve_id: str, queue_id: Optional[int] = None) -> Tuple[str, Optional[int], Optional[Dict]]:
        """
        Check context readiness for CVE.
        
        Returns:
            Tuple of (readiness_status, context_snapshot_id, context_data)
            readiness_status: 'ready', 'auto_built', 'blocked_missing_context'
        """
        logger.info(f"Checking context readiness for {cve_id}...")
        
        # Run context builder script
        context_builder_script = Path(__file__).parent / "02_85_build_context_snapshot_v0_1_0.py"
        
        if not context_builder_script.exists():
            logger.error(f"Context builder script not found: {context_builder_script}")
            return 'blocked_missing_context', None, None
        
        try:
            # Run as subprocess to get JSON output
            cmd = [sys.executable, str(context_builder_script), '--cve', cve_id, '--json']
            logger.info(f"Executing context builder: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60  # 1 minute timeout
            )
            
            if result.returncode == 0:
                try:
                    json_output = json.loads(result.stdout.strip())
                    readiness_status = json_output.get('readiness_status', 'blocked_missing_context')
                    context_snapshot_id = json_output.get('context_snapshot_id')
                    context_data = json_output.get('context_data')
                    
                    logger.info(f"Context readiness: {readiness_status}")
                    if context_snapshot_id:
                        logger.info(f"Context snapshot ID: {context_snapshot_id}")
                    
                    return readiness_status, context_snapshot_id, context_data
                    
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse context builder JSON output: {e}")
                    return 'blocked_missing_context', None, None
            else:
                logger.error(f"Context builder failed with return code: {result.returncode}")
                if result.stderr:
                    logger.error(f"Context builder stderr: {result.stderr}")
                return 'blocked_missing_context', None, None
                
        except subprocess.TimeoutExpired:
            logger.error(f"Context builder timed out for {cve_id}")
            return 'blocked_missing_context', None, None
        except Exception as e:
            logger.error(f"Error running context builder: {e}")
            return 'blocked_missing_context', None, None
    
    def run_generation(self, cve_id: str, queue_id: Optional[int] = None) -> Tuple[bool, str]:
        """
        Run canonical generation script for CVE.
        
        Returns:
            Tuple of (success: bool, final_status: str)
        """
        logger.info(f"Running generation for {cve_id}...")
        
        # Update queue status to processing
        if queue_id:
            self.update_queue_status(queue_id, 'processing')
        
        # Run the canonical generation script
        generation_script = Path(__file__).parent / "03_01_run_playbook_generation_v0_1_1_real_retrieval.py"
        
        if not generation_script.exists():
            logger.error(f"Generation script not found: {generation_script}")
            return False, 'failed'
        
        try:
            # Run as subprocess to capture output
            cmd = [sys.executable, str(generation_script), '--cve', cve_id]
            logger.info(f"Executing: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            # Log output
            if result.stdout:
                logger.info(f"Generation stdout:\n{result.stdout}")
            if result.stderr:
                logger.warning(f"Generation stderr:\n{result.stderr}")
            
            # Check result
            if result.returncode == 0:
                # Check if generation was successful by looking for approved playbook
                approved = self.db.fetch_one(
                    """
                    SELECT ap.id 
                    FROM approved_playbooks ap
                    JOIN generation_runs gr ON ap.generation_run_id = gr.id
                    WHERE gr.cve_id = %s
                    """,
                    (cve_id,)
                )
                
                if approved:
                    logger.info(f"Generation successful - approved playbook ID: {approved['id']}")
                    return True, 'completed'
                else:
                    logger.warning(f"Generation completed but no approved playbook for {cve_id}")
                    return False, 'failed'
            else:
                logger.error(f"Generation failed with return code: {result.returncode}")
                return False, 'failed'
                
        except subprocess.TimeoutExpired:
            logger.error(f"Generation timed out for {cve_id}")
            return False, 'failed'
        except Exception as e:
            logger.error(f"Error running generation: {e}")
            return False, 'failed'
    
    def process_one_cve(self) -> bool:
        """
        Process exactly one CVE from queue or discovery.
        
        Returns:
            True if a CVE was processed (successfully or not), False if no CVE to process
        """
        logger.info("=" * 60)
        logger.info("QUEUE PROCESSOR - SINGLE CVE PROCESSING")
        logger.info("=" * 60)
        
        try:
            # Step 1: Assert database target
            self.assert_database_target()
            
            # Step 2: Run queue selector
            selector_result = self.run_queue_selector()
            
            if not selector_result:
                logger.info("No CVE from selector - attempting to seed from discovery")
                selector_result = self.seed_queue_from_discovery()
                
                if not selector_result:
                    logger.warning("No eligible CVEs found in discovery")
                    return False
            
            cve_id = selector_result['cve_id']
            queue_id = selector_result.get('queue_id')
            
            logger.info(f"Selected CVE: {cve_id} (queue_id: {queue_id})")
            
            # Step 3: Check idempotency
            if not self.check_idempotency(cve_id):
                logger.warning(f"CVE {cve_id} failed idempotency check - skipping")
                if queue_id:
                    self.update_queue_status(queue_id, 'skipped')
                return False
            
            # Step 4: Check context readiness
            readiness_status, context_snapshot_id, context_data = self.check_context_readiness(cve_id, queue_id)
            
            if readiness_status == 'blocked_missing_context':
                logger.error(f"Context blocked for {cve_id}: missing required context data")
                if queue_id:
                    self.update_queue_status(queue_id, 'blocked_missing_context')
                else:
                    self.update_queue_status(None, 'blocked_missing_context', cve_id)
                
                # Store results
                self.results = {
                    'cve_id': cve_id,
                    'queue_id': queue_id,
                    'success': False,
                    'final_status': 'blocked_missing_context',
                    'context_readiness': readiness_status,
                    'processed': True
                }
                
                logger.info("\n" + "=" * 60)
                logger.info("PROCESSING BLOCKED - MISSING CONTEXT")
                logger.info("-" * 60)
                logger.info(f"CVE ID: {cve_id}")
                logger.info(f"Queue ID: {queue_id}")
                logger.info(f"Context Readiness: {readiness_status}")
                logger.info("=" * 60)
                
                return True
            
            logger.info(f"Context ready for generation: {readiness_status}")
            if context_snapshot_id:
                logger.info(f"Using context snapshot ID: {context_snapshot_id}")
            
            # Step 5: Run generation
            success, final_status = self.run_generation(cve_id, queue_id)
            
            # Step 6: Update queue status based on result
            if queue_id:
                self.update_queue_status(queue_id, final_status)
            else:
                # Create queue item for tracking if not already exists
                self.update_queue_status(None, final_status, cve_id)
            
            # Store results
            self.results = {
                'cve_id': cve_id,
                'queue_id': queue_id,
                'success': success,
                'final_status': final_status,
                'context_readiness': readiness_status,
                'context_snapshot_id': context_snapshot_id,
                'processed': True
            }
            
            logger.info("\n" + "=" * 60)
            logger.info("PROCESSING COMPLETE")
            logger.info("-" * 60)
            logger.info(f"CVE ID: {cve_id}")
            logger.info(f"Queue ID: {queue_id}")
            logger.info(f"Context Readiness: {readiness_status}")
            if context_snapshot_id:
                logger.info(f"Context Snapshot ID: {context_snapshot_id}")
            logger.info(f"Success: {success}")
            logger.info(f"Final Status: {final_status}")
            logger.info("=" * 60)
            
            return True
            
        except Exception as e:
            logger.error(f"Processing failed: {e}")
            import traceback
            traceback.print_exc()
            return False


def main():
    """Main entry point."""
    processor = QueueProcessor()
    processed = processor.process_one_cve()
    
    if processed:
        logger.info("Successfully processed one CVE")
        sys.exit(0)
    else:
        logger.info("No CVE processed")
        sys.exit(1)


if __name__ == "__main__":
    main()