#!/usr/bin/env python3
"""
Queue Selector - Select next CVE from queue for processing.
Version: v0.1.0
Timestamp: 2026-04-08

Purpose:
- Select exactly one eligible CVE for processing
- Priority: queue rows already marked pending and missing playbooks
- If queue is empty, seed one pending candidate from discovery
- Select deterministically (oldest pending first, or lowest id first)
- No generation logic in this script
"""

import os
import sys
import json
import logging
import argparse
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.db import get_database_client
from src.retrieval.vulnstrike_db_client import VulnstrikeDBClient

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class QueueSelector:
    """Select next CVE from queue for processing."""
    
    def __init__(self):
        self.db = get_database_client()
        self.vulnstrike_db = VulnstrikeDBClient()
        self.results = {
            "timestamp": datetime.utcnow().isoformat(),
            "selected": False,
            "selection_source": None,
            "queue_item": None
        }
        
        logger.info("QueueSelector initialized")
    
    def check_cve_has_approved_playbook(self, cve_id: str) -> bool:
        """Check if CVE already has an approved playbook."""
        query = """
        SELECT ap.id
        FROM approved_playbooks ap
        JOIN generation_runs gr ON ap.generation_run_id = gr.id
        WHERE gr.cve_id = %s
        LIMIT 1
        """
        
        result = self.db.fetch_one(query, (cve_id,))
        return result is not None
    
    def find_eligible_queue_item(self) -> Optional[Dict[str, Any]]:
        """
        Find eligible queue item (pending, failed, retry status).
        
        Returns:
            Queue item dict or None if no eligible items
        """
        logger.info("Looking for eligible queue items...")
        
        # First, check for pending items that don't have approved playbooks
        query = """
        SELECT q.id, q.cve_id, q.status, q.priority, q.created_at
        FROM cve_queue q
        WHERE q.status IN ('pending', 'failed', 'retry')
        ORDER BY 
            CASE q.status 
                WHEN 'pending' THEN 1
                WHEN 'failed' THEN 2
                WHEN 'retry' THEN 3
            END,
            q.priority ASC,
            q.created_at ASC,
            q.id ASC
        LIMIT 10
        """
        
        candidates = self.db.fetch_all(query)
        logger.info(f"Found {len(candidates)} candidate queue items")
        
        for candidate in candidates:
            cve_id = candidate['cve_id']
            queue_id = candidate['id']
            status = candidate['status']
            
            # Check if CVE already has approved playbook
            if self.check_cve_has_approved_playbook(cve_id):
                logger.info(f"Queue item {queue_id} (CVE: {cve_id}) already has approved playbook - marking as completed")
                self._mark_queue_completed(queue_id, "already_approved")
                continue
            
            logger.info(f"Found eligible queue item: ID={queue_id}, CVE={cve_id}, status={status}")
            return candidate
        
        return None
    
    def _mark_queue_completed(self, queue_id: int, reason: str):
        """Mark queue item as completed with reason."""
        try:
            self.db.execute(
                "UPDATE cve_queue SET status = 'completed', updated_at = NOW() WHERE id = %s",
                (queue_id,)
            )
            logger.info(f"Marked queue item {queue_id} as completed (reason: {reason})")
        except Exception as e:
            logger.error(f"Failed to mark queue item {queue_id} as completed: {e}")
    
    def discover_missing_playbook_cve(self) -> Optional[str]:
        """Discover one CVE missing approved playbook from vulnstrike database."""
        logger.info("Discovering CVEs missing approved playbooks...")
        
        try:
            # Get CVEs with approved playbooks
            approved_cves_query = """
            SELECT DISTINCT gr.cve_id
            FROM approved_playbooks ap
            JOIN generation_runs gr ON ap.generation_run_id = gr.id
            """
            approved_cves = self.db.fetch_all(approved_cves_query)
            approved_cve_ids = {row['cve_id'] for row in approved_cves}
            logger.info(f"Found {len(approved_cve_ids)} CVEs with approved playbooks")
            
            # Get recent CVEs from vulnstrike
            with self.vulnstrike_db._create_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT cve_id, published, description
                        FROM nvd_cve_data
                        WHERE published >= '2025-01-01'
                        ORDER BY published DESC
                        LIMIT 20
                    """)
                    recent_cves = cur.fetchall()
            
            logger.info(f"Found {len(recent_cves)} recent CVEs from vulnstrike")
            
            # Find first CVE without approved playbook
            for cve_row in recent_cves:
                cve_id = cve_row[0]
                if cve_id not in approved_cve_ids:
                    logger.info(f"Found CVE without approved playbook: {cve_id}")
                    return cve_id
            
            logger.warning("No CVEs found without approved playbooks")
            return None
            
        except Exception as e:
            logger.error(f"Failed to discover missing playbook CVE: {e}")
            return None
    
    def seed_queue_with_cve(self, cve_id: str) -> Optional[int]:
        """Seed queue with a CVE if not already present."""
        logger.info(f"Seeding queue with CVE: {cve_id}")
        
        try:
            # Check if CVE already in queue
            existing = self.db.fetch_one(
                "SELECT id, status FROM cve_queue WHERE cve_id = %s",
                (cve_id,)
            )
            
            if existing:
                logger.info(f"CVE {cve_id} already in queue (ID: {existing['id']}, status: {existing['status']})")
                return existing['id']
            
            # Insert new queue item
            query = """
            INSERT INTO cve_queue (cve_id, status, priority, created_at, updated_at)
            VALUES (%s, 'pending', 5, NOW(), NOW())
            RETURNING id
            """
            
            result = self.db.execute(query, (cve_id,), fetch=True)
            if result and len(result) > 0 and 'id' in result[0]:
                queue_id = result[0]['id']
                logger.info(f"Inserted queue item ID: {queue_id} for CVE: {cve_id}")
                return queue_id
            else:
                logger.error(f"Failed to insert queue item for CVE: {cve_id}")
                return None
                
        except Exception as e:
            logger.error(f"Failed to seed queue with CVE {cve_id}: {e}")
            return None
    
    def select_next_cve(self) -> Optional[Dict[str, Any]]:
        """
        Select next CVE for processing.
        
        Returns:
            Dict with queue item info or None if no eligible CVE
        """
        logger.info("SELECT NEXT CVE FROM QUEUE")
        logger.info("=" * 60)
        
        # Step 1: Check for eligible queue items
        queue_item = self.find_eligible_queue_item()
        
        if queue_item:
            self.results["selected"] = True
            self.results["selection_source"] = "existing_queue"
            self.results["queue_item"] = queue_item
            logger.info(f"Selected from existing queue: ID={queue_item['id']}, CVE={queue_item['cve_id']}")
            return queue_item
        
        # Step 2: Queue is empty, discover and seed one CVE
        logger.info("No eligible queue items found, discovering missing-playbook CVE...")
        cve_id = self.discover_missing_playbook_cve()
        
        if not cve_id:
            logger.error("No CVEs available for processing")
            self.results["selected"] = False
            self.results["selection_source"] = "no_cves_available"
            return None
        
        # Step 3: Seed queue with discovered CVE
        queue_id = self.seed_queue_with_cve(cve_id)
        
        if not queue_id:
            logger.error(f"Failed to seed queue with CVE: {cve_id}")
            self.results["selected"] = False
            self.results["selection_source"] = "seed_failed"
            return None
        
        # Step 4: Get the newly seeded queue item
        queue_item = self.db.fetch_one(
            "SELECT id, cve_id, status, priority, created_at FROM cve_queue WHERE id = %s",
            (queue_id,)
        )
        
        if queue_item:
            self.results["selected"] = True
            self.results["selection_source"] = "seeded_from_discovery"
            self.results["queue_item"] = queue_item
            logger.info(f"Selected from seeded queue: ID={queue_item['id']}, CVE={queue_item['cve_id']}")
            return queue_item
        else:
            logger.error(f"Failed to retrieve seeded queue item ID: {queue_id}")
            self.results["selected"] = False
            self.results["selection_source"] = "retrieve_failed"
            return None
    
    def print_summary(self):
        """Print selection summary."""
        print("\n" + "=" * 80)
        print("QUEUE SELECTOR - SUMMARY")
        print("=" * 80)
        print(f"Timestamp: {self.results['timestamp']}")
        print(f"Selected: {self.results['selected']}")
        print(f"Selection Source: {self.results['selection_source']}")
        
        if self.results['queue_item']:
            item = self.results['queue_item']
            print(f"\nSelected Queue Item:")
            print(f"  Queue ID: {item['id']}")
            print(f"  CVE ID: {item['cve_id']}")
            print(f"  Status: {item['status']}")
            print(f"  Priority: {item.get('priority', 'N/A')}")
            print(f"  Created At: {item.get('created_at', 'N/A')}")
            
            # Check eligibility
            has_playbook = self.check_cve_has_approved_playbook(item['cve_id'])
            print(f"  Has Approved Playbook: {has_playbook}")
            print(f"  Eligible: {not has_playbook}")
        else:
            print("\nNo queue item selected")
        
        print("=" * 80)
    
    def get_output_json(self) -> Dict[str, Any]:
        """Get output in required JSON shape."""
        if not self.results['queue_item']:
            return {
                "selected": False,
                "reason": self.results['selection_source']
            }
        
        item = self.results['queue_item']
        has_playbook = self.check_cve_has_approved_playbook(item['cve_id'])
        
        return {
            "queue_id": item['id'],
            "cve_id": item['cve_id'],
            "status": item['status'],
            "eligible": not has_playbook,
            "reason": "missing approved playbook" if not has_playbook else "already approved"
        }


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(description='Select next CVE from queue for processing')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('--json', action='store_true', help='Output JSON only')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Run selector
    selector = QueueSelector()
    selected_item = selector.select_next_cve()
    
    if args.json:
        # Output JSON only
        output = selector.get_output_json()
        print(json.dumps(output, indent=2))
    else:
        # Print summary
        selector.print_summary()
    
    # Exit code based on selection success
    if selected_item:
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()