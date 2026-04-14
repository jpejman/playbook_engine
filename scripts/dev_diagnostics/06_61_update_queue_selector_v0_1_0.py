#!/usr/bin/env python3
"""
Queue Selector Update - Enhanced CVE Selection Policy
Version: v0.1.0
Timestamp: 2026-04-08

Purpose:
- Update queue selector to avoid re-processing same CVE
- Prefer new eligible CVEs when available
- Track most recently processed CVEs
"""

import os
import sys
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List, Set
from datetime import datetime, timedelta

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.db import get_database_client
from src.retrieval.vulnstrike_db_client import VulnstrikeDBClient

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class EnhancedQueueSelector:
    """Enhanced queue selector with new-CVE preference policy."""
    
    def __init__(self):
        self.db = get_database_client()
        self.vulnstrike_db = VulnstrikeDBClient()
        self.results = {
            "timestamp": datetime.utcnow().isoformat(),
            "selected": False,
            "selection_source": None,
            "queue_item": None,
            "selection_reason": None
        }
        
        logger.info("EnhancedQueueSelector initialized with new-CVE preference policy")
    
    def get_recently_processed_cves(self, limit: int = 5) -> Set[str]:
        """Get set of recently processed CVEs to avoid re-processing."""
        query = """
        SELECT gr.cve_id, MAX(gr.created_at) as last_processed
        FROM generation_runs gr
        GROUP BY gr.cve_id
        ORDER BY last_processed DESC
        LIMIT %s
        """
        
        results = self.db.fetch_all(query, (limit,))
        return {row['cve_id'] for row in results}
    
    def get_approved_cves(self) -> Set[str]:
        """Get set of CVEs with approved playbooks."""
        query = """
        SELECT DISTINCT gr.cve_id
        FROM approved_playbooks ap
        JOIN generation_runs gr ON ap.generation_run_id = gr.id
        """
        
        results = self.db.fetch_all(query)
        return {row['cve_id'] for row in results}
    
    def check_cve_eligible(self, cve_id: str) -> Dict[str, Any]:
        """Check if CVE is eligible for processing."""
        approved_cves = self.get_approved_cves()
        recently_processed = self.get_recently_processed_cves()
        
        eligibility = {
            "cve_id": cve_id,
            "has_approved_playbook": cve_id in approved_cves,
            "recently_processed": cve_id in recently_processed,
            "eligible": True,
            "reasons": []
        }
        
        if eligibility["has_approved_playbook"]:
            eligibility["eligible"] = False
            eligibility["reasons"].append("already_approved")
        
        if eligibility["recently_processed"]:
            eligibility["eligible"] = False
            eligibility["reasons"].append("recently_processed")
        
        return eligibility
    
    def find_eligible_queue_item(self) -> Optional[Dict[str, Any]]:
        """
        Find eligible queue item with new-CVE preference.
        
        Selection priority:
        1. Pending items for CVEs never processed before
        2. Pending items for CVEs not recently processed
        3. Failed/retry items for new CVEs
        4. Failed/retry items for recently processed CVEs (last resort)
        """
        logger.info("Looking for eligible queue items with new-CVE preference...")
        
        # Get recently processed CVEs to avoid
        recently_processed = self.get_recently_processed_cves()
        approved_cves = self.get_approved_cves()
        
        # Query all candidate queue items
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
            q.created_at ASC
        LIMIT 20
        """
        
        candidates = self.db.fetch_all(query)
        logger.info(f"Found {len(candidates)} candidate queue items")
        
        # Categorize candidates
        new_cve_candidates = []
        recent_cve_candidates = []
        approved_cve_candidates = []
        
        for candidate in candidates:
            cve_id = candidate['cve_id']
            
            if cve_id in approved_cves:
                approved_cve_candidates.append(candidate)
            elif cve_id in recently_processed:
                recent_cve_candidates.append(candidate)
            else:
                new_cve_candidates.append(candidate)
        
        logger.info(f"Categorized: {len(new_cve_candidates)} new CVEs, "
                   f"{len(recent_cve_candidates)} recently processed, "
                   f"{len(approved_cve_candidates)} already approved")
        
        # Selection priority: new CVEs first
        for candidate in new_cve_candidates:
            cve_id = candidate['cve_id']
            logger.info(f"Found new CVE candidate: {cve_id}")
            return candidate
        
        # If no new CVEs, check recently processed (but avoid if other options exist)
        if len(recent_cve_candidates) > 0 and len(new_cve_candidates) == 0:
            logger.warning("No new CVEs available, considering recently processed CVEs")
            # Check if we should discover new CVEs instead
            new_cve_from_discovery = self.discover_missing_playbook_cve(exclude=recently_processed)
            if new_cve_from_discovery:
                logger.info(f"Discovered new CVE instead of re-processing: {new_cve_from_discovery}")
                return None  # Signal to seed new CVE
            
            # Last resort: use recently processed CVE
            candidate = recent_cve_candidates[0]
            logger.warning(f"Using recently processed CVE as last resort: {candidate['cve_id']}")
            return candidate
        
        # Mark approved CVEs as completed
        for candidate in approved_cve_candidates:
            self._mark_queue_completed(candidate['id'], "already_approved")
        
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
    
    def discover_missing_playbook_cve(self, exclude: Optional[Set[str]] = None) -> Optional[str]:
        """Discover one CVE missing approved playbook, excluding specified CVEs."""
        logger.info("Discovering CVEs missing approved playbooks (with exclusion)...")
        
        if exclude is None:
            exclude = set()
        
        try:
            # Get CVEs with approved playbooks
            approved_cves = self.get_approved_cves()
            all_excluded = approved_cves.union(exclude)
            
            logger.info(f"Excluding {len(all_excluded)} CVEs (approved: {len(approved_cves)}, "
                       f"recently processed: {len(exclude)})")
            
            # Get recent CVEs from vulnstrike
            with self.vulnstrike_db._create_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT cve_id, published, description
                        FROM nvd_cve_data
                        WHERE published >= '2025-01-01'
                        ORDER BY published DESC
                        LIMIT 30
                    """)
                    recent_cves = cur.fetchall()
            
            logger.info(f"Found {len(recent_cves)} recent CVEs from vulnstrike")
            
            # Find first CVE without approved playbook and not excluded
            for cve_row in recent_cves:
                cve_id = cve_row[0]
                if cve_id not in all_excluded:
                    logger.info(f"Found eligible CVE: {cve_id}")
                    return cve_id
            
            logger.warning("No eligible CVEs found (all excluded or already approved)")
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
                # Update status to pending if not already
                if existing['status'] != 'pending':
                    self.db.execute(
                        "UPDATE cve_queue SET status = 'pending', updated_at = NOW() WHERE id = %s",
                        (existing['id'],)
                    )
                return existing['id']
            
            # Insert new queue item
            query = """
            INSERT INTO cve_queue (cve_id, status, priority, created_at, updated_at)
            VALUES (%s, 'pending', 5, NOW(), NOW())
            RETURNING id
            """
            
            try:
                # Use a transaction for INSERT ... RETURNING
                conn = self.db.begin_transaction()
                with conn.cursor() as cursor:
                    cursor.execute(query, (cve_id,))
                    result = cursor.fetchone()
                    conn.commit()
                    
                if result and len(result) > 0:
                    queue_id = result[0]
                    logger.info(f"Inserted queue item ID: {queue_id} for CVE: {cve_id}")
                    return queue_id
                else:
                    logger.error(f"INSERT succeeded but no ID returned for CVE: {cve_id}")
                    logger.error(f"Result: {result}")
                    return None
            except Exception as e:
                logger.error(f"INSERT failed for CVE {cve_id}: {e}")
                return None
                
        except Exception as e:
            logger.error(f"Failed to seed queue with CVE {cve_id}: {e}")
            return None
    
    def select_next_cve(self) -> Optional[Dict[str, Any]]:
        """
        Select next CVE for processing with new-CVE preference.
        
        Returns:
            Dict with queue item info or None if no eligible CVE
        """
        logger.info("ENHANCED SELECT NEXT CVE FROM QUEUE")
        logger.info("=" * 60)
        
        # Step 1: Check for eligible queue items with new-CVE preference
        queue_item = self.find_eligible_queue_item()
        
        if queue_item:
            self.results["selected"] = True
            self.results["selection_source"] = "existing_queue"
            self.results["queue_item"] = queue_item
            self.results["selection_reason"] = "new_cve_preferred" if queue_item['cve_id'] not in self.get_recently_processed_cves() else "recent_cve_fallback"
            
            logger.info(f"Selected from queue: ID={queue_item['id']}, CVE={queue_item['cve_id']}")
            logger.info(f"Selection reason: {self.results['selection_reason']}")
            return queue_item
        
        # Step 2: Queue has no eligible items, discover and seed NEW CVE
        logger.info("No eligible queue items found, discovering NEW missing-playbook CVE...")
        
        # Get recently processed to exclude
        recently_processed = self.get_recently_processed_cves()
        cve_id = self.discover_missing_playbook_cve(exclude=recently_processed)
        
        if not cve_id:
            logger.error("No NEW CVEs available for processing (all excluded or already approved)")
            self.results["selected"] = False
            self.results["selection_source"] = "no_new_cves_available"
            self.results["selection_reason"] = "all_cves_excluded_or_approved"
            return None
        
        # Step 3: Seed queue with discovered NEW CVE
        queue_id = self.seed_queue_with_cve(cve_id)
        
        if not queue_id:
            logger.error(f"Failed to seed queue with NEW CVE: {cve_id}")
            self.results["selected"] = False
            self.results["selection_source"] = "seed_failed"
            self.results["selection_reason"] = "queue_insert_failed"
            return None
        
        # Step 4: Get the newly seeded queue item
        # Need to use a fresh connection to see the committed insert
        queue_item = self.db.fetch_one(
            "SELECT id, cve_id, status, priority, created_at FROM cve_queue WHERE id = %s",
            (queue_id,)
        )
        
        if queue_item:
            self.results["selected"] = True
            self.results["selection_source"] = "seeded_new_from_discovery"
            self.results["queue_item"] = queue_item
            self.results["selection_reason"] = "new_cve_discovered"
            
            logger.info(f"Selected NEW CVE from discovery: ID={queue_item['id']}, CVE={queue_item['cve_id']}")
            logger.info(f"Selection reason: {self.results['selection_reason']}")
            return queue_item
        else:
            logger.error(f"Failed to retrieve seeded queue item ID: {queue_id}")
            self.results["selected"] = False
            self.results["selection_source"] = "retrieve_failed"
            self.results["selection_reason"] = "queue_retrieve_failed"
            return None
    
    def print_summary(self):
        """Print selection summary."""
        print("\n" + "=" * 80)
        print("ENHANCED QUEUE SELECTOR - SUMMARY")
        print("=" * 80)
        print(f"Timestamp: {self.results['timestamp']}")
        print(f"Selected: {self.results['selected']}")
        print(f"Selection Source: {self.results['selection_source']}")
        print(f"Selection Reason: {self.results['selection_reason']}")
        
        if self.results['queue_item']:
            item = self.results['queue_item']
            print(f"\nSelected Queue Item:")
            print(f"  Queue ID: {item['id']}")
            print(f"  CVE ID: {item['cve_id']}")
            print(f"  Status: {item['status']}")
            print(f"  Priority: {item.get('priority', 'N/A')}")
            print(f"  Created At: {item.get('created_at', 'N/A')}")
            
            # Check eligibility
            eligibility = self.check_cve_eligible(item['cve_id'])
            print(f"  Has Approved Playbook: {eligibility['has_approved_playbook']}")
            print(f"  Recently Processed: {eligibility['recently_processed']}")
            print(f"  Eligible: {eligibility['eligible']}")
            if eligibility['reasons']:
                print(f"  Eligibility Reasons: {', '.join(eligibility['reasons'])}")
        else:
            print("\nNo queue item selected")
        
        # Show recently processed CVEs
        recently_processed = self.get_recently_processed_cves()
        print(f"\nRecently Processed CVEs (to avoid): {len(recently_processed)}")
        if recently_processed:
            for i, cve in enumerate(list(recently_processed)[:5]):
                print(f"  {i+1}. {cve}")
            if len(recently_processed) > 5:
                print(f"  ... and {len(recently_processed) - 5} more")
        
        print("=" * 80)
    
    def get_output_json(self) -> Dict[str, Any]:
        """Get output in required JSON shape."""
        if not self.results['queue_item']:
            return {
                "selected": False,
                "reason": self.results['selection_reason'],
                "source": self.results['selection_source']
            }
        
        item = self.results['queue_item']
        eligibility = self.check_cve_eligible(item['cve_id'])
        
        return {
            "queue_id": item['id'],
            "cve_id": item['cve_id'],
            "status": item['status'],
            "eligible": eligibility['eligible'],
            "is_new_cve": not eligibility['recently_processed'],
            "selection_reason": self.results['selection_reason'],
            "selection_source": self.results['selection_source']
        }


def main():
    """Main execution function."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Enhanced queue selector with new-CVE preference')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('--json', action='store_true', help='Output JSON only')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Run enhanced selector
    selector = EnhancedQueueSelector()
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