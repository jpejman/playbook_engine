#!/usr/bin/env python3
"""
Playbook Engine - CVE Discovery Script
Version: v0.1.0
Timestamp: 2026-04-08

Purpose:
- Discover CVEs that are missing approved playbooks
- Query vulnstrike.nvd_cve_data for source CVEs
- Compare against playbook_engine.approved_playbooks (via generation_runs)
- Output structured list of missing CVEs

Design Rules:
- Discovery is separate from generation
- No generation logic in this script
- Output structured JSON for downstream consumption
"""

import os
import sys
import json
import argparse
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.retrieval.vulnstrike_db_client import get_vulnstrike_db_client
from src.utils.db import get_database_client

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class MissingPlaybookDiscoverer:
    """Discover CVEs missing approved playbooks."""
    
    def __init__(self):
        self.vulnstrike_client = get_vulnstrike_db_client()
        self.playbook_client = get_database_client()
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "source_table": "nvd_cve_data",
            "candidates": []
        }
        
        logger.info("MissingPlaybookDiscoverer initialized")
    
    def assert_database_targets(self):
        """Assert connected to correct databases."""
        logger.info("Verifying database targets...")
        
        # Verify vulnstrike database
        self.vulnstrike_client.assert_database_target()
        
        # Verify playbook_engine database
        from src.utils.db import assert_expected_database
        assert_expected_database('playbook_engine')
        
        logger.info("Database targets verified")
    
    def get_cves_with_approved_playbooks(self) -> List[str]:
        """Get list of CVEs that already have approved playbooks."""
        logger.info("Querying CVEs with approved playbooks...")
        
        with self.playbook_client.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT DISTINCT gr.cve_id
                    FROM generation_runs gr
                    JOIN approved_playbooks ap ON gr.id = ap.generation_run_id
                    WHERE ap.id IS NOT NULL
                """)
                results = cur.fetchall()
                cves_with_playbooks = [row[0] for row in results]
                
                logger.info(f"Found {len(cves_with_playbooks)} CVEs with approved playbooks")
                return cves_with_playbooks
    
    def get_cves_from_source_table(self, limit: Optional[int] = None, 
                                  cve_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get CVEs from source table (nvd_cve_data).
        
        Args:
            limit: Maximum number of CVEs to return
            cve_id: Optional specific CVE to query
            
        Returns:
            List of CVE records with id, severity, etc.
        """
        logger.info(f"Querying source CVEs from nvd_cve_data (limit: {limit}, cve: {cve_id})...")
        
        with self.vulnstrike_client._create_connection() as conn:
            with conn.cursor() as cur:
                # Build query - get basic fields first, we'll extract severity later
                # Use single line to avoid %s formatting issues
                # Note: Use %% to escape percent sign in LIKE clause
                query = "SELECT cve_id, published, description, metrics, vuln_status FROM nvd_cve_data WHERE description IS NOT NULL AND description NOT LIKE 'Rejected reason:%%'"
                
                params = []
                
                # Add CVE filter if specified
                if cve_id:
                    query += " AND cve_id = %s"
                    params.append(cve_id)
                
                # Add ordering and limit
                query += " ORDER BY published DESC"
                if limit:
                    query += " LIMIT %s"
                    params.append(limit)
                
                logger.debug(f"Executing query: {query}")
                logger.debug(f"With params: {params}")
                cur.execute(query, tuple(params))
                results = cur.fetchall()
                
                # Convert to structured format
                cves = []
                for row in results:
                    # Extract severity from metrics JSON
                    cvss_score = 0.0
                    severity = "UNKNOWN"
                    metrics = row[3]
                    
                    if metrics:
                        try:
                            import json
                            if isinstance(metrics, str):
                                metrics_data = json.loads(metrics)
                            else:
                                metrics_data = metrics
                            
                            # Try to extract from cvssMetricV31 first
                            if 'cvssMetricV31' in metrics_data and metrics_data['cvssMetricV31']:
                                cvss_data = metrics_data['cvssMetricV31'][0].get('cvssData', {})
                                cvss_score = float(cvss_data.get('baseScore', 0.0))
                                severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                            # Fall back to cvssMetricV30
                            elif 'cvssMetricV30' in metrics_data and metrics_data['cvssMetricV30']:
                                cvss_data = metrics_data['cvssMetricV30'][0].get('cvssData', {})
                                cvss_score = float(cvss_data.get('baseScore', 0.0))
                                severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                            # Fall back to cvssMetricV2
                            elif 'cvssMetricV2' in metrics_data and metrics_data['cvssMetricV2']:
                                cvss_data = metrics_data['cvssMetricV2'][0].get('cvssData', {})
                                cvss_score = float(cvss_data.get('baseScore', 0.0))
                                # V2 doesn't have baseSeverity, calculate from score
                                if cvss_score >= 9.0:
                                    severity = "CRITICAL"
                                elif cvss_score >= 7.0:
                                    severity = "HIGH"
                                elif cvss_score >= 4.0:
                                    severity = "MEDIUM"
                                elif cvss_score > 0:
                                    severity = "LOW"
                        except Exception as e:
                            logger.debug(f"Failed to extract severity for {row[0]}: {e}")
                    
                    cve = {
                        "cve_id": row[0],
                        "published": row[1].isoformat() if row[1] else None,
                        "description": row[2][:200] + "..." if row[2] and len(row[2]) > 200 else row[2],
                        "cvss_score": cvss_score,
                        "severity": severity,
                        "vuln_status": row[4] or "UNKNOWN",
                        "source_table": "nvd_cve_data",
                        "has_playbook": False  # Will be updated later
                    }
                    cves.append(cve)
                
                logger.info(f"Found {len(cves)} CVEs from source table")
                return cves
    
    def discover_missing_playbooks(self, limit: Optional[int] = None, 
                                  cve_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Discover CVEs missing approved playbooks.
        
        Args:
            limit: Maximum number of CVEs to check
            cve_id: Optional specific CVE to check
            
        Returns:
            List of CVEs missing playbooks
        """
        logger.info("Starting missing-playbook discovery...")
        
        # Step 1: Get CVEs with approved playbooks
        cves_with_playbooks = self.get_cves_with_approved_playbooks()
        
        # Step 2: Get CVEs from source table
        source_cves = self.get_cves_from_source_table(limit, cve_id)
        
        # Step 3: Identify missing playbooks
        missing_cves = []
        for cve in source_cves:
            cve_id_str = cve["cve_id"]
            has_playbook = cve_id_str in cves_with_playbooks
            
            if not has_playbook:
                cve["has_playbook"] = False
                missing_cves.append(cve)
            else:
                cve["has_playbook"] = True
                logger.debug(f"CVE {cve_id_str} already has approved playbook")
        
        logger.info(f"Found {len(missing_cves)} CVEs missing approved playbooks")
        
        # Store results
        self.results["candidates"] = missing_cves
        self.results["total_candidates"] = len(missing_cves)
        self.results["cves_with_playbooks"] = cves_with_playbooks
        self.results["source_cves_checked"] = len(source_cves)
        
        return missing_cves
    
    def print_results(self, output_json: Optional[str] = None):
        """Print discovery results."""
        candidates = self.results["candidates"]
        
        if not candidates:
            logger.warning("No missing-playbook CVEs found")
            print("\nNo CVEs missing approved playbooks found.")
            return
        
        print("\n" + "=" * 80)
        print("MISSING PLAYBOOK DISCOVERY RESULTS")
        print("=" * 80)
        print(f"Source Table: {self.results['source_table']}")
        print(f"Timestamp: {self.results['timestamp']}")
        print(f"Total Candidates: {self.results['total_candidates']}")
        print(f"CVEs With Playbooks: {len(self.results['cves_with_playbooks'])}")
        print(f"Source CVEs Checked: {self.results['source_cves_checked']}")
        print("-" * 80)
        
        # Print top candidates
        print("\nTop Missing CVEs:")
        for i, cve in enumerate(candidates[:10], 1):
            print(f"{i:2}. {cve['cve_id']:20} | {cve['severity']:8} | "
                  f"CVSS: {cve['cvss_score']:.1f} | Published: {cve['published'][:10] if cve['published'] else 'N/A'}")
            if cve.get('description'):
                desc = cve['description']
                if len(desc) > 100:
                    desc = desc[:97] + "..."
                print(f"   {desc}")
        
        if len(candidates) > 10:
            print(f"\n... and {len(candidates) - 10} more")
        
        print("=" * 80)
        
        # Save to JSON if requested
        if output_json:
            output_path = Path(output_json)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, default=str)
            
            logger.info(f"Results saved to {output_path}")
            print(f"\nJSON output saved to: {output_path}")
    
    def run_discovery(self, limit: Optional[int] = None, 
                     cve_id: Optional[str] = None,
                     output_json: Optional[str] = None) -> bool:
        """Run complete discovery workflow."""
        logger.info("PLAYBOOK ENGINE - MISSING PLAYBOOK DISCOVERY")
        logger.info("=" * 60)
        
        try:
            # Step 1: Assert database targets
            self.assert_database_targets()
            
            # Step 2: Run discovery
            missing_cves = self.discover_missing_playbooks(limit, cve_id)
            
            # Step 3: Print results
            self.print_results(output_json)
            
            # Step 4: Return success status
            success = len(missing_cves) > 0
            if success:
                logger.info(f"Discovery successful: found {len(missing_cves)} missing CVEs")
            else:
                logger.warning("Discovery completed but found no missing CVEs")
            
            return success
            
        except Exception as e:
            logger.error(f"Discovery failed: {e}")
            import traceback
            traceback.print_exc()
            return False


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(description='Discover CVEs missing approved playbooks')
    parser.add_argument('--limit', type=int, default=100, 
                       help='Maximum number of CVEs to check (default: 100)')
    parser.add_argument('--cve', type=str, 
                       help='Check specific CVE ID instead of discovering')
    parser.add_argument('--output-json', type=str,
                       help='Save results to JSON file')
    parser.add_argument('--verbose', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Run discovery
    discoverer = MissingPlaybookDiscoverer()
    success = discoverer.run_discovery(
        limit=args.limit,
        cve_id=args.cve,
        output_json=args.output_json
    )
    
    if success:
        logger.info("\nDiscovery completed successfully")
        sys.exit(0)
    else:
        logger.error("\nDiscovery failed or found no missing CVEs")
        sys.exit(1)


if __name__ == "__main__":
    main()