#!/usr/bin/env python3
"""
VS.ai — Playbook Engine Gen-3
OpenSearch-First Production Selector
Version: v1.0.0
Timestamp (UTC): 2026-04-10

Purpose:
- Select CVEs from OpenSearch NVD index first (primary source)
- Use PostgreSQL only for filtering/state checks
- Implement required flow: OpenSearch → PostgreSQL filter → fresh CVE

Required Flow:
1. Query OpenSearch NVD index for candidate CVEs
2. Return CVE IDs plus basic metadata
3. Filter each candidate against PostgreSQL
4. Select one fresh eligible CVE
5. Output chosen CVE and filtering reasons
"""

import sys
import json
import argparse
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.retrieval.opensearch_client import RealOpenSearchClient
from src.utils.db import DatabaseClient
from scripts.prod.time_utils import get_utc_now, datetime_to_iso

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class OpenSearchFirstSelector:
    """OpenSearch-first CVE selector for production."""
    
    def __init__(self):
        self.opensearch_client = RealOpenSearchClient()
        self.db = DatabaseClient()
        self.results = {
            "timestamp_utc": datetime_to_iso(get_utc_now()),
            "selected_cve": None,
            "source_of_selection": "OpenSearch NVD",
            "number_of_candidates_returned_from_opensearch": 0,
            "number_filtered_out_by_postgres": 0,
            "reason_selected": [],
            "candidates_from_opensearch": [],
            "filtered_candidates": [],
            "eligible_candidates": []
        }
        
        logger.info("OpenSearchFirstSelector initialized")
    
    def query_opensearch_nvd(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Query OpenSearch NVD index for candidate CVEs.
        
        Args:
            limit: Maximum number of CVEs to return
            
        Returns:
            List of CVE candidates with basic metadata
        """
        logger.info(f"Querying OpenSearch NVD index for candidate CVEs (limit: {limit})...")
        
        try:
            # Query OpenSearch for recent CVEs from NVD index
            # The 'cve' index has CVE IDs as document _id field
            query = {
                "query": {
                    "match_all": {}
                },
                "sort": [
                    {"_id": {"order": "desc"}}  # Sort by CVE ID (newer CVEs have higher numbers)
                ],
                "size": limit,
                "_source": True  # Get all available source fields
            }
            
            # Execute search on 'cve' index
            response = self.opensearch_client.client.search(
                index="cve",
                body=query
            )
            
            hits = response.get('hits', {}).get('hits', [])
            candidates = []
            
            for hit in hits:
                # CVE ID is the document _id in the 'cve' index
                cve_id = hit.get('_id', '')
                if not cve_id or not cve_id.startswith('CVE-'):
                    continue  # Skip non-CVE documents
                    
                source = hit.get('_source', {})
                # Extract data from the CVE document structure
                cve_id_from_source = source.get('id', cve_id)
                
                # Extract description from descriptions array
                description = ''
                descriptions = source.get('descriptions', [])
                if descriptions and len(descriptions) > 0:
                    description = descriptions[0].get('value', '')
                
                # Extract CVSS score from metrics
                cvss_score = 0.0
                metrics = source.get('metrics', {})
                if 'cvssMetricV40' in metrics and metrics['cvssMetricV40']:
                    cvss_data = metrics['cvssMetricV40'][0].get('cvssData', {})
                    cvss_score = float(cvss_data.get('baseScore', 0.0))
                elif 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                    cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
                    cvss_score = float(cvss_data.get('baseScore', 0.0))
                elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                    cvss_data = metrics['cvssMetricV30'][0].get('cvssData', {})
                    cvss_score = float(cvss_data.get('baseScore', 0.0))
                elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                    cvss_data = metrics['cvssMetricV2'][0].get('cvssData', {})
                    cvss_score = float(cvss_data.get('baseScore', 0.0))
                
                # Extract severity from CVSS data or calculate from score
                severity = 'UNKNOWN'
                if cvss_score >= 9.0:
                    severity = 'CRITICAL'
                elif cvss_score >= 7.0:
                    severity = 'HIGH'
                elif cvss_score >= 4.0:
                    severity = 'MEDIUM'
                elif cvss_score > 0:
                    severity = 'LOW'
                
                # Safely convert score to float
                try:
                    score = float(hit.get('_score', 0.0)) if hit.get('_score') is not None else 0.0
                except (TypeError, ValueError):
                    score = 0.0
                
                candidate = {
                    "cve_id": cve_id_from_source,
                    "severity": severity,
                    "description": description,
                    "published": source.get('published', ''),
                    "lastModified": source.get('lastModified', source.get('published', '')),
                    "cvss_score": cvss_score,
                    "score": score,
                    "index": hit.get('_index', 'cve'),
                    "source_fields": list(source.keys())  # Track what fields are available
                }
                
                # Truncate description if too long
                if candidate['description'] and len(candidate['description']) > 200:
                    candidate['description'] = candidate['description'][:200] + "..."
                
                candidates.append(candidate)
            
            logger.info(f"Found {len(candidates)} candidate CVEs from OpenSearch NVD index")
            return candidates
            
        except Exception as e:
            logger.error(f"Failed to query OpenSearch NVD index: {e}")
            # Fallback: try to get CVEs from spring-ai-document-index
            try:
                logger.info("Trying fallback to spring-ai-document-index...")
                # Search for documents containing CVE in content
                query = {
                    "query": {
                        "match": {"content": "CVE-"}
                    },
                    "size": limit,
                    "_source": ["content", "metadata"]
                }
                
                response = self.opensearch_client.client.search(
                    index="spring-ai-document-index",
                    body=query
                )
                
                hits = response.get('hits', {}).get('hits', [])
                candidates = []
                
                for hit in hits:
                    source = hit.get('_source', {})
                    content = source.get('content', '')
                    
                    # Try to extract CVE ID from content
                    import re
                    cve_matches = re.findall(r'CVE-\d{4}-\d+', content)
                    if not cve_matches:
                        continue
                    
                    cve_id = cve_matches[0]
                    candidate = {
                        "cve_id": cve_id,
                        "severity": "UNKNOWN",
                        "description": content[:200] + "..." if len(content) > 200 else content,
                        "published": "",
                        "lastModified": "",
                        "cvss_score": 0.0,
                        "score": float(hit.get('_score', 0.0)),
                        "index": hit.get('_index', 'spring-ai-document-index'),
                        "source_fields": ["content_extracted"]
                    }
                    candidates.append(candidate)
                
                logger.info(f"Found {len(candidates)} candidate CVEs from OpenSearch (fallback to spring-ai-document-index)")
                return candidates
                
            except Exception as e2:
                logger.error(f"Fallback query also failed: {e2}")
                return []
    
    def filter_against_postgresql(self, candidates: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Filter candidates against PostgreSQL state.
        
        Args:
            candidates: List of CVE candidates from OpenSearch
            
        Returns:
            Tuple of (eligible_candidates, filtered_out_candidates)
        """
        logger.info(f"Filtering {len(candidates)} candidates against PostgreSQL state...")
        
        eligible = []
        filtered_out = []
        
        for candidate in candidates:
            cve_id = candidate['cve_id']
            
            # Check PostgreSQL state
            is_eligible, filter_reasons = self._check_postgresql_state(cve_id)
            
            if is_eligible:
                candidate['filter_reasons'] = filter_reasons
                eligible.append(candidate)
            else:
                candidate['filter_reasons'] = filter_reasons
                filtered_out.append(candidate)
        
        logger.info(f"After PostgreSQL filtering: {len(eligible)} eligible, {len(filtered_out)} filtered out")
        return eligible, filtered_out
    
    def _check_postgresql_state(self, cve_id: str) -> Tuple[bool, List[str]]:
        """
        Check PostgreSQL state for a CVE.
        
        Returns:
            Tuple of (is_eligible, list_of_filter_reasons)
        """
        filter_reasons = []
        
        # Check if already has approved playbook
        has_approved = self.db.fetch_one(
            """
            SELECT EXISTS (
                SELECT 1 
                FROM approved_playbooks ap
                JOIN generation_runs gr ON ap.generation_run_id = gr.id
                WHERE gr.cve_id = %s
            ) as has_approved
            """,
            (cve_id,)
        )
        
        if has_approved and has_approved.get('has_approved'):
            filter_reasons.append("Already has approved playbook")
            return False, filter_reasons
        
        # Check queue status
        queue_status = self.db.fetch_one(
            """
            SELECT status FROM cve_queue WHERE cve_id = %s
            """,
            (cve_id,)
        )
        
        if queue_status:
            status = queue_status.get('status', '')
            if status in ['completed', 'archived']:
                filter_reasons.append(f"Queue status is '{status}'")
                return False, filter_reasons
        
        # Check if recently processed (in last 24 hours)
        recent_processing = self.db.fetch_one(
            """
            SELECT EXISTS (
                SELECT 1 
                FROM generation_runs 
                WHERE cve_id = %s 
                AND created_at > NOW() - INTERVAL '24 hours'
            ) as recently_processed
            """,
            (cve_id,)
        )
        
        if recent_processing and recent_processing.get('recently_processed'):
            filter_reasons.append("Recently processed (within 24 hours)")
            # Not necessarily ineligible, but note it
        
        # Check if test/excluded CVE
        is_test = (
            cve_id.startswith('CVE-TEST-') or
            cve_id.startswith('TEST-') or
            cve_id.startswith('DEMO-') or
            cve_id.startswith('SYNTHETIC-') or
            cve_id.startswith('SEEDED-')
        )
        
        if is_test:
            filter_reasons.append("Test/excluded CVE pattern")
            return False, filter_reasons
        
        # Check if previously reused validation CVE
        # For now, we'll exclude CVEs that have been processed multiple times
        process_count = self.db.fetch_one(
            """
            SELECT COUNT(*) as count 
            FROM generation_runs 
            WHERE cve_id = %s
            """,
            (cve_id,)
        )
        
        if process_count and process_count.get('count', 0) > 3:
            filter_reasons.append(f"Processed {process_count.get('count')} times (potential validation reuse)")
            # Still eligible, but noted
        
        # If we get here, CVE is eligible
        if not filter_reasons:
            filter_reasons.append("Passed all PostgreSQL filters")
        
        return True, filter_reasons
    
    def _extract_cve_year(self, cve_id: str) -> int:
        """Extract year from CVE ID (e.g., CVE-2025-1234 -> 2025)."""
        try:
            # CVE format: CVE-YYYY-NNNN
            parts = cve_id.split('-')
            if len(parts) >= 2:
                return int(parts[1])
        except (ValueError, IndexError):
            pass
        return 0
    
    def select_fresh_cve(self, eligible_candidates: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Select one fresh CVE from eligible candidates.
        
        Selection criteria:
        1. Newer CVE (higher year in CVE ID)
        2. Higher CVSS score
        3. Higher OpenSearch score
        
        Args:
            eligible_candidates: List of eligible CVE candidates
            
        Returns:
            Selected CVE or None if no candidates
        """
        if not eligible_candidates:
            logger.warning("No eligible candidates to select from")
            return None
        
        # Sort candidates by selection criteria
        # Prefer newer CVEs (higher year in CVE ID), then higher CVSS, then higher OpenSearch score
        sorted_candidates = sorted(
            eligible_candidates,
            key=lambda x: (
                -self._extract_cve_year(x['cve_id']),  # Newer CVEs first (higher year)
                -float(x.get('cvss_score', 0.0) or 0.0),  # Higher CVSS first
                -float(x.get('score', 0.0) or 0.0)  # Higher OpenSearch score first
            )
        )
        
        selected = sorted_candidates[0]
        logger.info(f"Selected CVE: {selected['cve_id']} (CVSS: {selected.get('cvss_score', 0.0)}, Published: {selected.get('published', 'N/A')})")
        
        # Build selection reason
        cvss_score = selected.get('cvss_score', 0.0) or 0.0
        os_score = selected.get('score', 0.0) or 0.0
        cve_year = self._extract_cve_year(selected['cve_id'])
        selection_reason = [
            f"Newest CVE among eligible candidates: {cve_year}",
            f"CVSS score: {cvss_score}",
            f"OpenSearch score: {os_score:.2f}"
        ]
        
        selected['selection_reason'] = selection_reason
        return selected
    
    def run_selection(self, limit: int = 50) -> Dict[str, Any]:
        """
        Run complete OpenSearch-first selection process.
        
        Args:
            limit: Maximum number of CVEs to query from OpenSearch
            
        Returns:
            Selection results
        """
        logger.info("Starting OpenSearch-first CVE selection...")
        
        # Step 1: Query OpenSearch NVD index
        candidates = self.query_opensearch_nvd(limit)
        self.results['number_of_candidates_returned_from_opensearch'] = len(candidates)
        self.results['candidates_from_opensearch'] = candidates
        
        if not candidates:
            logger.error("No candidates returned from OpenSearch NVD index")
            return self.results
        
        # Step 2: Filter against PostgreSQL
        eligible_candidates, filtered_candidates = self.filter_against_postgresql(candidates)
        self.results['number_filtered_out_by_postgres'] = len(filtered_candidates)
        self.results['filtered_candidates'] = filtered_candidates
        self.results['eligible_candidates'] = eligible_candidates
        
        # Step 3: Select fresh CVE
        selected_cve = self.select_fresh_cve(eligible_candidates)
        
        if selected_cve:
            self.results['selected_cve'] = selected_cve['cve_id']
            self.results['reason_selected'] = selected_cve.get('selection_reason', [])
            logger.info(f"Successfully selected CVE: {selected_cve['cve_id']}")
        else:
            logger.warning("No CVE selected from eligible candidates")
        
        return self.results
    
    def print_results(self, output_json: bool = False):
        """Print selection results."""
        if output_json:
            print(json.dumps(self.results, indent=2, default=str))
            return
        
        print("\n" + "=" * 80)
        print("OPENSEARCH-FIRST CVE SELECTION RESULTS")
        print("=" * 80)
        print(f"Timestamp (UTC): {self.results['timestamp_utc']}")
        print(f"Source of Selection: {self.results['source_of_selection']}")
        print(f"Candidates from OpenSearch NVD: {self.results['number_of_candidates_returned_from_opensearch']}")
        print(f"Filtered out by PostgreSQL: {self.results['number_filtered_out_by_postgres']}")
        print(f"Eligible candidates: {len(self.results['eligible_candidates'])}")
        
        if self.results['selected_cve']:
            print(f"\nSELECTED CVE: {self.results['selected_cve']}")
            print("-" * 40)
            print("Selection Reasons:")
            for reason in self.results['reason_selected']:
                print(f"  • {reason}")
            
            # Show selected CVE details
            selected_details = None
            for candidate in self.results['eligible_candidates']:
                if candidate['cve_id'] == self.results['selected_cve']:
                    selected_details = candidate
                    break
            
            if selected_details:
                print(f"\nSelected CVE Details:")
                print(f"  CVSS Score: {selected_details.get('cvss_score', 'N/A')}")
                print(f"  Severity: {selected_details.get('severity', 'N/A')}")
                print(f"  Published: {selected_details.get('published', 'N/A')}")
                print(f"  Description: {selected_details.get('description', 'N/A')}")
        else:
            print("\nNO CVE SELECTED")
        
        # Show top filtered candidates if any
        if self.results['filtered_candidates']:
            print(f"\nTop 5 Filtered Out Candidates:")
            for i, candidate in enumerate(self.results['filtered_candidates'][:5], 1):
                reasons = candidate.get('filter_reasons', ['Unknown'])
                print(f"  {i}. {candidate['cve_id']}: {', '.join(reasons)}")
        
        print("=" * 80)


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(description='OpenSearch-first CVE selector for production')
    parser.add_argument('--limit', type=int, default=50, help='Maximum CVEs to query from OpenSearch (default: 50)')
    parser.add_argument('--json', action='store_true', help='Output JSON format only')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Run selection
    selector = OpenSearchFirstSelector()
    results = selector.run_selection(args.limit)
    
    # Print results
    selector.print_results(args.json)
    
    # Exit code
    if results['selected_cve']:
        print(f"\nSelected CVE for production: {results['selected_cve']}")
        sys.exit(0)
    else:
        print("\nNo CVE selected - check OpenSearch connectivity or PostgreSQL filters")
        sys.exit(1)


if __name__ == "__main__":
    main()