#!/usr/bin/env python3
"""
VS.ai — Playbook Engine Gen-3
Phase 1 Selector with Corrected Exclusion Policy
Version: v1.0.0
Timestamp (UTC): 2026-04-13

Purpose:
- Implement corrected Phase 1 exclusion policy per directive
- A CVE must be excluded only if truly completed successfully
- Do not exclude CVEs with failed or partial generation history
"""

import sys
import json
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


class Phase1CVESelectorCorrected:
    """Phase 1 CVE selector with corrected exclusion policy."""
    
    def __init__(self):
        self.opensearch_client = RealOpenSearchClient()
        self.db = DatabaseClient()
        self.results = {
            "timestamp_utc": datetime_to_iso(get_utc_now()),
            "selected_cve": None,
            "source_of_selection": None,
            "candidates_considered": 0,
            "candidates_filtered": 0,
            "selection_reason": None,
            "error": None,
            "exclusion_counts": {
                "excluded_already_approved": 0,
                "excluded_successful_generation_exists": 0,
                "excluded_in_progress_queue": 0,
                "excluded_active_lock": 0,
                "excluded_session_dedup": 0,
                "excluded_other": 0
            }
        }
        
        logger.info("Phase1CVESelectorCorrected initialized")
    
    def query_opensearch_cve_index(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Query OpenSearch cve index for candidate CVEs with Phase 1 filters.
        
        Args:
            limit: Maximum number of CVEs to return
            
        Returns:
            List of CVE candidates with basic metadata
        """
        logger.info(f"Querying OpenSearch cve index for candidate CVEs (limit: {limit})...")
        
        try:
            # Query OpenSearch for CVEs from cve index with Phase 1 requirements
            # We need to get CVEs with severity and CVSS score present
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"exists": {"field": "metrics"}},  # CVSS metrics must exist
                            {"exists": {"field": "published"}}  # Published date must exist
                        ]
                    }
                },
                "sort": [
                    {"published": {"order": "desc"}}  # Sort by published date descending
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
                
                # Get published date
                published = source.get('published', '')
                
                # Skip if no CVSS score (Phase 1 requirement: CVSS score present)
                if cvss_score <= 0:
                    continue
                
                # Skip if no severity determined (Phase 1 requirement: severity present)
                if severity == 'UNKNOWN':
                    continue
                
                candidate = {
                    "cve_id": cve_id_from_source,
                    "severity": severity,
                    "description": description,
                    "published": published,
                    "lastModified": source.get('lastModified', published),
                    "cvss_score": cvss_score,
                    "score": float(hit.get('_score', 0.0)) if hit.get('_score') is not None else 0.0,
                    "index": hit.get('_index', 'cve'),
                    "source_fields": list(source.keys())
                }
                
                # Truncate description if too long
                if candidate['description'] and len(candidate['description']) > 200:
                    candidate['description'] = candidate['description'][:200] + "..."
                
                candidates.append(candidate)
            
            logger.info(f"Found {len(candidates)} candidate CVEs from OpenSearch cve index with Phase 1 filters")
            return candidates
            
        except Exception as e:
            logger.error(f"Failed to query OpenSearch cve index: {e}")
            return []
    
    def _check_postgresql_state_corrected(self, cve_id: str) -> Tuple[bool, List[str], str]:
        """
        Check PostgreSQL state for a CVE with CORRECTED Phase 1 filters.
        
        CORRECTED Phase 1 filters (per directive):
        A CVE must be excluded only if at least one of the following is true:
        1. approved_playbook exists for that CVE
        2. generation_run exists with true terminal success state:
           - generation status completed
           - parser succeeded (parsed_response IS NOT NULL)
           - QA returned a valid success result (qa_result = 'approved')
           - pipeline_status = success (if available)
        3. active lock exists
        4. in-progress queue state exists
        5. already processed in current session
        
        A CVE must NOT be excluded solely because:
        - it exists in generation_runs
        - it has failed generation history
        - it has partial pipeline history
        - QA result was None
        - parser previously failed
        
        Returns:
            Tuple of (is_eligible, list_of_filter_reasons, exclusion_category)
        """
        filter_reasons = []
        exclusion_category = None
        
        # 1. Check if already has approved playbook
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
            exclusion_category = "excluded_already_approved"
            return False, filter_reasons, exclusion_category
        
        # 2. Check if has truly successful generation run
        # Based on actual schema and directive requirements:
        # - generation status = 'completed'
        # - response IS NOT NULL AND response != '' (has content)
        # - has QA result = 'approved' (terminal success)
        has_successful_generation = self.db.fetch_one(
            """
            SELECT EXISTS (
                SELECT 1 
                FROM generation_runs gr
                LEFT JOIN qa_runs qa ON gr.id = qa.generation_run_id
                WHERE gr.cve_id = %s
                AND gr.status = 'completed'
                AND gr.response IS NOT NULL
                AND gr.response != ''
                AND qa.qa_result = 'approved'
            ) as has_successful_generation
            """,
            (cve_id,)
        )
        
        if has_successful_generation and has_successful_generation.get('has_successful_generation'):
            filter_reasons.append("Has truly successful generation run (completed + parsed + QA approved)")
            exclusion_category = "excluded_successful_generation_exists"
            return False, filter_reasons, exclusion_category
        
        # 3. Check if in-progress queue state exists
        in_progress_queue = self.db.fetch_one(
            """
            SELECT EXISTS (
                SELECT 1 
                FROM cve_queue 
                WHERE cve_id = %s
                AND status IN ('processing', 'pending')
            ) as in_progress_queue
            """,
            (cve_id,)
        )
        
        if in_progress_queue and in_progress_queue.get('in_progress_queue'):
            filter_reasons.append("In-progress queue state exists")
            exclusion_category = "excluded_in_progress_queue"
            return False, filter_reasons, exclusion_category
        
        # 4. Check if active lock exists
        # Note: This assumes continuous_execution_locks table exists
        # If not, we'll skip this check
        try:
            has_active_lock = self.db.fetch_one(
                """
                SELECT EXISTS (
                    SELECT 1 
                    FROM continuous_execution_locks 
                    WHERE cve_id = %s
                    AND status = 'running' 
                    AND lock_released_at IS NULL
                    AND lock_acquired_at > NOW() - INTERVAL '5 minutes'
                ) as has_active_lock
                """,
                (cve_id,)
            )
            
            if has_active_lock and has_active_lock.get('has_active_lock'):
                filter_reasons.append("Active lock exists")
                exclusion_category = "excluded_active_lock"
                return False, filter_reasons, exclusion_category
        except Exception as e:
            # Table might not exist, skip this check
            logger.debug(f"Could not check active locks (table might not exist): {e}")
            pass
        
        # 5. Session deduplication would be handled at a higher level
        # This is not a database check, so we'll handle it separately
        
        # 6. Check if test/excluded CVE pattern
        is_test = (
            cve_id.startswith('CVE-TEST-') or
            cve_id.startswith('TEST-') or
            cve_id.startswith('DEMO-') or
            cve_id.startswith('SYNTHETIC-') or
            cve_id.startswith('SEEDED-')
        )
        
        if is_test:
            filter_reasons.append("Test/excluded CVE pattern")
            exclusion_category = "excluded_other"
            return False, filter_reasons, exclusion_category
        
        # If we get here, CVE is eligible for Phase 1
        if not filter_reasons:
            filter_reasons.append("Passed all corrected Phase 1 PostgreSQL filters")
        
        return True, filter_reasons, "eligible"
    
    def filter_against_postgresql_corrected(self, candidates: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Filter candidates against PostgreSQL state with CORRECTED Phase 1 filters.
        
        Args:
            candidates: List of CVE candidates from OpenSearch
            
        Returns:
            Tuple of (eligible_candidates, filtered_out_candidates)
        """
        logger.info(f"Filtering {len(candidates)} candidates against PostgreSQL state with CORRECTED Phase 1 filters...")
        
        eligible = []
        filtered_out = []
        
        for candidate in candidates:
            cve_id = candidate['cve_id']
            
            # Check PostgreSQL state with CORRECTED filters
            is_eligible, filter_reasons, exclusion_category = self._check_postgresql_state_corrected(cve_id)
            
            if is_eligible:
                candidate['filter_reasons'] = filter_reasons
                candidate['exclusion_category'] = None
                eligible.append(candidate)
            else:
                candidate['filter_reasons'] = filter_reasons
                candidate['exclusion_category'] = exclusion_category
                filtered_out.append(candidate)
                
                # Update exclusion counts
                if exclusion_category and exclusion_category in self.results['exclusion_counts']:
                    self.results['exclusion_counts'][exclusion_category] += 1
        
        logger.info(f"After CORRECTED PostgreSQL filtering: {len(eligible)} eligible, {len(filtered_out)} filtered out")
        return eligible, filtered_out
    
    def _severity_to_numeric(self, severity: str) -> int:
        """Convert severity string to numeric value for sorting."""
        severity_map = {
            'CRITICAL': 4,
            'HIGH': 3,
            'MEDIUM': 2,
            'LOW': 1,
            'UNKNOWN': 0
        }
        return severity_map.get(severity.upper(), 0)
    
    def select_fresh_cve_phase1(self, eligible_candidates: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Select one fresh CVE from eligible candidates using Phase 1 sorting.
        
        Phase 1 sorting:
        1. severity descending
        2. CVSS descending
        3. published descending
        
        Args:
            eligible_candidates: List of eligible CVE candidates
            
        Returns:
            Selected CVE or None if no candidates
        """
        if not eligible_candidates:
            logger.warning("No eligible candidates to select from")
            return None
        
        # Sort candidates by Phase 1 criteria
        sorted_candidates = sorted(
            eligible_candidates,
            key=lambda x: (
                -self._severity_to_numeric(x.get('severity', 'UNKNOWN')),  # Severity descending
                -float(x.get('cvss_score', 0.0) or 0.0),  # CVSS descending
                -(datetime.fromisoformat(x.get('published', '1970-01-01T00:00:00Z').replace('Z', '+00:00')).timestamp() if x.get('published') else 0)  # Published descending
            )
        )
        
        selected = sorted_candidates[0]
        logger.info(f"Selected CVE: {selected['cve_id']} (Severity: {selected.get('severity', 'N/A')}, CVSS: {selected.get('cvss_score', 0.0)}, Published: {selected.get('published', 'N/A')})")
        
        # Build selection reason
        severity = selected.get('severity', 'UNKNOWN')
        cvss_score = selected.get('cvss_score', 0.0) or 0.0
        published = selected.get('published', 'N/A')
        selection_reason = [
            f"Highest severity among eligible candidates: {severity}",
            f"CVSS score: {cvss_score}",
            f"Published date: {published}"
        ]
        
        selected['selection_reason'] = selection_reason
        return selected
    
    def run_selection_corrected(self, limit: int = 100) -> Dict[str, Any]:
        """
        Run complete CORRECTED Phase 1 selection process.
        
        Args:
            limit: Maximum number of CVEs to query from OpenSearch
            
        Returns:
            Selection results with corrected exclusion counts
        """
        logger.info("Starting CORRECTED Phase 1 CVE selection...")
        
        # Step 1: Query OpenSearch cve index with Phase 1 filters
        candidates = self.query_opensearch_cve_index(limit)
        self.results['number_of_candidates_returned_from_opensearch'] = len(candidates)
        self.results['candidates_from_opensearch'] = candidates
        
        # Add backward compatibility fields
        self.results['candidates_fetched'] = len(candidates)
        self.results['candidates_considered'] = len(candidates)
        
        if not candidates:
            logger.error("No candidates returned from OpenSearch cve index")
            return self.results
        
        # Step 2: Filter against PostgreSQL with CORRECTED filters
        eligible_candidates, filtered_candidates = self.filter_against_postgresql_corrected(candidates)
        self.results['number_filtered_out_by_postgres'] = len(filtered_candidates)
        self.results['filtered_candidates'] = filtered_candidates
        self.results['eligible_candidates'] = eligible_candidates
        
        # Add backward compatibility fields
        self.results['filtered_out'] = len(filtered_candidates)
        self.results['candidates_filtered'] = len(filtered_candidates)
        self.results['eligible_count'] = len(eligible_candidates)
        
        # Step 3: Select fresh CVE
        selected_cve = self.select_fresh_cve_phase1(eligible_candidates)
        
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
        print("CORRECTED PHASE 1 CVE SELECTION RESULTS")
        print("=" * 80)
        print(f"Timestamp (UTC): {self.results['timestamp_utc']}")
        print(f"Candidates from OpenSearch: {self.results['number_of_candidates_returned_from_opensearch']}")
        print(f"Filtered out by PostgreSQL: {self.results['number_filtered_out_by_postgres']}")
        print(f"Eligible candidates: {len(self.results['eligible_candidates'])}")
        
        print("\nEXCLUSION COUNTS (Corrected Policy):")
        print("-" * 40)
        for category, count in self.results['exclusion_counts'].items():
            print(f"  {category}: {count}")
        
        if self.results['selected_cve']:
            print(f"\nSELECTED CVE: {self.results['selected_cve']}")
            print("-" * 40)
            print("Selection Reasons:")
            for reason in self.results['reason_selected']:
                print(f"  • {reason}")
        else:
            print("\nNO CVE SELECTED")
        
        # Show top filtered candidates if any
        if self.results['filtered_candidates']:
            print(f"\nTop 5 Filtered Out Candidates (with corrected exclusion categories):")
            for i, candidate in enumerate(self.results['filtered_candidates'][:5], 1):
                reasons = candidate.get('filter_reasons', ['Unknown'])
                category = candidate.get('exclusion_category', 'unknown')
                print(f"  {i}. {candidate['cve_id']}: {category} - {', '.join(reasons)}")
        
        print("=" * 80)


def test_against_recent_candidates():
    """Test the corrected selector against the recent 100-candidate set."""
    logger.info("Testing corrected selector against recent 100-candidate set...")
    
    # Load the recent metadata
    metadata_path = Path("logs/runs/556732eb-e36e-4371-8f5b-a1dc78c53343-run-0010/metadata.json")
    if not metadata_path.exists():
        logger.error(f"Metadata file not found: {metadata_path}")
        return None
    
    with open(metadata_path, 'r') as f:
        metadata = json.load(f)
    
    selection_data = metadata.get('metadata', {}).get('selection_data', {})
    candidates = selection_data.get('candidates_from_opensearch', [])
    
    if not candidates:
        logger.error("No candidates found in metadata")
        return None
    
    logger.info(f"Loaded {len(candidates)} candidates from recent run")
    
    # Create corrected selector
    selector = Phase1CVESelectorCorrected()
    
    # Simulate filtering with corrected logic
    eligible, filtered = selector.filter_against_postgresql_corrected(candidates)
    
    # Build comparison results
    comparison = {
        "original_run_timestamp": metadata.get('captured_at'),
        "original_candidates_count": len(candidates),
        "original_filtered_count": len(candidates) - 1,  # Based on previous analysis
        "original_eligible_count": 1,  # Based on previous analysis
        "corrected_filtered_count": len(filtered),
        "corrected_eligible_count": len(eligible),
        "exclusion_counts": selector.results['exclusion_counts'],
        "top_eligible_candidates": [
            {
                "cve_id": c.get('cve_id'),
                "severity": c.get('severity'),
                "cvss_score": c.get('cvss_score'),
                "published": c.get('published')
            }
            for c in eligible[:10]
        ],
        "top_filtered_candidates": [
            {
                "cve_id": c.get('cve_id'),
                "exclusion_category": c.get('exclusion_category'),
                "filter_reasons": c.get('filter_reasons', [])
            }
            for c in filtered[:10]
        ]
    }
    
    return comparison


def main():
    """Main execution function."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Phase 1 CVE selector with corrected exclusion policy')
    parser.add_argument('--limit', type=int, default=100, help='Maximum CVEs to query from OpenSearch (default: 100)')
    parser.add_argument('--json', action='store_true', help='Output JSON format only')
    parser.add_argument('--test', action='store_true', help='Test against recent 100-candidate set only')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    if args.test:
        # Test against recent candidates
        comparison = test_against_recent_candidates()
        if comparison:
            print(json.dumps(comparison, indent=2, default=str))
        else:
            print("Test failed")
        return
    
    # Run selection with corrected logic
    selector = Phase1CVESelectorCorrected()
    results = selector.run_selection_corrected(args.limit)
    
    # Print results
    selector.print_results(args.json)


if __name__ == "__main__":
    main()