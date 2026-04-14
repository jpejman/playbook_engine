#!/usr/bin/env python3
"""
VS.ai — Playbook Engine Gen-3
Phase 1 Single-CVE Continuous Runner
Version: v1.0.0
Timestamp (UTC): 2026-04-10

OBJECTIVE

Implement a repeatable production run that selects and processes exactly one fresh CVE per execution using Phase 1 selection rules.

PHASE 1 CVE SELECTION RULES

Source of candidates:
- OpenSearch cve index only

Filter:
- severity present
- CVSS score present
- not already approved in PostgreSQL
- not already processed in PostgreSQL

Sort:
1. severity descending
2. CVSS descending
3. published descending

PROCESSING RULE

Each execution must:
1. select exactly one fresh CVE
2. build context
3. run generation
4. persist generation_runs row
5. run QA
6. stop

Do not select multiple CVEs in one execution.
Do not batch.
Do not require manual CVE input.

OUTPUT FOR EACH RUN

Return:
- timestamp_utc
- selected_cve
- source_of_selection = OpenSearch cve
- context_snapshot_id
- generation_run_id
- status
- generation_source
- llm_error_info
- qa_result
- qa_score
- approved_playbook_id if any

DEFINITION OF COMPLETE FOR PHASE 1

A CVE is considered completed for this phase when it has:
- been selected from OpenSearch cve
- had context built
- had generation attempted
- had a generation_runs row persisted
- had QA executed

APPROVAL is not required for Phase 1 completion because parser/contract issue is a separate downstream blocker.

GOAL

Allow repeated execution of the same runner so that each run processes one fresh CVE and then moves to the next one on the following run.
"""

import sys
import json
import subprocess
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


class Phase1CVESelector:
    """Phase 1 CVE selector implementing exact Phase 1 rules."""
    
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
            "error": None
        }
        
        logger.info("Phase1CVESelector initialized")
    
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
    
    def filter_against_postgresql(self, candidates: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Filter candidates against PostgreSQL state with Phase 1 filters.
        
        Args:
            candidates: List of CVE candidates from OpenSearch
            
        Returns:
            Tuple of (eligible_candidates, filtered_out_candidates)
        """
        logger.info(f"Filtering {len(candidates)} candidates against PostgreSQL state with Phase 1 filters...")
        
        eligible = []
        filtered_out = []
        
        for candidate in candidates:
            cve_id = candidate['cve_id']
            
            # Check PostgreSQL state with Phase 1 filters
            is_eligible, filter_reasons = self._check_postgresql_state_phase1(cve_id)
            
            if is_eligible:
                candidate['filter_reasons'] = filter_reasons
                eligible.append(candidate)
            else:
                candidate['filter_reasons'] = filter_reasons
                filtered_out.append(candidate)
        
        logger.info(f"After PostgreSQL filtering: {len(eligible)} eligible, {len(filtered_out)} filtered out")
        return eligible, filtered_out
    
    def _check_postgresql_state_phase1(self, cve_id: str) -> Tuple[bool, List[str]]:
        """
        Check PostgreSQL state for a CVE with Phase 1 filters.
        
        Phase 1 filters:
        - not already approved in PostgreSQL
        - not already processed in PostgreSQL
        
        Returns:
            Tuple of (is_eligible, list_of_filter_reasons)
        """
        filter_reasons = []
        
        # Check if already has approved playbook (Phase 1: not already approved)
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
            filter_reasons.append("Already has approved playbook (Phase 1 filter)")
            return False, filter_reasons
        
        # Check if already processed (Phase 1: not already processed)
        # We consider a CVE as processed if it has any generation_runs entry
        has_processed = self.db.fetch_one(
            """
            SELECT EXISTS (
                SELECT 1 
                FROM generation_runs 
                WHERE cve_id = %s
            ) as has_processed
            """,
            (cve_id,)
        )
        
        if has_processed and has_processed.get('has_processed'):
            filter_reasons.append("Already processed in generation_runs (Phase 1 filter)")
            return False, filter_reasons
        
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
        
        # If we get here, CVE is eligible for Phase 1
        if not filter_reasons:
            filter_reasons.append("Passed all Phase 1 PostgreSQL filters")
        
        return True, filter_reasons
    
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
    
    def run_selection_phase1(self, limit: int = 100) -> Dict[str, Any]:
        """
        Run complete Phase 1 selection process.
        
        Args:
            limit: Maximum number of CVEs to query from OpenSearch
            
        Returns:
            Selection results
        """
        logger.info("Starting Phase 1 CVE selection...")
        
        # Step 1: Query OpenSearch cve index with Phase 1 filters
        candidates = self.query_opensearch_cve_index(limit)
        self.results['number_of_candidates_returned_from_opensearch'] = len(candidates)
        self.results['candidates_from_opensearch'] = candidates
        
        if not candidates:
            logger.error("No candidates returned from OpenSearch cve index with Phase 1 filters")
            return self.results
        
        # Step 2: Filter against PostgreSQL with Phase 1 filters
        eligible_candidates, filtered_candidates = self.filter_against_postgresql(candidates)
        self.results['number_filtered_out_by_postgres'] = len(filtered_candidates)
        self.results['filtered_candidates'] = filtered_candidates
        self.results['eligible_candidates'] = eligible_candidates
        
        # Step 3: Select fresh CVE using Phase 1 sorting
        selected_cve = self.select_fresh_cve_phase1(eligible_candidates)
        
        if selected_cve:
            self.results['selected_cve'] = selected_cve['cve_id']
            self.results['reason_selected'] = selected_cve.get('selection_reason', [])
            logger.info(f"Successfully selected CVE: {selected_cve['cve_id']}")
        else:
            logger.warning("No CVE selected from eligible candidates")
        
        return self.results


class Phase1ContinuousRunner:
    """Phase 1 single-CVE continuous runner."""
    
    def __init__(self):
        self.results = {
            "timestamp_utc": datetime_to_iso(get_utc_now()),
            "selected_cve": None,
            "source_of_selection": "OpenSearch cve",
            "context_snapshot_id": None,
            "generation_run_id": None,
            "status": "not_started",
            "generation_source": "real_retrieval",
            "llm_error_info": None,
            "qa_result": None,
            "qa_score": None,
            "approved_playbook_id": None,
            "phase1_complete": False,
            "errors": []
        }
        
        logger.info("Phase1ContinuousRunner initialized")
    
    def run_selection(self, limit: int = 100) -> Optional[Dict[str, Any]]:
        """Run Phase 1 selection."""
        logger.info("Step 1: Running Phase 1 selection...")
        
        try:
            selector = Phase1CVESelector()
            selection_results = selector.run_selection_phase1(limit)
            
            if not selection_results.get('selected_cve'):
                error_msg = "No CVE selected from Phase 1 selector"
                logger.error(error_msg)
                self.results['errors'].append(error_msg)
                return None
            
            # Update results with selection data
            self.results['selected_cve'] = selection_results['selected_cve']
            logger.info(f"Selected CVE: {self.results['selected_cve']}")
            return selection_results
            
        except Exception as e:
            error_msg = f"Selection failed: {e}"
            logger.error(error_msg)
            self.results['errors'].append(error_msg)
            return None
    
    def run_context_snapshot(self, cve_id: str) -> Optional[int]:
        """Run context snapshot builder."""
        logger.info(f"Step 2: Building context snapshot for {cve_id}...")
        
        try:
            # Run the context snapshot script
            cmd = [
                sys.executable, 
                "scripts/prod/02_85_build_context_snapshot_v0_1_0.py",
                "--cve", cve_id,
                "--json"
            ]
            
            cwd_path = Path(__file__).parent.parent.parent.resolve()
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=cwd_path
            )
            
            if result.returncode != 0:
                error_msg = f"Context snapshot failed: {result.stderr}"
                logger.error(error_msg)
                self.results['errors'].append(error_msg)
                return None
            
            # Parse JSON output
            output_data = json.loads(result.stdout)
            context_snapshot_id = output_data.get('context_snapshot_id')
            
            if context_snapshot_id:
                self.results['context_snapshot_id'] = context_snapshot_id
                logger.info(f"Context snapshot created: ID {context_snapshot_id}")
                return context_snapshot_id
            else:
                error_msg = f"No context snapshot ID returned: {output_data}"
                logger.error(error_msg)
                self.results['errors'].append(error_msg)
                return None
                
        except Exception as e:
            error_msg = f"Context snapshot execution failed: {e}"
            logger.error(error_msg)
            self.results['errors'].append(error_msg)
            return None
    
    def run_generation(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Run playbook generation."""
        logger.info(f"Step 3: Running playbook generation for {cve_id}...")
        
        try:
            # Run the generation script
            cmd = [
                sys.executable,
                "scripts/prod/03_01_run_playbook_generation_v0_1_1_real_retrieval.py",
                "--cve", cve_id
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=Path(__file__).parent.parent.parent
            )
            
            # Parse the output to find key information
            generation_data = {
                "status": "unknown",
                "generation_run_id": None,
                "llm_error_info": None
            }
            
            # Parse the output to find key information
            # Combine stdout and stderr for parsing (generation script logs to stderr)
            combined_output = result.stdout + "\n" + result.stderr
            output_lines = combined_output.split('\n')
            for line in output_lines:
                if "Generation Run ID:" in line:
                    parts = line.split("Generation Run ID:")
                    if len(parts) > 1:
                        generation_data["generation_run_id"] = parts[1].strip()
                elif "Final generation status:" in line:
                    parts = line.split("Final generation status:")
                    if len(parts) > 1:
                        generation_data["status"] = parts[1].strip()
                elif "LLM error info stored:" in line:
                    parts = line.split("LLM error info stored:")
                    if len(parts) > 1:
                        generation_data["llm_error_info"] = parts[1].strip()
            
            # Extract generation info
            generation_run_id = generation_data.get('generation_run_id')
            status = generation_data.get('status', 'failed')
            llm_error_info = generation_data.get('llm_error_info')
            
            self.results['generation_run_id'] = generation_run_id
            self.results['status'] = status
            self.results['llm_error_info'] = llm_error_info
            
            if generation_run_id:
                logger.info(f"Generation run created: ID {generation_run_id}, status: {status}")
            else:
                logger.warning(f"Generation may have failed: status={status}")
            
            return generation_data
            
        except Exception as e:
            error_msg = f"Generation execution failed: {e}"
            logger.error(error_msg)
            self.results['errors'].append(error_msg)
            self.results['status'] = 'execution_failed'
            return None
    
    def run_qa(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Run QA enforcement."""
        logger.info(f"Step 4: Running QA enforcement for {cve_id}...")
        
        try:
            # Run the QA script
            cmd = [
                sys.executable,
                "scripts/prod/06_08_qa_enforcement_gate_canonical_v0_2_0.py",
                "--cve", cve_id
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=Path(__file__).parent.parent.parent
            )
            
            # Parse the output to find key information
            qa_data: Dict[str, Any] = {
                "result": None,
                "score": None
            }
            
            # Parse the output to find key information
            # Combine stdout and stderr for parsing (QA script may log to stderr)
            combined_output = result.stdout + "\n" + result.stderr
            output_lines = combined_output.split('\n')
            for line in output_lines:
                if "QA Result:" in line:
                    parts = line.split("QA Result:")
                    if len(parts) > 1:
                        qa_data["result"] = parts[1].strip()
                elif "QA Score:" in line:
                    parts = line.split("QA Score:")
                    if len(parts) > 1:
                        score_str = parts[1].strip()
                        try:
                            qa_data["score"] = float(score_str)
                        except ValueError:
                            qa_data["score"] = 0.0
            
            # Extract QA info
            qa_result = qa_data.get('result')
            qa_score = qa_data.get('score')
            
            self.results['qa_result'] = qa_result
            self.results['qa_score'] = qa_score
            
            if qa_result:
                logger.info(f"QA result: {qa_result}, score: {qa_score}")
            else:
                logger.warning(f"QA may have failed: no result found in output")
            
            return qa_data
            
        except Exception as e:
            error_msg = f"QA execution failed: {e}"
            logger.error(error_msg)
            self.results['errors'].append(error_msg)
            return None
    
    def check_approved_playbook(self, cve_id: str) -> Optional[str]:
        """Check if CVE has an approved playbook."""
        try:
            from src.utils.db import DatabaseClient
            db = DatabaseClient()
            
            approved_playbook = db.fetch_one(
                """
                SELECT ap.id
                FROM approved_playbooks ap
                JOIN generation_runs gr ON ap.generation_run_id = gr.id
                WHERE gr.cve_id = %s
                LIMIT 1
                """,
                (cve_id,)
            )
            
            if approved_playbook and approved_playbook.get('id'):
                approved_id = approved_playbook.get('id')
                self.results['approved_playbook_id'] = approved_id
                logger.info(f"Found approved playbook ID: {approved_id}")
                return approved_id
            
            return None
            
        except Exception as e:
            logger.warning(f"Could not check approved playbook: {e}")
            return None
    
    def run_phase1(self, limit: int = 100) -> Dict[str, Any]:
        """Run complete Phase 1 single-CVE processing."""
        logger.info("Starting Phase 1 single-CVE continuous runner...")
        
        # Step 1: Selection (exactly one fresh CVE)
        selection_results = self.run_selection(limit)
        if not selection_results:
            self.results['phase1_complete'] = False
            return self.results
        
        cve_id = self.results['selected_cve']
        
        # Step 2: Build context
        context_snapshot_id = self.run_context_snapshot(cve_id)
        if not context_snapshot_id:
            self.results['phase1_complete'] = False
            return self.results
        
        # Step 3: Run generation (persists generation_runs row)
        generation_data = self.run_generation(cve_id)
        if not generation_data:
            self.results['phase1_complete'] = False
            return self.results
        
        # Step 4: Run QA
        qa_data = self.run_qa(cve_id)
        
        # Step 5: Check for approved playbook (optional output)
        self.check_approved_playbook(cve_id)
        
        # Mark Phase 1 as complete
        self.results['phase1_complete'] = True
        logger.info(f"Phase 1 completed for CVE: {cve_id}")
        
        return self.results
    
    def print_results(self, output_json: bool = False):
        """Print Phase 1 results."""
        if output_json:
            print(json.dumps(self.results, indent=2, default=str))
            return
        
        print("\n" + "=" * 80)
        print("PHASE 1 SINGLE-CVE CONTINUOUS RUNNER RESULTS")
        print("=" * 80)
        print(f"Timestamp (UTC): {self.results['timestamp_utc']}")
        print(f"Source of Selection: {self.results['source_of_selection']}")
        
        if self.results['selected_cve']:
            print(f"\nSELECTED CVE: {self.results['selected_cve']}")
            print("-" * 40)
            
            print(f"\nContext Snapshot ID: {self.results['context_snapshot_id']}")
            print(f"Generation Run ID: {self.results['generation_run_id']}")
            print(f"Generation Source: {self.results['generation_source']}")
            print(f"Status: {self.results['status']}")
            
            if self.results['llm_error_info']:
                print(f"LLM Error Info: {self.results['llm_error_info']}")
            
            print(f"QA Result: {self.results['qa_result']}")
            print(f"QA Score: {self.results['qa_score']}")
            
            if self.results['approved_playbook_id']:
                print(f"Approved Playbook ID: {self.results['approved_playbook_id']}")
            
            print(f"\nPhase 1 Complete: {self.results['phase1_complete']}")
        else:
            print("\nNO CVE SELECTED")
        
        if self.results['errors']:
            print(f"\nErrors ({len(self.results['errors'])}):")
            for error in self.results['errors']:
                print(f"  • {error}")
        
        print("=" * 80)


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(description='Phase 1 single-CVE continuous runner')
    parser.add_argument('--limit', type=int, default=100, help='Maximum CVEs to query from OpenSearch (default: 100)')
    parser.add_argument('--json', action='store_true', help='Output JSON format only')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Run Phase 1
    runner = Phase1ContinuousRunner()
    results = runner.run_phase1(args.limit)
    
    # Print results
    runner.print_results(args.json)
    
    # Exit code
    if results['phase1_complete']:
        print(f"\nPhase 1 completed successfully for CVE: {results['selected_cve']}")
        sys.exit(0)
    else:
        print(f"\nPhase 1 failed: {len(results['errors'])} errors")
        sys.exit(1)


if __name__ == "__main__":
    main()