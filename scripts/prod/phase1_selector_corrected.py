#!/usr/bin/env python3
"""
VS.ai — Playbook Engine Gen-3
Phase 1 Selector with Corrected Exclusion Policy
Version: v1.0.2
Timestamp (UTC): 2026-04-14

Purpose:
- Implement corrected Phase 1 exclusion policy per directive
- Exclude CVEs that already exist in the real production playbook store: vulnstrike.public.playbooks
- Exclude CVEs only if truly completed successfully or already present in production
- Do not exclude CVEs with failed or partial generation history
"""

import os
import sys
import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime

import psycopg2
import psycopg2.extras

# Add repo root to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.retrieval.opensearch_client import RealOpenSearchClient
from src.utils.db import DatabaseClient
from scripts.prod.time_utils import get_utc_now, datetime_to_iso

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class ProductionDatabaseClient:
    """
    Lightweight read-only client for the vulnstrike database.

    Purpose:
    - Check whether a CVE already exists in the real production playbook store:
      vulnstrike.public.playbooks

    Notes:
    - Uses the same host/port/user/password defaults as the main DB client
    - Hard-codes database='vulnstrike'
    """

    def __init__(self):
        self.host = os.getenv('DB_HOST', '10.0.0.110')
        self.port = os.getenv('DB_PORT', '5432')
        self.database = 'vulnstrike'
        self.user = os.getenv('DB_USER', 'vulnstrike')
        self.password = os.getenv('DB_PASSWORD', 'vulnstrike')

        logger.info(f"Production DB client initialized for {self.host}:{self.port}/{self.database}")

    def fetch_one(self, query: str, params: Optional[Tuple] = None) -> Optional[Dict[str, Any]]:
        conn = psycopg2.connect(
            host=self.host,
            port=self.port,
            database=self.database,
            user=self.user,
            password=self.password
        )
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(query, params)
                return cur.fetchone()
        finally:
            conn.close()


class Phase1CVESelectorCorrected:
    """Phase 1 CVE selector with corrected exclusion policy."""

    def __init__(self):
        self.opensearch_client = RealOpenSearchClient()

        # Main pipeline/workflow DB
        self.db = DatabaseClient()

        # Real production playbook DB
        self.production_db = ProductionDatabaseClient()

        self.results = {
            "timestamp_utc": datetime_to_iso(get_utc_now()),
            "selected_cve": None,
            "source_of_selection": None,
            "candidates_considered": 0,
            "candidates_filtered": 0,
            "selection_reason": None,
            "error": None,
            "exclusion_counts": {
                "excluded_already_in_production": 0,
                "excluded_already_approved": 0,
                "excluded_successful_generation_exists": 0,
                "excluded_in_progress_queue": 0,
                "excluded_active_lock": 0,
                "excluded_session_dedup": 0,
                "excluded_other": 0
            }
        }

        logger.info("Phase1CVESelectorCorrected initialized")

    def _has_existing_generated_playbook(self, cve_id: str) -> bool:
        """
        Return True if playbook_engine already has a non-empty generated playbook
        for this CVE, regardless of QA state.
        """
        row = self.db.fetch_one(
            """
            SELECT 1
            FROM generation_runs gr
            WHERE gr.cve_id = %s
              AND gr.status = 'completed'
              AND gr.response IS NOT NULL
              AND btrim(gr.response) <> ''
            LIMIT 1
            """,
            (cve_id,),
        )
        return row is not None

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
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"exists": {"field": "metrics"}},
                            {"exists": {"field": "published"}}
                        ]
                    }
                },
                "sort": [
                    {"published": {"order": "desc"}}
                ],
                "size": limit,
                "_source": True
            }

            response = self.opensearch_client.client.search(
                index="cve",
                body=query
            )

            hits = response.get('hits', {}).get('hits', [])
            candidates: List[Dict[str, Any]] = []

            for hit in hits:
                cve_id = hit.get('_id', '')
                if not cve_id or not cve_id.startswith('CVE-'):
                    continue

                source = hit.get('_source', {})
                cve_id_from_source = source.get('id', cve_id)

                description = ''
                descriptions = source.get('descriptions', [])
                if descriptions and len(descriptions) > 0:
                    description = descriptions[0].get('value', '')

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

                severity = 'UNKNOWN'
                if cvss_score >= 9.0:
                    severity = 'CRITICAL'
                elif cvss_score >= 7.0:
                    severity = 'HIGH'
                elif cvss_score >= 4.0:
                    severity = 'MEDIUM'
                elif cvss_score > 0:
                    severity = 'LOW'

                published = source.get('published', '')

                if cvss_score <= 0:
                    continue

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

                if candidate['description'] and len(candidate['description']) > 200:
                    candidate['description'] = candidate['description'][:200] + "..."

                candidates.append(candidate)

            logger.info(f"Found {len(candidates)} candidate CVEs from OpenSearch cve index with Phase 1 filters")
            return candidates

        except Exception as e:
            logger.error(f"Failed to query OpenSearch cve index: {e}")
            self.results["error"] = str(e)
            return []

    def query_opensearch_cve_index_paged(self, size: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """
        Query OpenSearch cve index for one page of candidate CVEs.
        """
        logger.info(f"Querying OpenSearch cve index for candidate CVEs (size: {size}, offset: {offset}).")

        try:
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"exists": {"field": "metrics"}},
                            {"exists": {"field": "published"}}
                        ]
                    }
                },
                "sort": [
                    {"published": {"order": "desc"}}
                ],
                "from": offset,
                "size": size,
                "_source": True
            }

            response = self.opensearch_client.client.search(
                index="cve",
                body=query
            )

            hits = response.get("hits", {}).get("hits", [])
            candidates = []

            for hit in hits:
                cve_id = hit.get("_id", "")
                if not cve_id or not cve_id.startswith("CVE-"):
                    continue

                source = hit.get("_source", {})
                cve_id_from_source = source.get("id", cve_id)

                description = ""
                descriptions = source.get("descriptions", [])
                if descriptions and len(descriptions) > 0:
                    description = descriptions[0].get("value", "")

                cvss_score = 0.0
                metrics = source.get("metrics", {})
                if "cvssMetricV40" in metrics and metrics["cvssMetricV40"]:
                    cvss_data = metrics["cvssMetricV40"][0].get("cvssData", {})
                    cvss_score = float(cvss_data.get("baseScore", 0.0))
                elif "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                    cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                    cvss_score = float(cvss_data.get("baseScore", 0.0))
                elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
                    cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
                    cvss_score = float(cvss_data.get("baseScore", 0.0))
                elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                    cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
                    cvss_score = float(cvss_data.get("baseScore", 0.0))

                severity = "UNKNOWN"
                if cvss_score >= 9.0:
                    severity = "CRITICAL"
                elif cvss_score >= 7.0:
                    severity = "HIGH"
                elif cvss_score >= 4.0:
                    severity = "MEDIUM"
                elif cvss_score > 0:
                    severity = "LOW"

                published = source.get("published", "")

                if cvss_score <= 0:
                    continue

                if severity == "UNKNOWN":
                    continue

                candidate = {
                    "cve_id": cve_id_from_source,
                    "description": description[:200] + "." if description and len(description) > 200 else description,
                    "published": published,
                    "cvss_score": cvss_score,
                    "severity": severity,
                    "index": hit.get("_index", "cve"),
                    "source_fields": list(source.keys())
                }

                candidates.append(candidate)

            logger.info(f"Found {len(candidates)} candidate CVEs from OpenSearch cve index page")
            return candidates

        except Exception as e:
            logger.error(f"Failed to query OpenSearch cve index page: {e}")
            return []

    def _check_postgresql_state_corrected(self, cve_id: str) -> Tuple[bool, List[str], str]:
        """
        Check database state for a CVE with corrected Phase 1 filters.

        Corrected filters:
        1. Exclude if already exists in production table: vulnstrike.public.playbooks
        2. Exclude if approved_playbook exists
        3. Exclude if generation_run exists with terminal success:
           - gr.status = completed
           - gr.response has content
           - qa.qa_result = approved
        4. Exclude if active lock exists
        5. Exclude if in-progress queue state exists
        6. Exclude test/synthetic CVE IDs

        Do NOT exclude solely because:
        - it exists in generation_runs
        - it has failed generation history
        - it has partial pipeline history
        - QA result was None
        - parser previously failed
        """
        filter_reasons: List[str] = []
        exclusion_category: Optional[str] = None

        # 1. HARD EXCLUDE — already exists in real production playbook store
        exists_in_production = self.production_db.fetch_one(
            """
            SELECT EXISTS (
                SELECT 1
                FROM public.playbooks
                WHERE cve_id = %s
            ) AS exists_in_production
            """,
            (cve_id,)
        )

        if exists_in_production and exists_in_production.get("exists_in_production"):
            filter_reasons.append("Already exists in production playbooks (vulnstrike.public.playbooks)")
            exclusion_category = "excluded_already_in_production"
            return False, filter_reasons, exclusion_category

        # 2. Check if already has approved playbook in workflow DB
        has_approved = self.db.fetch_one(
            """
            SELECT EXISTS (
                SELECT 1
                FROM approved_playbooks ap
                JOIN generation_runs gr ON ap.generation_run_id = gr.id
                WHERE gr.cve_id = %s
            ) AS has_approved
            """,
            (cve_id,)
        )

        if has_approved and has_approved.get("has_approved"):
            filter_reasons.append("Already has approved playbook")
            exclusion_category = "excluded_already_approved"
            return False, filter_reasons, exclusion_category

        # 3. Check if has existing generated playbook (completed + non-empty response)
        if self._has_existing_generated_playbook(cve_id):
            filter_reasons.append("Has existing generated playbook (completed + non-empty response)")
            exclusion_category = "excluded_successful_generation_exists"
            return False, filter_reasons, exclusion_category

        # 4. Check if in-progress queue state exists
        try:
            in_progress_queue = self.db.fetch_one(
                """
                SELECT EXISTS (
                    SELECT 1
                    FROM cve_queue
                    WHERE cve_id = %s
                      AND status IN ('processing', 'pending')
                ) AS in_progress_queue
                """,
                (cve_id,)
            )

            if in_progress_queue and in_progress_queue.get("in_progress_queue"):
                filter_reasons.append("In-progress queue state exists")
                exclusion_category = "excluded_in_progress_queue"
                return False, filter_reasons, exclusion_category
        except Exception as e:
            logger.debug(f"Could not check cve_queue for {cve_id}: {e}")

        # 5. Check if active lock exists
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
                ) AS has_active_lock
                """,
                (cve_id,)
            )

            if has_active_lock and has_active_lock.get("has_active_lock"):
                filter_reasons.append("Active lock exists")
                exclusion_category = "excluded_active_lock"
                return False, filter_reasons, exclusion_category
        except Exception as e:
            logger.debug(f"Could not check active locks for {cve_id}: {e}")

        # 6. Exclude test/synthetic CVE patterns
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

        filter_reasons.append("Passed all corrected Phase 1 database filters")
        return True, filter_reasons, "eligible"

    def filter_against_postgresql_corrected(
        self,
        candidates: List[Dict[str, Any]]
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Filter candidates against database state with corrected Phase 1 filters.
        """
        logger.info(f"Filtering {len(candidates)} candidates against PostgreSQL state with CORRECTED Phase 1 filters...")

        eligible: List[Dict[str, Any]] = []
        filtered_out: List[Dict[str, Any]] = []

        for candidate in candidates:
            cve_id = candidate["cve_id"]

            is_eligible, filter_reasons, exclusion_category = self._check_postgresql_state_corrected(cve_id)

            if is_eligible:
                candidate["filter_reasons"] = filter_reasons
                candidate["exclusion_category"] = None
                eligible.append(candidate)
            else:
                candidate["filter_reasons"] = filter_reasons
                candidate["exclusion_category"] = exclusion_category
                filtered_out.append(candidate)

                if exclusion_category and exclusion_category in self.results["exclusion_counts"]:
                    self.results["exclusion_counts"][exclusion_category] += 1

        logger.info(f"After CORRECTED PostgreSQL filtering: {len(eligible)} eligible, {len(filtered_out)} filtered out")
        return eligible, filtered_out

    def _severity_to_numeric(self, severity: str) -> int:
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

        Sorting:
        1. severity descending
        2. CVSS descending
        3. published descending
        """
        if not eligible_candidates:
            logger.warning("No eligible candidates to select from")
            return None

        sorted_candidates = sorted(
            eligible_candidates,
            key=lambda x: (
                -self._severity_to_numeric(x.get('severity', 'UNKNOWN')),
                -float(x.get('cvss_score', 0.0) or 0.0),
                -(datetime.fromisoformat(x.get('published', '1970-01-01T00:00:00Z').replace('Z', '+00:00')).timestamp() if x.get('published') else 0)
            )
        )

        selected = sorted_candidates[0]
        logger.info(
            f"Selected CVE: {selected['cve_id']} "
            f"(Severity: {selected.get('severity', 'N/A')}, "
            f"CVSS: {selected.get('cvss_score', 0.0)}, "
            f"Published: {selected.get('published', 'N/A')})"
        )

        severity = selected.get('severity', 'UNKNOWN')
        cvss_score = selected.get('cvss_score', 0.0) or 0.0
        published = selected.get('published', 'N/A')
        selection_reason = [
            f"Highest severity among eligible candidates: {severity}",
            f"CVSS score: {cvss_score}",
            f"Published date: {published}"
        ]

        selected["selection_reason"] = selection_reason
        return selected

    def run_selection_corrected(self, limit: int = 100) -> Dict[str, Any]:
        """
        Run complete corrected Phase 1 selection process with paged scanning.
        
        Note: The 'limit' parameter is kept for backward compatibility but is ignored.
        The new paged scanning logic uses fixed parameters:
        - Scan OpenSearch in pages (batches of 100)
        - Continue scanning until we have at least 10 eligible CVEs OR we've scanned 1000 total rows
        - Preserve all exclusion rules
        """
        logger.info("Starting CORRECTED Phase 1 CVE selection with paged scanning...")
        
        page_size = 100
        max_total_scanned = 1000
        min_eligible_needed = 10
        
        all_candidates = []
        all_eligible = []
        all_filtered = []
        
        offset = 0
        total_scanned = 0
        
        logger.info(f"Starting paged scan: page_size={page_size}, max_total_scanned={max_total_scanned}, min_eligible_needed={min_eligible_needed}")
        
        while total_scanned < max_total_scanned and len(all_eligible) < min_eligible_needed:
            logger.info(f"Scanning page at offset {offset}...")
            
            page_candidates = self.query_opensearch_cve_index_paged(size=page_size, offset=offset)
            
            if not page_candidates:
                logger.info("No more candidates returned from OpenSearch")
                break
            
            all_candidates.extend(page_candidates)
            
            # Filter this page against PostgreSQL
            page_eligible, page_filtered = self.filter_against_postgresql_corrected(page_candidates)
            all_eligible.extend(page_eligible)
            all_filtered.extend(page_filtered)
            
            offset += len(page_candidates)
            total_scanned += len(page_candidates)
            
            logger.info(f"Page scan complete: {len(page_candidates)} candidates, {len(page_eligible)} eligible, {len(page_filtered)} filtered")
            logger.info(f"Cumulative: {total_scanned} total scanned, {len(all_eligible)} eligible so far")
        
        logger.info(f"Paged scan complete: scanned {total_scanned} total candidates, found {len(all_eligible)} eligible candidates")
        
        # Update results with full scanned set
        self.results["number_of_candidates_returned_from_opensearch"] = len(all_candidates)
        self.results["candidates_from_opensearch"] = all_candidates
        
        self.results["candidates_fetched"] = len(all_candidates)
        self.results["candidates_considered"] = len(all_candidates)
        
        if not all_candidates:
            logger.error("No candidates returned from OpenSearch cve index after paged scanning")
            return self.results
        
        self.results["number_filtered_out_by_postgres"] = len(all_filtered)
        self.results["filtered_candidates"] = all_filtered
        self.results["eligible_candidates"] = all_eligible
        
        self.results["filtered_out"] = len(all_filtered)
        self.results["candidates_filtered"] = len(all_filtered)
        self.results["eligible_count"] = len(all_eligible)
        
        # Add scanning metadata
        self.results["scanning_metadata"] = {
            "page_size": page_size,
            "max_total_scanned": max_total_scanned,
            "min_eligible_needed": min_eligible_needed,
            "total_scanned": total_scanned,
            "pages_scanned": offset // page_size,
            "scanning_stopped_reason": "reached_max_scanned" if total_scanned >= max_total_scanned else "found_enough_eligible" if len(all_eligible) >= min_eligible_needed else "no_more_candidates"
        }
        
        selected_cve = self.select_fresh_cve_phase1(all_eligible)
        
        if selected_cve:
            self.results["selected_cve"] = selected_cve["cve_id"]
            self.results["reason_selected"] = selected_cve.get("selection_reason", [])
            logger.info(f"Successfully selected CVE: {selected_cve['cve_id']}")
        else:
            logger.warning("No CVE selected from eligible candidates")
        
        return self.results

    def print_results(self, output_json: bool = False):
        if output_json:
            print(json.dumps(self.results, indent=2, default=str))
            return

        print("\n" + "=" * 80)
        print("CORRECTED PHASE 1 CVE SELECTION RESULTS (WITH PAGED SCANNING)")
        print("=" * 80)
        print(f"Timestamp (UTC): {self.results['timestamp_utc']}")
        print(f"Candidates from OpenSearch: {self.results.get('number_of_candidates_returned_from_opensearch', 0)}")
        print(f"Filtered out by PostgreSQL: {self.results.get('number_filtered_out_by_postgres', 0)}")
        print(f"Eligible candidates: {len(self.results.get('eligible_candidates', []))}")

        # Display scanning metadata if available
        if "scanning_metadata" in self.results:
            scanning = self.results["scanning_metadata"]
            print("\nSCANNING METADATA:")
            print("-" * 40)
            print(f"  Total scanned: {scanning.get('total_scanned', 0)}")
            print(f"  Pages scanned: {scanning.get('pages_scanned', 0)}")
            print(f"  Stopped reason: {scanning.get('scanning_stopped_reason', 'unknown')}")
            print(f"  Page size: {scanning.get('page_size', 100)}")
            print(f"  Max scan limit: {scanning.get('max_total_scanned', 1000)}")
            print(f"  Min eligible needed: {scanning.get('min_eligible_needed', 10)}")

        print("\nEXCLUSION COUNTS (Corrected Policy):")
        print("-" * 40)
        for category, count in self.results["exclusion_counts"].items():
            print(f"  {category}: {count}")

        if self.results["selected_cve"]:
            print(f"\nSELECTED CVE: {self.results['selected_cve']}")
            print("-" * 40)
            print("Selection Reasons:")
            for reason in self.results.get("reason_selected", []):
                print(f"  • {reason}")
        else:
            print("\nNO CVE SELECTED")

        if self.results.get("filtered_candidates"):
            print("\nTop 5 Filtered Out Candidates (with corrected exclusion categories):")
            for i, candidate in enumerate(self.results["filtered_candidates"][:5], 1):
                reasons = candidate.get("filter_reasons", ["Unknown"])
                category = candidate.get("exclusion_category", "unknown")
                print(f"  {i}. {candidate['cve_id']}: {category} - {', '.join(reasons)}")

        print("=" * 80)


def test_against_recent_candidates():
    """Test the corrected selector against the recent 100-candidate set."""
    logger.info("Testing corrected selector against recent 100-candidate set...")

    metadata_path = Path("logs/runs/556732eb-e36e-4371-8f5b-a1dc78c53343-run-0010/metadata.json")
    if not metadata_path.exists():
        logger.error(f"Metadata file not found: {metadata_path}")
        return None

    with open(metadata_path, 'r') as f:
        metadata = json.load(f)

    selection_data = metadata.get("metadata", {}).get("selection_data", {})
    candidates = selection_data.get("candidates_from_opensearch", [])

    if not candidates:
        logger.error("No candidates found in metadata")
        return None

    logger.info(f"Loaded {len(candidates)} candidates from recent run")

    selector = Phase1CVESelectorCorrected()
    eligible, filtered = selector.filter_against_postgresql_corrected(candidates)

    comparison = {
        "original_run_timestamp": metadata.get("captured_at"),
        "original_candidates_count": len(candidates),
        "corrected_filtered_count": len(filtered),
        "corrected_eligible_count": len(eligible),
        "exclusion_counts": selector.results["exclusion_counts"],
        "top_eligible_candidates": [
            {
                "cve_id": c.get("cve_id"),
                "severity": c.get("severity"),
                "cvss_score": c.get("cvss_score"),
                "published": c.get("published")
            }
            for c in eligible[:10]
        ],
        "top_filtered_candidates": [
            {
                "cve_id": c.get("cve_id"),
                "exclusion_category": c.get("exclusion_category"),
                "filter_reasons": c.get("filter_reasons", [])
            }
            for c in filtered[:10]
        ]
    }

    return comparison


def main():
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
        comparison = test_against_recent_candidates()
        if comparison:
            print(json.dumps(comparison, indent=2, default=str))
        else:
            print("Test failed")
        return

    selector = Phase1CVESelectorCorrected()
    selector.run_selection_corrected(args.limit)
    selector.print_results(args.json)


if __name__ == "__main__":
    main()