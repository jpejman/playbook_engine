#!/usr/bin/env python3
"""
Context Snapshot Builder - Auto-build context snapshot for CVE
Version: v0.1.0
Timestamp: 2026-04-08

Purpose:
- Build and persist a context snapshot for one CVE using available source data
- Use discovery source data from vulnstrike database
- Use OpenSearch enrichment if useful
- Only create snapshot when enough real data exists
- Report readiness status: ready, auto_built, blocked_missing_context

Required behavior:
1. Assert DB targets
2. Accept --cve parameter
3. Inspect whether snapshot already exists
4. If exists and usable, report 'ready'
5. If missing, gather source fields from available sources
6. Construct normalized context object
7. Persist to context snapshot table if minimum fields exist
8. Report 'auto_built' or 'blocked_missing_context'

Hard rule: Do not call generation in this script.
"""

import os
import sys
import json
import logging
import argparse
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
from datetime import datetime

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.utils.db import get_database_client, assert_expected_database
from src.retrieval.vulnstrike_db_client import VulnstrikeDBClient
from src.retrieval.opensearch_client import RealOpenSearchClient
from scripts.prod.time_utils import get_utc_now, datetime_to_iso

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class ContextSnapshotBuilder:
    """Build context snapshot for CVE from available source data."""
    
    def __init__(self):
        self.db = get_database_client()
        self.vulnstrike_db = VulnstrikeDBClient()
        self.opensearch_client = RealOpenSearchClient()
        self.cve_id = None
        self.results = {
            "timestamp": datetime_to_iso(get_utc_now()),
            "cve_id": None,
            "readiness_status": None,
            "context_snapshot_id": None,
            "context_data": None,
            "build_source": [],
            "error": None
        }
        
        logger.info("ContextSnapshotBuilder initialized")
    
    def assert_database_target(self):
        """Assert connected to correct database."""
        logger.info("Verifying database target...")
        assert_expected_database('playbook_engine')
        logger.info("Connected to playbook_engine")
    
    def check_existing_snapshot(self, cve_id: str) -> Tuple[Optional[int], Optional[Dict]]:
        """
        Check if context snapshot already exists and is usable.
        
        Returns:
            Tuple of (snapshot_id, context_data) or (None, None) if not found/invalid
        """
        logger.info(f"Checking for existing context snapshot for {cve_id}...")
        
        snapshot = self.db.fetch_one(
            "SELECT id, context_data FROM cve_context_snapshot WHERE cve_id = %s",
            (cve_id,)
        )
        
        if not snapshot:
            logger.info(f"No existing context snapshot found for {cve_id}")
            return None, None
        
        snapshot_id = snapshot['id']
        context_data = snapshot['context_data']
        
        # Validate the existing snapshot has minimum required fields
        if self._validate_context_data(context_data):
            logger.info(f"Found valid existing context snapshot ID: {snapshot_id}")
            return snapshot_id, context_data
        else:
            logger.warning(f"Existing context snapshot {snapshot_id} is invalid - missing required fields")
            return None, None
    
    def _validate_context_data(self, context_data: Dict) -> bool:
        """
        Validate context data has minimum required fields and is not placeholder.
        
        Minimum required:
        - cve_id: Must match target CVE
        - description: Non-empty string
        
        Also checks for placeholder/synthetic content.
        
        Returns:
            True if valid, False otherwise
        """
        if not isinstance(context_data, dict):
            logger.warning(f"Context data is not a dict: {type(context_data)}")
            return False
        
        # Check cve_id matches
        cve_id = context_data.get('cve_id')
        if cve_id != self.cve_id:
            logger.warning(f"Context data cve_id mismatch: {cve_id} != {self.cve_id}")
            return False
        
        # Check description exists and is non-empty
        description = context_data.get('description', '')
        if not description or not isinstance(description, str) or description.strip() == '':
            logger.warning(f"Missing or empty description in context data")
            return False
        
        # Check for placeholder content
        if self._contains_placeholder_content(context_data):
            logger.warning(f"Context data contains placeholder/synthetic content")
            return False
        
        return True
    
    def _contains_placeholder_content(self, context_data: Dict) -> bool:
        """
        Check if context data contains placeholder/synthetic content.
        
        Returns:
            True if placeholder content detected, False otherwise
        """
        # Placeholder indicators (similar to canonical validator)
        placeholder_indicators = {
            "vendor": ["test vendor", "example vendor", "demo vendor", "placeholder vendor"],
            "product": ["test product", "example product", "demo product", "placeholder product"],
            "description": ["test vulnerability", "for demonstration", "example description", "placeholder description"],
            "versions": ["1.0.0", "1.1.0", "1.2.0", "2.0.0", "2.1.0"],  # Generic version patterns
            "cve_references": ["cve-test", "example.com", "test-cve", "placeholder-cve"]
        }
        
        # Check vendor field
        vendor = str(context_data.get("vendor", "")).lower()
        for indicator in placeholder_indicators["vendor"]:
            if indicator in vendor:
                logger.warning(f"Vendor field contains placeholder: '{context_data.get('vendor')}'")
                return True
        
        # Check product field
        product = str(context_data.get("product", "")).lower()
        for indicator in placeholder_indicators["product"]:
            if indicator in product:
                logger.warning(f"Product field contains placeholder: '{context_data.get('product')}'")
                return True
        
        # Check description field
        description = str(context_data.get("description", "")).lower()
        for indicator in placeholder_indicators["description"]:
            if indicator in description:
                logger.warning(f"Description contains placeholder phrase: '{indicator}'")
                return True
        
        # Check affected_versions and fixed_versions
        for version_field in ["affected_versions", "fixed_versions"]:
            if version_field in context_data and isinstance(context_data[version_field], list):
                for version in context_data[version_field]:
                    version_str = str(version).lower()
                    for indicator in placeholder_indicators["versions"]:
                        if version_str == indicator:
                            logger.warning(f"Version {version} in {version_field} appears generic/placeholder")
                            return True
        
        # Check references
        if "references" in context_data and isinstance(context_data["references"], list):
            for ref in context_data["references"]:
                ref_str = str(ref).lower()
                for indicator in placeholder_indicators["cve_references"]:
                    if indicator in ref_str:
                        logger.warning(f"Reference contains placeholder: '{ref}'")
                        return True
        
        return False
    
    def gather_source_data(self, cve_id: str) -> Dict[str, Any]:
        """
        Gather source data from all available sources.
        
        Sources:
        1. Vulnstrike database (primary)
        2. OpenSearch (enrichment)
        
        Returns:
            Combined source data dict
        """
        logger.info(f"Gathering source data for {cve_id}...")
        
        source_data = {
            "cve_id": cve_id,
            "sources_used": [],
            "vulnstrike_data": None,
            "opensearch_data": None
        }
        
        # 1. Get data from vulnstrike database
        vulnstrike_data = self._get_vulnstrike_data(cve_id)
        if vulnstrike_data:
            source_data["vulnstrike_data"] = vulnstrike_data
            source_data["sources_used"].append("vulnstrike")
            logger.info(f"Found vulnstrike data for {cve_id}")
        else:
            logger.warning(f"No vulnstrike data found for {cve_id}")
        
        # 2. Get enrichment data from OpenSearch
        opensearch_data = self._get_opensearch_data(cve_id)
        if opensearch_data:
            source_data["opensearch_data"] = opensearch_data
            source_data["sources_used"].append("opensearch")
            logger.info(f"Found OpenSearch data for {cve_id}")
        else:
            logger.info(f"No OpenSearch data found for {cve_id}")
        
        return source_data
    
    def _get_vulnstrike_data(self, cve_id: str) -> Optional[Dict]:
        """Get CVE data from vulnstrike database."""
        try:
            with self.vulnstrike_db._create_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT cve_id, published, description, metrics, vuln_status, 
                               last_modified, source_identifier
                        FROM nvd_cve_data 
                        WHERE cve_id = %s
                        """,
                        (cve_id,)
                    )
                    result = cur.fetchone()
            
            if result:
                return {
                    "cve_id": result[0],
                    "published": result[1],
                    "description": result[2],
                    "metrics": result[3],
                    "vuln_status": result[4],
                    "last_modified": result[5],
                    "source_identifier": result[6]
                }
            else:
                return None
                
        except Exception as e:
            logger.error(f"Failed to get vulnstrike data for {cve_id}: {e}")
            return None
    
    def _get_opensearch_data(self, cve_id: str) -> Optional[Dict]:
        """Get enrichment data from OpenSearch."""
        try:
            # Search for exact CVE match in OpenSearch
            hits = self.opensearch_client.search_cve_exact(cve_id)
            
            if hits:
                # Take the first (most relevant) hit
                hit = hits[0]
                return {
                    "score": hit.get('score', 0),
                    "source": hit.get('source', {}),
                    "index": hit.get('index', 'unknown'),
                    "title": hit.get('title', ''),
                    "content": hit.get('content', ''),
                    "metadata": hit.get('metadata', {})
                }
            else:
                return None
                
        except Exception as e:
            logger.warning(f"OpenSearch query failed for {cve_id}: {e}")
            return None
    
    def build_context_from_source_data(self, source_data: Dict) -> Optional[Dict]:
        """
        Build normalized context object from source data.
        
        Returns:
            Normalized context dict or None if insufficient data
        """
        logger.info("Building normalized context from source data...")
        
        # Try to get data from vulnstrike first, then OpenSearch
        vulnstrike_data = source_data.get('vulnstrike_data')
        opensearch_data = source_data.get('opensearch_data')
        
        # Determine which data source to use
        use_opensearch = False
        data_source = None
        
        if vulnstrike_data:
            data_source = vulnstrike_data
            source_name = "vulnstrike"
        elif opensearch_data:
            data_source = opensearch_data
            source_name = "opensearch"
            use_opensearch = True
        else:
            logger.error("No source data available - cannot build context")
            return None
        
        # Extract description - this is the minimum required field
        description = ''
        if use_opensearch:
            # For OpenSearch data, description is in 'content' field
            description = data_source.get('content', '')
        else:
            # For vulnstrike data, description is in 'description' field
            description = data_source.get('description', '')
        
        if not description or description.strip() == '':
            logger.error(f"No description available in {source_name} data - cannot build context")
            return None
        
        # Start building context with defaults
        context = {
            "cve_id": self.cve_id,
            "description": description.strip(),
            "published_date": "",
            "last_modified_date": "",
            "cvss_score": 0.0,
            "severity": "UNKNOWN",
            "vulnerability_type": "Unknown",
            "cwe": "NVD-CWE-noinfo",
            "attack_vector": "NETWORK",
            "attack_complexity": "MEDIUM",
            "privileges_required": "NONE",
            "user_interaction": "NONE",
            "scope": "UNCHANGED",
            "confidentiality_impact": "HIGH",
            "integrity_impact": "HIGH",
            "availability_impact": "HIGH",
            "affected_products": [],
            "references": []
        }
        
        # Extract metadata from OpenSearch data if available
        if use_opensearch:
            metadata = data_source.get('metadata', {})
            context["published_date"] = str(metadata.get('published', ''))
            context["last_modified_date"] = str(metadata.get('lastModified', metadata.get('published', '')))
            context["cvss_score"] = float(metadata.get('cvss_score', 0.0))
            context["severity"] = metadata.get('severity', 'UNKNOWN')
            
            # Extract CWE from metadata if available
            cwe = metadata.get('cwe', '')
            if cwe:
                context["cwe"] = cwe
            
            # For OpenSearch data, we don't have detailed CVSS metrics
            # Use severity to infer some fields
            if context["severity"] == "CRITICAL":
                context["confidentiality_impact"] = "HIGH"
                context["integrity_impact"] = "HIGH"
                context["availability_impact"] = "HIGH"
            elif context["severity"] == "HIGH":
                context["confidentiality_impact"] = "HIGH"
                context["integrity_impact"] = "HIGH"
                context["availability_impact"] = "HIGH"
            elif context["severity"] == "MEDIUM":
                context["confidentiality_impact"] = "LOW"
                context["integrity_impact"] = "LOW"
                context["availability_impact"] = "LOW"
        
        else:
            # Use vulnstrike data
            context["published_date"] = str(data_source.get('published', ''))
            context["last_modified_date"] = str(data_source.get('last_modified', data_source.get('published', '')))
            
            # Try to extract CVSS data from metrics
            metrics = data_source.get('metrics')
            if metrics:
                try:
                    # Try to get CVSS v3.1 data
                    if isinstance(metrics, dict) and "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                        cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                        context["cvss_score"] = cvss_data.get("baseScore", 0.0)
                        context["severity"] = cvss_data.get("baseSeverity", "UNKNOWN")
                        
                        # Map CVSS metrics to our fields
                        cvss_mapping = {
                            "attackVector": "attack_vector",
                            "attackComplexity": "attack_complexity",
                            "privilegesRequired": "privileges_required",
                            "userInteraction": "user_interaction",
                            "scope": "scope",
                            "confidentialityImpact": "confidentiality_impact",
                            "integrityImpact": "integrity_impact",
                            "availabilityImpact": "availability_impact"
                        }
                        
                        for cvss_key, our_key in cvss_mapping.items():
                            if cvss_key in cvss_data:
                                context[our_key] = cvss_data[cvss_key].upper()
                                
                except Exception as e:
                    logger.warning(f"Failed to parse CVSS metrics: {e}")
        
        # Add build metadata
        context["context_build_metadata"] = {
            "build_source": source_data.get('sources_used', []),
            "build_status": "auto_built",
            "build_timestamp": datetime_to_iso(get_utc_now()),
            "data_source": source_name
        }
        
        logger.info(f"Built context with {len(context)} fields from {source_name}")
        return context
    
    def persist_context_snapshot(self, context_data: Dict) -> Optional[int]:
        """Persist context snapshot to database."""
        logger.info("Persisting context snapshot to database...")
        
        try:
            with self.db.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO cve_context_snapshot (cve_id, context_data, confidence_score)
                        VALUES (%s, %s, %s)
                        RETURNING id
                        """,
                        (
                            self.cve_id,
                            json.dumps(context_data),
                            1.0  # Default confidence for auto-built
                        )
                    )
                    result = cur.fetchone()
                    conn.commit()
            
            if result:
                snapshot_id = result[0]
                logger.info(f"Created context snapshot ID: {snapshot_id}")
                return snapshot_id
            else:
                logger.error("Failed to get snapshot ID from database")
                return None
                
        except Exception as e:
            logger.error(f"Failed to persist context snapshot: {e}")
            return None
    
    def build_context_snapshot(self, cve_id: str) -> Dict[str, Any]:
        """
        Build context snapshot for CVE.
        
        Returns:
            Results dict with readiness status and details
        """
        self.cve_id = cve_id
        self.results['cve_id'] = cve_id
        
        logger.info(f"BUILD CONTEXT SNAPSHOT FOR {cve_id}")
        logger.info("=" * 60)
        
        try:
            # Step 1: Assert database target
            self.assert_database_target()
            
            # Step 2: Check for existing valid snapshot
            snapshot_id, context_data = self.check_existing_snapshot(cve_id)
            
            if snapshot_id and context_data:
                # Existing valid snapshot found
                self.results['readiness_status'] = 'ready'
                self.results['context_snapshot_id'] = snapshot_id
                self.results['context_data'] = context_data
                self.results['build_source'] = ['existing']
                logger.info(f"Context snapshot ready (existing ID: {snapshot_id})")
                return self.results
            
            # Step 3: Gather source data
            source_data = self.gather_source_data(cve_id)
            
            # Step 4: Build context from source data
            context_data = self.build_context_from_source_data(source_data)
            
            if not context_data:
                # Insufficient data to build context
                self.results['readiness_status'] = 'blocked_missing_context'
                self.results['error'] = 'Insufficient source data to build context (missing description)'
                logger.error(f"Context blocked: {self.results['error']}")
                return self.results
            
            # Step 5: Persist context snapshot
            snapshot_id = self.persist_context_snapshot(context_data)
            
            if snapshot_id:
                # Successfully built and persisted
                self.results['readiness_status'] = 'auto_built'
                self.results['context_snapshot_id'] = snapshot_id
                self.results['context_data'] = context_data
                self.results['build_source'] = source_data.get('sources_used', [])
                logger.info(f"Context snapshot auto-built (ID: {snapshot_id})")
            else:
                # Failed to persist
                self.results['readiness_status'] = 'blocked_missing_context'
                self.results['error'] = 'Failed to persist context snapshot'
                logger.error(f"Context blocked: {self.results['error']}")
            
            return self.results
            
        except Exception as e:
            logger.error(f"Context snapshot build failed: {e}")
            import traceback
            traceback.print_exc()
            
            self.results['readiness_status'] = 'blocked_missing_context'
            self.results['error'] = str(e)
            return self.results
    
    def print_summary(self):
        """Print build summary."""
        print("\n" + "=" * 80)
        print("CONTEXT SNAPSHOT BUILDER - SUMMARY")
        print("=" * 80)
        print(f"Timestamp: {self.results['timestamp']}")
        print(f"CVE ID: {self.results['cve_id']}")
        print(f"Readiness Status: {self.results['readiness_status']}")
        
        if self.results['context_snapshot_id']:
            print(f"Context Snapshot ID: {self.results['context_snapshot_id']}")
        
        if self.results['build_source']:
            print(f"Build Source: {', '.join(self.results['build_source'])}")
        
        if self.results['error']:
            print(f"Error: {self.results['error']}")
        
        if self.results['context_data']:
            print(f"\nContext Data Fields:")
            context = self.results['context_data']
            print(f"  Description: {context.get('description', '')[:100]}...")
            print(f"  CVSS Score: {context.get('cvss_score', 'N/A')}")
            print(f"  CWE: {context.get('cwe', 'N/A')}")
            print(f"  Attack Vector: {context.get('attack_vector', 'N/A')}")
            print(f"  Fields Total: {len(context)}")
        
        print("=" * 80)


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(description='Build context snapshot for CVE')
    parser.add_argument('--cve', required=True, help='CVE ID to build context snapshot for')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('--json', action='store_true', help='Output JSON only')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Run builder
    builder = ContextSnapshotBuilder()
    results = builder.build_context_snapshot(args.cve)
    
    if args.json:
        # Output JSON only
        print(json.dumps(results, indent=2))
    else:
        # Print summary
        builder.print_summary()
    
    # Exit code based on readiness status
    if results['readiness_status'] in ['ready', 'auto_built']:
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()