"""
CVE selector for evaluation framework v0.3.0
Version: v0.3.0
"""

from __future__ import annotations

import logging
from typing import List, Optional
import random

from scripts.prod.continuous_pipeline_v0_3_0.config import ContinuousPipelineConfig
from scripts.prod.continuous_pipeline_v0_3_0.db_clients import PlaybookEngineClient
from scripts.prod.continuous_pipeline_v0_3_0.opensearch_client import OpenSearchClient

logger = logging.getLogger(__name__)


class EvaluationSelector:
    """Selects CVEs for evaluation from various sources."""
    
    def __init__(self):
        self.db = PlaybookEngineClient()
        self.opensearch = OpenSearchClient()
        
    def select_from_queue(self, limit: int = 1) -> List[str]:
        """
        Select CVEs from the queue.
        
        Args:
            limit: Maximum number of CVEs to select
            
        Returns:
            List of CVE IDs
        """
        logger.info(f"Selecting {limit} CVEs from queue")
        
        query = """
            SELECT cve_id 
            FROM public.cve_queue 
            WHERE status = 'pending'
            ORDER BY created_at ASC
            LIMIT %s
        """
        
        results = self.db.execute(query, (limit,))
        cves = [row[0] for row in results] if results else []
        
        logger.info(f"Selected {len(cves)} CVEs from queue: {cves}")
        return cves
    
    def select_from_opensearch(self, limit: int = 1) -> List[str]:
        """
        Select CVEs directly from OpenSearch.
        
        Args:
            limit: Maximum number of CVEs to select
            
        Returns:
            List of CVE IDs
        """
        logger.info(f"Selecting {limit} CVEs from OpenSearch")
        
        try:
            # Query OpenSearch for recent CVEs
            query = {
                "size": limit,
                "sort": [
                    {"published": {"order": "desc"}}
                ],
                "_source": ["cve_id"]
            }
            
            response = self.opensearch.search(
                index=ContinuousPipelineConfig.OPENSEARCH_INDEX,
                body=query
            )
            
            cves = []
            if 'hits' in response and 'hits' in response['hits']:
                for hit in response['hits']['hits']:
                    if '_source' in hit and 'cve_id' in hit['_source']:
                        cves.append(hit['_source']['cve_id'])
            
            logger.info(f"Selected {len(cves)} CVEs from OpenSearch: {cves}")
            return cves
            
        except Exception as e:
            logger.error(f"Failed to select CVEs from OpenSearch: {e}")
            return []
    
    def select_from_file(self, file_path: str) -> List[str]:
        """
        Select CVEs from a file.
        
        Args:
            file_path: Path to file containing CVE IDs (one per line)
            
        Returns:
            List of CVE IDs
        """
        logger.info(f"Selecting CVEs from file: {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                cves = [line.strip() for line in f if line.strip()]
            
            logger.info(f"Selected {len(cves)} CVEs from file: {cves}")
            return cves
            
        except Exception as e:
            logger.error(f"Failed to read CVE file {file_path}: {e}")
            return []
    
    def select_random(self, limit: int = 1, exclude_processed: bool = True) -> List[str]:
        """
        Select random CVEs from OpenSearch.
        
        Args:
            limit: Maximum number of CVEs to select
            exclude_processed: Whether to exclude CVEs already in generation_runs
            
        Returns:
            List of CVE IDs
        """
        logger.info(f"Selecting {limit} random CVEs")
        
        try:
            # First get total count
            count_query = {
                "size": 0,
                "query": {"match_all": {}}
            }
            
            count_response = self.opensearch.search(
                index=ContinuousPipelineConfig.OPENSEARCH_INDEX,
                body=count_query
            )
            
            total = count_response.get('hits', {}).get('total', {}).get('value', 0)
            if total == 0:
                logger.warning("No CVEs found in OpenSearch")
                return []
            
            # Get random sample
            random_offset = random.randint(0, max(0, total - limit))
            
            query = {
                "size": limit,
                "from": random_offset,
                "sort": [{"_id": "asc"}],
                "_source": ["cve_id"]
            }
            
            response = self.opensearch.search(
                index=ContinuousPipelineConfig.OPENSEARCH_INDEX,
                body=query
            )
            
            cves = []
            if 'hits' in response and 'hits' in response['hits']:
                for hit in response['hits']['hits']:
                    if '_source' in hit and 'cve_id' in hit['_source']:
                        cves.append(hit['_source']['cve_id'])
            
            # Filter out already processed CVEs if requested
            if exclude_processed and cves:
                processed_cves = self._get_processed_cves(cves)
                cves = [cve for cve in cves if cve not in processed_cves]
            
            logger.info(f"Selected {len(cves)} random CVEs: {cves}")
            return cves
            
        except Exception as e:
            logger.error(f"Failed to select random CVEs: {e}")
            return []
    
    def _get_processed_cves(self, cves: List[str]) -> List[str]:
        """Get CVEs that already have generation runs."""
        if not cves:
            return []
        
        placeholders = ','.join(['%s'] * len(cves))
        query = f"""
            SELECT DISTINCT cve_id 
            FROM public.generation_runs 
            WHERE cve_id IN ({placeholders})
            AND evaluation_mode = FALSE
        """
        
        results = self.db.execute(query, tuple(cves))
        return [row[0] for row in results] if results else []