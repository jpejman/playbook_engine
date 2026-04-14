#!/usr/bin/env python3
"""
Real OpenSearch Client for Playbook Engine Retrieval
Version: v0.2.1-fix
Timestamp: 2026-04-08

Purpose:
- Real retrieval from OpenSearch with normalized hit contract
- Support for exact CVE lookup, keyword query, and vector/hybrid queries
- Normalized output format for evidence aggregation
"""

import os
import logging
import json
from typing import Dict, List, Any, Optional
from opensearchpy import OpenSearch, RequestsHttpConnection
from opensearchpy.exceptions import OpenSearchException

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class RealOpenSearchClient:
    """
    Real OpenSearch client for evidence retrieval.
    
    Features:
    - Load config from environment variables
    - Exact CVE lookup
    - Keyword query
    - Vector/hybrid query support
    - Normalized hit contract
    """
    
    def __init__(self):
        """Initialize OpenSearch client with environment variables."""
        self.base_url = os.getenv('OPENSEARCH_BASE_URL', 'http://10.0.0.50:9200')
        self.username = os.getenv('OPENSEARCH_USERNAME', 'admin')
        self.password = os.getenv('OPENSEARCH_PASSWORD', 'admin')
        self.timeout = int(os.getenv('OPENSEARCH_TIMEOUT_SECONDS', '30'))
        
        # Parse indexes from environment
        indexes_str = os.getenv('OPENSEARCH_INDEXES', 'cve,chat_history,spring-ai-document-index')
        self.indexes = [idx.strip() for idx in indexes_str.split(',')]
        
        # Initialize client
        self.client = self._create_client()
        
    def _create_client(self) -> OpenSearch:
        """Create and return OpenSearch client instance."""
        try:
            # Parse host and port from base URL
            from urllib.parse import urlparse
            parsed = urlparse(self.base_url)
            host = parsed.hostname
            port = parsed.port or 9200
            use_ssl = parsed.scheme == 'https'
            
            client = OpenSearch(
                hosts=[{'host': host, 'port': port}],
                http_auth=(self.username, self.password),
                use_ssl=use_ssl,
                verify_certs=False,  # For development only
                connection_class=RequestsHttpConnection,
                timeout=self.timeout,
                max_retries=3,
                retry_on_timeout=True
            )
            logger.info(f"Real OpenSearch client initialized for {self.base_url}")
            return client
        except Exception as e:
            logger.error(f"Failed to create OpenSearch client: {e}")
            raise
    
    def ping(self) -> bool:
        """Ping the OpenSearch cluster to verify connectivity."""
        try:
            return self.client.ping()
        except OpenSearchException as e:
            logger.error(f"OpenSearch ping failed: {e}")
            return False
    
    def search_cve_exact(self, cve_id: str) -> List[Dict[str, Any]]:
        """
        Search for exact CVE match across configured indexes.
        
        Args:
            cve_id: CVE identifier (e.g., "CVE-TEST-0001")
            
        Returns:
            List of normalized hits
        """
        logger.info(f"Searching for exact CVE: {cve_id}")
        
        normalized_hits = []
        
        for index in self.indexes:
            try:
                logger.debug(f"Searching index {index} for exact CVE: {cve_id}")
                
                # Special handling for 'cve' index where CVE ID is the document _id
                if index == 'cve':
                    # Try to get document by ID first (most efficient)
                    try:
                        response = self.client.get(index=index, id=cve_id)
                        if response.get('found'):
                            hit = {
                                '_id': response['_id'],
                                '_index': response['_index'],
                                '_source': response['_source'],
                                '_score': 1.0  # Exact match gets highest score
                            }
                            normalized = self._normalize_hit(hit, index)
                            if normalized:
                                normalized_hits.append(normalized)
                                logger.info(f"Found exact CVE match in {index} via document ID")
                                continue  # Skip to next index
                    except Exception as e:
                        logger.debug(f"Document get failed for {cve_id} in {index}: {e}")
                        # Fall back to search
                
                # For all indexes, try searching by various fields
                query = {
                    "query": {
                        "bool": {
                            "should": [
                                {"term": {"cve_id": cve_id}},
                                {"term": {"cve_id.keyword": cve_id}},
                                {"match": {"cve_id": cve_id}},
                                {"term": {"id": cve_id}},  # Some indexes use 'id' field
                                {"term": {"id.keyword": cve_id}}
                            ]
                        }
                    },
                    "size": 10
                }
                
                response = self.client.search(
                    index=index,
                    body=query
                )
                
                hits = response.get('hits', {}).get('hits', [])
                logger.info(f"Found {len(hits)} hits in index {index}")
                
                for hit in hits:
                    normalized = self._normalize_hit(hit, index)
                    if normalized:
                        normalized_hits.append(normalized)
                        
            except Exception as e:
                logger.warning(f"Search failed for index {index}: {e}")
                continue
        
        # Sort by score descending
        normalized_hits.sort(key=lambda x: x.get('score', 0), reverse=True)
        
        logger.info(f"Total normalized hits: {len(normalized_hits)}")
        return normalized_hits
    
    def search_keyword(self, keywords: str, fields: List[str] = None) -> List[Dict[str, Any]]:
        """
        Search using keyword query across configured indexes.
        
        Args:
            keywords: Search keywords
            fields: Fields to search (default: ["title", "content", "description"])
            
        Returns:
            List of normalized hits
        """
        logger.info(f"Searching for keywords: {keywords[:50]}...")
        
        if fields is None:
            fields = ["title", "content", "description"]
        
        query = {
            "query": {
                "multi_match": {
                    "query": keywords,
                    "fields": fields,
                    "type": "best_fields",
                    "tie_breaker": 0.3
                }
            },
            "size": 10
        }
        
        return self._execute_search(query, "keyword")
    
    def search_hybrid(self, cve_context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Hybrid search combining CVE context and keywords.
        
        Args:
            cve_context: CVE context dictionary with description, cwe, etc.
            
        Returns:
            List of normalized hits
        """
        logger.info("Performing hybrid search with CVE context")
        
        # Build search terms from CVE context
        search_terms = []
        
        if cve_context.get('description'):
            search_terms.append(cve_context['description'])
        
        if cve_context.get('cwe'):
            search_terms.append(cve_context['cwe'])
        
        if cve_context.get('vulnerability_type'):
            search_terms.append(cve_context['vulnerability_type'])
        
        if cve_context.get('affected_products'):
            for product in cve_context['affected_products'][:3]:  # Limit to first 3 products
                search_terms.append(product)
        
        search_text = " ".join(search_terms)
        
        query = {
            "query": {
                "bool": {
                    "should": [
                        {
                            "multi_match": {
                                "query": search_text,
                                "fields": ["title^2", "content", "description^1.5", "tags"],
                                "type": "best_fields"
                            }
                        },
                        {
                            "match": {
                                "content": {
                                    "query": search_text,
                                    "minimum_should_match": "30%"
                                }
                            }
                        }
                    ]
                }
            },
            "size": 15
        }
        
        return self._execute_search(query, "hybrid")
    
    def _execute_search(self, query: Dict[str, Any], search_type: str) -> List[Dict[str, Any]]:
        """
        Execute search across all configured indexes and normalize results.
        
        Args:
            query: OpenSearch query
            search_type: Type of search for logging
            
        Returns:
            List of normalized hits
        """
        normalized_hits = []
        
        for index in self.indexes:
            try:
                logger.debug(f"Searching index {index} with {search_type} query")
                
                response = self.client.search(
                    index=index,
                    body=query,
                    size=query.get('size', 10)
                )
                
                hits = response.get('hits', {}).get('hits', [])
                logger.info(f"Found {len(hits)} hits in index {index}")
                
                for hit in hits:
                    normalized = self._normalize_hit(hit, index)
                    if normalized:
                        normalized_hits.append(normalized)
                        
            except OpenSearchException as e:
                logger.warning(f"Search failed for index {index}: {e}")
                continue
        
        # Sort by score descending
        normalized_hits.sort(key=lambda x: x.get('score', 0), reverse=True)
        
        logger.info(f"Total normalized hits: {len(normalized_hits)}")
        return normalized_hits
    
    def _normalize_hit(self, hit: Dict[str, Any], source_index: str) -> Optional[Dict[str, Any]]:
        """
        Normalize OpenSearch hit to standard contract.
        
        Contract:
        {
            "doc_id": "...",
            "source_index": "...",
            "score": 12.34,
            "title": "...",
            "content": "...",
            "metadata": {...}
        }
        
        Args:
            hit: Raw OpenSearch hit
            source_index: Source index name
            
        Returns:
            Normalized hit or None if invalid
        """
        try:
            source = hit.get('_source', {})
            doc_id = hit.get('_id', '')
            
            # Special handling for 'cve' index
            if source_index == 'cve':
                # Extract CVE ID from source['id'] or doc_id
                cve_id = source.get('id', doc_id)
                
                # Extract description from descriptions array
                description = ''
                descriptions = source.get('descriptions', [])
                if descriptions and len(descriptions) > 0:
                    description = descriptions[0].get('value', '')
                
                # Extract published date
                published = source.get('published', '')
                
                # Extract CVSS metrics
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
                
                # Calculate severity from CVSS score
                severity = 'UNKNOWN'
                if cvss_score >= 9.0:
                    severity = 'CRITICAL'
                elif cvss_score >= 7.0:
                    severity = 'HIGH'
                elif cvss_score >= 4.0:
                    severity = 'MEDIUM'
                elif cvss_score > 0:
                    severity = 'LOW'
                
                # Use CVE ID as title
                title = cve_id
                content = description
                
                # Build metadata with CVE-specific fields
                metadata = {
                    "source_index": source_index,
                    "hit_type": hit.get('_type', '_doc'),
                    "raw_fields": list(source.keys()),
                    "timestamp": published,
                    "cve_id": cve_id,
                    "severity": severity,
                    "cvss_score": cvss_score,
                    "published": published,
                    "lastModified": source.get('lastModified', ''),
                    "vulnStatus": source.get('vulnStatus', ''),
                    "sourceIdentifier": source.get('sourceIdentifier', ''),
                    "retrieval_source": "opensearch_nvd"
                }
                
                # Add CWE if available
                weaknesses = source.get('weaknesses', [])
                if weaknesses and len(weaknesses) > 0:
                    weakness_desc = weaknesses[0].get('description', [])
                    if weakness_desc and len(weakness_desc) > 0:
                        metadata['cwe'] = weakness_desc[0].get('value', '')
            
            else:
                # Generic handling for other indexes
                # Extract title from various possible fields
                title = source.get('title') or source.get('name') or source.get('cve_id') or doc_id
                
                # Extract content from various possible fields
                content = source.get('content') or source.get('description') or source.get('summary') or ''
                
                # Build metadata
                metadata = {
                    "source_index": source_index,
                    "hit_type": hit.get('_type', '_doc'),
                    "raw_fields": list(source.keys()),
                    "timestamp": source.get('timestamp') or source.get('created_at') or source.get('published_date'),
                    "uri": source.get('uri') or source.get('url') or source.get('reference'),
                    "retrieval_source": "opensearch"
                }
                
                # Add any additional fields that might be useful
                for field in ['cve_id', 'cwe', 'severity', 'cvss_score', 'tags', 'source']:
                    if field in source:
                        metadata[field] = source[field]
            
            normalized = {
                "doc_id": doc_id,
                "source_index": source_index,
                "score": hit.get('_score', 0.0),
                "title": str(title)[:200],  # Truncate long titles
                "content": str(content)[:1000],  # Truncate long content
                "metadata": metadata
            }
            
            return normalized
            
        except Exception as e:
            logger.warning(f"Failed to normalize hit: {e}")
            return None
    
    def get_index_info(self) -> Dict[str, Any]:
        """Get information about all configured indexes."""
        try:
            info = {}
            for index in self.indexes:
                try:
                    stats = self.client.indices.stats(index=index)
                    info[index] = {
                        "exists": True,
                        "doc_count": stats['indices'][index]['total']['docs']['count'],
                        "size_bytes": stats['indices'][index]['total']['store']['size_in_bytes']
                    }
                except OpenSearchException:
                    info[index] = {"exists": False}
            
            return info
        except Exception as e:
            logger.error(f"Failed to get index info: {e}")
            return {}
    
    def close(self):
        """Close the OpenSearch client connection."""
        if hasattr(self, 'client'):
            self.client.close()
            logger.info("OpenSearch client connection closed")


# Convenience function for quick access
def get_real_opensearch_client() -> RealOpenSearchClient:
    """
    Factory function to get a real OpenSearch client instance.
    
    Returns:
        RealOpenSearchClient instance
    """
    return RealOpenSearchClient()