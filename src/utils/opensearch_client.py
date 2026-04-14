# OpenSearch Client Module
# Version: v0.1.2
# Timestamp: 2026-04-07

"""
Reusable OpenSearch client for playbook engine.
Provides connectivity to OpenSearch cluster for both vector and non-vector indexes.
"""

import os
import logging
from typing import Dict, List, Optional, Any
from opensearchpy import OpenSearch, RequestsHttpConnection
from opensearchpy.exceptions import OpenSearchException

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class OpenSearchClient:
    """
    Reusable OpenSearch client for querying standard and vector indexes.
    
    Supports:
    - Standard document indexes
    - Metadata-only queries
    - Scroll/export workflows
    - Playbook retrieval from chat_history
    - CVE retrieval from cve index
    - Vector index access patterns
    """
    
    def __init__(self):
        """Initialize OpenSearch client with environment variables."""
        self.host = os.getenv('OPENSEARCH_HOST', '10.0.0.50')
        self.port = int(os.getenv('OPENSEARCH_PORT', '9200'))
        self.user = os.getenv('OPENSEARCH_USER', 'admin')
        self.password = os.getenv('OPENSEARCH_PASSWORD', '')
        self.use_ssl = os.getenv('OPENSEARCH_USE_SSL', 'false').lower() == 'true'
        
        # Index names with defaults
        self.index_default = os.getenv('OPENSEARCH_INDEX', 'chat_history')
        self.index_playbook = os.getenv('OPENSEARCH_INDEX_PLAYBOOK', 'chat_history')
        self.index_cve = os.getenv('OPENSEARCH_INDEX_CVE', 'cve')
        self.index_vector = os.getenv('OPENSEARCH_INDEX_VECTOR', 'spring-ai-document-index')
        self.index_qa_results = os.getenv('OPENSEARCH_INDEX_QA_RESULTS', 'playbook_qa_results-000001')
        
        # Initialize client
        self.client = self._create_client()
        
    def _create_client(self) -> OpenSearch:
        """Create and return OpenSearch client instance."""
        try:
            client = OpenSearch(
                hosts=[{'host': self.host, 'port': self.port}],
                http_auth=(self.user, self.password),
                use_ssl=self.use_ssl,
                verify_certs=False,  # For development only
                connection_class=RequestsHttpConnection,
                timeout=30,
                max_retries=3,
                retry_on_timeout=True
            )
            logger.info(f"OpenSearch client initialized for {self.host}:{self.port}")
            return client
        except Exception as e:
            logger.error(f"Failed to create OpenSearch client: {e}")
            raise
    
    def ping(self) -> bool:
        """
        Ping the OpenSearch cluster to verify connectivity.
        
        Returns:
            bool: True if cluster is reachable, False otherwise
        """
        try:
            return self.client.ping()
        except OpenSearchException as e:
            logger.error(f"OpenSearch ping failed: {e}")
            return False
    
    def search(self, index: str, body: Dict[str, Any], size: int = 100) -> Dict[str, Any]:
        """
        Execute a search query against specified index.
        
        Args:
            index: Target index name
            body: Search query body
            size: Maximum number of results to return
            
        Returns:
            Dictionary containing search results
        """
        try:
            response = self.client.search(
                index=index,
                body=body,
                size=size
            )
            return response
        except OpenSearchException as e:
            logger.error(f"Search failed for index {index}: {e}")
            raise
    
    def get_all_playbooks(self, size: int = 1000) -> Dict[str, Any]:
        """
        Retrieve all playbooks from chat_history index.
        
        Uses query pattern: {"term": {"is_play_book": true}}
        
        Args:
            size: Maximum number of playbooks to retrieve
            
        Returns:
            Dictionary containing playbook results
        """
        query = {
            "query": {
                "term": {
                    "is_play_book": True
                }
            },
            "sort": [
                {"timestamp": {"order": "desc"}}
            ]
        }
        
        return self.search(self.index_playbook, query, size)
    
    def get_playbook_metadata(self, size: int = 1000) -> Dict[str, Any]:
        """
        Retrieve metadata-only playbook records.
        
        Args:
            size: Maximum number of records to retrieve
            
        Returns:
            Dictionary containing playbook metadata
        """
        query = {
            "query": {
                "term": {
                    "is_play_book": True
                }
            },
            "_source": ["id", "timestamp", "title", "description", "tags"],
            "sort": [
                {"timestamp": {"order": "desc"}}
            ]
        }
        
        return self.search(self.index_playbook, query, size)
    
    def get_cve(self, cve_id: str) -> Dict[str, Any]:
        """
        Retrieve a specific CVE from the cve index.
        
        Args:
            cve_id: CVE identifier (e.g., "CVE-2021-44228")
            
        Returns:
            Dictionary containing CVE data
        """
        query = {
            "query": {
                "term": {
                    "cve_id": cve_id
                }
            }
        }
        
        try:
            response = self.search(self.index_cve, query, size=1)
            hits = response.get('hits', {}).get('hits', [])
            return hits[0] if hits else {}
        except (OpenSearchException, IndexError) as e:
            logger.error(f"Failed to retrieve CVE {cve_id}: {e}")
            return {}
    
    def scroll_search(self, index: str, body: Dict[str, Any], scroll: str = "5m") -> List[Dict[str, Any]]:
        """
        Execute a scroll search for large exports.
        
        Args:
            index: Target index name
            body: Search query body
            scroll: Scroll timeout duration
            
        Returns:
            List of all documents matching the query
        """
        all_documents = []
        
        try:
            # Initial search
            response = self.client.search(
                index=index,
                body=body,
                scroll=scroll,
                size=100  # Batch size
            )
            
            scroll_id = response.get('_scroll_id')
            hits = response.get('hits', {}).get('hits', [])
            all_documents.extend(hits)
            
            # Continue scrolling while there are results
            while hits:
                response = self.client.scroll(
                    scroll_id=scroll_id,
                    scroll=scroll
                )
                scroll_id = response.get('_scroll_id')
                hits = response.get('hits', {}).get('hits', [])
                all_documents.extend(hits)
            
            # Clear scroll context
            if scroll_id:
                self.client.clear_scroll(scroll_id=scroll_id)
            
            return all_documents
            
        except OpenSearchException as e:
            logger.error(f"Scroll search failed for index {index}: {e}")
            raise
    
    def get_index_info(self, index: Optional[str] = None) -> Dict[str, Any]:
        """
        Get information about an index or all indices.
        
        Args:
            index: Specific index name, or None for all indices
            
        Returns:
            Dictionary containing index information
        """
        try:
            if index:
                return self.client.indices.get(index=index)
            else:
                return self.client.indices.get(index="*")
        except OpenSearchException as e:
            logger.error(f"Failed to get index info for {index or 'all'}: {e}")
            raise
    
    def close(self):
        """Close the OpenSearch client connection."""
        if hasattr(self, 'client'):
            self.client.close()
            logger.info("OpenSearch client connection closed")


# Convenience function for quick access
def get_opensearch_client() -> OpenSearchClient:
    """
    Factory function to get an OpenSearch client instance.
    
    Returns:
        OpenSearchClient instance
    """
    return OpenSearchClient()