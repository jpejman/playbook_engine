"""
Retrieval Repository for retrieval run and document operations.
"""

import logging
import json
from typing import Dict, List, Optional, Any

from utils.db import DatabaseClient

logger = logging.getLogger(__name__)


class RetrievalRepository:
    """Repository for retrieval run and document operations."""
    
    def __init__(self, db_client: Optional[DatabaseClient] = None):
        self.db_client = db_client or DatabaseClient()
    
    def create_retrieval_run(
        self,
        cve_id: str,
        queue_id: Optional[int],
        retrieval_type: str,
        keyword_query: Optional[str] = None,
        vector_query_metadata: Optional[Dict[str, Any]] = None,
        retrieval_metadata: Optional[Dict[str, Any]] = None
    ) -> Optional[int]:
        """
        Create a new retrieval run.
        
        Args:
            cve_id: CVE identifier
            queue_id: Queue entry ID
            retrieval_type: Type of retrieval ('keyword', 'vector', 'hybrid')
            keyword_query: Keyword query used
            vector_query_metadata: Vector query metadata
            retrieval_metadata: Additional retrieval metadata
            
        Returns:
            Retrieval run ID or None if failed
        """
        sql = """
        INSERT INTO retrieval_runs (
            cve_id, queue_id, retrieval_type,
            keyword_query, vector_query_metadata, retrieval_metadata
        )
        VALUES (%s, %s, %s, %s, %s::jsonb, %s::jsonb)
        RETURNING id
        """
        
        try:
            result = self.db_client.fetch_one(sql, (
                cve_id,
                queue_id,
                retrieval_type,
                keyword_query,
                json.dumps(vector_query_metadata) if vector_query_metadata else None,
                json.dumps(retrieval_metadata) if retrieval_metadata else None
            ))
            if result:
                logger.info(f"Created retrieval run for CVE {cve_id}")
                return result['id']
        except Exception as e:
            logger.error(f"Failed to create retrieval run for CVE {cve_id}: {e}")
        
        return None
    
    def add_retrieval_documents(
        self,
        retrieval_run_id: int,
        documents: List[Dict[str, Any]]
    ) -> int:
        """
        Add retrieved documents to a retrieval run.
        
        Args:
            retrieval_run_id: Retrieval run ID
            documents: List of document dictionaries with keys:
                - source_index: Source index name
                - document_id: Document identifier
                - score: Retrieval score
                - rank: Rank position
                - document_metadata: Additional document metadata
                
        Returns:
            Number of documents added
        """
        if not documents:
            return 0
        
        sql = """
        INSERT INTO retrieval_documents (
            retrieval_run_id, source_index, document_id,
            score, rank, document_metadata
        )
        VALUES (%s, %s, %s, %s, %s, %s::jsonb)
        ON CONFLICT (retrieval_run_id, document_id) DO UPDATE SET
            score = EXCLUDED.score,
            rank = EXCLUDED.rank,
            document_metadata = EXCLUDED.document_metadata
        """
        
        params = []
        for doc in documents:
            params.append((
                retrieval_run_id,
                doc.get('source_index'),
                doc.get('document_id'),
                doc.get('score'),
                doc.get('rank'),
                json.dumps(doc.get('document_metadata', {}))
            ))
        
        try:
            self.db_client.execute_many(sql, params)
            count = len(documents)
            logger.info(f"Added {count} documents to retrieval run {retrieval_run_id}")
            return count
        except Exception as e:
            logger.error(f"Failed to add documents to retrieval run {retrieval_run_id}: {e}")
            return 0
    
    def get_retrieval_run(self, retrieval_run_id: int) -> Optional[Dict[str, Any]]:
        """
        Get retrieval run by ID.
        
        Args:
            retrieval_run_id: Retrieval run ID
            
        Returns:
            Retrieval run details or None
        """
        sql = """
        SELECT 
            rr.id, rr.cve_id, rr.queue_id, rr.retrieval_type,
            rr.keyword_query, rr.vector_query_metadata, rr.retrieval_metadata,
            rr.created_at,
            COUNT(rd.id) as document_count
        FROM retrieval_runs rr
        LEFT JOIN retrieval_documents rd ON rr.id = rd.retrieval_run_id
        WHERE rr.id = %s
        GROUP BY rr.id
        """
        
        try:
            return self.db_client.fetch_one(sql, (retrieval_run_id,))
        except Exception as e:
            logger.error(f"Failed to get retrieval run {retrieval_run_id}: {e}")
            return None
    
    def get_retrieval_documents(
        self,
        retrieval_run_id: int,
        limit: int = 100,
        min_score: Optional[float] = None
    ) -> List[Dict[str, Any]]:
        """
        Get documents for a retrieval run.
        
        Args:
            retrieval_run_id: Retrieval run ID
            limit: Maximum number of documents to return
            min_score: Minimum score threshold
            
        Returns:
            List of retrieval documents
        """
        sql = """
        SELECT 
            id, source_index, document_id, score, rank,
            document_metadata, created_at
        FROM retrieval_documents
        WHERE retrieval_run_id = %s
        """
        
        params = [retrieval_run_id]
        
        if min_score is not None:
            sql += " AND score >= %s"
            params.append(min_score)
        
        sql += " ORDER BY rank ASC LIMIT %s"
        params.append(limit)
        
        try:
            return self.db_client.fetch_all(sql, tuple(params))
        except Exception as e:
            logger.error(f"Failed to get documents for retrieval run {retrieval_run_id}: {e}")
            return []
    
    def get_retrieval_runs_by_cve(self, cve_id: str, limit: int = 5) -> List[Dict[str, Any]]:
        """
        Get retrieval runs for a CVE.
        
        Args:
            cve_id: CVE identifier
            limit: Maximum number of runs to return
            
        Returns:
            List of retrieval runs
        """
        sql = """
        SELECT 
            rr.id, rr.retrieval_type, rr.created_at,
            COUNT(rd.id) as document_count,
            AVG(rd.score) as avg_score
        FROM retrieval_runs rr
        LEFT JOIN retrieval_documents rd ON rr.id = rd.retrieval_run_id
        WHERE rr.cve_id = %s
        GROUP BY rr.id
        ORDER BY rr.created_at DESC
        LIMIT %s
        """
        
        try:
            return self.db_client.fetch_all(sql, (cve_id, limit))
        except Exception as e:
            logger.error(f"Failed to get retrieval runs for CVE {cve_id}: {e}")
            return []
    
    def get_top_documents_by_cve(
        self,
        cve_id: str,
        limit: int = 20,
        source_index: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get top retrieved documents for a CVE across all runs.
        
        Args:
            cve_id: CVE identifier
            limit: Maximum number of documents to return
            source_index: Filter by source index
            
        Returns:
            List of top documents
        """
        sql = """
        SELECT 
            rd.document_id, rd.source_index, rd.score, rd.rank,
            rd.document_metadata, rd.created_at,
            rr.retrieval_type, rr.id as retrieval_run_id
        FROM retrieval_documents rd
        JOIN retrieval_runs rr ON rd.retrieval_run_id = rr.id
        WHERE rr.cve_id = %s
        """
        
        params = [cve_id]
        
        if source_index:
            sql += " AND rd.source_index = %s"
            params.append(source_index)
        
        sql += " ORDER BY rd.score DESC, rd.rank ASC LIMIT %s"
        params.append(limit)
        
        try:
            return self.db_client.fetch_all(sql, tuple(params))
        except Exception as e:
            logger.error(f"Failed to get top documents for CVE {cve_id}: {e}")
            return []
    
    def get_retrieval_stats(self) -> Dict[str, Any]:
        """
        Get retrieval statistics.
        
        Returns:
            Dictionary with retrieval statistics
        """
        sql = """
        SELECT 
            COUNT(DISTINCT rr.id) as total_runs,
            COUNT(DISTINCT rr.cve_id) as unique_cves,
            COUNT(DISTINCT rd.id) as total_documents,
            AVG(rd.score) as avg_document_score,
            MIN(rr.created_at) as first_retrieval,
            MAX(rr.created_at) as last_retrieval,
            COUNT(DISTINCT rd.source_index) as unique_indices
        FROM retrieval_runs rr
        LEFT JOIN retrieval_documents rd ON rr.id = rd.retrieval_run_id
        """
        
        try:
            result = self.db_client.fetch_one(sql)
            return dict(result) if result else {}
        except Exception as e:
            logger.error(f"Failed to get retrieval stats: {e}")
            return {}
    
    def get_document_frequency(self, document_id: str, source_index: str) -> int:
        """
        Get how many times a document has been retrieved.
        
        Args:
            document_id: Document identifier
            source_index: Source index name
            
        Returns:
            Frequency count
        """
        sql = """
        SELECT COUNT(*) as frequency
        FROM retrieval_documents
        WHERE document_id = %s AND source_index = %s
        """
        
        try:
            result = self.db_client.fetch_one(sql, (document_id, source_index))
            return result['frequency'] if result else 0
        except Exception as e:
            logger.error(f"Failed to get document frequency: {e}")
            return 0