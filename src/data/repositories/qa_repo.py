"""
QA Repository for quality assurance run operations.
"""

import logging
import json
from typing import Dict, List, Optional, Any

from utils.db import DatabaseClient

logger = logging.getLogger(__name__)


class QARepository:
    """Repository for quality assurance run operations."""
    
    def __init__(self, db_client: Optional[DatabaseClient] = None):
        self.db_client = db_client or DatabaseClient()
    
    def create_qa_run(
        self,
        generation_run_id: int,
        qa_result: str,
        qa_score: Optional[float] = None,
        qa_feedback: Optional[str] = None
    ) -> Optional[int]:
        """
        Create a new QA run.
        
        Args:
            generation_run_id: Generation run ID
            qa_result: QA result ('approved', 'rejected', 'needs_revision')
            qa_score: QA score (0.0-1.0)
            qa_feedback: QA feedback text
            
        Returns:
            QA run ID or None if failed
        """
        sql = """
        INSERT INTO qa_runs (generation_run_id, qa_result, qa_score, qa_feedback)
        VALUES (%s, %s, %s, %s)
        RETURNING id
        """
        
        try:
            result = self.db_client.fetch_one(sql, (
                generation_run_id,
                qa_result,
                qa_score,
                qa_feedback
            ))
            if result:
                logger.info(f"Created QA run for generation run {generation_run_id}")
                return result['id']
        except Exception as e:
            logger.error(f"Failed to create QA run for generation run {generation_run_id}: {e}")
        
        return None
    
    def get_qa_run(self, qa_run_id: int) -> Optional[Dict[str, Any]]:
        """
        Get QA run by ID.
        
        Args:
            qa_run_id: QA run ID
            
        Returns:
            QA run details or None
        """
        sql = """
        SELECT 
            qr.id, qr.generation_run_id, qr.qa_result, qr.qa_score,
            qr.qa_feedback, qr.created_at,
            gr.cve_id, gr.model_name, gr.prompt_template_version_id
        FROM qa_runs qr
        JOIN generation_runs gr ON qr.generation_run_id = gr.id
        WHERE qr.id = %s
        """
        
        try:
            return self.db_client.fetch_one(sql, (qa_run_id,))
        except Exception as e:
            logger.error(f"Failed to get QA run {qa_run_id}: {e}")
            return None
    
    def get_qa_runs_by_generation(self, generation_run_id: int) -> List[Dict[str, Any]]:
        """
        Get QA runs for a generation run.
        
        Args:
            generation_run_id: Generation run ID
            
        Returns:
            List of QA runs
        """
        sql = """
        SELECT 
            id, qa_result, qa_score, qa_feedback, created_at
        FROM qa_runs
        WHERE generation_run_id = %s
        ORDER BY created_at DESC
        """
        
        try:
            return self.db_client.fetch_all(sql, (generation_run_id,))
        except Exception as e:
            logger.error(f"Failed to get QA runs for generation run {generation_run_id}: {e}")
            return []
    
    def get_qa_runs_by_cve(self, cve_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get QA runs for a CVE.
        
        Args:
            cve_id: CVE identifier
            limit: Maximum number of runs to return
            
        Returns:
            List of QA runs
        """
        sql = """
        SELECT 
            qr.id, qr.generation_run_id, qr.qa_result, qr.qa_score,
            qr.qa_feedback, qr.created_at,
            gr.cve_id, gr.model_name
        FROM qa_runs qr
        JOIN generation_runs gr ON qr.generation_run_id = gr.id
        WHERE gr.cve_id = %s
        ORDER BY qr.created_at DESC
        LIMIT %s
        """
        
        try:
            return self.db_client.fetch_all(sql, (cve_id, limit))
        except Exception as e:
            logger.error(f"Failed to get QA runs for CVE {cve_id}: {e}")
            return []
    
    def get_qa_stats(self) -> Dict[str, Any]:
        """
        Get QA statistics.
        
        Returns:
            Dictionary with QA statistics
        """
        sql = """
        SELECT 
            COUNT(*) as total_runs,
            COUNT(DISTINCT generation_run_id) as unique_generations,
            AVG(qa_score) as avg_score,
            COUNT(CASE WHEN qa_result = 'approved' THEN 1 END) as approved,
            COUNT(CASE WHEN qa_result = 'rejected' THEN 1 END) as rejected,
            COUNT(CASE WHEN qa_result = 'needs_revision' THEN 1 END) as needs_revision,
            MIN(created_at) as first_qa,
            MAX(created_at) as last_qa
        FROM qa_runs
        """
        
        try:
            result = self.db_client.fetch_one(sql)
            return dict(result) if result else {}
        except Exception as e:
            logger.error(f"Failed to get QA stats: {e}")
            return {}
    
    def get_qa_result_distribution(self) -> Dict[str, int]:
        """
        Get distribution of QA results.
        
        Returns:
            Dictionary with result counts
        """
        sql = """
        SELECT qa_result, COUNT(*) as count
        FROM qa_runs
        GROUP BY qa_result
        ORDER BY count DESC
        """
        
        try:
            results = self.db_client.fetch_all(sql)
            return {row['qa_result']: row['count'] for row in results}
        except Exception as e:
            logger.error(f"Failed to get QA result distribution: {e}")
            return {}
    
    def get_low_scoring_runs(self, threshold: float = 0.5, limit: int = 20) -> List[Dict[str, Any]]:
        """
        Get low-scoring QA runs.
        
        Args:
            threshold: Score threshold
            limit: Maximum number of runs to return
            
        Returns:
            List of low-scoring QA runs
        """
        sql = """
        SELECT 
            qr.id, qr.generation_run_id, qr.qa_score, qr.qa_result,
            qr.qa_feedback, qr.created_at,
            gr.cve_id, gr.model_name
        FROM qa_runs qr
        JOIN generation_runs gr ON qr.generation_run_id = gr.id
        WHERE qr.qa_score < %s
        ORDER BY qr.qa_score ASC
        LIMIT %s
        """
        
        try:
            return self.db_client.fetch_all(sql, (threshold, limit))
        except Exception as e:
            logger.error(f"Failed to get low-scoring QA runs: {e}")
            return []
    
    def update_qa_feedback(self, qa_run_id: int, qa_feedback: str) -> bool:
        """
        Update QA feedback.
        
        Args:
            qa_run_id: QA run ID
            qa_feedback: Updated feedback text
            
        Returns:
            True if successful
        """
        sql = """
        UPDATE qa_runs
        SET qa_feedback = %s
        WHERE id = %s
        """
        
        try:
            self.db_client.execute(sql, (qa_feedback, qa_run_id))
            logger.info(f"Updated feedback for QA run {qa_run_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to update feedback for QA run {qa_run_id}: {e}")
            return False
    
    def get_recent_qa_runs(self, hours: int = 24) -> List[Dict[str, Any]]:
        """
        Get recent QA runs.
        
        Args:
            hours: Time window in hours
            
        Returns:
            List of recent QA runs
        """
        sql = """
        SELECT 
            qr.id, qr.generation_run_id, qr.qa_result, qr.qa_score,
            qr.created_at, gr.cve_id, gr.model_name
        FROM qa_runs qr
        JOIN generation_runs gr ON qr.generation_run_id = gr.id
        WHERE qr.created_at > NOW() - INTERVAL '%s hours'
        ORDER BY qr.created_at DESC
        """
        
        try:
            return self.db_client.fetch_all(sql, (hours,))
        except Exception as e:
            logger.error(f"Failed to get recent QA runs: {e}")
            return []