"""
Generation Repository for playbook generation run operations.
"""

import logging
import json
from typing import Dict, List, Optional, Any

from utils.db import DatabaseClient

logger = logging.getLogger(__name__)


class GenerationRepository:
    """Repository for playbook generation run operations."""
    
    def __init__(self, db_client: Optional[DatabaseClient] = None):
        self.db_client = db_client or DatabaseClient()
    
    def create_generation_run(
        self,
        cve_id: str,
        queue_id: Optional[int],
        prompt_template_version_id: Optional[int],
        rendered_prompt: str,
        prompt_inputs: Dict[str, Any],
        model_name: Optional[str] = None
    ) -> Optional[int]:
        """
        Create a new generation run.
        
        Args:
            cve_id: CVE identifier
            queue_id: Queue entry ID
            prompt_template_version_id: Prompt template version ID
            rendered_prompt: Rendered prompt text
            prompt_inputs: Prompt inputs as dictionary
            model_name: Model name used for generation
            
        Returns:
            Generation run ID or None if failed
        """
        sql = """
        INSERT INTO generation_runs (
            cve_id, queue_id, prompt_template_version_id,
            rendered_prompt, prompt_inputs, model_name, status
        )
        VALUES (%s, %s, %s, %s, %s::jsonb, %s, 'pending')
        RETURNING id
        """
        
        try:
            result = self.db_client.fetch_one(sql, (
                cve_id,
                queue_id,
                prompt_template_version_id,
                rendered_prompt,
                json.dumps(prompt_inputs),
                model_name
            ))
            if result:
                logger.info(f"Created generation run for CVE {cve_id}")
                return result['id']
        except Exception as e:
            logger.error(f"Failed to create generation run for CVE {cve_id}: {e}")
        
        return None
    
    def update_generation_result(
        self,
        generation_run_id: int,
        raw_response: str,
        parsed_response: Dict[str, Any],
        status: str = 'completed'
    ) -> bool:
        """
        Update generation run with results.
        
        Args:
            generation_run_id: Generation run ID
            raw_response: Raw model response
            parsed_response: Parsed response as dictionary
            status: Final status ('completed' or 'failed')
            
        Returns:
            True if successful
        """
        sql = """
        UPDATE generation_runs
        SET raw_response = %s,
            parsed_response = %s::jsonb,
            status = %s
        WHERE id = %s
        """
        
        try:
            self.db_client.execute(sql, (
                raw_response,
                json.dumps(parsed_response),
                status,
                generation_run_id
            ))
            logger.info(f"Updated generation run {generation_run_id} with results")
            return True
        except Exception as e:
            logger.error(f"Failed to update generation run {generation_run_id}: {e}")
            return False
    
    def get_generation_run(self, generation_run_id: int) -> Optional[Dict[str, Any]]:
        """
        Get generation run by ID.
        
        Args:
            generation_run_id: Generation run ID
            
        Returns:
            Generation run details or None
        """
        sql = """
        SELECT 
            gr.id, gr.cve_id, gr.queue_id, gr.prompt_template_version_id,
            gr.rendered_prompt, gr.prompt_inputs, gr.model_name,
            gr.raw_response, gr.parsed_response, gr.status, gr.created_at,
            pt.name as prompt_template_name,
            ptv.version as prompt_template_version
        FROM generation_runs gr
        LEFT JOIN prompt_template_versions ptv ON gr.prompt_template_version_id = ptv.id
        LEFT JOIN prompt_templates pt ON ptv.template_id = pt.id
        WHERE gr.id = %s
        """
        
        try:
            return self.db_client.fetch_one(sql, (generation_run_id,))
        except Exception as e:
            logger.error(f"Failed to get generation run {generation_run_id}: {e}")
            return None
    
    def get_generation_runs_by_cve(self, cve_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get generation runs for a CVE.
        
        Args:
            cve_id: CVE identifier
            limit: Maximum number of runs to return
            
        Returns:
            List of generation runs
        """
        sql = """
        SELECT 
            gr.id, gr.cve_id, gr.status, gr.model_name,
            gr.created_at, pt.name as prompt_template_name,
            ptv.version as prompt_template_version
        FROM generation_runs gr
        LEFT JOIN prompt_template_versions ptv ON gr.prompt_template_version_id = ptv.id
        LEFT JOIN prompt_templates pt ON ptv.template_id = pt.id
        WHERE gr.cve_id = %s
        ORDER BY gr.created_at DESC
        LIMIT %s
        """
        
        try:
            return self.db_client.fetch_all(sql, (cve_id, limit))
        except Exception as e:
            logger.error(f"Failed to get generation runs for CVE {cve_id}: {e}")
            return []
    
    def get_failed_generation_runs(self, hours: int = 24) -> List[Dict[str, Any]]:
        """
        Get failed generation runs within specified time window.
        
        Args:
            hours: Time window in hours
            
        Returns:
            List of failed generation runs
        """
        sql = """
        SELECT 
            gr.id, gr.cve_id, gr.queue_id, gr.model_name,
            gr.created_at, gr.raw_response
        FROM generation_runs gr
        WHERE gr.status = 'failed'
        AND gr.created_at > NOW() - INTERVAL '%s hours'
        ORDER BY gr.created_at DESC
        """
        
        try:
            return self.db_client.fetch_all(sql, (hours,))
        except Exception as e:
            logger.error(f"Failed to get failed generation runs: {e}")
            return []
    
    def mark_generation_failed(self, generation_run_id: int, error_message: Optional[str] = None) -> bool:
        """
        Mark generation run as failed.
        
        Args:
            generation_run_id: Generation run ID
            error_message: Optional error message
            
        Returns:
            True if successful
        """
        sql = """
        UPDATE generation_runs
        SET status = 'failed',
            raw_response = COALESCE(raw_response, %s)
        WHERE id = %s
        """
        
        try:
            self.db_client.execute(sql, (error_message, generation_run_id))
            logger.info(f"Marked generation run {generation_run_id} as failed")
            return True
        except Exception as e:
            logger.error(f"Failed to mark generation run {generation_run_id} as failed: {e}")
            return False
    
    def get_generation_stats(self) -> Dict[str, Any]:
        """
        Get generation run statistics.
        
        Returns:
            Dictionary with generation statistics
        """
        sql = """
        SELECT 
            COUNT(*) as total_runs,
            COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed,
            COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed,
            COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending,
            COUNT(DISTINCT cve_id) as unique_cves,
            MIN(created_at) as first_run,
            MAX(created_at) as last_run
        FROM generation_runs
        """
        
        try:
            result = self.db_client.fetch_one(sql)
            return dict(result) if result else {}
        except Exception as e:
            logger.error(f"Failed to get generation stats: {e}")
            return {}