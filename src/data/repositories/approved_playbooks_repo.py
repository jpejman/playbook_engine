"""
Approved Playbooks Repository for approved playbook operations.
"""

import logging
import json
from typing import Dict, List, Optional, Any

from utils.db import DatabaseClient

logger = logging.getLogger(__name__)


class ApprovedPlaybooksRepository:
    """Repository for approved playbook operations."""
    
    def __init__(self, db_client: Optional[DatabaseClient] = None):
        self.db_client = db_client or DatabaseClient()
    
    def approve_playbook(
        self,
        cve_id: str,
        generation_run_id: Optional[int],
        playbook: Dict[str, Any],
        version: int = 1
    ) -> Optional[int]:
        """
        Approve a playbook.
        
        Args:
            cve_id: CVE identifier
            generation_run_id: Generation run ID that produced this playbook
            playbook: Playbook JSON data
            version: Playbook version
            
        Returns:
            Approved playbook ID or None if failed
        """
        sql = """
        INSERT INTO approved_playbooks (cve_id, generation_run_id, playbook, version)
        VALUES (%s, %s, %s::jsonb, %s)
        ON CONFLICT (cve_id, version) DO UPDATE SET
            generation_run_id = EXCLUDED.generation_run_id,
            playbook = EXCLUDED.playbook,
            approved_at = NOW()
        RETURNING id
        """
        
        try:
            result = self.db_client.fetch_one(sql, (
                cve_id,
                generation_run_id,
                json.dumps(playbook),
                version
            ))
            if result:
                logger.info(f"Approved playbook for CVE {cve_id} version {version}")
                return result['id']
        except Exception as e:
            logger.error(f"Failed to approve playbook for CVE {cve_id}: {e}")
        
        return None
    
    def get_approved_playbook(
        self,
        cve_id: str,
        version: Optional[int] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Get approved playbook for a CVE.
        
        Args:
            cve_id: CVE identifier
            version: Specific version (latest if None)
            
        Returns:
            Approved playbook or None
        """
        if version:
            sql = """
            SELECT 
                ap.id, ap.cve_id, ap.generation_run_id,
                ap.playbook, ap.version, ap.approved_at,
                gr.model_name, gr.prompt_template_version_id
            FROM approved_playbooks ap
            LEFT JOIN generation_runs gr ON ap.generation_run_id = gr.id
            WHERE ap.cve_id = %s AND ap.version = %s
            """
            params = (cve_id, version)
        else:
            sql = """
            SELECT 
                ap.id, ap.cve_id, ap.generation_run_id,
                ap.playbook, ap.version, ap.approved_at,
                gr.model_name, gr.prompt_template_version_id
            FROM approved_playbooks ap
            LEFT JOIN generation_runs gr ON ap.generation_run_id = gr.id
            WHERE ap.cve_id = %s
            ORDER BY ap.version DESC
            LIMIT 1
            """
            params = (cve_id,)
        
        try:
            return self.db_client.fetch_one(sql, params)
        except Exception as e:
            logger.error(f"Failed to get approved playbook for CVE {cve_id}: {e}")
            return None
    
    def get_approved_playbook_versions(self, cve_id: str) -> List[Dict[str, Any]]:
        """
        Get all approved playbook versions for a CVE.
        
        Args:
            cve_id: CVE identifier
            
        Returns:
            List of approved playbook versions
        """
        sql = """
        SELECT 
            id, version, approved_at,
            generation_run_id
        FROM approved_playbooks
        WHERE cve_id = %s
        ORDER BY version DESC
        """
        
        try:
            return self.db_client.fetch_all(sql, (cve_id,))
        except Exception as e:
            logger.error(f"Failed to get approved playbook versions for CVE {cve_id}: {e}")
            return []
    
    def get_recently_approved(self, limit: int = 20) -> List[Dict[str, Any]]:
        """
        Get recently approved playbooks.
        
        Args:
            limit: Maximum number of playbooks to return
            
        Returns:
            List of recently approved playbooks
        """
        sql = """
        SELECT 
            ap.id, ap.cve_id, ap.version, ap.approved_at,
            gr.model_name
        FROM approved_playbooks ap
        LEFT JOIN generation_runs gr ON ap.generation_run_id = gr.id
        ORDER BY ap.approved_at DESC
        LIMIT %s
        """
        
        try:
            return self.db_client.fetch_all(sql, (limit,))
        except Exception as e:
            logger.error(f"Failed to get recently approved playbooks: {e}")
            return []
    
    def get_approved_playbooks_by_date_range(
        self,
        start_date: str,
        end_date: str,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get approved playbooks within a date range.
        
        Args:
            start_date: Start date (YYYY-MM-DD)
            end_date: End date (YYYY-MM-DD)
            limit: Maximum number of playbooks to return
            
        Returns:
            List of approved playbooks
        """
        sql = """
        SELECT 
            ap.id, ap.cve_id, ap.version, ap.approved_at,
            gr.model_name
        FROM approved_playbooks ap
        LEFT JOIN generation_runs gr ON ap.generation_run_id = gr.id
        WHERE ap.approved_at >= %s::timestamp
        AND ap.approved_at <= %s::timestamp
        ORDER BY ap.approved_at DESC
        LIMIT %s
        """
        
        try:
            return self.db_client.fetch_all(sql, (start_date, end_date, limit))
        except Exception as e:
            logger.error(f"Failed to get approved playbooks by date range: {e}")
            return []
    
    def get_approval_stats(self) -> Dict[str, Any]:
        """
        Get approval statistics.
        
        Returns:
            Dictionary with approval statistics
        """
        sql = """
        SELECT 
            COUNT(*) as total_approved,
            COUNT(DISTINCT cve_id) as unique_cves,
            MAX(version) as max_version,
            MIN(approved_at) as first_approval,
            MAX(approved_at) as last_approval,
            AVG(version) as avg_version
        FROM approved_playbooks
        """
        
        try:
            result = self.db_client.fetch_one(sql)
            return dict(result) if result else {}
        except Exception as e:
            logger.error(f"Failed to get approval stats: {e}")
            return {}
    
    def get_cves_with_approved_playbooks(self, limit: int = 100) -> List[str]:
        """
        Get CVE IDs that have approved playbooks.
        
        Args:
            limit: Maximum number of CVEs to return
            
        Returns:
            List of CVE IDs
        """
        sql = """
        SELECT DISTINCT cve_id
        FROM approved_playbooks
        ORDER BY cve_id
        LIMIT %s
        """
        
        try:
            results = self.db_client.fetch_all(sql, (limit,))
            return [row['cve_id'] for row in results]
        except Exception as e:
            logger.error(f"Failed to get CVEs with approved playbooks: {e}")
            return []
    
    def delete_approved_playbook(self, cve_id: str, version: int) -> bool:
        """
        Delete an approved playbook.
        
        Args:
            cve_id: CVE identifier
            version: Playbook version
            
        Returns:
            True if successful
        """
        sql = """
        DELETE FROM approved_playbooks
        WHERE cve_id = %s AND version = %s
        """
        
        try:
            self.db_client.execute(sql, (cve_id, version))
            logger.info(f"Deleted approved playbook for CVE {cve_id} version {version}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete approved playbook for CVE {cve_id}: {e}")
            return False
    
    def get_playbook_by_generation_run(self, generation_run_id: int) -> Optional[Dict[str, Any]]:
        """
        Get approved playbook by generation run ID.
        
        Args:
            generation_run_id: Generation run ID
            
        Returns:
            Approved playbook or None
        """
        sql = """
        SELECT 
            ap.id, ap.cve_id, ap.version, ap.approved_at,
            ap.playbook
        FROM approved_playbooks ap
        WHERE ap.generation_run_id = %s
        """
        
        try:
            return self.db_client.fetch_one(sql, (generation_run_id,))
        except Exception as e:
            logger.error(f"Failed to get approved playbook for generation run {generation_run_id}: {e}")
            return None
    
    def search_approved_playbooks(
        self,
        search_term: Optional[str] = None,
        limit: int = 20
    ) -> List[Dict[str, Any]]:
        """
        Search approved playbooks.
        
        Args:
            search_term: Search term for CVE ID
            limit: Maximum number of results
            
        Returns:
            List of matching approved playbooks
        """
        sql = """
        SELECT 
            ap.id, ap.cve_id, ap.version, ap.approved_at,
            gr.model_name
        FROM approved_playbooks ap
        LEFT JOIN generation_runs gr ON ap.generation_run_id = gr.id
        WHERE 1=1
        """
        
        params = []
        
        if search_term:
            sql += " AND ap.cve_id ILIKE %s"
            params.append(f"%{search_term}%")
        
        sql += " ORDER BY ap.approved_at DESC LIMIT %s"
        params.append(limit)
        
        try:
            return self.db_client.fetch_all(sql, tuple(params))
        except Exception as e:
            logger.error(f"Failed to search approved playbooks: {e}")
            return []