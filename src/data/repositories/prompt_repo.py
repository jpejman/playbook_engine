"""
Prompt Repository for prompt template operations.
"""

import logging
from typing import Dict, List, Optional, Any

from utils.db import DatabaseClient

logger = logging.getLogger(__name__)


class PromptRepository:
    """Repository for prompt template operations."""
    
    def __init__(self, db_client: Optional[DatabaseClient] = None):
        self.db_client = db_client or DatabaseClient()
    
    def create_template(
        self,
        name: str,
        description: Optional[str] = None,
        is_active: bool = True
    ) -> Optional[int]:
        """
        Create a new prompt template.
        
        Args:
            name: Template name (must be unique)
            description: Template description
            is_active: Whether template is active
            
        Returns:
            Template ID or None if failed
        """
        sql = """
        INSERT INTO prompt_templates (name, description, is_active)
        VALUES (%s, %s, %s)
        ON CONFLICT (name) DO UPDATE SET
            description = EXCLUDED.description,
            is_active = EXCLUDED.is_active
        RETURNING id
        """
        
        try:
            result = self.db_client.fetch_one(sql, (name, description, is_active))
            if result:
                logger.info(f"Created/updated prompt template: {name}")
                return result['id']
        except Exception as e:
            logger.error(f"Failed to create prompt template {name}: {e}")
        
        return None
    
    def create_template_version(
        self,
        template_id: int,
        system_block: str,
        instruction_block: str,
        workflow_block: Optional[str] = None,
        output_schema_block: Optional[str] = None
    ) -> Optional[int]:
        """
        Create a new version of a prompt template.
        
        Args:
            template_id: Template ID
            system_block: System prompt block
            instruction_block: Instruction prompt block
            workflow_block: Workflow description block
            output_schema_block: Output schema block
            
        Returns:
            Template version ID or None if failed
        """
        # Get next version number
        version_sql = """
        SELECT COALESCE(MAX(version), 0) + 1 as next_version
        FROM prompt_template_versions
        WHERE template_id = %s
        """
        
        try:
            version_result = self.db_client.fetch_one(version_sql, (template_id,))
            if not version_result:
                return None
            
            next_version = version_result['next_version']
            
            # Create new version
            insert_sql = """
            INSERT INTO prompt_template_versions (
                template_id, version, system_block,
                instruction_block, workflow_block, output_schema_block
            )
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id
            """
            
            result = self.db_client.fetch_one(insert_sql, (
                template_id,
                next_version,
                system_block,
                instruction_block,
                workflow_block,
                output_schema_block
            ))
            
            if result:
                logger.info(f"Created version {next_version} for template {template_id}")
                return result['id']
                
        except Exception as e:
            logger.error(f"Failed to create template version for template {template_id}: {e}")
        
        return None
    
    def get_template(self, template_id: Optional[int] = None, name: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Get prompt template by ID or name.
        
        Args:
            template_id: Template ID
            name: Template name
            
        Returns:
            Template details or None
        """
        if not template_id and not name:
            return None
        
        sql = """
        SELECT id, name, description, is_active, created_at
        FROM prompt_templates
        WHERE """
        
        params = []
        if template_id:
            sql += "id = %s"
            params.append(template_id)
        elif name:
            sql += "name = %s"
            params.append(name)
        
        try:
            return self.db_client.fetch_one(sql, tuple(params))
        except Exception as e:
            logger.error(f"Failed to get prompt template: {e}")
            return None
    
    def get_template_version(
        self,
        version_id: Optional[int] = None,
        template_id: Optional[int] = None,
        version_number: Optional[int] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Get prompt template version.
        
        Args:
            version_id: Version ID
            template_id: Template ID with version_number
            version_number: Version number with template_id
            
        Returns:
            Template version details or None
        """
        if version_id:
            sql = """
            SELECT 
                ptv.id, ptv.template_id, ptv.version,
                ptv.system_block, ptv.instruction_block,
                ptv.workflow_block, ptv.output_schema_block,
                ptv.created_at,
                pt.name as template_name,
                pt.description as template_description
            FROM prompt_template_versions ptv
            JOIN prompt_templates pt ON ptv.template_id = pt.id
            WHERE ptv.id = %s
            """
            params = (version_id,)
        elif template_id and version_number:
            sql = """
            SELECT 
                ptv.id, ptv.template_id, ptv.version,
                ptv.system_block, ptv.instruction_block,
                ptv.workflow_block, ptv.output_schema_block,
                ptv.created_at,
                pt.name as template_name,
                pt.description as template_description
            FROM prompt_template_versions ptv
            JOIN prompt_templates pt ON ptv.template_id = pt.id
            WHERE ptv.template_id = %s AND ptv.version = %s
            """
            params = (template_id, version_number)
        else:
            return None
        
        try:
            return self.db_client.fetch_one(sql, params)
        except Exception as e:
            logger.error(f"Failed to get template version: {e}")
            return None
    
    def get_latest_template_version(self, template_id: int) -> Optional[Dict[str, Any]]:
        """
        Get latest version of a template.
        
        Args:
            template_id: Template ID
            
        Returns:
            Latest template version or None
        """
        sql = """
        SELECT 
            ptv.id, ptv.template_id, ptv.version,
            ptv.system_block, ptv.instruction_block,
            ptv.workflow_block, ptv.output_schema_block,
            ptv.created_at
        FROM prompt_template_versions ptv
        WHERE ptv.template_id = %s
        ORDER BY ptv.version DESC
        LIMIT 1
        """
        
        try:
            return self.db_client.fetch_one(sql, (template_id,))
        except Exception as e:
            logger.error(f"Failed to get latest version for template {template_id}: {e}")
            return None
    
    def get_active_templates(self) -> List[Dict[str, Any]]:
        """
        Get all active prompt templates.
        
        Returns:
            List of active templates
        """
        sql = """
        SELECT 
            pt.id, pt.name, pt.description, pt.created_at,
            MAX(ptv.version) as latest_version,
            COUNT(ptv.id) as version_count
        FROM prompt_templates pt
        LEFT JOIN prompt_template_versions ptv ON pt.id = ptv.template_id
        WHERE pt.is_active = TRUE
        GROUP BY pt.id, pt.name, pt.description, pt.created_at
        ORDER BY pt.name
        """
        
        try:
            return self.db_client.fetch_all(sql)
        except Exception as e:
            logger.error(f"Failed to get active templates: {e}")
            return []
    
    def get_template_versions(self, template_id: int, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get all versions of a template.
        
        Args:
            template_id: Template ID
            limit: Maximum number of versions to return
            
        Returns:
            List of template versions
        """
        sql = """
        SELECT 
            id, version, system_block, instruction_block,
            workflow_block, output_schema_block, created_at
        FROM prompt_template_versions
        WHERE template_id = %s
        ORDER BY version DESC
        LIMIT %s
        """
        
        try:
            return self.db_client.fetch_all(sql, (template_id, limit))
        except Exception as e:
            logger.error(f"Failed to get versions for template {template_id}: {e}")
            return []
    
    def deactivate_template(self, template_id: int) -> bool:
        """
        Deactivate a prompt template.
        
        Args:
            template_id: Template ID
            
        Returns:
            True if successful
        """
        sql = """
        UPDATE prompt_templates
        SET is_active = FALSE
        WHERE id = %s
        """
        
        try:
            self.db_client.execute(sql, (template_id,))
            logger.info(f"Deactivated template {template_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to deactivate template {template_id}: {e}")
            return False
    
    def activate_template(self, template_id: int) -> bool:
        """
        Activate a prompt template.
        
        Args:
            template_id: Template ID
            
        Returns:
            True if successful
        """
        sql = """
        UPDATE prompt_templates
        SET is_active = TRUE
        WHERE id = %s
        """
        
        try:
            self.db_client.execute(sql, (template_id,))
            logger.info(f"Activated template {template_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to activate template {template_id}: {e}")
            return False
    
    def get_template_usage_stats(self, template_id: int) -> Dict[str, Any]:
        """
        Get usage statistics for a template.
        
        Args:
            template_id: Template ID
            
        Returns:
            Dictionary with usage statistics
        """
        sql = """
        SELECT 
            COUNT(DISTINCT gr.id) as total_generations,
            COUNT(DISTINCT gr.cve_id) as unique_cves,
            MIN(gr.created_at) as first_used,
            MAX(gr.created_at) as last_used,
            COUNT(DISTINCT gr.model_name) as unique_models
        FROM generation_runs gr
        WHERE gr.prompt_template_version_id IN (
            SELECT id FROM prompt_template_versions WHERE template_id = %s
        )
        """
        
        try:
            result = self.db_client.fetch_one(sql, (template_id,))
            return dict(result) if result else {}
        except Exception as e:
            logger.error(f"Failed to get usage stats for template {template_id}: {e}")
            return {}
    
    def search_templates(
        self,
        search_term: Optional[str] = None,
        is_active: Optional[bool] = None,
        limit: int = 20
    ) -> List[Dict[str, Any]]:
        """
        Search for prompt templates.
        
        Args:
            search_term: Search term for name or description
            is_active: Filter by active status
            limit: Maximum number of results
            
        Returns:
            List of matching templates
        """
        sql = """
        SELECT 
            pt.id, pt.name, pt.description, pt.is_active, pt.created_at,
            MAX(ptv.version) as latest_version
        FROM prompt_templates pt
        LEFT JOIN prompt_template_versions ptv ON pt.id = ptv.template_id
        WHERE 1=1
        """
        
        params = []
        
        if search_term:
            sql += " AND (pt.name ILIKE %s OR pt.description ILIKE %s)"
            params.extend([f"%{search_term}%", f"%{search_term}%"])
        
        if is_active is not None:
            sql += " AND pt.is_active = %s"
            params.append(is_active)
        
        sql += """
        GROUP BY pt.id, pt.name, pt.description, pt.is_active, pt.created_at
        ORDER BY pt.created_at DESC
        LIMIT %s
        """
        params.append(limit)
        
        try:
            return self.db_client.fetch_all(sql, tuple(params))
        except Exception as e:
            logger.error(f"Failed to search templates: {e}")
            return []