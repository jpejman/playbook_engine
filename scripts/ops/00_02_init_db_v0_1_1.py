#!/usr/bin/env python3
"""
Playbook Engine Database Initialization Script
Version: v0.1.1
Timestamp: 2026-04-07

Initializes the PostgreSQL database with expanded schema for playbook engine.
Includes tables for queue orchestration, retrieval lineage, prompt versioning,
generation run tracking, QA tracking, and approved playbook storage.
"""

import os
import sys
import logging
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from utils.db import DatabaseClient

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def create_tables(db_client):
    """Create all required tables for playbook engine."""
    
    # SQL statements for table creation
    tables_sql = [
        # 1. cve_queue - Queue for CVE processing
        """
        CREATE TABLE IF NOT EXISTS cve_queue (
            id SERIAL PRIMARY KEY,
            cve_id VARCHAR(50) NOT NULL UNIQUE,
            status VARCHAR(20) NOT NULL DEFAULT 'pending',
            priority INTEGER NOT NULL DEFAULT 5,
            retry_count INTEGER NOT NULL DEFAULT 0,
            source VARCHAR(100),
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            CHECK (status IN ('pending', 'processing', 'completed', 'failed', 'retry'))
        )
        """,
        
        # 2. cve_context_snapshot - Snapshot of CVE context at processing time
        """
        CREATE TABLE IF NOT EXISTS cve_context_snapshot (
            id SERIAL PRIMARY KEY,
            cve_id VARCHAR(50) NOT NULL,
            source VARCHAR(100) NOT NULL,
            snapshot_json JSONB NOT NULL,
            snapshot_hash VARCHAR(64) NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            UNIQUE(cve_id, snapshot_hash)
        )
        """,
        
        # 3. retrieval_runs - Tracking of retrieval operations
        """
        CREATE TABLE IF NOT EXISTS retrieval_runs (
            id SERIAL PRIMARY KEY,
            cve_id VARCHAR(50) NOT NULL,
            queue_id INTEGER REFERENCES cve_queue(id) ON DELETE CASCADE,
            retrieval_type VARCHAR(50) NOT NULL,
            keyword_query TEXT,
            vector_query_metadata JSONB,
            retrieval_metadata JSONB,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        )
        """,
        
        # 4. retrieval_documents - Documents retrieved for each run
        """
        CREATE TABLE IF NOT EXISTS retrieval_documents (
            id SERIAL PRIMARY KEY,
            retrieval_run_id INTEGER NOT NULL REFERENCES retrieval_runs(id) ON DELETE CASCADE,
            source_index VARCHAR(100) NOT NULL,
            document_id VARCHAR(255) NOT NULL,
            score FLOAT,
            rank INTEGER NOT NULL,
            document_metadata JSONB,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            UNIQUE(retrieval_run_id, document_id)
        )
        """,
        
        # 5. prompt_templates - Prompt template definitions
        """
        CREATE TABLE IF NOT EXISTS prompt_templates (
            id SERIAL PRIMARY KEY,
            name VARCHAR(100) NOT NULL UNIQUE,
            description TEXT,
            is_active BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        )
        """,
        
        # 6. prompt_template_versions - Versioned prompt templates
        """
        CREATE TABLE IF NOT EXISTS prompt_template_versions (
            id SERIAL PRIMARY KEY,
            template_id INTEGER NOT NULL REFERENCES prompt_templates(id) ON DELETE CASCADE,
            version INTEGER NOT NULL,
            system_block TEXT NOT NULL,
            instruction_block TEXT NOT NULL,
            workflow_block TEXT,
            output_schema_block TEXT,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            UNIQUE(template_id, version)
        )
        """,
        
        # 7. generation_runs - Tracking of playbook generation runs
        """
        CREATE TABLE IF NOT EXISTS generation_runs (
            id SERIAL PRIMARY KEY,
            cve_id VARCHAR(50) NOT NULL,
            queue_id INTEGER REFERENCES cve_queue(id) ON DELETE CASCADE,
            prompt_template_version_id INTEGER REFERENCES prompt_template_versions(id) ON DELETE SET NULL,
            rendered_prompt TEXT NOT NULL,
            prompt_inputs JSONB NOT NULL,
            model_name VARCHAR(100),
            raw_response TEXT,
            parsed_response JSONB,
            status VARCHAR(20) NOT NULL DEFAULT 'pending',
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            CHECK (status IN ('pending', 'processing', 'completed', 'failed'))
        )
        """,
        
        # 8. qa_runs - Quality assurance runs for generated playbooks
        """
        CREATE TABLE IF NOT EXISTS qa_runs (
            id SERIAL PRIMARY KEY,
            generation_run_id INTEGER NOT NULL REFERENCES generation_runs(id) ON DELETE CASCADE,
            qa_result VARCHAR(20) NOT NULL,
            qa_score FLOAT,
            qa_feedback TEXT,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            CHECK (qa_result IN ('approved', 'rejected', 'needs_revision'))
        )
        """,
        
        # 9. approved_playbooks - Final approved playbooks
        """
        CREATE TABLE IF NOT EXISTS approved_playbooks (
            id SERIAL PRIMARY KEY,
            cve_id VARCHAR(50) NOT NULL,
            generation_run_id INTEGER REFERENCES generation_runs(id) ON DELETE SET NULL,
            playbook JSONB NOT NULL,
            version INTEGER NOT NULL DEFAULT 1,
            approved_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            UNIQUE(cve_id, version)
        )
        """
    ]
    
    # Create tables
    for i, sql in enumerate(tables_sql, 1):
        try:
            db_client.execute(sql)
            logger.info(f"Created table {i}/9")
        except Exception as e:
            logger.error(f"Failed to create table {i}: {e}")
            raise


def create_indexes(db_client):
    """Create performance indexes for common queries."""
    
    indexes_sql = [
        # cve_queue indexes
        "CREATE INDEX IF NOT EXISTS idx_cve_queue_status ON cve_queue(status)",
        "CREATE INDEX IF NOT EXISTS idx_cve_queue_priority ON cve_queue(priority)",
        "CREATE INDEX IF NOT EXISTS idx_cve_queue_created_at ON cve_queue(created_at)",
        
        # cve_context_snapshot indexes
        "CREATE INDEX IF NOT EXISTS idx_cve_context_cve_id ON cve_context_snapshot(cve_id)",
        "CREATE INDEX IF NOT EXISTS idx_cve_context_created_at ON cve_context_snapshot(created_at)",
        
        # retrieval_runs indexes
        "CREATE INDEX IF NOT EXISTS idx_retrieval_runs_cve_id ON retrieval_runs(cve_id)",
        "CREATE INDEX IF NOT EXISTS idx_retrieval_runs_queue_id ON retrieval_runs(queue_id)",
        "CREATE INDEX IF NOT EXISTS idx_retrieval_runs_created_at ON retrieval_runs(created_at)",
        
        # retrieval_documents indexes
        "CREATE INDEX IF NOT EXISTS idx_retrieval_docs_run_id ON retrieval_documents(retrieval_run_id)",
        "CREATE INDEX IF NOT EXISTS idx_retrieval_docs_score ON retrieval_documents(score)",
        "CREATE INDEX IF NOT EXISTS idx_retrieval_docs_source_index ON retrieval_documents(source_index)",
        
        # prompt_templates indexes
        "CREATE INDEX IF NOT EXISTS idx_prompt_templates_active ON prompt_templates(is_active)",
        
        # prompt_template_versions indexes
        "CREATE INDEX IF NOT EXISTS idx_prompt_versions_template_id ON prompt_template_versions(template_id)",
        "CREATE INDEX IF NOT EXISTS idx_prompt_versions_created_at ON prompt_template_versions(created_at)",
        
        # generation_runs indexes
        "CREATE INDEX IF NOT EXISTS idx_generation_runs_cve_id ON generation_runs(cve_id)",
        "CREATE INDEX IF NOT EXISTS idx_generation_runs_queue_id ON generation_runs(queue_id)",
        "CREATE INDEX IF NOT EXISTS idx_generation_runs_status ON generation_runs(status)",
        "CREATE INDEX IF NOT EXISTS idx_generation_runs_created_at ON generation_runs(created_at)",
        
        # qa_runs indexes
        "CREATE INDEX IF NOT EXISTS idx_qa_runs_generation_id ON qa_runs(generation_run_id)",
        "CREATE INDEX IF NOT EXISTS idx_qa_runs_result ON qa_runs(qa_result)",
        "CREATE INDEX IF NOT EXISTS idx_qa_runs_score ON qa_runs(qa_score)",
        
        # approved_playbooks indexes
        "CREATE INDEX IF NOT EXISTS idx_approved_playbooks_cve_id ON approved_playbooks(cve_id)",
        "CREATE INDEX IF NOT EXISTS idx_approved_playbooks_version ON approved_playbooks(version)",
        "CREATE INDEX IF NOT EXISTS idx_approved_playbooks_approved_at ON approved_playbooks(approved_at)"
    ]
    
    # Create indexes
    for i, sql in enumerate(indexes_sql, 1):
        try:
            db_client.execute(sql)
            logger.info(f"Created index {i}/{len(indexes_sql)}")
        except Exception as e:
            logger.error(f"Failed to create index {i}: {e}")
            # Non-critical, continue


def create_triggers(db_client):
    """Create database triggers for automatic updates."""
    
    triggers_sql = [
        # Update timestamp trigger for cve_queue
        """
        CREATE OR REPLACE FUNCTION update_updated_at_column()
        RETURNS TRIGGER AS $$
        BEGIN
            NEW.updated_at = NOW();
            RETURN NEW;
        END;
        $$ language 'plpgsql'
        """,
        
        """
        DROP TRIGGER IF EXISTS update_cve_queue_updated_at ON cve_queue;
        CREATE TRIGGER update_cve_queue_updated_at
            BEFORE UPDATE ON cve_queue
            FOR EACH ROW
            EXECUTE FUNCTION update_updated_at_column();
        """
    ]
    
    # Create triggers
    for sql in triggers_sql:
        try:
            db_client.execute(sql)
            logger.info("Created/updated triggers")
        except Exception as e:
            logger.warning(f"Could not create triggers: {e}")
            # Triggers are optional


def insert_initial_data(db_client):
    """Insert initial data like default prompt templates."""
    
    # Default prompt template for playbook generation
    default_template_sql = """
    INSERT INTO prompt_templates (name, description, is_active)
    VALUES ('playbook_generation_v1', 'Default template for security playbook generation', TRUE)
    ON CONFLICT (name) DO NOTHING
    RETURNING id
    """
    
    try:
        result = db_client.fetch_one(default_template_sql)
        if result:
            template_id = result['id']
            
            # Insert initial version
            version_sql = """
            INSERT INTO prompt_template_versions (template_id, version, system_block, instruction_block, workflow_block, output_schema_block)
            VALUES (%s, 1, %s, %s, %s, %s)
            ON CONFLICT (template_id, version) DO NOTHING
            """
            
            system_block = """You are a security playbook generation assistant. Generate comprehensive remediation playbooks for security vulnerabilities."""
            
            instruction_block = """Based on the provided CVE information and retrieved context, generate a detailed security playbook that includes:
1. Pre-remediation checks and preparations
2. Step-by-step remediation procedures
3. Verification steps
4. Rollback procedures if needed
5. References and additional resources

Format the playbook in clear, actionable sections."""
            
            workflow_block = """1. Analyze CVE details and severity
2. Review retrieved context from vulnerability databases
3. Identify affected systems and components
4. Generate remediation steps based on best practices
5. Include verification procedures
6. Add rollback instructions for safety"""
            
            output_schema_block = """{
  "title": "string",
  "cve_id": "string",
  "severity": "string",
  "affected_components": ["string"],
  "pre_remediation_checks": ["string"],
  "remediation_steps": [{
    "step_number": "integer",
    "description": "string",
    "commands": ["string"],
    "verification": "string"
  }],
  "verification_procedures": ["string"],
  "rollback_procedures": ["string"],
  "references": ["string"]
}"""
            
            db_client.execute(version_sql, (
                template_id,
                system_block,
                instruction_block,
                workflow_block,
                output_schema_block
            ))
            
            logger.info("Inserted default prompt template")
    except Exception as e:
        logger.warning(f"Could not insert initial data: {e}")
        # Initial data is optional


def main():
    """Main initialization function."""
    logger.info("Starting Playbook Engine database initialization (v0.1.1)")
    logger.info("=" * 60)
    
    try:
        # Initialize database client
        db_client = DatabaseClient()
        
        # Test connection
        if not db_client.test_connection():
            logger.error("Database connection test failed")
            sys.exit(1)
        
        logger.info("Database connection successful")
        
        # Create tables
        logger.info("Creating tables...")
        create_tables(db_client)
        
        # Create indexes
        logger.info("Creating indexes...")
        create_indexes(db_client)
        
        # Create triggers
        logger.info("Creating triggers...")
        create_triggers(db_client)
        
        # Insert initial data
        logger.info("Inserting initial data...")
        insert_initial_data(db_client)
        
        logger.info("=" * 60)
        logger.info("Database initialization completed successfully!")
        logger.info("Schema version: v0.1.1")
        logger.info("Tables created: 9")
        
        # Verify table counts
        count_sql = "SELECT COUNT(*) as table_count FROM information_schema.tables WHERE table_schema = 'public'"
        result = db_client.fetch_one(count_sql)
        if result:
            logger.info(f"Total tables in public schema: {result['table_count']}")
        
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        sys.exit(1)
    finally:
        # Clean up connections
        if 'db_client' in locals():
            db_client.close_all()


if __name__ == "__main__":
    main()