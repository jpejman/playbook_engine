#!/usr/bin/env python3
"""
VS.ai — Playbook Engine Gen-3
Schema Update for Generation Diagnostics
Version: v1.0.0
Timestamp (UTC): 2026-04-13

Purpose:
- Add llm_error_info column to generation_runs table for storing diagnostic information
- Create logs directory structure for debug JSON files
"""

import sys
import os
import logging
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.utils.db import DatabaseClient

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def update_generation_runs_schema(db_client):
    """Add llm_error_info column to generation_runs table."""
    
    # Check if column already exists
    check_column_sql = """
    SELECT column_name 
    FROM information_schema.columns 
    WHERE table_name = 'generation_runs' 
    AND column_name = 'llm_error_info'
    """
    
    result = db_client.fetch_one(check_column_sql)
    
    if result:
        logger.info("llm_error_info column already exists in generation_runs table")
        return True
    
    # Add the column
    add_column_sql = """
    ALTER TABLE generation_runs 
    ADD COLUMN llm_error_info JSONB
    """
    
    try:
        db_client.execute(add_column_sql)
        logger.info("Added llm_error_info column to generation_runs table")
        return True
    except Exception as e:
        logger.error(f"Failed to add llm_error_info column: {e}")
        return False


def create_logs_directory_structure():
    """Create directory structure for debug logs."""
    
    logs_dir = Path("logs")
    runs_dir = logs_dir / "runs"
    
    try:
        # Create logs directory if it doesn't exist
        logs_dir.mkdir(exist_ok=True)
        logger.info(f"Created/verified logs directory: {logs_dir}")
        
        # Create runs directory for debug JSON files
        runs_dir.mkdir(exist_ok=True)
        logger.info(f"Created/verified runs directory: {runs_dir}")
        
        # Create sessions directory for session reports
        sessions_dir = logs_dir / "sessions"
        sessions_dir.mkdir(exist_ok=True)
        logger.info(f"Created/verified sessions directory: {sessions_dir}")
        
        return True
    except Exception as e:
        logger.error(f"Failed to create logs directory structure: {e}")
        return False


def create_generation_debug_table(db_client):
    """Create a separate table for detailed generation debug information."""
    
    create_table_sql = """
    CREATE TABLE IF NOT EXISTS generation_debug_info (
        id SERIAL PRIMARY KEY,
        generation_run_id INTEGER REFERENCES generation_runs(id) ON DELETE CASCADE,
        raw_llm_payload JSONB,
        response_size_bytes INTEGER,
        latency_milliseconds INTEGER,
        error_classification VARCHAR(50),
        prompt_size_chars INTEGER,
        api_status_code INTEGER,
        model_used VARCHAR(100),
        error_message TEXT,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        UNIQUE(generation_run_id)
    )
    """
    
    try:
        db_client.execute(create_table_sql)
        logger.info("Created generation_debug_info table")
        
        # Create index for faster queries
        db_client.execute(
            "CREATE INDEX IF NOT EXISTS idx_generation_debug_run_id ON generation_debug_info(generation_run_id)"
        )
        db_client.execute(
            "CREATE INDEX IF NOT EXISTS idx_generation_debug_error ON generation_debug_info(error_classification)"
        )
        db_client.execute(
            "CREATE INDEX IF NOT EXISTS idx_generation_debug_created ON generation_debug_info(created_at)"
        )
        
        return True
    except Exception as e:
        logger.error(f"Failed to create generation_debug_info table: {e}")
        return False


def main():
    """Main execution function."""
    logger.info("Starting schema update for generation diagnostics...")
    
    try:
        # Initialize database client
        db_client = DatabaseClient()
        
        # Test connection
        if not db_client.test_connection():
            logger.error("Database connection test failed")
            sys.exit(1)
        
        logger.info("Database connection successful")
        
        # Update generation_runs schema
        logger.info("Updating generation_runs schema...")
        if not update_generation_runs_schema(db_client):
            logger.error("Failed to update generation_runs schema")
            sys.exit(1)
        
        # Create generation debug table
        logger.info("Creating generation_debug_info table...")
        if not create_generation_debug_table(db_client):
            logger.warning("Failed to create generation_debug_info table (non-critical)")
        
        # Create logs directory structure
        logger.info("Creating logs directory structure...")
        if not create_logs_directory_structure():
            logger.warning("Failed to create logs directory structure (non-critical)")
        
        logger.info("=" * 60)
        logger.info("Schema update completed successfully!")
        logger.info("Changes made:")
        logger.info("  1. Added llm_error_info column to generation_runs table")
        logger.info("  2. Created generation_debug_info table for detailed diagnostics")
        logger.info("  3. Created logs/runs/ directory for debug JSON files")
        
        # Verify the update
        verify_sql = """
        SELECT column_name, data_type 
        FROM information_schema.columns 
        WHERE table_name = 'generation_runs' 
        AND column_name = 'llm_error_info'
        """
        
        result = db_client.fetch_one(verify_sql)
        if result:
            logger.info(f"Verified: llm_error_info column exists (type: {result['data_type']})")
        else:
            logger.warning("Could not verify llm_error_info column creation")
        
    except Exception as e:
        logger.error(f"Schema update failed: {e}")
        sys.exit(1)
    finally:
        # Clean up connections
        if 'db_client' in locals():
            db_client.close_all()


if __name__ == "__main__":
    main()