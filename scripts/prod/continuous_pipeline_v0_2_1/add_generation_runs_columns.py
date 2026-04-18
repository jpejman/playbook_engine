"""
Script to add missing columns to generation_runs table for v0.2.2 metadata enrichment.
Version: v0.2.2
Timestamp (UTC): 2026-04-18T15:29:46Z
"""

from __future__ import annotations

import sys
import os
import logging

# Add the parent directory to the path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from scripts.prod.continuous_pipeline_v0_2_1.db_clients import PlaybookEngineClient

logger = logging.getLogger(__name__)


def add_missing_columns():
    """Add missing columns to generation_runs table."""
    db = PlaybookEngineClient()
    
    # Check current columns
    columns = db.table_columns('public', 'generation_runs')
    logger.info(f"Current generation_runs columns: {columns}")
    
    # Columns to add
    columns_to_add = [
        ('run_duration_seconds', 'NUMERIC(10,3)'),
        ('creator_script', 'VARCHAR(255)')
    ]
    
    # Note: model column already exists based on earlier check
    
    for column_name, column_type in columns_to_add:
        if column_name not in columns:
            logger.info(f"Adding column {column_name} with type {column_type}")
            try:
                db.execute(
                    f"ALTER TABLE public.generation_runs ADD COLUMN {column_name} {column_type}",
                    None
                )
                logger.info(f"Successfully added column {column_name}")
            except Exception as e:
                logger.error(f"Failed to add column {column_name}: {e}")
        else:
            logger.info(f"Column {column_name} already exists")
    
    # Verify final schema
    final_columns = db.table_columns('public', 'generation_runs')
    logger.info(f"Final generation_runs columns: {final_columns}")
    
    # Check for all required columns
    required_columns = ['model', 'run_duration_seconds', 'creator_script']
    missing = [col for col in required_columns if col not in final_columns]
    
    if missing:
        logger.error(f"Missing required columns: {missing}")
        return False
    
    logger.info("All required columns are present in generation_runs table")
    return True


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    success = add_missing_columns()
    exit(0 if success else 1)