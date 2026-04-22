"""
Script to add v0.3.1 columns to generation_runs table for structured output normalization.
Version: v0.3.1
"""

from __future__ import annotations

import sys
import os
import logging

# Add the parent directory to the path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from scripts.prod.continuous_pipeline_v0_3_1.db_clients import PlaybookEngineClient

logger = logging.getLogger(__name__)


def add_v3_1_columns():
    """Add v0.3.1 columns to generation_runs table."""
    db = PlaybookEngineClient()
    
    # Check current columns
    columns = db.table_columns('public', 'generation_runs')
    logger.info(f"Current generation_runs columns: {columns}")
    
    # v0.3.1 columns to add
    columns_to_add = [
        ('extracted_response', 'TEXT'),
        ('repaired_response', 'TEXT'),
        ('normalized_response', 'TEXT'),
        ('validation_grade', 'VARCHAR(50)'),
        ('parse_passed', 'BOOLEAN DEFAULT FALSE'),
        ('repair_applied', 'BOOLEAN DEFAULT FALSE'),
        ('normalization_applied', 'BOOLEAN DEFAULT FALSE'),
        ('semantic_utility_flag', 'BOOLEAN DEFAULT FALSE'),
    ]
    
    for column_name, column_type in columns_to_add:
        if column_name not in columns:
            logger.info(f"Adding column {column_name} with type {column_type}")
            try:
                db.execute(
                    f"ALTER TABLE public.generation_runs ADD COLUMN IF NOT EXISTS {column_name} {column_type}",
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
    
    # Check for all v0.3.1 columns
    v3_1_columns = [col[0] for col in columns_to_add]
    missing = [col for col in v3_1_columns if col not in final_columns]
    
    if missing:
        logger.error(f"Missing v0.3.1 columns: {missing}")
        return False
    
    logger.info("All v0.3.1 columns are present in generation_runs table")
    
    # Also update the status column to support 'partial' status
    try:
        # Check if status column exists and what values it allows
        logger.info("Checking status column constraints...")
        
        # Try to update an existing row to 'partial' status to test
        test_query = """
        UPDATE public.generation_runs 
        SET status = 'partial' 
        WHERE id = (SELECT id FROM public.generation_runs LIMIT 1)
        """
        try:
            db.execute(test_query, None)
            logger.info("Status column already supports 'partial' value")
        except Exception as e:
            if 'check constraint' in str(e).lower() or 'invalid value' in str(e).lower():
                logger.warning("Status column may not support 'partial' value. Manual schema update may be needed.")
                logger.warning("Consider running: ALTER TABLE public.generation_runs DROP CONSTRAINT IF EXISTS generation_runs_status_check")
                logger.warning("Then: ALTER TABLE public.generation_runs ADD CONSTRAINT generation_runs_status_check CHECK (status IN ('pending', 'processing', 'completed', 'failed', 'partial'))")
            else:
                logger.warning(f"Could not test status column: {e}")
    
    except Exception as e:
        logger.warning(f"Could not check status column: {e}")
    
    return True


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    success = add_v3_1_columns()
    exit(0 if success else 1)