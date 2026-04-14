#!/usr/bin/env python3
"""
Playbook Engine Database Verification Script
Version: v0.1.1
Timestamp: 2026-04-07

Verifies the PostgreSQL database schema and configuration for playbook engine.
Checks table existence, indexes, foreign keys, and data integrity.
"""

import os
import sys
import logging
from pathlib import Path
from typing import Dict, List, Any
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


class DatabaseVerifier:
    """Verifies database schema and configuration."""
    
    # Expected tables and their required columns
    EXPECTED_TABLES = {
        'cve_queue': ['id', 'cve_id', 'status', 'priority', 'created_at'],
        'cve_context_snapshot': ['id', 'cve_id', 'snapshot_json', 'snapshot_hash', 'created_at'],
        'retrieval_runs': ['id', 'cve_id', 'retrieval_type', 'created_at'],
        'retrieval_documents': ['id', 'retrieval_run_id', 'source_index', 'document_id', 'rank', 'created_at'],
        'prompt_templates': ['id', 'name', 'is_active', 'created_at'],
        'prompt_template_versions': ['id', 'template_id', 'version', 'system_block', 'instruction_block', 'created_at'],
        'generation_runs': ['id', 'cve_id', 'rendered_prompt', 'status', 'created_at'],
        'qa_runs': ['id', 'generation_run_id', 'qa_result', 'created_at'],
        'approved_playbooks': ['id', 'cve_id', 'playbook', 'version', 'approved_at']
    }
    
    # Expected indexes
    EXPECTED_INDEXES = [
        'idx_cve_queue_status',
        'idx_cve_queue_priority',
        'idx_cve_context_cve_id',
        'idx_retrieval_runs_cve_id',
        'idx_retrieval_docs_run_id',
        'idx_prompt_templates_active',
        'idx_generation_runs_cve_id',
        'idx_generation_runs_status',
        'idx_qa_runs_generation_id',
        'idx_approved_playbooks_cve_id'
    ]
    
    # Foreign key relationships
    EXPECTED_FOREIGN_KEYS = [
        ('retrieval_runs', 'queue_id', 'cve_queue', 'id'),
        ('retrieval_documents', 'retrieval_run_id', 'retrieval_runs', 'id'),
        ('prompt_template_versions', 'template_id', 'prompt_templates', 'id'),
        ('generation_runs', 'queue_id', 'cve_queue', 'id'),
        ('generation_runs', 'prompt_template_version_id', 'prompt_template_versions', 'id'),
        ('qa_runs', 'generation_run_id', 'generation_runs', 'id'),
        ('approved_playbooks', 'generation_run_id', 'generation_runs', 'id')
    ]
    
    def __init__(self, db_client: DatabaseClient):
        self.db_client = db_client
        self.verification_results = {}
    
    def verify_connection(self) -> bool:
        """Verify database connection."""
        try:
            result = self.db_client.test_connection()
            self.verification_results['connection'] = {
                'status': 'PASS' if result else 'FAIL',
                'message': 'Connection successful' if result else 'Connection failed'
            }
            return result
        except Exception as e:
            self.verification_results['connection'] = {
                'status': 'FAIL',
                'message': f'Connection error: {e}'
            }
            return False
    
    def verify_tables(self) -> Dict[str, Any]:
        """Verify all expected tables exist with required columns."""
        results = {}
        
        # Get all tables in public schema
        tables_sql = """
        SELECT table_name, column_name, data_type, is_nullable
        FROM information_schema.columns
        WHERE table_schema = 'public'
        ORDER BY table_name, ordinal_position
        """
        
        try:
            columns = self.db_client.fetch_all(tables_sql)
            
            # Group columns by table
            table_columns = {}
            for col in columns:
                table_name = col['table_name']
                if table_name not in table_columns:
                    table_columns[table_name] = []
                table_columns[table_name].append(col['column_name'])
            
            # Check each expected table
            for expected_table, required_columns in self.EXPECTED_TABLES.items():
                if expected_table not in table_columns:
                    results[expected_table] = {
                        'status': 'FAIL',
                        'message': f'Table not found',
                        'found_columns': []
                    }
                    continue
                
                found_columns = table_columns[expected_table]
                missing_columns = [col for col in required_columns if col not in found_columns]
                
                if missing_columns:
                    results[expected_table] = {
                        'status': 'FAIL',
                        'message': f'Missing columns: {missing_columns}',
                        'found_columns': found_columns
                    }
                else:
                    results[expected_table] = {
                        'status': 'PASS',
                        'message': f'Table exists with all required columns',
                        'found_columns': found_columns
                    }
            
            # Check for extra tables
            extra_tables = [t for t in table_columns.keys() if t not in self.EXPECTED_TABLES]
            if extra_tables:
                results['extra_tables'] = {
                    'status': 'INFO',
                    'message': f'Extra tables found: {extra_tables}',
                    'tables': extra_tables
                }
            
        except Exception as e:
            results['error'] = {
                'status': 'ERROR',
                'message': f'Failed to verify tables: {e}'
            }
        
        self.verification_results['tables'] = results
        return results
    
    def verify_indexes(self) -> Dict[str, Any]:
        """Verify expected indexes exist."""
        results = {}
        
        # Get all indexes
        indexes_sql = """
        SELECT indexname, tablename
        FROM pg_indexes
        WHERE schemaname = 'public'
        """
        
        try:
            indexes = self.db_client.fetch_all(indexes_sql)
            index_names = [idx['indexname'] for idx in indexes]
            
            # Check each expected index
            for expected_index in self.EXPECTED_INDEXES:
                if expected_index in index_names:
                    results[expected_index] = {
                        'status': 'PASS',
                        'message': 'Index exists'
                    }
                else:
                    results[expected_index] = {
                        'status': 'FAIL',
                        'message': 'Index not found'
                    }
            
            # Count total indexes
            results['summary'] = {
                'total_indexes': len(index_names),
                'expected_indexes': len(self.EXPECTED_INDEXES),
                'found_indexes': sum(1 for r in results.values() if r['status'] == 'PASS')
            }
            
        except Exception as e:
            results['error'] = {
                'status': 'ERROR',
                'message': f'Failed to verify indexes: {e}'
            }
        
        self.verification_results['indexes'] = results
        return results
    
    def verify_foreign_keys(self) -> Dict[str, Any]:
        """Verify foreign key relationships."""
        results = {}
        
        # Get foreign keys
        fk_sql = """
        SELECT
            tc.table_name,
            kcu.column_name,
            ccu.table_name AS foreign_table_name,
            ccu.column_name AS foreign_column_name
        FROM information_schema.table_constraints AS tc
        JOIN information_schema.key_column_usage AS kcu
            ON tc.constraint_name = kcu.constraint_name
        JOIN information_schema.constraint_column_usage AS ccu
            ON ccu.constraint_name = tc.constraint_name
        WHERE tc.constraint_type = 'FOREIGN KEY'
        AND tc.table_schema = 'public'
        """
        
        try:
            foreign_keys = self.db_client.fetch_all(fk_sql)
            
            # Convert to lookup format
            fk_lookup = {}
            for fk in foreign_keys:
                key = (fk['table_name'], fk['column_name'])
                fk_lookup[key] = (fk['foreign_table_name'], fk['foreign_column_name'])
            
            # Check each expected foreign key
            for table, column, foreign_table, foreign_column in self.EXPECTED_FOREIGN_KEYS:
                key = (table, column)
                if key in fk_lookup:
                    actual_foreign = fk_lookup[key]
                    if (actual_foreign[0] == foreign_table and 
                        actual_foreign[1] == foreign_column):
                        results[f'{table}.{column}'] = {
                            'status': 'PASS',
                            'message': f'References {foreign_table}.{foreign_column}'
                        }
                    else:
                        results[f'{table}.{column}'] = {
                            'status': 'FAIL',
                            'message': f'References {actual_foreign[0]}.{actual_foreign[1]} (expected {foreign_table}.{foreign_column})'
                        }
                else:
                    results[f'{table}.{column}'] = {
                        'status': 'FAIL',
                        'message': 'Foreign key not found'
                    }
            
            # Count total foreign keys
            results['summary'] = {
                'total_foreign_keys': len(foreign_keys),
                'expected_foreign_keys': len(self.EXPECTED_FOREIGN_KEYS),
                'found_foreign_keys': sum(1 for r in results.values() if r['status'] == 'PASS')
            }
            
        except Exception as e:
            results['error'] = {
                'status': 'ERROR',
                'message': f'Failed to verify foreign keys: {e}'
            }
        
        self.verification_results['foreign_keys'] = results
        return results
    
    def verify_data_integrity(self) -> Dict[str, Any]:
        """Perform basic data integrity checks."""
        results = {}
        
        checks = [
            # Check for duplicate CVE IDs in queue
            ("Duplicate CVE IDs in queue", 
             "SELECT cve_id, COUNT(*) FROM cve_queue GROUP BY cve_id HAVING COUNT(*) > 1"),
            
            # Check for invalid status values
            ("Invalid status values in cve_queue",
             "SELECT DISTINCT status FROM cve_queue WHERE status NOT IN ('pending', 'processing', 'completed', 'failed', 'retry')"),
            
            # Check for orphaned retrieval documents
            ("Orphaned retrieval documents",
             "SELECT rd.id FROM retrieval_documents rd LEFT JOIN retrieval_runs rr ON rd.retrieval_run_id = rr.id WHERE rr.id IS NULL LIMIT 5"),
            
            # Check for inactive prompt templates with versions
            ("Inactive templates with versions",
             "SELECT pt.id, pt.name FROM prompt_templates pt JOIN prompt_template_versions ptv ON pt.id = ptv.template_id WHERE NOT pt.is_active LIMIT 5")
        ]
        
        for check_name, sql in checks:
            try:
                data = self.db_client.fetch_all(sql)
                if data:
                    results[check_name] = {
                        'status': 'WARN',
                        'message': f'Found {len(data)} issues',
                        'sample': data[:3]  # Show first 3 issues
                    }
                else:
                    results[check_name] = {
                        'status': 'PASS',
                        'message': 'No issues found'
                    }
            except Exception as e:
                results[check_name] = {
                    'status': 'ERROR',
                    'message': f'Check failed: {e}'
                }
        
        self.verification_results['data_integrity'] = results
        return results
    
    def generate_summary(self) -> Dict[str, Any]:
        """Generate verification summary."""
        summary = {
            'total_checks': 0,
            'passed_checks': 0,
            'failed_checks': 0,
            'warnings': 0,
            'errors': 0
        }
        
        for category, results in self.verification_results.items():
            if isinstance(results, dict):
                for check_name, check_result in results.items():
                    if isinstance(check_result, dict):
                        summary['total_checks'] += 1
                        status = check_result.get('status', 'UNKNOWN')
                        if status == 'PASS':
                            summary['passed_checks'] += 1
                        elif status == 'FAIL':
                            summary['failed_checks'] += 1
                        elif status == 'WARN':
                            summary['warnings'] += 1
                        elif status == 'ERROR':
                            summary['errors'] += 1
        
        return summary
    
    def print_report(self):
        """Print verification report."""
        print("\n" + "=" * 70)
        print("PLAYBOOK ENGINE DATABASE VERIFICATION REPORT")
        print("Version: v0.1.1")
        print("=" * 70)
        
        # Print connection status
        conn_result = self.verification_results.get('connection', {})
        print(f"\n1. CONNECTION: {conn_result.get('status', 'UNKNOWN')}")
        print(f"   {conn_result.get('message', 'No message')}")
        
        # Print table verification
        print("\n2. TABLE VERIFICATION:")
        table_results = self.verification_results.get('tables', {})
        for table_name, result in table_results.items():
            if table_name not in ['extra_tables', 'error']:
                status = result.get('status', 'UNKNOWN')
                symbol = '[PASS]' if status == 'PASS' else '[FAIL]' if status == 'FAIL' else '[WARN]'
                print(f"   {symbol} {table_name}: {result.get('message', '')}")
        
        # Print indexes
        print("\n3. INDEX VERIFICATION:")
        index_results = self.verification_results.get('indexes', {})
        if 'summary' in index_results:
            summary = index_results['summary']
            print(f"   Found {summary.get('found_indexes', 0)}/{summary.get('expected_indexes', 0)} expected indexes")
        
        # Print foreign keys
        print("\n4. FOREIGN KEY VERIFICATION:")
        fk_results = self.verification_results.get('foreign_keys', {})
        if 'summary' in fk_results:
            summary = fk_results['summary']
            print(f"   Found {summary.get('found_foreign_keys', 0)}/{summary.get('expected_foreign_keys', 0)} expected foreign keys")
        
        # Print data integrity
        print("\n5. DATA INTEGRITY CHECKS:")
        integrity_results = self.verification_results.get('data_integrity', {})
        for check_name, result in integrity_results.items():
            status = result.get('status', 'UNKNOWN')
            symbol = '[PASS]' if status == 'PASS' else '[FAIL]' if status == 'FAIL' else '[WARN]' if status == 'WARN' else '[ERR]'
            print(f"   {symbol} {check_name}: {result.get('message', '')}")
        
        # Print summary
        summary = self.generate_summary()
        print("\n" + "=" * 70)
        print("VERIFICATION SUMMARY:")
        print(f"   Total Checks: {summary['total_checks']}")
        print(f"   Passed: {summary['passed_checks']}")
        print(f"   Failed: {summary['failed_checks']}")
        print(f"   Warnings: {summary['warnings']}")
        print(f"   Errors: {summary['errors']}")
        
        # Overall status
        if summary['failed_checks'] == 0 and summary['errors'] == 0:
            print("\n[PASS] DATABASE VERIFICATION PASSED")
        else:
            print("\n[FAIL] DATABASE VERIFICATION FAILED")
        print("=" * 70 + "\n")


def main():
    """Main verification function."""
    logger.info("Starting Playbook Engine database verification (v0.1.1)")
    
    try:
        # Initialize database client
        db_client = DatabaseClient()
        
        # Create verifier
        verifier = DatabaseVerifier(db_client)
        
        # Run verifications
        logger.info("Verifying database connection...")
        if not verifier.verify_connection():
            logger.error("Database connection failed")
            sys.exit(1)
        
        logger.info("Verifying tables...")
        verifier.verify_tables()
        
        logger.info("Verifying indexes...")
        verifier.verify_indexes()
        
        logger.info("Verifying foreign keys...")
        verifier.verify_foreign_keys()
        
        logger.info("Verifying data integrity...")
        verifier.verify_data_integrity()
        
        # Print report
        verifier.print_report()
        
        # Exit with appropriate code
        summary = verifier.generate_summary()
        if summary['failed_checks'] > 0 or summary['errors'] > 0:
            sys.exit(1)
        
    except Exception as e:
        logger.error(f"Verification failed: {e}")
        sys.exit(1)
    finally:
        # Clean up connections
        if 'db_client' in locals():
            db_client.close_all()


if __name__ == "__main__":
    main()