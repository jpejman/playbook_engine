"""
Diagnostics for continuous pipeline v0.3.0 evaluation framework
Version: v0.3.0
"""

from __future__ import annotations

import sys
import os
import logging
from typing import List, Dict, Any

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from scripts.prod.continuous_pipeline_v0_3_0.config import ContinuousPipelineConfig
from scripts.prod.continuous_pipeline_v0_3_0.db_clients import PlaybookEngineClient
from scripts.prod.continuous_pipeline_v0_3_0.opensearch_client import OpenSearchClient
from scripts.prod.continuous_pipeline_v0_3_0.llm_client import LLMClient

logger = logging.getLogger(__name__)


class DiagnosticsV0_3_0:
    """Diagnostics for v0.3.0 evaluation framework."""
    
    def __init__(self):
        self.db = PlaybookEngineClient()
        self.opensearch = OpenSearchClient()
        self.llm = LLMClient()
    
    def run_all_checks(self) -> Dict[str, Any]:
        """Run all diagnostic checks."""
        logger.info("Running v0.3.0 diagnostic checks...")
        
        results = {
            'database': self.check_database(),
            'opensearch': self.check_opensearch(),
            'llm': self.check_llm_connection(),
            'evaluation_columns': self.check_evaluation_columns(),
            'queue': self.check_queue_status(),
            'generation_runs': self.check_generation_runs_stats()
        }
        
        # Overall status
        all_passed = all(result.get('status') == 'OK' for result in results.values())
        results['overall'] = {
            'status': 'OK' if all_passed else 'FAILED',
            'message': 'All checks passed' if all_passed else 'Some checks failed'
        }
        
        self._print_summary(results)
        return results
    
    def check_database(self) -> Dict[str, Any]:
        """Check database connectivity and required tables."""
        logger.info("Checking database connectivity...")
        
        try:
            # Test connection
            self.db.execute("SELECT 1")
            
            # Check required tables exist
            tables = ['generation_runs', 'cve_queue']
            missing_tables = []
            
            for table in tables:
                query = """
                    SELECT EXISTS (
                        SELECT FROM information_schema.tables 
                        WHERE table_schema = 'public' 
                        AND table_name = %s
                    )
                """
                result = self.db.execute(query, (table,))
                if not result or not result[0][0]:
                    missing_tables.append(table)
            
            if missing_tables:
                return {
                    'status': 'FAILED',
                    'message': f'Missing tables: {missing_tables}',
                    'details': {'missing_tables': missing_tables}
                }
            
            return {
                'status': 'OK',
                'message': 'Database connectivity OK, required tables exist',
                'details': {'tables_checked': tables}
            }
            
        except Exception as e:
            return {
                'status': 'FAILED',
                'message': f'Database connection failed: {e}',
                'details': {'error': str(e)}
            }
    
    def check_opensearch(self) -> Dict[str, Any]:
        """Check OpenSearch connectivity and index."""
        logger.info("Checking OpenSearch connectivity...")
        
        try:
            # Test connection
            self.opensearch.ping()
            
            # Check index exists
            index = ContinuousPipelineConfig.OPENSEARCH_INDEX
            if not self.opensearch.index_exists(index):
                return {
                    'status': 'FAILED',
                    'message': f'OpenSearch index {index} does not exist',
                    'details': {'index': index}
                }
            
            # Get document count
            count = self.opensearch.count(index)
            
            return {
                'status': 'OK',
                'message': f'OpenSearch connectivity OK, index {index} has {count} documents',
                'details': {'index': index, 'document_count': count}
            }
            
        except Exception as e:
            return {
                'status': 'FAILED',
                'message': f'OpenSearch connection failed: {e}',
                'details': {'error': str(e)}
            }
    
    def check_llm_connection(self) -> Dict[str, Any]:
        """Check LLM service connectivity."""
        logger.info("Checking LLM service connectivity...")
        
        try:
            # Test with a simple model list request
            models = self.llm.list_models()
            
            return {
                'status': 'OK',
                'message': f'LLM service connectivity OK, found {len(models)} models',
                'details': {'models_found': len(models)}
            }
            
        except Exception as e:
            return {
                'status': 'FAILED',
                'message': f'LLM service connection failed: {e}',
                'details': {'error': str(e)}
            }
    
    def check_evaluation_columns(self) -> Dict[str, Any]:
        """Check evaluation columns exist in generation_runs table."""
        logger.info("Checking evaluation columns in generation_runs...")
        
        required_columns = [
            'evaluation_mode',
            'evaluation_batch_id', 
            'evaluation_label'
        ]
        
        try:
            # Get table columns
            columns = self.db.table_columns('public', 'generation_runs')
            
            missing_columns = []
            for column in required_columns:
                if column not in columns:
                    missing_columns.append(column)
            
            if missing_columns:
                return {
                    'status': 'FAILED',
                    'message': f'Missing evaluation columns: {missing_columns}',
                    'details': {
                        'missing_columns': missing_columns,
                        'existing_columns': columns
                    }
                }
            
            return {
                'status': 'OK',
                'message': 'All evaluation columns exist in generation_runs',
                'details': {
                    'required_columns': required_columns,
                    'found_columns': [col for col in required_columns if col in columns]
                }
            }
            
        except Exception as e:
            return {
                'status': 'FAILED',
                'message': f'Failed to check evaluation columns: {e}',
                'details': {'error': str(e)}
            }
    
    def check_queue_status(self) -> Dict[str, Any]:
        """Check CVE queue status."""
        logger.info("Checking CVE queue status...")
        
        try:
            # Get queue statistics
            query = """
                SELECT 
                    status,
                    COUNT(*) as count
                FROM public.cve_queue
                GROUP BY status
                ORDER BY status
            """
            
            results = self.db.execute(query)
            stats = {row['status']: row['count'] for row in results} if results else {}
            
            total = sum(stats.values())
            pending = stats.get('pending', 0)
            
            return {
                'status': 'OK',
                'message': f'Queue has {total} total items, {pending} pending',
                'details': {
                    'total': total,
                    'pending': pending,
                    'stats': stats
                }
            }
            
        except Exception as e:
            return {
                'status': 'FAILED',
                'message': f'Failed to check queue status: {e}',
                'details': {'error': str(e)}
            }
    
    def check_generation_runs_stats(self) -> Dict[str, Any]:
        """Check generation_runs statistics."""
        logger.info("Checking generation_runs statistics...")
        
        try:
            # Get overall stats
            query = """
                SELECT 
                    COUNT(*) as total,
                    COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed,
                    COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed,
                    COUNT(CASE WHEN evaluation_mode = TRUE THEN 1 END) as evaluation_runs
                FROM public.generation_runs
            """
            
            result = self.db.execute(query)
            if not result:
                return {
                    'status': 'FAILED',
                    'message': 'No data in generation_runs',
                    'details': {}
                }
            
            stats = result[0]
            
            # Get recent evaluation batches
            eval_query = """
                SELECT 
                    evaluation_batch_id,
                    evaluation_label,
                    COUNT(*) as run_count,
                    MIN(created_at) as first_run,
                    MAX(created_at) as last_run
                FROM public.generation_runs
                WHERE evaluation_mode = TRUE
                GROUP BY evaluation_batch_id, evaluation_label
                ORDER BY MAX(created_at) DESC
                LIMIT 5
            """
            
            eval_results = self.db.execute(eval_query)
            eval_batches = []
            if eval_results:
                for row in eval_results:
                    eval_batches.append({
                        'batch_id': row['evaluation_batch_id'],
                        'label': row['evaluation_label'],
                        'run_count': row['run_count'],
                        'first_run': row['first_run'].isoformat() if row['first_run'] else None,
                        'last_run': row['last_run'].isoformat() if row['last_run'] else None
                    })
            
            return {
                'status': 'OK',
                'message': f'Generation runs: {stats["total"]} total, {stats["completed"]} completed, {stats["failed"]} failed, {stats["evaluation_runs"]} evaluation runs',
                'details': {
                    'total': stats['total'],
                    'completed': stats['completed'],
                    'failed': stats['failed'],
                    'evaluation_runs': stats['evaluation_runs'],
                    'recent_evaluation_batches': eval_batches
                }
            }
            
        except Exception as e:
            return {
                'status': 'FAILED',
                'message': f'Failed to check generation_runs stats: {e}',
                'details': {'error': str(e)}
            }
    
    def _print_summary(self, results: Dict[str, Any]):
        """Print diagnostic summary."""
        print("\n" + "="*80)
        print("v0.3.0 DIAGNOSTIC SUMMARY")
        print("="*80)
        
        for check_name, result in results.items():
            if check_name == 'overall':
                continue
                
            status = result.get('status', 'UNKNOWN')
            message = result.get('message', 'No message')
            
            status_symbol = "[OK]" if status == 'OK' else "[FAIL]"
            print(f"{status_symbol} {check_name.upper():20} {message}")
        
        print("-"*80)
        overall = results.get('overall', {})
        overall_status = overall.get('status', 'UNKNOWN')
        overall_message = overall.get('message', 'No message')
        
        if overall_status == 'OK':
            print(f"[OK] OVERALL: {overall_message}")
        else:
            print(f"[FAIL] OVERALL: {overall_message}")
        
        print("="*80)


def main():
    """Main entry point for diagnostics."""
    logging.basicConfig(level=logging.INFO)
    
    diagnostics = DiagnosticsV0_3_0()
    results = diagnostics.run_all_checks()
    
    # Exit with appropriate code
    overall_status = results.get('overall', {}).get('status', 'FAILED')
    sys.exit(0 if overall_status == 'OK' else 1)


if __name__ == '__main__':
    main()