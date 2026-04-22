"""
Diagnostics for continuous_pipeline_v0_3_1
Version: v0.3.1

Purpose:
- Check database schema for v0.3.1 columns
- Show validation grade statistics
- Display recent evaluation runs by grade
"""

import sys
import os
import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta

# Add the parent directory to the path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from scripts.prod.continuous_pipeline_v0_3_1.db_clients import PlaybookEngineClient

logger = logging.getLogger(__name__)


class DiagnosticsV0_3_1:
    """
    Diagnostics for v0.3.1 pipeline.
    
    Checks for new validation columns and provides grade statistics.
    """
    
    def __init__(self):
        self.db = PlaybookEngineClient()
    
    def check_schema(self) -> Dict[str, Any]:
        """
        Check if v0.3.1 columns exist in generation_runs table.
        
        Returns:
            Dictionary with schema check results
        """
        results = {
            "table": "public.generation_runs",
            "columns_checked": [],
            "missing_columns": [],
            "present_columns": [],
            "all_columns_present": False,
        }
        
        try:
            # Get all columns in generation_runs table
            columns = self.db.table_columns("public", "generation_runs")
            results["all_columns"] = columns
            
            # v0.3.1 specific columns
            v3_1_columns = [
                "extracted_response",
                "repaired_response", 
                "normalized_response",
                "validation_grade",
                "parse_passed",
                "repair_applied",
                "normalization_applied",
                "semantic_utility_flag",
            ]
            
            for column in v3_1_columns:
                results["columns_checked"].append(column)
                if column in columns:
                    results["present_columns"].append(column)
                else:
                    results["missing_columns"].append(column)
            
            results["all_columns_present"] = len(results["missing_columns"]) == 0
            
            return results
            
        except Exception as e:
            logger.error("Failed to check schema: %s", e)
            return {
                "error": str(e),
                "table": "public.generation_runs",
                "columns_checked": [],
                "missing_columns": [],
                "present_columns": [],
                "all_columns_present": False,
            }
    
    def get_grade_statistics(self, days: int = 7) -> Dict[str, Any]:
        """
        Get validation grade statistics for recent evaluation runs.
        
        Args:
            days: Number of days to look back
            
        Returns:
            Dictionary with grade statistics
        """
        try:
            # Get grade counts
            query = """
            SELECT 
                validation_grade,
                COUNT(*) as count,
                COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed_count,
                COUNT(CASE WHEN status = 'partial' THEN 1 END) as partial_count,
                COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed_count
            FROM public.generation_runs
            WHERE evaluation_mode = TRUE
              AND created_at >= NOW() - INTERVAL '%s days'
              AND validation_grade IS NOT NULL
            GROUP BY validation_grade
            ORDER BY count DESC
            """
            
            rows = self.db.fetch_all(query, (days,))
            
            # Get total counts
            total_query = """
            SELECT 
                COUNT(*) as total,
                COUNT(CASE WHEN validation_grade IN ('STRICT_PASS', 'NORMALIZED_PASS', 'REPAIR_PASS') THEN 1 END) as passing_count,
                COUNT(CASE WHEN validation_grade = 'SEMANTIC_PARTIAL' THEN 1 END) as partial_count,
                COUNT(CASE WHEN validation_grade = 'HARD_FAIL' THEN 1 END) as fail_count
            FROM public.generation_runs
            WHERE evaluation_mode = TRUE
              AND created_at >= NOW() - INTERVAL '%s days'
              AND validation_grade IS NOT NULL
            """
            
            total_row = self.db.fetch_one(total_query, (days,))
            
            # Get model breakdown
            model_query = """
            SELECT 
                model,
                validation_grade,
                COUNT(*) as count
            FROM public.generation_runs
            WHERE evaluation_mode = TRUE
              AND created_at >= NOW() - INTERVAL '%s days'
              AND validation_grade IS NOT NULL
            GROUP BY model, validation_grade
            ORDER BY model, count DESC
            """
            
            model_rows = self.db.fetch_all(model_query, (days,))
            
            # Organize model data
            model_stats = {}
            for row in model_rows:
                model = row["model"]
                grade = row["validation_grade"]
                count = row["count"]
                
                if model not in model_stats:
                    model_stats[model] = {}
                
                model_stats[model][grade] = count
            
            return {
                "period_days": days,
                "total_runs": total_row["total"] if total_row else 0,
                "passing_runs": total_row["passing_count"] if total_row else 0,
                "partial_runs": total_row["partial_count"] if total_row else 0,
                "fail_runs": total_row["fail_count"] if total_row else 0,
                "grade_distribution": rows,
                "model_breakdown": model_stats,
            }
            
        except Exception as e:
            logger.error("Failed to get grade statistics: %s", e)
            return {
                "error": str(e),
                "period_days": days,
                "total_runs": 0,
                "grade_distribution": [],
                "model_breakdown": {},
            }
    
    def get_recent_runs_by_grade(self, limit: int = 10, grade: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get recent evaluation runs, optionally filtered by grade.
        
        Args:
            limit: Maximum number of runs to return
            grade: Optional grade to filter by
            
        Returns:
            List of recent runs
        """
        try:
            if grade:
                query = """
                SELECT 
                    cve_id,
                    model,
                    evaluation_label,
                    validation_grade,
                    parse_passed,
                    repair_applied,
                    normalization_applied,
                    semantic_utility_flag,
                    status,
                    created_at
                FROM public.generation_runs
                WHERE evaluation_mode = TRUE
                  AND validation_grade = %s
                ORDER BY created_at DESC
                LIMIT %s
                """
                params = (grade, limit)
            else:
                query = """
                SELECT 
                    cve_id,
                    model,
                    evaluation_label,
                    validation_grade,
                    parse_passed,
                    repair_applied,
                    normalization_applied,
                    semantic_utility_flag,
                    status,
                    created_at
                FROM public.generation_runs
                WHERE evaluation_mode = TRUE
                  AND validation_grade IS NOT NULL
                ORDER BY created_at DESC
                LIMIT %s
                """
                params = (limit,)
            
            rows = self.db.fetch_all(query, params)
            
            # Convert datetime objects to strings for JSON serialization
            for row in rows:
                if "created_at" in row and row["created_at"]:
                    row["created_at"] = row["created_at"].isoformat()
            
            return rows
            
        except Exception as e:
            logger.error("Failed to get recent runs: %s", e)
            return []
    
    def run_full_diagnostics(self) -> Dict[str, Any]:
        """
        Run full diagnostics suite.
        
        Returns:
            Comprehensive diagnostics results
        """
        logger.info("Running v0.3.1 diagnostics...")
        
        schema_check = self.check_schema()
        grade_stats = self.get_grade_statistics(days=7)
        recent_runs = self.get_recent_runs_by_grade(limit=10)
        
        results = {
            "timestamp": datetime.now().isoformat(),
            "pipeline_version": "v0.3.1",
            "schema_check": schema_check,
            "grade_statistics": grade_stats,
            "recent_runs": recent_runs,
        }
        
        return results
    
    def print_diagnostics(self) -> None:
        """Print formatted diagnostics to console."""
        results = self.run_full_diagnostics()
        
        print("=" * 80)
        print("CONTINUOUS PIPELINE v0.3.1 DIAGNOSTICS")
        print("=" * 80)
        print(f"Timestamp: {results['timestamp']}")
        print()
        
        # Schema check
        schema = results["schema_check"]
        print("SCHEMA CHECK")
        print("-" * 40)
        print(f"Table: {schema.get('table', 'unknown')}")
        print(f"All columns present: {schema.get('all_columns_present', False)}")
        
        if schema.get("missing_columns"):
            print(f"Missing columns: {', '.join(schema['missing_columns'])}")
        else:
            print("All v0.3.1 columns are present")
        
        print()
        
        # Grade statistics
        stats = results["grade_statistics"]
        print("GRADE STATISTICS (Last 7 days)")
        print("-" * 40)
        print(f"Total evaluation runs: {stats.get('total_runs', 0)}")
        print(f"Passing runs (STRICT/NORMALIZED/REPAIR): {stats.get('passing_runs', 0)}")
        print(f"Partial runs (SEMANTIC_PARTIAL): {stats.get('partial_runs', 0)}")
        print(f"Failed runs (HARD_FAIL): {stats.get('fail_runs', 0)}")
        
        if stats.get("grade_distribution"):
            print("\nGrade distribution:")
            for row in stats["grade_distribution"]:
                grade = row["validation_grade"]
                count = row["count"]
                completed = row.get("completed_count", 0)
                partial = row.get("partial_count", 0)
                failed = row.get("failed_count", 0)
                
                print(f"  {grade}: {count} total ({completed} completed, {partial} partial, {failed} failed)")
        
        print()
        
        # Recent runs
        recent = results["recent_runs"]
        print("RECENT EVALUATION RUNS")
        print("-" * 40)
        
        if not recent:
            print("No recent evaluation runs found")
        else:
            for i, run in enumerate(recent, 1):
                cve = run.get("cve_id", "unknown")
                model = run.get("model", "unknown")
                grade = run.get("validation_grade", "unknown")
                created = run.get("created_at", "unknown")
                
                print(f"{i}. {cve} - {model} - {grade} - {created}")


def main():
    """Main entry point for diagnostics."""
    import logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    diagnostics = DiagnosticsV0_3_1()
    diagnostics.print_diagnostics()


if __name__ == "__main__":
    main()