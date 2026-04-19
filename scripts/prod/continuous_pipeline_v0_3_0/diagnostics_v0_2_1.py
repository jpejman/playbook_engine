"""
Diagnostics for continuous_pipeline_v0_2_1
Version: v0.2.1
Timestamp (UTC): 2026-04-17T14:36:53Z
"""

from __future__ import annotations

import sys
import traceback
from datetime import datetime, timedelta
from typing import Any

from .config import ContinuousPipelineConfig
from .db_clients import PlaybookEngineClient, VulnstrikeProductionClient
from .feeder_state import FeederStateService
from .opensearch_client import OpenSearchClient
from .queue_schema import QueueSchemaService


class DiagnosticsV021:
    def __init__(self):
        self.playbook_engine = PlaybookEngineClient()
        self.vulnstrike_prod = VulnstrikeProductionClient()
        self.opensearch = OpenSearchClient()
        self.config = ContinuousPipelineConfig
        self.queue_schema = QueueSchemaService()
        self.feeder_state = FeederStateService()

    def run(self) -> bool:
        print("=== Continuous Pipeline v0.2.1 Diagnostics ===\n")
        
        all_ok = True
        
        # DB connection diagnostics
        all_ok &= self._check_db_connections()
        
        # Table existence checks
        all_ok &= self._check_table_existence()
        
        # Queue status counts (including dead_letter)
        all_ok &= self._check_queue_counts()
        
        # Stale processing count
        all_ok &= self._check_stale_processing()
        
        # OpenSearch connection
        all_ok &= self._check_opensearch()
        
        # Sample CVEs from OpenSearch
        all_ok &= self._check_opensearch_sample()
        
        # Feeder state
        all_ok &= self._check_feeder_state()
        
        # Recent queue rows
        all_ok &= self._check_recent_queue_rows()
        
        # Recent generation runs
        all_ok &= self._check_recent_generation_runs()
        
        print(f"\n=== Diagnostics {'PASSED' if all_ok else 'FAILED'} ===")
        return all_ok

    def _check_db_connections(self) -> bool:
        print("--- Database Connections ---")
        
        # PlaybookEngineClient
        print(f"PlaybookEngineClient:")
        print(f"  Host: {self.playbook_engine.host}")
        print(f"  Port: {self.playbook_engine.port}")
        print(f"  Database: {self.playbook_engine.database}")
        print(f"  User: {self.playbook_engine.user}")
        
        try:
            with self.playbook_engine.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT current_database(), inet_server_addr(), inet_server_port(), version()")
                    row = cur.fetchone()
                    print(f"  Current DB: {row[0]}")
                    print(f"  Server Addr: {row[1]}")
                    print(f"  Server Port: {row[2]}")
                    print(f"  PostgreSQL: {row[3].split()[0]}")
            print("  [OK] Connection successful")
        except Exception as e:
            print(f"  [ERROR] Connection failed: {e}")
            return False
        
        # VulnstrikeProductionClient
        print(f"\nVulnstrikeProductionClient:")
        print(f"  Host: {self.vulnstrike_prod.host}")
        print(f"  Port: {self.vulnstrike_prod.port}")
        print(f"  Database: {self.vulnstrike_prod.database}")
        print(f"  User: {self.vulnstrike_prod.user}")
        
        try:
            with self.vulnstrike_prod.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT current_database(), inet_server_addr(), inet_server_port(), version()")
                    row = cur.fetchone()
                    print(f"  Current DB: {row[0]}")
                    print(f"  Server Addr: {row[1]}")
                    print(f"  Server Port: {row[2]}")
                    print(f"  PostgreSQL: {row[3].split()[0]}")
            print("  [OK] Connection successful")
        except Exception as e:
            print(f"  [ERROR] Connection failed: {e}")
            return False
        
        return True

    def _check_table_existence(self) -> bool:
        print("\n--- Table Existence ---")
        
        tables_to_check = [
            ("playbook_engine", "public.cve_queue"),
            ("playbook_engine", "public.cve_context_snapshot"),
            ("playbook_engine", "public.generation_runs"),
            ("vulnstrike", "public.playbooks"),
            ("vulnstrike", "public.approved_playbooks"),
        ]
        
        all_exist = True
        for db_name, fq_table in tables_to_check:
            schema, table = fq_table.split('.', 1)
            client = self.playbook_engine if db_name == "playbook_engine" else self.vulnstrike_prod
            
            try:
                row = client.fetch_one(
                    """
                    SELECT EXISTS (
                        SELECT 1 FROM information_schema.tables 
                        WHERE table_schema = %s AND table_name = %s
                    ) AS exists
                    """,
                    (schema, table)
                )
                exists = bool(row and row.get('exists'))
                status = "[OK]" if exists else "[MISSING]"
                print(f"{status} {db_name}.{fq_table}")
                if not exists:
                    all_exist = False
            except Exception as e:
                print(f"[ERROR] {db_name}.{fq_table} (check failed: {e})")
                all_exist = False
        
        return all_exist

    def _check_queue_counts(self) -> bool:
        print("\n--- Queue Status Counts ---")
        
        try:
            rows = self.playbook_engine.fetch_all(
                """
                SELECT status, COUNT(*) as count
                FROM public.cve_queue
                GROUP BY status
                ORDER BY 
                    CASE status 
                        WHEN 'pending' THEN 1
                        WHEN 'processing' THEN 2
                        WHEN 'completed' THEN 3
                        WHEN 'failed' THEN 4
                        WHEN 'dead_letter' THEN 5
                        ELSE 6
                    END
                """
            )
            
            if not rows:
                print("  No rows in cve_queue")
                return True
            
            total = 0
            for row in rows:
                count = row['count']
                total += count
                status = row['status']
                print(f"  {status}: {count}")
            
            print(f"  ---")
            print(f"  TOTAL: {total}")
            
            # Check for dead_letter status
            dead_letter_count = next((r['count'] for r in rows if r['status'] == 'dead_letter'), 0)
            if dead_letter_count > 0:
                print(f"  [NOTE] {dead_letter_count} dead_letter items (non-retryable failures)")
            
            return True
        except Exception as e:
            print(f"  [ERROR] Failed to get queue counts: {e}")
            return False

    def _check_stale_processing(self) -> bool:
        print("\n--- Stale Processing Rows ---")
        
        try:
            # Check for rows stuck in 'processing' for more than 30 minutes
            stale_threshold = datetime.utcnow() - timedelta(minutes=30)
            
            row = self.playbook_engine.fetch_one(
                """
                SELECT COUNT(*) as count
                FROM public.cve_queue
                WHERE status = 'processing'
                AND updated_at < %s
                """,
                (stale_threshold,)
            )
            
            stale_count = int(row['count']) if row else 0
            print(f"  Stale processing rows (>30 min): {stale_count}")
            
            if stale_count > 0:
                print(f"  [WARNING] {stale_count} rows stuck in processing")
                print(f"  [INFO] Run queue_schema.recover_stale_processing() to reset them")
            
            return True
        except Exception as e:
            print(f"  [ERROR] Failed to check stale processing: {e}")
            return False

    def _check_opensearch(self) -> bool:
        print("\n--- OpenSearch Connection ---")
        print(f"  URL: {self.config.OPENSEARCH_URL}")
        print(f"  Index: {self.config.OPENSEARCH_INDEX}")
        print(f"  Username: {self.config.OPENSEARCH_USERNAME}")
        print(f"  Verify TLS: {self.config.OPENSEARCH_VERIFY_TLS}")
        
        try:
            # Try to get cluster health or index info
            result = self.opensearch._request('GET', '/_cluster/health')
            status = result.get('status', 'unknown')
            print(f"  [OK] Connection successful (cluster status: {status})")
            
            # Check if index exists using diagnostic_info method
            try:
                diag_info = self.opensearch.diagnostic_info()
                if diag_info.get('connected'):
                    print(f"  [OK] Index exists (doc count: {diag_info.get('document_count', 0)})")
                    return True
                else:
                    print(f"  [ERROR] Index check failed: {diag_info.get('error', 'Unknown error')}")
                    return False
            except Exception as e:
                print(f"  [ERROR] Index check failed: {e}")
                return False
                
        except Exception as e:
            print(f"  [ERROR] Connection failed: {e}")
            return False

    def _check_opensearch_sample(self) -> bool:
        print("\n--- OpenSearch Sample CVEs ---")
        
        try:
            candidates = self.opensearch.search_candidates(from_offset=0, page_size=3)
            if not candidates:
                print("  [ERROR] No candidates returned from OpenSearch")
                return False
            
            print(f"  [OK] Retrieved {len(candidates)} candidate(s)")
            for i, candidate in enumerate(candidates, 1):
                cve_id = candidate.get('cve_id', 'unknown')
                description = candidate.get('description', '')[:100] + '...' if candidate.get('description') else 'no description'
                print(f"    {i}. {cve_id}: {description}")
            
            return True
        except Exception as e:
            print(f"  [ERROR] Failed to get sample CVEs: {e}")
            traceback.print_exc()
            return False

    def _check_feeder_state(self) -> bool:
        print("\n--- Feeder State ---")
        
        try:
            # Check config
            print(f"  Config:")
            print(f"    CP_FEED_USE_PERSISTENT_CURSOR: {self.config.CP_FEED_USE_PERSISTENT_CURSOR}")
            print(f"    CP_FEED_CURSOR_FEEDER_NAME: {self.config.CP_FEED_CURSOR_FEEDER_NAME}")
            print(f"    CP_FEED_CURSOR_PAGE_SIZE: {self.config.CP_FEED_CURSOR_PAGE_SIZE}")
            
            # Get feeder state
            feeder_name = self.config.CP_FEED_CURSOR_FEEDER_NAME
            state = self.feeder_state.get_state(feeder_name)
            
            if not state:
                print(f"  [INFO] No feeder state found for '{feeder_name}'")
                return True
            
            print(f"  State for '{feeder_name}':")
            print(f"    last_sort_value_1: {state.get('last_sort_value_1')}")
            print(f"    last_sort_value_2: {state.get('last_sort_value_2')}")
            print(f"    last_cve_id: {state.get('last_cve_id')}")
            print(f"    total_scanned: {state.get('total_scanned', 0)}")
            print(f"    total_enqueued: {state.get('total_enqueued', 0)}")
            print(f"    completed_full_pass: {state.get('completed_full_pass', False)}")
            print(f"    updated_at: {state.get('updated_at')}")
            
            return True
        except Exception as e:
            print(f"  [ERROR] Failed to check feeder state: {e}")
            return False

    def _check_recent_queue_rows(self) -> bool:
        print("\n--- Recent Queue Rows (last 10) ---")
        
        try:
            rows = self.playbook_engine.fetch_all(
                """
                SELECT id, cve_id, status, retry_count, created_at, updated_at, failure_type
                FROM public.cve_queue
                ORDER BY updated_at DESC
                LIMIT 10
                """
            )
            
            if not rows:
                print("  No rows in cve_queue")
                return True
            
            print(f"  Recent queue rows:")
            for i, row in enumerate(rows, 1):
                cve_id = row['cve_id']
                status = row['status']
                retry = row.get('retry_count', 0)
                failure = row.get('failure_type', '')
                updated = row.get('updated_at', '')
                print(f"    {i}. {cve_id}: {status} (retry={retry}, failure={failure}, updated={updated})")
            
            return True
        except Exception as e:
            print(f"  [ERROR] Failed to get recent queue rows: {e}")
            return False

    def _check_recent_generation_runs(self) -> bool:
        print("\n--- Recent Generation Runs (last 5) ---")
        
        try:
            rows = self.playbook_engine.fetch_all(
                """
                SELECT id, cve_id, status, created_at, llm_error_info
                FROM public.generation_runs
                ORDER BY created_at DESC
                LIMIT 5
                """
            )
            
            if not rows:
                print("  No generation runs found")
                return True
            
            print(f"  Recent generation runs:")
            for i, row in enumerate(rows, 1):
                run_id = row['id']
                cve_id = row['cve_id']
                status = row['status']
                created = row.get('created_at', '')
                error = row.get('llm_error_info', '')
                if error:
                    error = error[:50] + '...' if len(error) > 50 else error
                print(f"    {i}. Run #{run_id}: {cve_id} - {status} (created={created}, error={error})")
            
            return True
        except Exception as e:
            print(f"  [ERROR] Failed to get recent generation runs: {e}")
            return False


def main():
    diag = DiagnosticsV021()
    success = diag.run()
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()