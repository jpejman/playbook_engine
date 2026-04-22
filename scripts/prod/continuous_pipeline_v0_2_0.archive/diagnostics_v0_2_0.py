"""
Diagnostics for continuous_pipeline_v0_2_0
Version: v0.2.0
Timestamp (UTC): 2026-04-16T23:45:00Z
"""

from __future__ import annotations

import sys
import traceback
from typing import Any

from .config import ContinuousPipelineConfig
from .db_clients import PlaybookEngineClient, VulnstrikeProductionClient
from .opensearch_client import OpenSearchClient


class DiagnosticsV020:
    def __init__(self):
        self.playbook_engine = PlaybookEngineClient()
        self.vulnstrike_prod = VulnstrikeProductionClient()
        self.opensearch = OpenSearchClient()
        self.config = ContinuousPipelineConfig

    def run(self) -> bool:
        print("=== Continuous Pipeline v0.2.0 Diagnostics ===\n")
        
        all_ok = True
        
        # DB connection diagnostics
        all_ok &= self._check_db_connections()
        
        # Table existence checks
        all_ok &= self._check_table_existence()
        
        # Queue status counts
        all_ok &= self._check_queue_counts()
        
        # OpenSearch connection
        all_ok &= self._check_opensearch()
        
        # Sample CVEs from OpenSearch
        all_ok &= self._check_opensearch_sample()
        
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
                    cur.execute("SELECT current_database(), inet_server_addr(), inet_server_port()")
                    row = cur.fetchone()
                    print(f"  Current DB: {row[0]}")
                    print(f"  Server Addr: {row[1]}")
                    print(f"  Server Port: {row[2]}")
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
                    cur.execute("SELECT current_database(), inet_server_addr(), inet_server_port()")
                    row = cur.fetchone()
                    print(f"  Current DB: {row[0]}")
                    print(f"  Server Addr: {row[1]}")
                    print(f"  Server Port: {row[2]}")
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
                ORDER BY status
                """
            )
            
            if not rows:
                print("  No rows in cve_queue")
                return True
            
            for row in rows:
                print(f"  {row['status']}: {row['count']}")
            
            return True
        except Exception as e:
            print(f"  [ERROR] Failed to get queue counts: {e}")
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
            
            # Check if index exists
            try:
                index_info = self.opensearch._request('GET', f'/{self.config.OPENSEARCH_INDEX}')
                doc_count = index_info.get(self.config.OPENSEARCH_INDEX, {}).get('total', {}).get('docs', {}).get('count', 0)
                print(f"  [OK] Index exists (doc count: {doc_count})")
                return True
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


def main():
    diag = DiagnosticsV020()
    success = diag.run()
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()