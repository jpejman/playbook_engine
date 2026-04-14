#!/usr/bin/env python3
"""
Vulnstrike Database Client for Evidence Retrieval
Version: v0.2.1-fix
Timestamp: 2026-04-08

Purpose:
- Read-only access to vulnstrike database for CVE-relevant records
- Separate connection config from playbook_engine
- Normalized output format matching OpenSearch contract
"""

import os
import logging
import json
from typing import Dict, List, Any, Optional, Tuple
import psycopg2
import psycopg2.extras
from dotenv import load_dotenv
from pathlib import Path

# Load environment variables from repo root
repo_root = Path(__file__).resolve().parents[3]
env_path = repo_root / '.env'
load_dotenv(env_path)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class VulnstrikeDBClient:
    """
    Read-only client for vulnstrike database.
    
    Features:
    - Separate connection config from playbook_engine
    - Read-only access only
    - Explicit DB assertion: must be connected to vulnstrike
    - Normalized output contract matching OpenSearch
    """
    
    def __init__(self):
        """Initialize vulnstrike database client with environment variables."""
        self.host = os.getenv('VULNSTRIKE_DB_HOST', os.getenv('DB_HOST', '10.0.0.110'))
        self.port = os.getenv('VULNSTRIKE_DB_PORT', os.getenv('DB_PORT', '5432'))
        self.database = os.getenv('VULNSTRIKE_DB_NAME', 'vulnstrike')
        self.user = os.getenv('VULNSTRIKE_DB_USER', os.getenv('DB_USER', 'vulnstrike'))
        self.password = os.getenv('VULNSTRIKE_DB_PASSWORD', os.getenv('DB_PASSWORD', 'vulnstrike'))
        
        logger.info(f"Vulnstrike DB client initialized for {self.host}:{self.port}/{self.database}")
    
    def _create_connection(self):
        """Create a new database connection to vulnstrike."""
        try:
            conn = psycopg2.connect(
                host=self.host,
                port=self.port,
                database=self.database,
                user=self.user,
                password=self.password
            )
            return conn
        except Exception as e:
            logger.error(f"Failed to create vulnstrike database connection: {e}")
            raise
    
    def assert_database_target(self):
        """Assert connected to vulnstrike database."""
        try:
            with self._create_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT current_database()")
                    result = cur.fetchone()
                    if not result:
                        raise RuntimeError("Failed to get current database name")
                    current_db = result[0]
                    
                    if current_db != self.database:
                        raise RuntimeError(
                            f"Database mismatch: expected '{self.database}', "
                            f"but connected to '{current_db}'. "
                            f"Check VULNSTRIKE_DB_NAME configuration."
                        )
                    
                    logger.info(f"Database verification passed: connected to '{current_db}'")
                    return True
        except Exception as e:
            logger.error(f"Database assertion failed: {e}")
            raise
    
    def get_table_info(self) -> Dict[str, Any]:
        """
        Get information about tables in vulnstrike database.
        
        Returns:
            Dictionary with table names and row counts
        """
        try:
            with self._create_connection() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute("""
                        SELECT 
                            table_name,
                            (SELECT count(*) FROM information_schema.columns 
                             WHERE table_schema = 'public' AND table_name = t.table_name) as column_count
                        FROM information_schema.tables t
                        WHERE table_schema = 'public'
                          AND table_type = 'BASE TABLE'
                        ORDER BY table_name
                    """)
                    tables = cur.fetchall()
                    
                    table_info = {}
                    if not tables:
                        return table_info
                    
                    for table in tables:
                        table_name = table['table_name']
                        try:
                            cur.execute(f"SELECT COUNT(*) as row_count FROM {table_name}")
                            result = cur.fetchone()
                            if not result:
                                row_count = 0
                            else:
                                row_count = result['row_count']
                            table_info[table_name] = {
                                "column_count": table['column_count'],
                                "row_count": row_count
                            }
                        except Exception as e:
                            logger.warning(f"Could not get row count for table {table_name}: {e}")
                            table_info[table_name] = {
                                "column_count": table['column_count'],
                                "row_count": 0
                            }
                    
                    return table_info
        except Exception as e:
            logger.error(f"Failed to get table info: {e}")
            return {}
    
    def search_cve_data(self, cve_id: str) -> List[Dict[str, Any]]:
        """
        Search for CVE-relevant records across vulnstrike tables.
        
        Args:
            cve_id: CVE identifier (e.g., "CVE-TEST-0001")
            
        Returns:
            List of normalized evidence records
        """
        import time
        logger.info(f"Searching vulnstrike for CVE: {cve_id}")
        
        normalized_records = []
        timing_breakdown = {}
        
        # First, check for exact CVE matches in common tables
        find_tables_start = time.time()
        common_tables = self._find_cve_tables()
        timing_breakdown['table_discovery_time_seconds'] = time.time() - find_tables_start
        
        logger.info(f"Found {len(common_tables)} potential CVE tables in {timing_breakdown['table_discovery_time_seconds']:.3f}s")
        
        table_search_times = []
        normalization_times = []
        
        for table_name in common_tables:
            try:
                table_search_start = time.time()
                records = self._search_table_for_cve(table_name, cve_id)
                table_search_time = time.time() - table_search_start
                table_search_times.append(table_search_time)
                
                for record in records:
                    normalization_start = time.time()
                    normalized = self._normalize_record(record, table_name, cve_id)
                    normalization_time = time.time() - normalization_start
                    normalization_times.append(normalization_time)
                    
                    if normalized:
                        normalized_records.append(normalized)
            except Exception as e:
                logger.warning(f"Search failed for table {table_name}: {e}")
                continue
        
        if table_search_times:
            timing_breakdown['table_search_time_seconds'] = sum(table_search_times)
            timing_breakdown['avg_table_search_time_seconds'] = sum(table_search_times) / len(table_search_times)
            timing_breakdown['max_table_search_time_seconds'] = max(table_search_times)
        
        if normalization_times:
            timing_breakdown['normalization_time_seconds'] = sum(normalization_times)
            timing_breakdown['avg_normalization_time_seconds'] = sum(normalization_times) / len(normalization_times)
        
        # If no exact matches found, try broader search
        if not normalized_records:
            logger.info(f"No exact CVE matches found, trying broader search")
            broad_search_start = time.time()
            normalized_records = self._search_broad(cve_id)
            timing_breakdown['broad_search_time_seconds'] = time.time() - broad_search_start
            
            # Include broad search timing details if available
            if normalized_records and '_broad_search_timing' in normalized_records[0]:
                broad_timing = normalized_records[0].pop('_broad_search_timing')
                for timing_name, timing_value in broad_timing.items():
                    timing_breakdown[f'broad_{timing_name}'] = timing_value
        
        # Log timing breakdown
        logger.info(f"Found {len(normalized_records)} records for CVE {cve_id}")
        logger.info("Vulnstrike DB timing breakdown:")
        for timing_name, timing_value in timing_breakdown.items():
            logger.info(f"  {timing_name}: {timing_value:.3f}s")
        
        # Store timing breakdown in first record's metadata for analysis
        if normalized_records:
            normalized_records[0]['_timing_breakdown'] = timing_breakdown
        
        return normalized_records
    
    def _find_cve_tables(self) -> List[str]:
        """Find tables that likely contain CVE data."""
        try:
            with self._create_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT table_name 
                        FROM information_schema.columns 
                        WHERE table_schema = 'public' 
                          AND column_name ILIKE '%cve%'
                        GROUP BY table_name
                        ORDER BY table_name
                    """)
                    cve_tables = [row[0] for row in cur.fetchall()]
                    
                    # Also check for common security/vulnerability tables
                    cur.execute("""
                        SELECT table_name 
                        FROM information_schema.tables 
                        WHERE table_schema = 'public'
                          AND table_name ILIKE '%vuln%'
                          OR table_name ILIKE '%security%'
                          OR table_name ILIKE '%threat%'
                          OR table_name ILIKE '%attack%'
                        ORDER BY table_name
                    """)
                    security_tables = [row[0] for row in cur.fetchall()]
                    
                    all_tables = list(set(cve_tables + security_tables))
                    logger.info(f"Found {len(all_tables)} potential CVE/security tables")
                    return all_tables
        except Exception as e:
            logger.error(f"Failed to find CVE tables: {e}")
            return []
    
    def _search_table_for_cve(self, table_name: str, cve_id: str) -> List[Dict[str, Any]]:
        """Search a specific table for CVE records."""
        try:
            with self._create_connection() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    # First, get column names to build query
                    cur.execute("""
                        SELECT column_name 
                        FROM information_schema.columns 
                        WHERE table_schema = 'public' 
                          AND table_name = %s
                        ORDER BY ordinal_position
                    """, (table_name,))
                    
                    columns = [row['column_name'] for row in cur.fetchall()]
                    
                    # Build WHERE clause for CVE search
                    where_clauses = []
                    params = []
                    
                    for column in columns:
                        if 'cve' in column.lower():
                            where_clauses.append(f"{column} = %s")
                            params.append(cve_id)
                        elif column.lower() in ['id', 'name', 'title', 'description']:
                            where_clauses.append(f"{column} ILIKE %s")
                            params.append(f"%{cve_id}%")
                    
                    if not where_clauses:
                        # No CVE-related columns found, skip this table
                        return []
                    
                    where_sql = " OR ".join(where_clauses)
                    query = f"SELECT * FROM {table_name} WHERE {where_sql} LIMIT 10"
                    
                    cur.execute(query, params)
                    records = cur.fetchall()
                    
                    return [dict(record) for record in records]
                    
        except Exception as e:
            logger.warning(f"Failed to search table {table_name}: {e}")
            return []
    
    def _search_broad(self, cve_id: str) -> List[Dict[str, Any]]:
        """Perform broader search across all tables."""
        import time
        normalized_records = []
        broad_timing = {
            'tables_searched': 0,
            'tables_with_text_columns': 0,
            'tables_with_matches': 0,
            'column_discovery_time_seconds': 0.0,
            'query_execution_time_seconds': 0.0,
            'normalization_time_seconds': 0.0,
            'table_info_time_seconds': 0.0
        }
        
        try:
            table_info_start = time.time()
            table_info = self.get_table_info()
            broad_timing['table_info_time_seconds'] = time.time() - table_info_start
            
            tables_to_search = [name for name in table_info.keys() if table_info[name]['row_count'] > 0]
            broad_timing['tables_searched'] = len(tables_to_search)
            
            for table_name in tables_to_search:
                try:
                    # Get text columns for this table
                    column_discovery_start = time.time()
                    with self._create_connection() as conn:
                        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                            cur.execute("""
                                SELECT column_name 
                                FROM information_schema.columns 
                                WHERE table_schema = 'public' 
                                  AND table_name = %s
                                  AND data_type IN ('text', 'varchar', 'character varying')
                                ORDER BY ordinal_position
                            """, (table_name,))
                            
                            text_columns = [row['column_name'] for row in cur.fetchall()]
                    column_discovery_time = time.time() - column_discovery_start
                    broad_timing['column_discovery_time_seconds'] += column_discovery_time
                    
                    if text_columns:
                        broad_timing['tables_with_text_columns'] += 1
                        
                        # Build OR clause for all text columns
                        where_clauses = [f"{col} ILIKE %s" for col in text_columns]
                        where_sql = " OR ".join(where_clauses)
                        params = [f"%{cve_id}%"] * len(text_columns)
                        
                        query = f"SELECT * FROM {table_name} WHERE {where_sql} LIMIT 5"
                        
                        query_start = time.time()
                        with self._create_connection() as conn:
                            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                                cur.execute(query, params)
                                records = cur.fetchall()
                        query_time = time.time() - query_start
                        broad_timing['query_execution_time_seconds'] += query_time
                        
                        normalization_start = time.time()
                        for record in records:
                            normalized = self._normalize_record(
                                dict(record), table_name, cve_id, is_broad=True
                            )
                            if normalized:
                                normalized_records.append(normalized)
                                broad_timing['tables_with_matches'] += 1
                        normalization_time = time.time() - normalization_start
                        broad_timing['normalization_time_seconds'] += normalization_time
                            
                except Exception as e:
                    logger.debug(f"Broad search failed for table {table_name}: {e}")
                    continue
        
        except Exception as e:
            logger.error(f"Broad search failed: {e}")
        
        # Store timing in first record if any found
        if normalized_records:
            normalized_records[0]['_broad_search_timing'] = broad_timing
        
        return normalized_records
    
    def _normalize_record(self, record: Dict[str, Any], table_name: str, 
                         cve_id: str, is_broad: bool = False) -> Optional[Dict[str, Any]]:
        """
        Normalize database record to standard contract.
        
        Contract:
        {
            "doc_id": "...",
            "source_index": "vulnstrike.<table_name>",
            "score": 1.0,
            "title": "...",
            "content": "...",
            "metadata": {...}
        }
        
        Args:
            record: Database record as dictionary
            table_name: Source table name
            cve_id: CVE identifier
            is_broad: Whether this is from broad search
            
        Returns:
            Normalized record or None if invalid
        """
        try:
            # Generate document ID
            doc_id = f"{table_name}_{record.get('id', hash(str(record)) % 10000)}"
            
            # Extract title from record
            title = (
                record.get('title') or 
                record.get('name') or 
                record.get('cve_id') or 
                f"{table_name} record"
            )
            
            # Extract content from record
            content_fields = []
            for field in ['description', 'summary', 'content', 'details', 'notes']:
                if field in record and record[field]:
                    content_fields.append(str(record[field]))
            
            # If no standard content fields, use first few text fields
            if not content_fields:
                for key, value in record.items():
                    if isinstance(value, str) and len(value) > 10 and len(value) < 500:
                        content_fields.append(f"{key}: {value}")
                        if len(content_fields) >= 3:
                            break
            
            content = " | ".join(content_fields) if content_fields else str(record)[:500]
            
            # Build metadata
            metadata = {
                "source_index": f"vulnstrike.{table_name}",
                "table_name": table_name,
                "cve_id": cve_id,
                "search_type": "broad" if is_broad else "exact",
                "retrieval_source": "vulnstrike",
                "record_keys": list(record.keys()),
                "raw_table": table_name
            }
            
            # Add score based on search type
            score = 0.8 if is_broad else 1.0
            
            normalized = {
                "doc_id": doc_id,
                "source_index": f"vulnstrike.{table_name}",
                "score": score,
                "title": str(title)[:200],
                "content": str(content)[:1000],
                "metadata": metadata
            }
            
            return normalized
            
        except Exception as e:
            logger.warning(f"Failed to normalize record from {table_name}: {e}")
            return None
    
    def test_connection(self) -> bool:
        """
        Test database connection.
        
        Returns:
            bool: True if connection successful
        """
        try:
            with self._create_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT 1")
                    result = cursor.fetchone()
                    if result and result[0] == 1:
                        logger.info("Vulnstrike DB connection test passed")
                        return True
                    return False
        except Exception as e:
            logger.error(f"Connection test failed: {e}")
            return False


# Convenience function for quick access
def get_vulnstrike_db_client() -> VulnstrikeDBClient:
    """
    Factory function to get a vulnstrike database client instance.
    
    Returns:
        VulnstrikeDBClient instance
    """
    return VulnstrikeDBClient()