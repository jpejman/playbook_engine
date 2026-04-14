# Database Client Module
# Version: v0.1.1
# Timestamp: 2026-04-07

"""
Real PostgreSQL database client for playbook engine.
Provides connection management, query execution, and transaction support.
"""

import os
import logging
import psycopg2
import psycopg2.extras
from typing import Dict, Any, Optional, List, Tuple, Union, Sequence
from contextlib import contextmanager
from dotenv import load_dotenv
from pathlib import Path

# Load environment variables from .env file in repo root
repo_root = Path(__file__).resolve().parents[2]
env_path = repo_root / '.env'
load_dotenv(env_path)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DatabaseClient:
    """
    Production-ready PostgreSQL database client.
    
    Features:
    - Connection management
    - Transaction support
    - Query execution with parameter binding
    - Fetch helpers (one/all)
    - Context manager support
    - Environment-based configuration
    """
    
    def __init__(self):
        """Initialize database client with environment variables."""
        self.host = os.getenv('DB_HOST', 'localhost')
        self.port = os.getenv('DB_PORT', '5432')
        self.database = os.getenv('DB_NAME', 'vulnstrike')
        self.user = os.getenv('DB_USER', 'vulnstrike')
        self.password = os.getenv('DB_PASSWORD', 'vulnstrike')
        
        logger.info(f"Database client initialized for {self.host}:{self.port}/{self.database}")
    
    def _create_connection(self):
        """Create a new database connection."""
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
            logger.error(f"Failed to create database connection: {e}")
            raise
    
    @contextmanager
    def get_connection(self):
        """
        Context manager for database connections.
        
        Usage:
            with db.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT * FROM table")
        
        Returns:
            psycopg2 connection object
        """
        conn = self._create_connection()
        try:
            yield conn
        except Exception as e:
            conn.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            conn.close()
    
    @contextmanager
    def get_cursor(self, connection=None):
        """
        Context manager for database cursors.
        
        Args:
            connection: Optional existing connection, creates new if None
            
        Returns:
            psycopg2 cursor object
        """
        if connection:
            cursor = connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            try:
                yield cursor
            finally:
                cursor.close()
        else:
            with self.get_connection() as conn:
                cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                try:
                    yield cursor
                finally:
                    cursor.close()
    
    def execute(self, query: str, params: Optional[Tuple] = None, fetch: bool = False) -> Optional[Sequence[Dict]]:
        """
        Execute a SQL query with optional parameters.
        
        Args:
            query: SQL query string
            params: Query parameters as tuple
            fetch: Whether to fetch results
            
        Returns:
            List of dictionaries if fetch=True, None otherwise
        """
        with self.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                try:
                    cursor.execute(query, params)
                    if fetch:
                        return cursor.fetchall()
                    conn.commit()
                    return None
                except Exception as e:
                    conn.rollback()
                    logger.error(f"Query execution failed: {e}")
                    logger.debug(f"Query: {query}")
                    logger.debug(f"Params: {params}")
                    raise
    
    def fetch_one(self, query: str, params: Optional[Tuple] = None) -> Optional[Dict]:
        """
        Execute query and fetch single result.
        
        Args:
            query: SQL query string
            params: Query parameters
            
        Returns:
            Single row as dictionary or None
        """
        with self.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                try:
                    cursor.execute(query, params)
                    return cursor.fetchone()
                except Exception as e:
                    logger.error(f"Fetch one failed: {e}")
                    raise
    
    def fetch_all(self, query: str, params: Optional[Tuple] = None) -> Sequence[Dict]:
        """
        Execute query and fetch all results.
        
        Args:
            query: SQL query string
            params: Query parameters
            
        Returns:
            List of rows as dictionaries
        """
        with self.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                try:
                    cursor.execute(query, params)
                    return cursor.fetchall()
                except Exception as e:
                    logger.error(f"Fetch all failed: {e}")
                    raise
    
    def execute_many(self, query: str, params_list: List[Tuple]) -> None:
        """
        Execute many queries with different parameters.
        
        Args:
            query: SQL query string
            params_list: List of parameter tuples
        """
        with self.get_connection() as conn:
            with conn.cursor() as cursor:
                try:
                    cursor.executemany(query, params_list)
                    conn.commit()
                except Exception as e:
                    conn.rollback()
                    logger.error(f"Execute many failed: {e}")
                    raise
    
    def begin_transaction(self):
        """Begin a transaction."""
        conn = self._create_connection()
        conn.autocommit = False
        return conn
    
    def commit_transaction(self, connection):
        """Commit a transaction."""
        try:
            connection.commit()
        finally:
            connection.autocommit = True
            connection.close()
    
    def rollback_transaction(self, connection):
        """Rollback a transaction."""
        try:
            connection.rollback()
        finally:
            connection.autocommit = True
            connection.close()
    
    def test_connection(self) -> bool:
        """
        Test database connection.
        
        Returns:
            bool: True if connection successful
        """
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT 1")
                    result = cursor.fetchone()
                    if result and result[0] == 1:
                        return True
                    return False
        except Exception as e:
            logger.error(f"Connection test failed: {e}")
            return False
    
    def close_all(self):
        """Close method for compatibility (no-op for simple connection)."""
        logger.info("Database client shutdown")


# Convenience function for quick access
def get_database_client() -> DatabaseClient:
    """
    Factory function to get a database client instance.
    
    Returns:
        DatabaseClient instance
    """
    return DatabaseClient()


# Required functions for pipeline validator
def get_conn():
    """Get a database connection."""
    client = DatabaseClient()
    return client._create_connection()

def fetch_one(query, params=None):
    """Execute query and fetch single result."""
    client = DatabaseClient()
    return client.fetch_one(query, params)

def fetch_all(query, params=None):
    """Execute query and fetch all results."""
    client = DatabaseClient()
    return client.fetch_all(query, params)

def execute(query, params=None):
    """Execute a SQL query."""
    client = DatabaseClient()
    return client.execute(query, params, fetch=False)

def execute_returning(query, params=None):
    """Execute a SQL query and return the result."""
    client = DatabaseClient()
    with client.get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(query, params)
            return cur.fetchone()


def get_current_database_name() -> str:
    """
    Get the name of the currently connected database.
    
    Returns:
        str: Current database name
    """
    client = DatabaseClient()
    result = client.fetch_one("SELECT current_database()")
    return result["current_database"] if result else ""


def assert_expected_database(expected_name: str):
    """
    Assert that the current database matches the expected name.
    
    Args:
        expected_name: Expected database name
        
    Raises:
        RuntimeError: If current database doesn't match expected
    """
    current_db = get_current_database_name()
    if current_db != expected_name:
        raise RuntimeError(
            f"Database mismatch: expected '{expected_name}', "
            f"but connected to '{current_db}'. "
            f"Check .env configuration."
        )
    logger.info(f"Database verification passed: connected to '{current_db}'")