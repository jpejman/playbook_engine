#!/usr/bin/env python3
"""
Create context snapshot for a CVE from vulnstrike database.
"""

import os
import sys
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional
import psycopg2
import psycopg2.extras
from dotenv import load_dotenv

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.db import get_database_client

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def get_cve_from_vulnstrike(cve_id: str) -> Optional[Dict[str, Any]]:
    """Get CVE data from vulnstrike database."""
    try:
        # Connect to vulnstrike database
        host = os.getenv('VULNSTRIKE_DB_HOST', os.getenv('DB_HOST', '10.0.0.110'))
        port = os.getenv('VULNSTRIKE_DB_PORT', os.getenv('DB_PORT', '5432'))
        database = 'vulnstrike'
        user = os.getenv('VULNSTRIKE_DB_USER', os.getenv('DB_USER', 'vulnstrike'))
        password = os.getenv('VULNSTRIKE_DB_PASSWORD', os.getenv('DB_PASSWORD', 'vulnstrike'))
        
        conn = psycopg2.connect(
            host=host,
            port=port,
            database=database,
            user=user,
            password=password
        )
        
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                'SELECT cve_id, published, description, metrics, vuln_status FROM nvd_cve_data WHERE cve_id = %s',
                (cve_id,)
            )
            result = cur.fetchone()
            
        conn.close()
        
        return result
        
    except Exception as e:
        logger.error(f"Failed to get CVE from vulnstrike: {e}")
        return None

def create_context_snapshot(cve_id: str) -> bool:
    """Create context snapshot for CVE in playbook_engine database."""
    # Get CVE data from vulnstrike
    cve_data = get_cve_from_vulnstrike(cve_id)
    
    if not cve_data:
        logger.error(f"No CVE data found for {cve_id} in vulnstrike database")
        return False
    
    # Build context data structure
    context_data = {
        "cve_id": cve_data["cve_id"],
        "description": cve_data["description"],
        "published_date": str(cve_data["published"]),
        "last_modified_date": str(cve_data["published"]),  # Use published as fallback
        "cvss_score": 0.0,
        "severity": "UNKNOWN",
        "vulnerability_type": "Unknown",
        "cwe": "NVD-CWE-noinfo",
        "attack_vector": "NETWORK",
        "attack_complexity": "MEDIUM",
        "privileges_required": "NONE",
        "user_interaction": "NONE",
        "scope": "UNCHANGED",
        "confidentiality_impact": "HIGH",
        "integrity_impact": "HIGH",
        "availability_impact": "HIGH",
        "affected_products": ["Unknown"],
        "references": []
    }
    
    # Try to extract CVSS data from metrics
    if cve_data["metrics"]:
        try:
            metrics = cve_data["metrics"]
            # Try to get CVSS v3.1 data
            if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                context_data["cvss_score"] = cvss_data.get("baseScore", 0.0)
                context_data["severity"] = cvss_data.get("baseSeverity", "UNKNOWN")
                
                # Map CVSS metrics to our fields
                cvss_mapping = {
                    "attackVector": "attack_vector",
                    "attackComplexity": "attack_complexity",
                    "privilegesRequired": "privileges_required",
                    "userInteraction": "user_interaction",
                    "scope": "scope",
                    "confidentialityImpact": "confidentiality_impact",
                    "integrityImpact": "integrity_impact",
                    "availabilityImpact": "availability_impact"
                }
                
                for cvss_key, our_key in cvss_mapping.items():
                    if cvss_key in cvss_data:
                        context_data[our_key] = cvss_data[cvss_key].upper()
                        
        except Exception as e:
            logger.warning(f"Failed to parse CVSS metrics: {e}")
    
    # Connect to playbook_engine and insert context snapshot
    db = get_database_client()
    
    try:
        # Check if snapshot already exists
        existing = db.fetch_one(
            "SELECT id FROM cve_context_snapshot WHERE cve_id = %s",
            (cve_id,)
        )
        
        if existing:
            logger.info(f"Context snapshot already exists for {cve_id} (ID: {existing['id']})")
            return True
        
        # Insert new snapshot
        with db.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO cve_context_snapshot (cve_id, context_data)
                    VALUES (%s, %s)
                    RETURNING id
                    """,
                    (cve_id, json.dumps(context_data))
                )
                result = cur.fetchone()
                conn.commit()
                
        if result:
            logger.info(f"Created context snapshot for {cve_id} (ID: {result[0]})")
            return True
        else:
            logger.error(f"Failed to create context snapshot for {cve_id}")
            return False
            
    except Exception as e:
        logger.error(f"Database error: {e}")
        return False

def main():
    """Main execution function."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Create context snapshot for CVE')
    parser.add_argument('--cve', required=True, help='CVE ID to create snapshot for')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    success = create_context_snapshot(args.cve)
    
    if success:
        logger.info(f"Successfully created context snapshot for {args.cve}")
        sys.exit(0)
    else:
        logger.error(f"Failed to create context snapshot for {args.cve}")
        sys.exit(1)

if __name__ == "__main__":
    main()