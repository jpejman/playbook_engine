#!/usr/bin/env python3
"""Check queue items."""

import os
import psycopg2
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
repo_root = Path(__file__).resolve().parent
env_path = repo_root / '.env'
load_dotenv(env_path)

# Get connection
host = os.getenv('DB_HOST', 'localhost')
port = os.getenv('DB_PORT', '5432')
database = os.getenv('DB_NAME', 'vulnstrike')
user = os.getenv('DB_USER', 'vulnstrike')
password = os.getenv('DB_PASSWORD', 'vulnstrike')

print(f'Connecting to {host}:{port}/{database}...')
conn = psycopg2.connect(
    host=host,
    port=port,
    database=database,
    user=user,
    password=password
)

# Check all queue items
with conn.cursor() as cursor:
    cursor.execute('SELECT id, cve_id, status FROM cve_queue ORDER BY id DESC LIMIT 20')
    results = cursor.fetchall()
    
    print('\nRecent queue items (last 20):')
    print('ID  | CVE ID            | Status')
    print('----|-------------------|-------------------')
    for r in results:
        print(f'{r[0]:3} | {r[1]:17} | {r[2]}')

conn.close()