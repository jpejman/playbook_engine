"""
Schema/runtime audit
Version: v0.1.0
Timestamp (UTC): 2026-04-15
"""

import argparse
import json
from pathlib import Path

from .audit_db import PlaybookEngineAuditClient, VulnstrikeAuditClient
from .table_catalog import TABLE_CATALOG


def get_client(database: str):
    if database == "playbook_engine":
        return PlaybookEngineAuditClient()
    if database == "vulnstrike":
        return VulnstrikeAuditClient()
    raise ValueError(f"Unsupported database: {database}")


def table_exists(client, schema: str, table: str):
    row = client.fetch_one(
        """
        SELECT EXISTS (
            SELECT 1
            FROM information_schema.tables
            WHERE table_schema = %s
              AND table_name = %s
        ) AS exists
        """,
        (schema, table),
    )
    return bool(row and row.get("exists"))


def get_columns(client, schema: str, table: str):
    rows = client.fetch_all(
        """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = %s
          AND table_name = %s
        ORDER BY ordinal_position
        """,
        (schema, table),
    )
    return [r["column_name"] for r in rows]


def get_row_count(client, schema: str, table: str):
    row = client.fetch_one(f"SELECT COUNT(*) AS row_count FROM {schema}.{table}")
    return int(row["row_count"]) if row else 0


def get_max_timestamp(client, schema: str, table: str, timestamp_candidates):
    cols = set(get_columns(client, schema, table))
    for col in timestamp_candidates:
        if col in cols:
            row = client.fetch_one(f"SELECT MAX({col}) AS max_ts FROM {schema}.{table}")
            return {"column": col, "value": row["max_ts"] if row else None}
    return {"column": None, "value": None}


def get_recent_activity_count(client, schema: str, table: str, timestamp_candidates, hours_back: int):
    cols = set(get_columns(client, schema, table))
    for col in timestamp_candidates:
        if col in cols:
            row = client.fetch_one(
                f"""
                SELECT COUNT(*) AS recent_count
                FROM {schema}.{table}
                WHERE {col} >= NOW() - (%s || ' hours')::interval
                """,
                (hours_back,),
            )
            return {"column": col, "recent_count": int(row["recent_count"]) if row else 0}
    return {"column": None, "recent_count": None}


def main():
    parser = argparse.ArgumentParser(description="Validate runtime table roles, columns, and recent activity")
    parser.add_argument("--recent-hours", type=int, default=24)
    parser.add_argument("--out", default="logs/diagnostics/schema_runtime_audit_v0_1_0.json")
    args = parser.parse_args()

    results = []

    for entry in TABLE_CATALOG:
        client = get_client(entry["database"])
        schema = entry["schema"]
        table = entry["table"]

        exists = table_exists(client, schema, table)

        result = {
            "database": entry["database"],
            "schema": schema,
            "table": table,
            "role": entry["role"],
            "exists": exists,
            "expected_columns": entry["expected_columns"],
        }

        if exists:
            actual_columns = get_columns(client, schema, table)
            missing_columns = [c for c in entry["expected_columns"] if c not in actual_columns]
            row_count = get_row_count(client, schema, table)
            max_timestamp = get_max_timestamp(client, schema, table, entry["timestamp_candidates"])
            recent_activity = get_recent_activity_count(client, schema, table, entry["timestamp_candidates"], args.recent_hours)

            result.update({
                "actual_columns": actual_columns,
                "missing_columns": missing_columns,
                "row_count": row_count,
                "max_timestamp": max_timestamp,
                "recent_activity": recent_activity,
                "appears_active_recently": bool(recent_activity["recent_count"]) if recent_activity["recent_count"] is not None else None,
            })
        else:
            result.update({
                "actual_columns": [],
                "missing_columns": entry["expected_columns"],
                "row_count": None,
                "max_timestamp": {"column": None, "value": None},
                "recent_activity": {"column": None, "recent_count": None},
                "appears_active_recently": False,
            })

        results.append(result)

    payload = {
        "recent_hours": args.recent_hours,
        "tables": results,
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")

    print(json.dumps(payload, indent=2, default=str))


if __name__ == "__main__":
    main()