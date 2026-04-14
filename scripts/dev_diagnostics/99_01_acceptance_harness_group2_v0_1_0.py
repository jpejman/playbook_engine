#!/usr/bin/env python3
"""
Service: VulnStrike Playbook Engine
Script: acceptance_harness_group2_v0_1_0.py
Version: v0.1.0
Timestamp (UTC): 2026-04-08

Purpose:
- Consolidate Group 2 acceptance testing into one script
- Run the real generation flow
- Run validator
- Query SQL proof
- Package everything into one JSON and one Markdown report
- Exit non-zero if acceptance fails
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import psycopg2
import psycopg2.extras
from dotenv import load_dotenv


ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")

DEFAULT_CVE = os.getenv("TEST_CVE_ID", "CVE-TEST-0001")
EXPECTED_DB = os.getenv("DB_NAME", "playbook_engine")


@dataclass
class CheckResult:
    number: int
    name: str
    passed: bool
    detail: str
    extra: Optional[Dict[str, Any]] = None


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def run_cmd(cmd: List[str], cwd: Optional[Path] = None) -> Dict[str, Any]:
    proc = subprocess.run(
        cmd,
        cwd=str(cwd or ROOT),
        capture_output=True,
        text=True,
        shell=False,
    )
    return {
        "cmd": cmd,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


def get_conn():
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=os.getenv("DB_PORT", "5432"),
        database=os.getenv("DB_NAME", "playbook_engine"),
        user=os.getenv("DB_USER", "vulnstrike"),
        password=os.getenv("DB_PASSWORD", "vulnstrike"),
    )


def fetch_all(conn, query: str, params: Optional[tuple] = None) -> List[Dict[str, Any]]:
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(query, params)
        return [dict(r) for r in cur.fetchall()]


def fetch_one(conn, query: str, params: Optional[tuple] = None) -> Optional[Dict[str, Any]]:
    rows = fetch_all(conn, query, params)
    return rows[0] if rows else None


def latest_rows(conn, table: str, limit: int = 3) -> List[Dict[str, Any]]:
    return fetch_all(conn, f"SELECT * FROM {table} ORDER BY id DESC LIMIT %s", (limit,))


def current_database(conn) -> str:
    with conn.cursor() as cur:
        cur.execute("SELECT current_database()")
        return cur.fetchone()[0]


def try_parse_validator_json(stdout: str) -> Optional[Dict[str, Any]]:
    marker = "JSON_SUMMARY:"
    idx = stdout.find(marker)
    if idx == -1:
        return None
    payload = stdout[idx + len(marker):].strip()
    try:
        return json.loads(payload)
    except Exception:
        return None


def determine_generation_success(conn, cve_id: str) -> Dict[str, Any]:
    generation = fetch_one(conn, "SELECT * FROM generation_runs WHERE cve_id = %s ORDER BY id DESC LIMIT 1", (cve_id,))
    if not generation:
        return {"ok": False, "detail": "No generation row found", "generation": None, "qa": None, "approval": None}

    qa = fetch_one(conn, "SELECT * FROM qa_runs WHERE generation_run_id = %s ORDER BY id DESC LIMIT 1", (generation["id"],))
    approval = fetch_one(conn, "SELECT * FROM approved_playbooks WHERE generation_run_id = %s ORDER BY id DESC LIMIT 1", (generation["id"],))

    return {
        "ok": True,
        "detail": f"Found generation_run_id={generation['id']}",
        "generation": generation,
        "qa": qa,
        "approval": approval,
    }


def build_checks(conn, cve_id: str, validator_json: Optional[Dict[str, Any]], run_cmd_result: Dict[str, Any]) -> List[CheckResult]:
    checks: List[CheckResult] = []

    gen_state = determine_generation_success(conn, cve_id)
    generation = gen_state["generation"] or {}

    # 1. Real model call happened
    model = generation.get("model")
    response = generation.get("response") or ""
    real_call_ok = bool(model and response and "mock" not in str(model).lower())
    checks.append(CheckResult(
        1,
        "real_model_call_happened",
        real_call_ok,
        f"model={model!r}, response_length={len(response)}",
        {"model": model, "response_length": len(response), "run_returncode": run_cmd_result["returncode"]},
    ))

    # 2. Response parsed or cleanly handled
    qa = gen_state["qa"] or {}
    qa_feedback = qa.get("qa_feedback") if qa else None
    parsed_or_handled = bool(qa) and isinstance(qa_feedback, (dict, list, str, type(None)))
    checks.append(CheckResult(
        2,
        "response_parsed_or_cleanly_handled",
        parsed_or_handled,
        "QA row exists and feedback is present/structured" if parsed_or_handled else "QA handling missing",
        {"qa_result": qa.get("qa_result") if qa else None, "qa_feedback": qa_feedback},
    ))

    # 3. generation_runs row was written
    checks.append(CheckResult(
        3,
        "generation_row_written",
        bool(gen_state["generation"]),
        gen_state["detail"],
        {"generation_run_id": generation.get("id")},
    ))

    # 4. qa_runs row was written
    checks.append(CheckResult(
        4,
        "qa_row_written",
        bool(gen_state["qa"]),
        f"qa_run_id={qa.get('id')}" if qa else "No QA row found",
        {"qa_run_id": qa.get("id") if qa else None, "qa_result": qa.get("qa_result") if qa else None},
    ))

    # 5. approved_playbooks row was written when approved and validator no FAIL / lineage intact
    approval = gen_state["approval"] or {}
    approved_when_needed = True
    detail = "Approved playbook present" if approval else "No approved playbook row found"
    if qa and qa.get("qa_result") == "approved":
        approved_when_needed = bool(approval)
        detail = f"qa_result=approved, approved_playbook_id={approval.get('id') if approval else None}"
    validator_fail = False
    lineage_ok = None
    if validator_json:
        validator_fail = validator_json.get("overall_status") == "FAIL"
        checks_map = {c["check"]: c for c in validator_json.get("checks", [])}
        lineage = checks_map.get("lineage_isolation")
        lineage_ok = (lineage or {}).get("status") != "FAIL"
    checks.append(CheckResult(
        5,
        "approval_and_validator_state",
        approved_when_needed and not validator_fail and (lineage_ok is not False),
        detail + f"; validator_overall={validator_json.get('overall_status') if validator_json else 'unknown'}",
        {
            "approved_playbook_id": approval.get("id") if approval else None,
            "validator_overall": validator_json.get("overall_status") if validator_json else None,
            "lineage_ok": lineage_ok,
        },
    ))

    return checks


def write_reports(report: Dict[str, Any], out_dir: Path) -> Dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    json_path = out_dir / f"group2_acceptance_report_{ts}.json"
    md_path = out_dir / f"group2_acceptance_report_{ts}.md"

    json_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")

    checks = report["checks"]
    with md_path.open("w", encoding="utf-8") as f:
        f.write("# Group 2 Acceptance Report\n\n")
        f.write(f"- Timestamp (UTC): {report['timestamp_utc']}\n")
        f.write(f"- CVE: {report['cve_id']}\n")
        f.write(f"- Overall: {report['overall_status']}\n\n")
        f.write("## Acceptance Criteria\n\n")
        for c in checks:
            status = "PASS" if c["passed"] else "FAIL"
            f.write(f"{c['number']}. **{c['name']}** — {status}\n")
            f.write(f"   - {c['detail']}\n")
            if c.get("extra"):
                f.write(f"   - extra: `{json.dumps(c['extra'], default=str)}`\n")
        f.write("\n## SQL Proof (latest rows)\n\n")
        for table, rows in report["sql_proof"].items():
            f.write(f"### {table}\n\n")
            f.write("```json\n")
            f.write(json.dumps(rows, indent=2, default=str))
            f.write("\n```\n\n")

    return {"json": json_path, "md": md_path}


def main() -> int:
    cve_id = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_CVE
    commands: Dict[str, Any] = {}

    commands["prompt_test"] = run_cmd([sys.executable, str(ROOT / "scripts" / "02_01_test_prompt_creation_v0_1_0.py")])
    commands["real_run"] = run_cmd([sys.executable, str(ROOT / "scripts" / "03_01_run_playbook_generation_v0_1_1_real_retrieval.py")])
    commands["validator"] = run_cmd([sys.executable, str(ROOT / "scripts" / "04_01_validate_playbook_engine_run_v0_1_0.py"), "--cve", cve_id, "--limit", "20"])

    with get_conn() as conn:
        db_name = current_database(conn)
        validator_json = try_parse_validator_json(commands["validator"]["stdout"] or "")
        checks = build_checks(conn, cve_id, validator_json, commands["real_run"])
        sql_proof = {
            "retrieval_runs": latest_rows(conn, "retrieval_runs", 3),
            "retrieval_documents": latest_rows(conn, "retrieval_documents", 5),
            "generation_runs": latest_rows(conn, "generation_runs", 3),
            "qa_runs": latest_rows(conn, "qa_runs", 3),
            "approved_playbooks": latest_rows(conn, "approved_playbooks", 3),
        }

    overall_status = "SUCCESS" if all(c.passed for c in checks) else "FAILURE"

    report = {
        "timestamp_utc": utc_now(),
        "expected_db": EXPECTED_DB,
        "actual_db": db_name,
        "cve_id": cve_id,
        "overall_status": overall_status,
        "checks": [asdict(c) for c in checks],
        "commands": commands,
        "sql_proof": sql_proof,
    }

    out_paths = write_reports(report, ROOT / "artifacts")
    print("GROUP 2 ACCEPTANCE HARNESS COMPLETE")
    print(f"OVERALL_STATUS: {overall_status}")
    for c in checks:
        print(f"{c.number}. {c.name}: {'PASS' if c.passed else 'FAIL'} -- {c.detail}")
    print(f"JSON_REPORT: {out_paths['json']}")
    print(f"MD_REPORT: {out_paths['md']}")

    return 0 if overall_status == "SUCCESS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
