CHECKS = [
    "generation_runs WITHOUT qa_runs",
    "qa_runs WITHOUT approved_playbooks (PASS only)",
    "retrieval_runs WITHOUT generation_runs",
    "cve_queue stuck in processing > X minutes",
]