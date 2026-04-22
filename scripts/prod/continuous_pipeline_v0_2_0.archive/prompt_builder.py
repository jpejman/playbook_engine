"""
Prompt builder for internal generation pipeline
Version: v0.2.0
Timestamp (UTC): 2026-04-16T23:45:00Z
"""

from __future__ import annotations

import json
from typing import Any


class PromptBuilder:
    def build(self, cve_doc: dict[str, Any]) -> str:
        compact_doc = {
            'cve_id': cve_doc.get('cve_id'),
            'severity': cve_doc.get('severity'),
            'cvss_score': cve_doc.get('cvss_score'),
            'published': cve_doc.get('published'),
            'vendor': cve_doc.get('vendor'),
            'product': cve_doc.get('product'),
            'description': cve_doc.get('description'),
            'references': cve_doc.get('references', [])[:10],
        }
        instructions = (
            'You are generating a remediation playbook for a vulnerability. '
            'Return valid JSON with a top-level key named "playbook". '
            'The playbook object must include: cve_id, summary, impact, detection, remediation_steps, validation_steps, rollback_steps, references. '
            'Use only the supplied CVE context and avoid placeholders. '
            'CVE context:\n'
        )
        return instructions + json.dumps(compact_doc, indent=2)
