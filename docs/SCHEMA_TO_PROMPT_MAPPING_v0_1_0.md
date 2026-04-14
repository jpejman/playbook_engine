# Schema-to-Prompt Mapping v0.1.0

## Overview
This document maps the canonical playbook schema (from Group 6.1) to prompt requirements for generation. The goal is to enforce the canonical schema in LLM outputs.

## Canonical Schema Requirements

### 1. Header Section (REQUIRED)
**Fields to enforce:**
- `title`: "Remediation Playbook for CVE-XXXX-XXXX"
- `cve_id`: CVE identifier (must match input)
- `vendor`: Vendor name (extract from context)
- `product`: Product name (extract from context)
- `severity`: CVSS severity (Critical/High/Medium/Low)
- `vulnerability_type`: Type of vulnerability
- `description`: Brief vulnerability description
- `affected_versions`: Array of affected versions
- `fixed_versions`: Array of fixed versions
- `affected_platforms`: Array of platforms (Linux/Windows/macOS)
- `references`: Array of reference URLs

**Current gap in generated outputs:**
- Missing `vendor`, `product`, `vulnerability_type` fields
- `affected_versions` and `fixed_versions` not structured as arrays
- `affected_platforms` not explicitly listed

### 2. Pre-Remediation Checks (REQUIRED)
**Structure to enforce:**
```json
"pre_remediation_checks": {
  "required_checks": [],
  "backup_steps": [],
  "prerequisites": []
}
```

**Current gap:**
- Generated playbooks have `pre_remediation_checks` as array, not structured object
- Missing `backup_steps` and `prerequisites` separation

### 3. Workflows (REQUIRED - at least one)
**Structure to enforce:**
```json
"workflows": [
  {
    "workflow_id": "workflow_1",
    "workflow_name": "Descriptive name",
    "workflow_type": "repository_update|manual_install|configuration_hardening|network_isolation|other",
    "applicability_conditions": {
      "os_family": ["Linux", "Windows"],
      "package_managers": ["apt", "yum"],
      "environments": ["production", "staging"]
    },
    "prerequisites": [],
    "steps": []
  }
]
```

**Current gap:**
- Generated playbooks use flat `remediation_steps` array, not structured workflows
- Missing `workflow_type`, `applicability_conditions`
- No workflow grouping for different remediation paths

### 4. Steps (REQUIRED within workflows)
**Fields to enforce per step:**
- `step_number`: Sequential integer
- `title`: Brief descriptive title
- `description`: Detailed explanation
- `commands`: Array of executable commands
- `target_os_or_platform`: OS/platform specificity
- `expected_result`: What should happen
- `verification`: How to verify success
- `rollback_hint`: Optional rollback guidance
- `evidence_based`: Boolean (true/false)

**Current gap:**
- Missing `target_os_or_platform`, `expected_result`, `rollback_hint`
- `evidence_based` flag exists but needs explicit mapping to retrieved evidence

### 5. Post-Remediation Validation (CONDITIONAL)
**Structure to enforce:**
```json
"post_remediation_validation": {
  "validation_steps": [],
  "testing_procedures": []
}
```

**Current gap:**
- Generated playbooks have `verification_procedures` as flat array, not structured validation

### 6. Additional Recommendations (OPTIONAL)
**Structure to enforce:**
```json
"additional_recommendations": [
  {
    "recommendation_id": "rec_1",
    "category": "security_hardening|monitoring|backup|documentation|other",
    "description": "Recommendation text",
    "priority": "high|medium|low",
    "implementation_guidance": "How to implement"
  }
]
```

**Current gap:**
- Not present in generated outputs

### 7. Retrieval Metadata (CONDITIONAL - for AI-generated)
**Structure to enforce:**
```json
"retrieval_metadata": {
  "decision": "strong|weak|none",
  "evidence_count": integer,
  "source_indexes": ["index1", "index2"],
  "generation_timestamp": "ISO timestamp"
}
```

**Current gap:**
- Present but needs to be at root level, not nested under `playbook`

## Prompt Changes Required

### 1. Output Schema Update
Replace current flat schema with canonical hierarchical schema:

**Current (flat):**
```json
{
  "playbook": {
    "title": "...",
    "cve_id": "...",
    "severity": "...",
    "retrieval_metadata": {...},
    "affected_components": [...],
    "vulnerability_context": {...},
    "remediation_steps": [...],
    "verification_procedures": [...],
    "rollback_procedures": [...],
    "references": [...]
  }
}
```

**Required (canonical):**
```json
{
  "header": {...},
  "pre_remediation_checks": {...},
  "workflows": [...],
  "post_remediation_validation": {...},
  "additional_recommendations": [...],
  "retrieval_metadata": {...}
}
```

### 2. Anti-Generic Enforcement Rules
Add to prompt instructions:

1. **Forbid generic remediation**: No "update to latest version" without specific version numbers when available
2. **Require OS/platform targeting**: Each step must specify `target_os_or_platform`
3. **Require version specificity**: Use `affected_versions` and `fixed_versions` from context
4. **Require workflow grouping**: Group steps into logical workflows (repository_update, manual_install, etc.)
5. **Require evidence mapping**: Mark steps as `evidence_based: true` when based on retrieved evidence
6. **Require rollback guidance**: Include `rollback_hint` for destructive operations

### 3. Context Field Expansion
Ensure these fields from context appear in prompt:

**From NVD/CVE data:**
- `vendor`, `product`, `component`
- `affected_versions`, `fixed_versions`
- `attack_complexity`, `privileges_required`, `user_interaction`
- `scope`, `deployment_type`

**From retrieval evidence:**
- Package names, service names, configuration paths
- OS/distribution specifics
- Command patterns from similar vulnerabilities

### 4. Workflow Type Guidance
Add guidance for workflow selection:

1. **repository_update**: When package updates are available in repositories
2. **manual_install**: When manual download/compilation is required
3. **configuration_hardening**: When security configuration changes are needed
4. **network_isolation**: When firewall/network rules are required
5. **other**: For custom remediation paths

## Implementation Plan

### Phase 1: Prompt Template Update
1. Update `IMPROVED_OUTPUT_SCHEMA_BLOCK` to match canonical schema
2. Add anti-generic enforcement instructions
3. Update context normalization to include all required fields

### Phase 2: Context Builder Update
1. Ensure all richer context fields are extracted and normalized
2. Map context fields to prompt variables
3. Validate context completeness before generation

### Phase 3: Queue Selection Enhancement
1. Add check to avoid re-processing same CVE
2. Prefer CVEs without any generation attempts
3. Track most recently processed CVEs

### Phase 4: Validation Update
1. Update QA validator to check canonical schema compliance
2. Add schema validation step before approval
3. Track schema compliance metrics

## Success Metrics

1. **Schema Compliance**: 100% of generated outputs match canonical schema
2. **Field Completeness**: All REQUIRED fields populated
3. **Anti-Generic Success**: No generic "update to latest" without specifics
4. **Workflow Structure**: At least one workflow with proper grouping
5. **Context Utilization**: All available context fields used in generation

---
*Mapping Version: v0.1.0*
*Based on: Canonical Playbook Schema v0.1.0*
*Generated: 2026-04-08*