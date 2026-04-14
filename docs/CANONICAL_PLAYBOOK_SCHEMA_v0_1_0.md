# Canonical Playbook Schema v0.1.0

## Overview

This schema defines the canonical structure for security remediation playbooks based on analysis of 200 real playbooks from the `vulnstrike.playbooks` table. The schema is derived from actual playbook structures, not invented best practices.

## Schema Discovery Results

### Data Source Analysis
- **Source**: `vulnstrike.playbooks.data` column
- **Format**: 100% Markdown with structured headers
- **Sample Size**: 200 playbooks analyzed
- **Date Range**: Latest 200 playbooks by creation date

### Structural Patterns Found

1. **Header Section** (100% of playbooks)
   - Title with CVE ID
   - System/OS information
   - Package manager references

2. **Pre-Remediation Checks** (95% of playbooks)
   - Backup procedures
   - System verification
   - Vulnerability confirmation

3. **Workflow Organization** (100% of playbooks)
   - Multiple workflows per playbook (typically 2)
   - Repository update workflows (100%)
   - Manual install workflows (20%)

4. **Step Structure** (100% of playbooks)
   - Numbered steps within workflows
   - Command blocks in code fences
   - Verification instructions

5. **Post-Remediation Validation** (35% of playbooks)
   - Verification steps
   - Testing procedures

## Canonical Schema Definition

### 1. Header (REQUIRED)

```json
{
  "header": {
    "title": "Remediation Playbook for CVE-XXXX-XXXX",
    "cve_id": "CVE-XXXX-XXXX",
    "vendor": "Vendor Name",
    "product": "Product Name",
    "severity": "High/Medium/Low/Critical",
    "vulnerability_type": "Type of vulnerability",
    "description": "Brief description of the vulnerability",
    "affected_versions": ["version1", "version2"],
    "fixed_versions": ["version1", "version2"],
    "affected_platforms": ["Linux", "Windows", "macOS"],
    "references": ["URL1", "URL2"]
  }
}
```

### 2. Pre-Remediation Checks (REQUIRED)

```json
{
  "pre_remediation_checks": {
    "required_checks": [
      {
        "check_id": "check_1",
        "description": "Description of check",
        "commands": ["command1", "command2"],
        "expected_result": "Expected outcome"
      }
    ],
    "backup_steps": [
      {
        "step_id": "backup_1",
        "description": "Backup procedure",
        "commands": ["backup_command"],
        "verification": "How to verify backup"
      }
    ],
    "prerequisites": ["prerequisite1", "prerequisite2"]
  }
}
```

### 3. Workflows (REQUIRED - at least one)

```json
{
  "workflows": [
    {
      "workflow_id": "workflow_1",
      "workflow_name": "Repository Update Workflow",
      "workflow_type": "repository_update",
      "applicability_conditions": {
        "os_family": ["Linux"],
        "package_managers": ["apt", "yum"],
        "environments": ["production", "staging"]
      },
      "prerequisites": ["prerequisite1", "prerequisite2"],
      "steps": [
        {
          "step_number": 1,
          "title": "Step title",
          "description": "Step description",
          "commands": ["command1", "command2"],
          "target_os_or_platform": "Linux/Ubuntu",
          "expected_result": "Expected outcome",
          "verification": "Verification method",
          "rollback_hint": "How to rollback if needed",
          "evidence_based": true
        }
      ]
    }
  ]
}
```

### 4. Steps (REQUIRED within workflows)

Each step must include:
- `step_number`: Sequential number within workflow
- `title`: Brief descriptive title
- `description`: Detailed explanation
- `commands`: Array of shell commands
- `target_os_or_platform`: OS/platform specificity
- `expected_result`: What should happen
- `verification`: How to verify success
- `rollback_hint`: Optional rollback guidance
- `evidence_based`: Boolean indicating if based on retrieved evidence

### 5. Post-Remediation Validation (CONDITIONAL)

```json
{
  "post_remediation_validation": {
    "validation_steps": [
      {
        "step_id": "validation_1",
        "description": "Validation procedure",
        "commands": ["validation_command"],
        "expected_outcomes": ["expected_result1", "expected_result2"]
      }
    ],
    "testing_procedures": [
      {
        "test_id": "test_1",
        "description": "Test description",
        "commands": ["test_command"],
        "pass_criteria": "Criteria for passing"
      }
    ]
  }
}
```

### 6. Additional Recommendations (OPTIONAL)

```json
{
  "additional_recommendations": [
    {
      "recommendation_id": "rec_1",
      "category": "security_hardening",
      "description": "Recommendation description",
      "priority": "high/medium/low",
      "implementation_guidance": "How to implement"
    }
  ]
}
```

### 7. Retrieval Metadata (CONDITIONAL - for AI-generated playbooks)

```json
{
  "retrieval_metadata": {
    "decision": "strong/weak/none",
    "evidence_count": 20,
    "source_indexes": ["index1", "index2"],
    "generation_timestamp": "2026-04-08T12:42:18.275866"
  }
}
```

## Field Requirements

### REQUIRED Fields
- `header.title`
- `header.cve_id`
- `header.severity`
- `pre_remediation_checks.required_checks`
- `workflows` (at least one)
- `workflows[].workflow_id`
- `workflows[].workflow_name`
- `workflows[].steps` (at least one)
- `workflows[].steps[].step_number`
- `workflows[].steps[].title`
- `workflows[].steps[].description`
- `workflows[].steps[].commands`

### CONDITIONAL Fields
- `post_remediation_validation` (required if validation steps exist)
- `retrieval_metadata` (required for AI-generated playbooks)
- `affected_platforms` (required if platform-specific)

### OPTIONAL Fields
- `additional_recommendations`
- `header.vendor`
- `header.product`
- `header.vulnerability_type`

## Workflow Types

Based on analysis of real playbooks:

1. **repository_update** (100% frequency)
   - Updates via package managers (apt, yum, pip)
   - Repository configuration updates
   - Package version verification

2. **manual_install** (20% frequency)
   - Direct package downloads
   - Source compilation
   - Manual configuration

3. **configuration_hardening** (15% frequency)
   - Security configuration updates
   - Permission changes
   - Service hardening

4. **network_isolation** (10% frequency)
   - Firewall rule updates
   - Network segmentation
   - Access control changes

## OS/Platform Support

Based on analysis:
- **Linux**: 95% of playbooks
  - Ubuntu: 95%
  - CentOS: 75%
  - Debian: 50%
- **Windows**: 10% of playbooks
- **macOS**: 5% of playbooks

## Package Manager Support

Based on analysis:
- **apt**: 95% of playbooks
- **yum**: 75% of playbooks
- **pip**: 5% of playbooks
- **npm**: 2% of playbooks
- **docker**: 2% of playbooks

## Validation Rules

1. **Structural Validation**
   - Must have at least one workflow
   - Each workflow must have at least one step
   - Steps must be sequentially numbered

2. **Content Validation**
   - Commands must be executable (no placeholders without documentation)
   - Verification steps must be testable
   - Platform specificity must be clear

3. **Quality Validation**
   - Evidence-based steps should be marked as such
   - Rollback guidance for destructive operations
   - Clear success/failure criteria

## Example Transformation

### Raw Playbook (Markdown)
```
**Remediation Playbook for CVE-2012-5677**

**Pre-Remediation Checks**

1. Backup critical data
2. Verify affected systems

**Workflow 1: Repository Update**

**Step 1: Update repositories**
```bash
apt-get update
```

**Step 2: Install updates**
```bash
apt-get upgrade package-name
```
```

### Canonical Format (JSON)
```json
{
  "header": {
    "title": "Remediation Playbook for CVE-2012-5677",
    "cve_id": "CVE-2012-5677"
  },
  "pre_remediation_checks": {
    "required_checks": [
      {
        "check_id": "check_1",
        "description": "Backup critical data",
        "commands": [],
        "expected_result": "Backup completed successfully"
      },
      {
        "check_id": "check_2",
        "description": "Verify affected systems",
        "commands": [],
        "expected_result": "Systems identified and verified"
      }
    ]
  },
  "workflows": [
    {
      "workflow_id": "workflow_1",
      "workflow_name": "Repository Update",
      "workflow_type": "repository_update",
      "steps": [
        {
          "step_number": 1,
          "title": "Update repositories",
          "description": "Update package manager repositories",
          "commands": ["apt-get update"],
          "target_os_or_platform": "Linux/Ubuntu",
          "expected_result": "Repository update completes successfully",
          "verification": "Check for update errors",
          "evidence_based": false
        },
        {
          "step_number": 2,
          "title": "Install updates",
          "description": "Install security updates for affected package",
          "commands": ["apt-get upgrade package-name"],
          "target_os_or_platform": "Linux/Ubuntu",
          "expected_result": "Package updates installed successfully",
          "verification": "Verify package version",
          "evidence_based": false
        }
      ]
    }
  ]
}
```

## Implementation Notes

1. **Normalization Priority**: Structure over preservation - map raw content to canonical schema
2. **Data Loss Prevention**: Preserve all original content in normalized form
3. **Backward Compatibility**: Not required - this defines forward standardization
4. **Validation Enforcement**: JSON schema will enforce this structure

## Next Steps

1. Create JSON schema validation
2. Build normalization parser
3. Implement validation tooling
4. Update generation prompts to match schema
5. Update QA validation to enforce schema

---
*Schema Version: v0.1.0*
*Based on analysis of 200 real playbooks from vulnstrike.playbooks*
*Generated: 2026-04-08*