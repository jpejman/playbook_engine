#!/usr/bin/env python3
"""
Update Canonical Components Documentation
Version: v0.1.0
Timestamp: 2026-04-08T13:51:46-04:00

Purpose:
- Recreate/update CANONICAL_COMPONENTS_v0_1_0.md with current version and timestamps
- Scan codebase for canonical components and deprecated scripts
- Generate up-to-date documentation

Usage:
    python scripts/06_02_update_canonical_components_v0_1_0.py
"""

import os
import sys
import json
import glob
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants
REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = REPO_ROOT / "docs"
SCRIPTS_DIR = REPO_ROOT / "scripts"
SRC_DIR = REPO_ROOT / "src"

CANONICAL_DOC_PATH = DOCS_DIR / "CANONICAL_COMPONENTS_v0_1_0.md"

def get_current_timestamp() -> str:
    """Get current timestamp in ISO format."""
    return datetime.now().isoformat()

def get_file_version(file_path: Path) -> Tuple[str, str]:
    """
    Extract version and timestamp from file header.
    
    Returns:
        Tuple of (version, timestamp)
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read(2000)  # Read first 2000 chars for header
            
        version = "unknown"
        timestamp = "unknown"
        
        # Look for version pattern
        import re
        version_pattern = r'Version:\s*(v[\d\.\-a-z]+)'
        timestamp_pattern = r'Timestamp.*?:\s*([\d\-T:\.]+(?:Z|[+-]\d{2}:\d{2})?)'
        
        version_match = re.search(version_pattern, content, re.IGNORECASE)
        if version_match:
            version = version_match.group(1)
        
        timestamp_match = re.search(timestamp_pattern, content, re.IGNORECASE)
        if timestamp_match:
            timestamp = timestamp_match.group(1)
        
        return version, timestamp
    except Exception as e:
        logger.warning(f"Failed to read version from {file_path}: {e}")
        return "unknown", "unknown"

def scan_canonical_client_modules() -> List[Dict[str, Any]]:
    """Scan for canonical client modules in src directory."""
    modules = []
    
    # Database clients
    db_clients = [
        {
            "name": "src/utils/db.py",
            "description": "get_database_client() for playbook_engine DB",
            "status": "primary"
        },
        {
            "name": "src/retrieval/vulnstrike_db_client.py",
            "description": "get_vulnstrike_db_client()",
            "status": "primary"
        }
    ]
    
    # OpenSearch clients
    opensearch_clients = [
        {
            "name": "src/retrieval/opensearch_client.py",
            "description": "get_real_opensearch_client()",
            "status": "primary"
        },
        {
            "name": "src/utils/opensearch_client.py",
            "description": "Legacy client (deprecated for new code)",
            "status": "deprecated"
        }
    ]
    
    # Evidence collection
    evidence_modules = [
        {
            "name": "src/retrieval/evidence_collector.py",
            "description": "EvidenceCollector class and collect_evidence() factory",
            "status": "core"
        }
    ]
    
    # Prompt construction
    prompt_modules = [
        {
            "name": "src/retrieval/prompt_input_builder.py",
            "description": "PromptInputBuilder class and build_prompt_inputs() factory",
            "status": "core"
        }
    ]
    
    # LLM client
    llm_modules = [
        {
            "name": "src/utils/llm_client.py",
            "description": "Placeholder only - no real LLM integration yet",
            "status": "placeholder"
        }
    ]
    
    # Combine all modules
    all_modules = []
    for module in db_clients + opensearch_clients + evidence_modules + prompt_modules + llm_modules:
        file_path = REPO_ROOT / module["name"]
        if file_path.exists():
            version, timestamp = get_file_version(file_path)
            module["version"] = version
            module["timestamp"] = timestamp
            all_modules.append(module)
        else:
            logger.warning(f"Module file not found: {module['name']}")
    
    return all_modules

def scan_canonical_run_scripts() -> List[Dict[str, Any]]:
    """Scan for canonical run scripts in scripts directory."""
    scripts = []
    
    # Define canonical scripts with their purposes
    canonical_scripts = [
        {
            "pattern": "00_01_verify_db_v0_1_1.py",
            "category": "db_verify",
            "description": "Verify database connectivity and basic schema"
        },
        {
            "pattern": "00_02_init_db_v0_1_1.py",
            "category": "db_init",
            "description": "Initialize playbook_engine database schema"
        },
        {
            "pattern": "01_01_seed_playbook_engine_v0_1_0.py",
            "category": "seeding",
            "description": "Seed playbook engine with test data"
        },
        {
            "pattern": "02_01_test_prompt_creation_v0_1_0.py",
            "category": "prompt_test",
            "description": "Test pre-LLM pipeline without actual LLM calls"
        },
        {
            "pattern": "03_01_run_playbook_generation_v0_1_1_real_retrieval.py",
            "category": "primary_generation",
            "description": "Complete retrieval-backed generation with real evidence"
        },
        {
            "pattern": "04_01_validate_playbook_engine_run_v0_1_0.py",
            "category": "validation",
            "description": "Validate DB target, schema, run integrity, retrieval quality, lineage"
        },
        {
            "pattern": "05_01_sql_proof_v0_2_1_fix.py",
            "category": "sql_proof",
            "description": "SQL proof of real retrieval-backed generation"
        },
        {
            "pattern": "05_02_project_dump_v0_1_0.py",
            "category": "documentation",
            "description": "Generate project dump documentation"
        },
        {
            "pattern": "05_03_test_db_v0_1_1.py",
            "category": "db_test",
            "description": "Test database functionality"
        },
        {
            "pattern": "06_01_add_retrieval_run_id_to_generation_runs.py",
            "category": "migration",
            "description": "Add retrieval_run_id column for lineage isolation"
        },
        {
            "pattern": "06_02_update_canonical_components_v0_1_0.py",
            "category": "documentation",
            "description": "Update canonical components documentation"
        },
        {
            "pattern": "99_01_acceptance_harness_group2_v0_1_0.py",
            "category": "acceptance",
            "description": "Acceptance harness for Group 2 testing"
        }
    ]
    
    for script_def in canonical_scripts:
        pattern = script_def["pattern"]
        matches = list(SCRIPTS_DIR.glob(pattern))
        
        if matches:
            for match in matches:
                version, timestamp = get_file_version(match)
                scripts.append({
                    "name": match.name,
                    "path": str(match.relative_to(REPO_ROOT)),
                    "category": script_def["category"],
                    "description": script_def["description"],
                    "version": version,
                    "timestamp": timestamp
                })
        else:
            logger.warning(f"Canonical script not found: {pattern}")
    
    return scripts

def scan_deprecated_scripts() -> List[Dict[str, Any]]:
    """Scan for deprecated scripts in scripts directory."""
    deprecated = []
    
    # Define deprecated scripts
    deprecated_patterns = [
        {
            "pattern": "03_00_run_playbook_generation_v0_1_0.py",
            "reason": "Initial version without real retrieval"
        },
        {
            "pattern": "03_00_run_playbook_generation_vector_v0_1_0.py",
            "reason": "Vector-based approach (superseded)"
        },
        {
            "pattern": "05_04_test_vector_run_proof_v0_1_0.py",
            "reason": "Vector proof (superseded by SQL proof)"
        },
        {
            "pattern": "04_00_pipeline_validator_v0_1_0.py",
            "reason": "Legacy validator (use validate_playbook_engine_run)"
        }
    ]
    
    for dep_def in deprecated_patterns:
        pattern = dep_def["pattern"]
        matches = list(SCRIPTS_DIR.glob(pattern))
        
        if matches:
            for match in matches:
                version, timestamp = get_file_version(match)
                deprecated.append({
                    "name": match.name,
                    "path": str(match.relative_to(REPO_ROOT)),
                    "reason": dep_def["reason"],
                    "version": version,
                    "timestamp": timestamp,
                    "status": "deprecated"
                })
    
    return deprecated

def generate_validation_sequence() -> List[Dict[str, Any]]:
    """Generate validation sequence documentation."""
    return [
        {
            "name": "Pre-Commit Validation",
            "commands": [
                "# 1. Run prompt-only test (no LLM calls)",
                "python scripts/02_01_test_prompt_creation_v0_1_0.py",
                "",
                "# 2. Run full validation",
                "python scripts/04_01_validate_playbook_engine_run_v0_1_0.py --cve CVE-TEST-0001 --limit 20",
                "",
                "# 3. Check for any FAIL status in validation output",
                "#    Must have: overall_status != \"FAIL\""
            ]
        },
        {
            "name": "Post-Run Validation",
            "commands": [
                "# 1. Validate the latest run",
                "python scripts/04_01_validate_playbook_engine_run_v0_1_0.py --cve CVE-TEST-0001",
                "",
                "# 2. Check specific metrics:",
                "#    - retrieval_quality: duplicate_ratio < 0.4",
                "#    - lineage_isolation: PASS (clean 1:1 mapping)",
                "#    - source_indexes: no low-value internal sources"
            ]
        },
        {
            "name": "Database Schema Validation",
            "commands": [
                "# 1. Verify database connectivity",
                "python scripts/00_01_verify_db_v0_1_1.py",
                "",
                "# 2. Run SQL proof",
                "python scripts/05_01_sql_proof_v0_2_1_fix.py",
                "",
                "# 3. Check schema columns in validation output"
            ]
        },
        {
            "name": "Evidence Pipeline Validation",
            "commands": [
                "# 1. Run prompt-only test",
                "python scripts/02_01_test_prompt_creation_v0_1_0.py",
                "",
                "# 2. Verify metrics in test output:",
                "#    - evidence_stats.reduction_percent > 30% (deduplication)",
                "#    - source_indexes filtered (no low-value sources)",
                "#    - prompt_valid: True"
            ]
        },
        {
            "name": "Lineage Validation",
            "commands": [
                "# Check lineage isolation in validation output:",
                "# Must show: \"Retrieval run maps cleanly to generation run via retrieval_run_id\"",
                "# With: generation_ids = [single_id] (not multiple IDs)"
            ]
        }
    ]

def generate_quality_gates() -> Dict[str, List[Dict[str, Any]]]:
    """Generate quality gates documentation."""
    return {
        "must_pass": [
            {"check": "Database Target", "condition": "Connected to playbook_engine"},
            {"check": "Schema", "condition": "All required tables and columns present"},
            {"check": "Retrieval Quality", "condition": "duplicate_ratio < 0.4"},
            {"check": "Lineage Isolation", "condition": "Clean 1:1 retrieval→generation mapping"},
            {"check": "Prompt Quality", "condition": "Contains all required sections"},
            {"check": "Source Filtering", "condition": "No low-value internal sources"}
        ],
        "warnings": [
            {"check": "Retrieval Decision", "condition": "\"weak\" allowed with warning"},
            {"check": "Source Diversity", "condition": "< 2 sources triggers WARN"},
            {"check": "Evidence Count", "condition": "< 3 usable documents triggers WARN"},
            {"check": "Prompt Length", "condition": "> 10000 chars triggers WARN"}
        ],
        "failures": [
            {"check": "Database", "condition": "Wrong target or missing schema"},
            {"check": "Retrieval", "condition": "duplicate_ratio > 0.6"},
            {"check": "Lineage", "condition": "Multiple generation runs linked to one retrieval"},
            {"check": "Prompt", "condition": "Missing required sections"},
            {"check": "Evidence", "condition": "Zero usable documents"}
        ]
    }

def generate_canonical_documentation() -> str:
    """Generate the complete canonical components documentation."""
    current_time = get_current_timestamp()
    
    # Scan components
    client_modules = scan_canonical_client_modules()
    run_scripts = scan_canonical_run_scripts()
    deprecated_scripts = scan_deprecated_scripts()
    validation_sequence = generate_validation_sequence()
    quality_gates = generate_quality_gates()
    
    # Build documentation
    doc = f"""# Canonical Components - Playbook Engine v0.1.0

**Version:** v0.1.0  
**Timestamp:** {current_time}  
**Purpose:** Reduce drift before LLM integration and provide reference for analysis
**Generated by:** scripts/update_canonical_components_v0_1_0.py

---

## 1. Canonical Client Modules

### 1.1 Database Clients
"""
    
    # Add client modules
    db_clients = [m for m in client_modules if "db" in m["name"].lower() and m["status"] != "deprecated"]
    for client in db_clients:
        doc += f"- **{client['name']}** - {client['description']} (v{client['version']})\n"
    
    doc += "\n### 1.2 OpenSearch Clients\n"
    os_clients = [m for m in client_modules if "opensearch" in m["name"].lower()]
    for client in os_clients:
        status = f" ({client['status']})" if client['status'] != "primary" else ""
        doc += f"- **{client['name']}** - {client['description']}{status} (v{client['version']})\n"
    
    doc += "\n### 1.3 Evidence Collection\n"
    evidence_modules = [m for m in client_modules if "evidence" in m["name"].lower()]
    for module in evidence_modules:
        doc += f"- **{module['name']}** - {module['description']} (v{module['version']})\n"
    
    doc += "\n### 1.4 Prompt Construction\n"
    prompt_modules = [m for m in client_modules if "prompt" in m["name"].lower()]
    for module in prompt_modules:
        doc += f"- **{module['name']}** - {module['description']} (v{module['version']})\n"
    
    doc += "\n### 1.5 LLM Client (Placeholder)\n"
    llm_modules = [m for m in client_modules if "llm" in m["name"].lower()]
    for module in llm_modules:
        doc += f"- **{module['name']}** - {module['description']} (v{module['version']})\n"
    
    doc += """

---

## 2. Canonical Run Scripts

"""
    
    # Group scripts by category
    script_categories = {}
    for script in run_scripts:
        category = script["category"]
        if category not in script_categories:
            script_categories[category] = []
        script_categories[category].append(script)
    
    for category, scripts in script_categories.items():
        category_name = category.replace("_", " ").title()
        doc += f"### 2.{list(script_categories.keys()).index(category) + 1} {category_name}\n"
        
        for script in scripts:
            doc += f"- **Script:** `{script['path']}`\n"
            doc += f"  **Version:** {script['version']}\n"
            doc += f"  **Purpose:** {script['description']}\n\n"
    
    doc += "---\n\n## 3. Deprecated Scripts\n\n"
    
    if deprecated_scripts:
        doc += "### 3.1 Legacy Generation Scripts\n"
        legacy_gen = [s for s in deprecated_scripts if "generation" in s["name"].lower()]
        for script in legacy_gen:
            doc += f"- **`{script['path']}`** - {script['reason']} (v{script['version']})\n"
        
        doc += "\n### 3.2 Legacy Test Scripts\n"
        legacy_test = [s for s in deprecated_scripts if "test" in s["name"].lower()]
        for script in legacy_test:
            doc += f"- **`{script['path']}`** - {script['reason']} (v{script['version']})\n"
        
        doc += "\n### 3.3 Other Deprecated Scripts\n"
        other_dep = [s for s in deprecated_scripts if s not in legacy_gen and s not in legacy_test]
        for script in other_dep:
            doc += f"- **`{script['path']}`** - {script['reason']} (v{script['version']})\n"
        
        doc += "\n**Status:** Do not use for new runs. Use canonical alternatives.\n"
    else:
        doc += "No deprecated scripts found.\n"
    
    doc += "\n---\n\n## 4. Required Validation Sequence After Every Change\n\n"
    
    for i, validation in enumerate(validation_sequence, 1):
        doc += f"### 4.{i} {validation['name']}\n```bash\n"
        doc += "\n".join(validation['commands'])
        doc += "\n```\n\n"
    
    doc += "---\n\n## 5. Quality Gates\n\n"
    
    doc += "### 5.1 Must-Pass Checks\n"
    for check in quality_gates["must_pass"]:
        doc += f"1. **{check['check']}:** {check['condition']}\n"
    
    doc += "\n### 5.2 Warning Thresholds\n"
    for check in quality_gates["warnings"]:
        doc += f"1. **{check['check']}:** {check['condition']}\n"
    
    doc += "\n### 5.3 Failure Conditions\n"
    for check in quality_gates["failures"]:
        doc += f"1. **{check['check']}:** {check['condition']}\n"
    
    doc += """
---

## 6. Component Dependencies

```
┌─────────────────┐    ┌──────────────────┐    ┌────────────────────┐
│   Database      │    │   OpenSearch     │    │   Prompt Template  │
│   Clients       │◄──►│   Clients        │◄──►│   (DB)             │
└─────────────────┘    └──────────────────┘    └────────────────────┘
         │                       │                        │
         ▼                       ▼                        ▼
┌─────────────────────────────────────────────────────────────┐
│               EvidenceCollector                             │
│               - collect_all_evidence()                      │
│               - deduplicate/filter                         │
│               - make_retrieval_decision()                   │
└─────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────┐
│               PromptInputBuilder                            │
│               - build_input_package()                       │
│               - render_prompt()                             │
│               - validate_prompt()                           │
└─────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────┐
│               Generation Scripts                            │
│               - RealRetrievalPlaybookGenerator              │
│               - Persist to DB                               │
│               - QA and Approval                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 7. Version Compatibility

### 7.1 Current Stable Versions
"""
    
    # Get unique versions
    all_components = client_modules + run_scripts
    versions = {}
    for comp in all_components:
        if comp["version"] != "unknown":
            versions[comp["name"]] = comp["version"]
    
    for name, version in sorted(versions.items())[:10]:  # Show first 10
        doc += f"- **{name}:** {version}\n"
    
    doc += """
### 7.2 Breaking Changes
- **v0.2.1-fix:** Added `retrieval_run_id` to `generation_runs` table
- **v0.2.1-fix:** Changed evidence deduplication and filtering logic
- **v0.1.1-real-retrieval:** Replaced mock evidence with real retrieval

### 7.3 Forward Compatibility
- All new code must use `retrieval_run_id` for lineage
- Evidence must be deduplicated and filtered
- Validation must pass all quality gates
- No LLM API calls until integration phase

---

## 8. Maintenance Checklist

### 8.1 Before LLM Integration
- [ ] All canonical components documented
- [ ] Deprecated scripts identified and not used
- [ ] Validation sequence established
- [ ] Quality gates passing
- [ ] Lineage isolation working
- [ ] Evidence pipeline deterministic

### 8.2 Regular Maintenance
- [ ] Run validation after every change
- [ ] Update this document for new components
- [ ] Mark deprecated scripts clearly
- [ ] Verify version compatibility
- [ ] Test with CVE-TEST-0001

### 8.3 Troubleshooting
1. **Validation fails:** Check database connectivity and schema
2. **High duplication:** Verify deduplication logic in evidence collector
3. **Lineage issues:** Check `retrieval_run_id` foreign key
4. **Prompt issues:** Verify prompt input builder validation
5. **Evidence issues:** Check OpenSearch and Vulnstrike DB connectivity

---

**Last Updated:** {current_time}  
**Maintainer:** Playbook Engine Team  
**Next Review:** Before LLM integration phase

*This document was automatically generated by `scripts/update_canonical_components_v0_1_0.py`*
""".format(current_time=current_time)
    
    return doc

def main():
    """Main execution function."""
    logger.info("Updating canonical components documentation...")
    
    # Ensure docs directory exists
    DOCS_DIR.mkdir(exist_ok=True)
    
    # Generate documentation
    documentation = generate_canonical_documentation()
    
    # Write to file
    try:
        with open(CANONICAL_DOC_PATH, 'w', encoding='utf-8') as f:
            f.write(documentation)
        
        logger.info(f"Successfully updated {CANONICAL_DOC_PATH}")
        
        # Print summary
        print("\n" + "="*80)
        print("CANONICAL COMPONENTS DOCUMENTATION UPDATED")
        print("="*80)
        print(f"Output: {CANONICAL_DOC_PATH}")
        print(f"Timestamp: {get_current_timestamp()}")
        print("\nSummary:")
        
        # Count components
        client_modules = scan_canonical_client_modules()
        run_scripts = scan_canonical_run_scripts()
        deprecated_scripts = scan_deprecated_scripts()
        
        print(f"- Canonical client modules: {len(client_modules)}")
        print(f"- Canonical run scripts: {len(run_scripts)}")
        print(f"- Deprecated scripts: {len(deprecated_scripts)}")
        print("\nTo view the documentation:")
        print(f"  cat {CANONICAL_DOC_PATH}")
        print("\n" + "="*80)
        
    except Exception as e:
        logger.error(f"Failed to update documentation: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()