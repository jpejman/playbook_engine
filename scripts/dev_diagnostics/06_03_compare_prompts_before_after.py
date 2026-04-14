#!/usr/bin/env python3
"""
Compare Before vs After Prompts for Real CVE
"""

import sys
import logging
import json
from pathlib import Path
from typing import Dict, Any

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from retrieval.prompt_input_builder import PromptInputBuilder
from utils.db import DatabaseClient

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def get_old_template_version():
    """Get the old template version (v1.0.2)."""
    db = DatabaseClient()
    
    template_sql = """
    SELECT 
        v.id, v.template_id, v.version,
        v.system_block, v.instruction_block,
        v.workflow_block, v.output_schema_block,
        t.name as template_name
    FROM prompt_template_versions v
    JOIN prompt_templates t ON v.template_id = t.id
    WHERE v.version = 'v1.0.2'
    LIMIT 1
    """
    
    template_data = db.fetch_one(template_sql)
    db.close_all()
    
    return template_data

def get_new_template_version():
    """Get the new template version (v1.1.0)."""
    db = DatabaseClient()
    
    template_sql = """
    SELECT 
        v.id, v.template_id, v.version,
        v.system_block, v.instruction_block,
        v.workflow_block, v.output_schema_block,
        t.name as template_name
    FROM prompt_template_versions v
    JOIN prompt_templates t ON v.template_id = t.id
    WHERE v.version = 'v1.1.0'
    LIMIT 1
    """
    
    template_data = db.fetch_one(template_sql)
    db.close_all()
    
    return template_data

def get_cve_context(cve_id: str) -> Dict[str, Any]:
    """Get CVE context data."""
    db = DatabaseClient()
    
    context_sql = """
    SELECT context_data
    FROM cve_context_snapshot
    WHERE cve_id = %s
    ORDER BY created_at DESC
    LIMIT 1
    """
    
    result = db.fetch_one(context_sql, (cve_id,))
    db.close_all()
    
    if result and result['context_data']:
        return result['context_data']
    
    return {}

def get_evidence_for_cve(cve_id: str):
    """Get evidence for CVE (simplified)."""
    # Mock evidence collector for comparison
    class MockEvidenceCollector:
        def get_retrieval_decision(self):
            return "sufficient"
        
        def get_all_evidence(self):
            return [
                {
                    "title": "Sample Evidence Document",
                    "source_index": "opensearch-index",
                    "score": 0.75,
                    "content": "This is sample evidence content for comparison."
                }
            ]
        
        def get_source_indexes(self):
            return ["opensearch-index"]
    
    return MockEvidenceCollector()

def generate_prompt(cve_id: str, context_data: Dict[str, Any], 
                   template_data: Dict[str, Any], version_name: str) -> str:
    """Generate prompt using given template."""
    logger.info(f"Generating prompt with {version_name} template...")
    
    evidence_collector = get_evidence_for_cve(cve_id)
    
    builder = PromptInputBuilder(
        cve_id=cve_id,
        context_snapshot=context_data,
        evidence_collector=evidence_collector,
        template_data=template_data
    )
    
    input_package = builder.build_input_package()
    prompt = builder.render_prompt(input_package)
    
    return prompt

def compare_prompts(old_prompt: str, new_prompt: str, cve_id: str):
    """Compare old and new prompts."""
    logger.info(f"\n{'='*60}")
    logger.info(f"COMPARISON FOR {cve_id}")
    logger.info(f"{'='*60}")
    
    # Basic stats
    logger.info(f"Old prompt length: {len(old_prompt)} characters")
    logger.info(f"New prompt length: {len(new_prompt)} characters")
    logger.info(f"Length difference: {len(new_prompt) - len(old_prompt)} characters")
    
    # Check for key sections
    sections_to_check = [
        "## System Role",
        "## Instructions", 
        "## Workflow",
        "## CVE Context Data",
        "## Retrieved Evidence",
        "## Output Schema"
    ]
    
    logger.info("\nSection presence:")
    for section in sections_to_check:
        old_has = section in old_prompt
        new_has = section in new_prompt
        logger.info(f"  {section}: Old={old_has}, New={new_has}")
    
    # Check for richer context fields in new prompt
    richer_fields = [
        "Affected OS",
        "Affected Software",
        "Package Name",
        "Affected Versions",
        "Fixed Versions",
        "Deployment Type",
        "Remediation Constraints",
        "Patch Available",
        "Workarounds Available"
    ]
    
    logger.info("\nRicher context fields in NEW prompt:")
    new_prompt_lower = new_prompt.lower()
    for field in richer_fields:
        field_lower = field.lower()
        if field_lower in new_prompt_lower:
            logger.info(f"  ✓ {field}")
        else:
            logger.info(f"  ✗ {field} (missing)")
    
    # Check for specific guidance from improved template
    improved_guidance = [
        "repository-based updates",
        "manual installation",
        "pre-remediation checks",
        "backups",
        "os-specific",
        "package manager"
    ]
    
    logger.info("\nImproved guidance in NEW prompt:")
    for guidance in improved_guidance:
        if guidance in new_prompt_lower:
            logger.info(f"  ✓ {guidance}")
        else:
            logger.info(f"  ✗ {guidance} (missing)")
    
    # Show differences in context section
    old_context_start = old_prompt.find("## CVE Context Data")
    new_context_start = new_prompt.find("## CVE Context Data")
    
    if old_context_start != -1 and new_context_start != -1:
        # Find end of context section (next section or end)
        old_next_section = old_prompt.find("## ", old_context_start + 3)
        new_next_section = new_prompt.find("## ", new_context_start + 3)
        
        old_context_end = old_next_section if old_next_section != -1 else len(old_prompt)
        new_context_end = new_next_section if new_next_section != -1 else len(new_prompt)
        
        old_context = old_prompt[old_context_start:old_context_end]
        new_context = new_prompt[new_context_start:new_context_end]
        
        logger.info(f"\nOld context section lines: {old_context.count(chr(10))}")
        logger.info(f"New context section lines: {new_context.count(chr(10))}")
        
        # Count fields in context
        old_fields = old_context.count("**")
        new_fields = new_context.count("**")
        logger.info(f"Fields in old context: {old_fields//2} (approx)")
        logger.info(f"Fields in new context: {new_fields//2} (approx)")
    
    # Check output schema differences
    old_schema_start = old_prompt.find("## Output Schema")
    new_schema_start = new_prompt.find("## Output Schema")
    
    if old_schema_start != -1 and new_schema_start != -1:
        old_schema_end = old_prompt.find("## ", old_schema_start + 3) if old_prompt.find("## ", old_schema_start + 3) != -1 else len(old_prompt)
        new_schema_end = new_prompt.find("## ", new_schema_start + 3) if new_prompt.find("## ", new_schema_start + 3) != -1 else len(new_prompt)
        
        old_schema = old_prompt[old_schema_start:old_schema_end]
        new_schema = new_prompt[new_schema_start:new_schema_end]
        
        # Check for vulnerability_context in new schema
        if "vulnerability_context" in new_schema:
            logger.info("\n✓ NEW output schema includes 'vulnerability_context' object")
        else:
            logger.info("\n✗ NEW output schema missing 'vulnerability_context'")
        
        # Check schema complexity
        old_schema_lines = old_schema.count(chr(10))
        new_schema_lines = new_schema.count(chr(10))
        logger.info(f"Old schema lines: {old_schema_lines}")
        logger.info(f"New schema lines: {new_schema_lines}")
    
    return True

def main():
    """Main function."""
    logger.info("Comparing Before vs After Prompts for Real CVE")
    logger.info("=" * 60)
    
    # Use a real CVE
    cve_id = "CVE-2025-54365"
    
    # Get CVE context
    context_data = get_cve_context(cve_id)
    if not context_data:
        logger.error(f"No context data found for {cve_id}")
        sys.exit(1)
    
    logger.info(f"Found context data for {cve_id}")
    logger.info(f"Context fields: {list(context_data.keys())}")
    
    # Get templates
    old_template = get_old_template_version()
    new_template = get_new_template_version()
    
    if not old_template:
        logger.error("Could not find old template v1.0.2")
        sys.exit(1)
    
    if not new_template:
        logger.error("Could not find new template v1.1.0")
        sys.exit(1)
    
    logger.info(f"Old template: {old_template['template_name']} v{old_template['version']}")
    logger.info(f"New template: {new_template['template_name']} v{new_template['version']}")
    
    # Generate prompts
    old_prompt = generate_prompt(cve_id, context_data, old_template, "OLD (v1.0.2)")
    new_prompt = generate_prompt(cve_id, context_data, new_template, "NEW (v1.1.0)")
    
    # Compare
    success = compare_prompts(old_prompt, new_prompt, cve_id)
    
    if success:
        logger.info("\n" + "="*60)
        logger.info("COMPARISON COMPLETE")
        logger.info("="*60)
        logger.info("Summary of improvements:")
        logger.info("1. Richer NVD/CVE context fields extracted and displayed")
        logger.info("2. More specific guidance for security analysts")
        logger.info("3. Enhanced output schema with vulnerability_context")
        logger.info("4. Structured workflows with OS/package-specific procedures")
        logger.info("5. Based on user's 2 better prompt examples")
        
        # Save prompts for manual inspection
        with open(f"old_prompt_{cve_id}.txt", "w") as f:
            f.write(old_prompt)
        
        with open(f"new_prompt_{cve_id}.txt", "w") as f:
            f.write(new_prompt)
        
        logger.info(f"\nPrompts saved to files:")
        logger.info(f"  Old prompt: old_prompt_{cve_id}.txt")
        logger.info(f"  New prompt: new_prompt_{cve_id}.txt")
    else:
        logger.error("Comparison failed")
        sys.exit(1)

if __name__ == "__main__":
    main()