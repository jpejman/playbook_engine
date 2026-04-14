#!/usr/bin/env python3
"""
Playbook Normalization Engine v0.1.0

Parses raw playbooks from vulnstrike.playbooks.data and normalizes them
into the canonical playbook schema.

Responsibilities:
1. Read playbooks_raw.json
2. Detect format and extract sections
3. Normalize into canonical schema
4. Output structured JSON

Author: Playbook Engine Team
Version: v0.1.0
Timestamp: 2026-04-08
"""

import json
import re
import os
import sys
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


@dataclass
class PlaybookSection:
    """Represents a section in a playbook."""
    level: int
    title: str
    content: str
    subsections: List['PlaybookSection']


class PlaybookParser:
    """Parser for markdown playbooks."""
    
    def __init__(self):
        self.section_pattern = re.compile(r'^(#+)\s*(.+)$', re.MULTILINE)
        self.command_pattern = re.compile(r'```(?:bash|sh|powershell)?\n(.*?)\n```', re.DOTALL)
        self.cve_pattern = re.compile(r'CVE-\d{4}-\d+')
        self.step_pattern = re.compile(r'^Step\s+(\d+):?\s*(.+)$', re.IGNORECASE | re.MULTILINE)
        self.workflow_pattern = re.compile(r'^Workflow\s+(\d+):?\s*(.+)$', re.IGNORECASE | re.MULTILINE)
    
    def parse_markdown(self, content: str) -> List[PlaybookSection]:
        """Parse markdown content into hierarchical sections."""
        lines = content.split('\n')
        sections = []
        stack = []  # Stack of (level, section) tuples
        
        current_section = None
        current_content = []
        
        for line in lines:
            header_match = self.section_pattern.match(line)
            if header_match:
                # Save previous section if exists
                if current_section:
                    current_section.content = '\n'.join(current_content).strip()
                    # Find parent in stack
                    while stack and stack[-1][0] >= len(header_match.group(1)):
                        stack.pop()
                    
                    if stack:
                        stack[-1][1].subsections.append(current_section)
                    else:
                        sections.append(current_section)
                
                # Start new section
                level = len(header_match.group(1))
                title = header_match.group(2).strip()
                current_section = PlaybookSection(level=level, title=title, content='', subsections=[])
                stack.append((level, current_section))
                current_content = []
            else:
                current_content.append(line)
        
        # Handle last section
        if current_section:
            current_section.content = '\n'.join(current_content).strip()
            while len(stack) > 1:
                stack.pop()
            if stack:
                parent_level, parent_section = stack[0]
                if parent_section != current_section:
                    parent_section.subsections.append(current_section)
                else:
                    sections.append(current_section)
        
        return sections
    
    def extract_cve_id(self, content: str) -> Optional[str]:
        """Extract CVE ID from content."""
        match = self.cve_pattern.search(content)
        return match.group(0) if match else None
    
    def extract_commands(self, content: str) -> List[str]:
        """Extract commands from code blocks."""
        commands = []
        for match in self.command_pattern.finditer(content):
            command_block = match.group(1).strip()
            # Split by newlines and clean up
            for line in command_block.split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):  # Skip comments
                    commands.append(line)
        return commands
    
    def extract_steps(self, content: str) -> List[Dict[str, Any]]:
        """Extract steps from section content."""
        steps = []
        
        # Look for step patterns
        for match in self.step_pattern.finditer(content):
            step_num = int(match.group(1))
            step_title = match.group(2).strip()
            
            # Extract content after step title
            start_pos = match.end()
            next_match = self.step_pattern.search(content[start_pos:])
            if next_match:
                step_content = content[start_pos:start_pos + next_match.start()].strip()
            else:
                step_content = content[start_pos:].strip()
            
            # Extract commands from step content
            commands = self.extract_commands(step_content)
            
            # Clean up description (remove command blocks)
            description = step_content
            for cmd in self.command_pattern.finditer(step_content):
                description = description.replace(cmd.group(0), '').strip()
            
            steps.append({
                'step_number': step_num,
                'title': step_title,
                'description': description,
                'commands': commands
            })
        
        return steps
    
    def extract_workflows(self, sections: List[PlaybookSection]) -> List[Dict[str, Any]]:
        """Extract workflows from sections."""
        workflows = []
        workflow_count = 0
        
        for section in sections:
            if 'workflow' in section.title.lower():
                workflow_count += 1
                workflow = {
                    'workflow_id': f'workflow_{workflow_count}',
                    'workflow_name': section.title,
                    'workflow_type': self.detect_workflow_type(section.title, section.content),
                    'steps': []
                }
                
                # Extract steps from workflow section and subsections
                all_steps = self.extract_steps(section.content)
                for subsection in section.subsections:
                    all_steps.extend(self.extract_steps(subsection.content))
                
                workflow['steps'] = all_steps
                workflows.append(workflow)
        
        return workflows
    
    def detect_workflow_type(self, title: str, content: str) -> str:
        """Detect workflow type based on title and content."""
        title_lower = title.lower()
        content_lower = content.lower()
        
        if 'repository' in title_lower or 'update' in title_lower:
            return 'repository_update'
        elif 'manual' in title_lower or 'install' in title_lower:
            return 'manual_install'
        elif 'configuration' in title_lower or 'harden' in title_lower:
            return 'configuration_hardening'
        elif 'network' in title_lower or 'isolate' in title_lower:
            return 'network_isolation'
        else:
            return 'other'
    
    def extract_pre_remediation_checks(self, sections: List[PlaybookSection]) -> Dict[str, Any]:
        """Extract pre-remediation checks from sections."""
        checks = {
            'required_checks': [],
            'backup_steps': [],
            'prerequisites': []
        }
        
        for section in sections:
            if 'pre-remediation' in section.title.lower() or 'pre remediation' in section.title.lower():
                # Parse checklist items
                lines = section.content.split('\n')
                check_count = 0
                
                for line in lines:
                    line = line.strip()
                    if line.startswith(('1.', '2.', '3.', '4.', '5.', '6.', '7.', '8.', '9.', '*', '-', '•')):
                        check_count += 1
                        check_item = re.sub(r'^[0-9*•\-\.\s]+', '', line).strip()
                        
                        # Check if it's a backup step
                        if 'backup' in line.lower():
                            checks['backup_steps'].append({
                                'step_id': f'backup_{check_count}',
                                'description': check_item
                            })
                        else:
                            checks['required_checks'].append({
                                'check_id': f'check_{check_count}',
                                'description': check_item
                            })
        
        return checks
    
    def extract_post_remediation_validation(self, sections: List[PlaybookSection]) -> Optional[Dict[str, Any]]:
        """Extract post-remediation validation from sections."""
        validation = {
            'validation_steps': [],
            'testing_procedures': []
        }
        
        validation_found = False
        
        for section in sections:
            if any(keyword in section.title.lower() for keyword in ['validation', 'verification', 'post-remediation', 'post remediation']):
                validation_found = True
                
                # Extract validation steps
                lines = section.content.split('\n')
                step_count = 0
                
                for line in lines:
                    line = line.strip()
                    if line.startswith(('1.', '2.', '3.', '4.', '5.', '*', '-', '•')):
                        step_count += 1
                        step_item = re.sub(r'^[0-9*•\-\.\s]+', '', line).strip()
                        
                        validation['validation_steps'].append({
                            'step_id': f'validation_{step_count}',
                            'description': step_item
                        })
        
        return validation if validation_found else None
    
    def extract_additional_recommendations(self, sections: List[PlaybookSection]) -> Optional[List[Dict[str, Any]]]:
        """Extract additional recommendations from sections."""
        recommendations = []
        
        for section in sections:
            if 'recommendation' in section.title.lower() or 'additional' in section.title.lower():
                lines = section.content.split('\n')
                rec_count = 0
                
                for line in lines:
                    line = line.strip()
                    if line.startswith(('1.', '2.', '3.', '4.', '5.', '*', '-', '•')):
                        rec_count += 1
                        rec_item = re.sub(r'^[0-9*•\-\.\s]+', '', line).strip()
                        
                        recommendations.append({
                            'recommendation_id': f'rec_{rec_count}',
                            'category': 'other',
                            'description': rec_item,
                            'priority': 'medium'
                        })
        
        return recommendations if recommendations else None


class PlaybookNormalizer:
    """Normalizes playbooks into canonical schema."""
    
    def __init__(self):
        self.parser = PlaybookParser()
    
    def normalize(self, raw_playbook: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize a raw playbook into canonical schema."""
        try:
            playbook_id = raw_playbook.get('id')
            cve_id = raw_playbook.get('cve_id')
            raw_content = raw_playbook.get('data', '')
            
            logger.info(f"Normalizing playbook {playbook_id} for {cve_id}")
            
            # Parse markdown structure
            sections = self.parser.parse_markdown(raw_content)
            
            # Extract CVE ID if not provided
            if not cve_id:
                cve_id = self.parser.extract_cve_id(raw_content)
            
            # Build canonical playbook
            canonical = {
                'header': self._build_header(raw_content, cve_id),
                'pre_remediation_checks': self.parser.extract_pre_remediation_checks(sections),
                'workflows': self.parser.extract_workflows(sections)
            }
            
            # Add optional sections if found
            post_validation = self.parser.extract_post_remediation_validation(sections)
            if post_validation:
                canonical['post_remediation_validation'] = post_validation
            
            recommendations = self.parser.extract_additional_recommendations(sections)
            if recommendations:
                canonical['additional_recommendations'] = recommendations
            
            # Add metadata
            canonical['_normalization_metadata'] = {
                'original_id': playbook_id,
                'normalized_at': datetime.utcnow().isoformat() + 'Z',
                'parser_version': 'v0.1.0'
            }
            
            return canonical
            
        except Exception as e:
            logger.error(f"Failed to normalize playbook {raw_playbook.get('id')}: {e}")
            return {
                'error': str(e),
                'original_id': raw_playbook.get('id'),
                'cve_id': raw_playbook.get('cve_id')
            }
    
    def _build_header(self, content: str, cve_id: str) -> Dict[str, Any]:
        """Build header section from content."""
        header = {
            'title': f'Remediation Playbook for {cve_id}',
            'cve_id': cve_id,
            'severity': 'Unknown'  # Default, would need extraction logic
        }
        
        # Try to extract severity from content
        severity_patterns = [
            (r'severity:\s*(\w+)', re.IGNORECASE),
            (r'critical', re.IGNORECASE),
            (r'high', re.IGNORECASE),
            (r'medium', re.IGNORECASE),
            (r'low', re.IGNORECASE)
        ]
        
        for pattern, flags in severity_patterns:
            match = re.search(pattern, content, flags)
            if match:
                if pattern.startswith('severity'):
                    header['severity'] = match.group(1).capitalize()
                else:
                    header['severity'] = match.group(0).capitalize()
                break
        
        return header


def main():
    """Main normalization pipeline."""
    # Ensure artifacts directory exists
    os.makedirs('artifacts', exist_ok=True)
    
    # Load raw playbooks
    raw_file = 'artifacts/playbooks_raw.json'
    if not os.path.exists(raw_file):
        logger.error(f"Raw playbooks file not found: {raw_file}")
        sys.exit(1)
    
    with open(raw_file, 'r', encoding='utf-8') as f:
        raw_playbooks = json.load(f)
    
    logger.info(f"Loaded {len(raw_playbooks)} raw playbooks")
    
    # Initialize normalizer
    normalizer = PlaybookNormalizer()
    
    # Normalize playbooks
    normalized_playbooks = []
    success_count = 0
    error_count = 0
    
    for i, raw_pb in enumerate(raw_playbooks):
        logger.info(f"Processing playbook {i+1}/{len(raw_playbooks)}")
        normalized = normalizer.normalize(raw_pb)
        
        if 'error' not in normalized:
            success_count += 1
            normalized_playbooks.append(normalized)
        else:
            error_count += 1
            logger.warning(f"Failed to normalize playbook {raw_pb.get('id')}: {normalized.get('error')}")
    
    # Save normalized playbooks
    output_file = 'artifacts/playbooks_normalized.json'
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(normalized_playbooks, f, indent=2, ensure_ascii=False)
    
    logger.info(f"Normalization complete:")
    logger.info(f"  Success: {success_count}")
    logger.info(f"  Errors: {error_count}")
    logger.info(f"  Output: {output_file}")
    
    # Generate validation report
    generate_validation_report(normalized_playbooks)


def generate_validation_report(normalized_playbooks: List[Dict[str, Any]]):
    """Generate validation report for normalized playbooks."""
    report = {
        'summary': {
            'total_playbooks': len(normalized_playbooks),
            'validation_date': datetime.utcnow().isoformat() + 'Z'
        },
        'schema_compliance': {
            'has_header': 0,
            'has_pre_remediation_checks': 0,
            'has_workflows': 0,
            'has_steps': 0,
            'has_post_validation': 0,
            'has_recommendations': 0
        },
        'workflow_analysis': {
            'total_workflows': 0,
            'workflow_types': {},
            'steps_per_workflow': []
        },
        'sample_playbooks': []
    }
    
    for pb in normalized_playbooks[:5]:  # Sample first 5
        # Check schema compliance
        if 'header' in pb:
            report['schema_compliance']['has_header'] += 1
        if 'pre_remediation_checks' in pb:
            report['schema_compliance']['has_pre_remediation_checks'] += 1
        if 'workflows' in pb:
            report['schema_compliance']['has_workflows'] += 1
            report['workflow_analysis']['total_workflows'] += len(pb['workflows'])
            
            for workflow in pb['workflows']:
                # Count workflow types
                wf_type = workflow.get('workflow_type', 'unknown')
                report['workflow_analysis']['workflow_types'][wf_type] = \
                    report['workflow_analysis']['workflow_types'].get(wf_type, 0) + 1
                
                # Count steps
                steps = workflow.get('steps', [])
                report['schema_compliance']['has_steps'] += len(steps)
                report['workflow_analysis']['steps_per_workflow'].append(len(steps))
        
        if 'post_remediation_validation' in pb:
            report['schema_compliance']['has_post_validation'] += 1
        if 'additional_recommendations' in pb:
            report['schema_compliance']['has_recommendations'] += 1
        
        # Add sample
        if len(report['sample_playbooks']) < 3:
            sample = {
                'cve_id': pb.get('header', {}).get('cve_id', 'unknown'),
                'workflow_count': len(pb.get('workflows', [])),
                'total_steps': sum(len(w.get('steps', [])) for w in pb.get('workflows', [])),
                'has_validation': 'post_remediation_validation' in pb
            }
            report['sample_playbooks'].append(sample)
    
        # Calculate percentages
        total = report['summary']['total_playbooks']
        compliance_keys = list(report['schema_compliance'].keys())
        for key in compliance_keys:
            if total > 0:
                report['schema_compliance'][f'{key}_percent'] = \
                    round(report['schema_compliance'][key] / total * 100, 1)
    
    # Calculate averages
    if report['workflow_analysis']['steps_per_workflow']:
        avg_steps = sum(report['workflow_analysis']['steps_per_workflow']) / \
                   len(report['workflow_analysis']['steps_per_workflow'])
        report['workflow_analysis']['average_steps_per_workflow'] = round(avg_steps, 1)
    
    # Save report
    report_file = 'artifacts/normalization_validation_report.json'
    with open(report_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    logger.info(f"Validation report saved: {report_file}")
    
    # Print summary
    print("\n=== Normalization Validation Report ===")
    print(f"Total playbooks normalized: {report['summary']['total_playbooks']}")
    print(f"\nSchema Compliance:")
    for key, value in report['schema_compliance'].items():
        if not key.endswith('_percent'):
            percent = report['schema_compliance'].get(f'{key}_percent', 0)
            print(f"  {key}: {value} ({percent}%)")
    
    print(f"\nWorkflow Analysis:")
    print(f"  Total workflows: {report['workflow_analysis']['total_workflows']}")
    print(f"  Average steps per workflow: {report['workflow_analysis'].get('average_steps_per_workflow', 0)}")
    print(f"  Workflow types: {report['workflow_analysis']['workflow_types']}")


if __name__ == '__main__':
    main()