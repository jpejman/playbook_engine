#!/usr/bin/env python3
"""
Test full pipeline with mock LLM response that matches hardened schema.
"""

import sys
import json
import logging
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from src.utils.playbook_parser import parse_playbook_response
from src.utils.qa_evaluator import evaluate_playbook_qa

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def test_mock_llm_response():
    """Test with a mock LLM response that should be approvable."""
    print("=" * 80)
    print("TESTING FULL PIPELINE WITH MOCK LLM RESPONSE")
    print("=" * 80)
    
    # Mock LLM response that matches our hardened schema
    mock_llm_response = '''{
  "playbook": {
    "title": "Remediation Playbook for CVE-TEST-0001 - Spring Framework Vulnerability",
    "cve_id": "CVE-TEST-0001",
    "severity": "High",
    "affected_components": [
      "Spring Framework 5.3.0-5.3.17",
      "Spring Boot 2.6.0-2.6.11",
      "Applications using Spring MVC with file upload"
    ],
    "remediation_steps": [
      {
        "step_number": 1,
        "description": "Identify affected Spring Framework versions in your application dependencies",
        "commands": [
          "mvn dependency:tree | grep spring-core",
          "gradle dependencies | grep spring-core",
          "check pom.xml or build.gradle for springframework version"
        ],
        "verification": "Verify that Spring Framework version is 5.3.0-5.3.17 or Spring Boot 2.6.0-2.6.11",
        "evidence_based": true
      },
      {
        "step_number": 2,
        "description": "Upgrade Spring Framework to patched version 5.3.18 or later",
        "commands": [
          "Update pom.xml: <spring.version>5.3.18</spring.version>",
          "Update build.gradle: implementation \\\"org.springframework:spring-core:5.3.18\\\"",
          "For Spring Boot: update to 2.6.12+ or 2.7.0+"
        ],
        "verification": "Run mvn dependency:tree or gradle dependencies to confirm upgraded version",
        "evidence_based": true
      },
      {
        "step_number": 3,
        "description": "Apply input validation for file upload endpoints",
        "commands": [
          "Implement @RequestParam with size limits in controller methods",
          "Add MultipartFile validation: file.getSize() < MAX_FILE_SIZE",
          "Configure spring.servlet.multipart.max-file-size and max-request-size in application.properties"
        ],
        "verification": "Test file upload with oversized files - should reject with appropriate error",
        "evidence_based": true
      },
      {
        "step_number": 4,
        "description": "Implement security headers and CORS configuration",
        "commands": [
          "Add spring.security.headers.content-security-policy in application.properties",
          "Configure CORS with allowed origins: @CrossOrigin(origins = \\\"https://trusted-domain.com\\\")",
          "Enable CSRF protection for state-changing operations"
        ],
        "verification": "Use browser developer tools to check security headers in response",
        "evidence_based": true
      }
    ],
    "verification_procedures": [
      "Run vulnerability scan with OWASP ZAP or similar tool",
      "Perform manual testing of file upload functionality",
      "Review application logs for any security-related warnings",
      "Verify all dependencies are updated via software composition analysis"
    ],
    "rollback_procedures": [
      "Revert to previous version from version control (git revert)",
      "Restore from backup if available",
      "Rollback deployment in Kubernetes: kubectl rollout undo deployment/app-name",
      "Restore database from backup if changes were made"
    ],
    "references": [
      "https://spring.io/security/cve-2021-22119",
      "https://nvd.nist.gov/vuln/detail/CVE-TEST-0001",
      "https://owasp.org/www-project-top-ten/",
      "Spring Security Reference: https://docs.spring.io/spring-security/reference/"
    ]
  }
}'''
    
    print("\n1. Testing parser with mock LLM response...")
    parser_result = parse_playbook_response(mock_llm_response)
    
    print(f"Parse OK: {parser_result['parsed_ok']}")
    print(f"Parse errors: {parser_result['parse_errors']}")
    
    if not parser_result['parsed_ok']:
        print("FAIL: Parser rejected the response")
        return False
    
    print("\n2. Testing QA evaluation...")
    qa_result = evaluate_playbook_qa(
        raw_response=mock_llm_response,
        parsed_playbook=parser_result['parsed_playbook'],
        parse_errors=parser_result['parse_errors'],
        has_retrieval_backing=True
    )
    
    print(f"QA Result: {qa_result['qa_result']}")
    print(f"QA Score: {qa_result['qa_score']:.3f}")
    print(f"QA Errors: {qa_result['qa_feedback']['errors']}")
    print(f"QA Warnings: {qa_result['qa_feedback']['warnings']}")
    print(f"QA Strengths: {qa_result['qa_feedback']['strengths']}")
    
    if qa_result['qa_result'] == 'approved':
        print("\nSUCCESS: Mock LLM response would be APPROVED by QA")
        
        # Show the parsed structure
        print("\n3. Parsed playbook structure:")
        playbook = parser_result['parsed_playbook']['playbook']
        print(f"Title: {playbook['title']}")
        print(f"CVE ID: {playbook['cve_id']}")
        print(f"Severity: {playbook['severity']}")
        print(f"Affected components: {len(playbook['affected_components'])}")
        print(f"Remediation steps: {len(playbook['remediation_steps'])}")
        print(f"Verification procedures: {len(playbook['verification_procedures'])}")
        print(f"Rollback procedures: {len(playbook['rollback_procedures'])}")
        print(f"References: {len(playbook['references'])}")
        
        # Show first remediation step details
        if playbook['remediation_steps']:
            first_step = playbook['remediation_steps'][0]
            print(f"\nFirst remediation step:")
            print(f"  Step number: {first_step['step_number']}")
            print(f"  Description: {first_step['description'][:80]}...")
            print(f"  Commands: {len(first_step['commands'])}")
            print(f"  Verification: {first_step['verification'][:80]}...")
            print(f"  Evidence based: {first_step['evidence_based']}")
        
        return True
    else:
        print("\nFAIL: Mock LLM response would NOT be approved")
        return False

if __name__ == '__main__':
    success = test_mock_llm_response()
    print("\n" + "=" * 80)
    if success:
        print("FINAL RESULT: PIPELINE WOULD PRODUCE APPROVED PLAYBOOK")
        print("The hardened prompt and parser/QA alignment are working correctly.")
    else:
        print("FINAL RESULT: PIPELINE NEEDS FURTHER ADJUSTMENT")
        print("Check parser and QA evaluator for issues with the schema.")
    print("=" * 80)