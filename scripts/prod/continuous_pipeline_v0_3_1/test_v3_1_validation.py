"""
Test script for v0.3.1 validation modules.
"""

import json
import logging
from json_extractor import JSONExtractor
from json_repair import JSONRepair
from schema_normalizer import SchemaNormalizer
from validation_grader import ValidationGrader

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def test_json_extractor():
    """Test JSON extraction from various formats."""
    print("Testing JSON Extractor...")
    extractor = JSONExtractor()
    
    test_cases = [
        # Direct JSON
        ('{"header": {"cve_id": "CVE-2023-4863"}}', "Direct JSON"),
        
        # JSON with markdown fences
        ('```json\n{"header": {"cve_id": "CVE-2023-4863"}}\n```', "JSON with markdown"),
        
        # JSON with prose
        ('Here is the response: {"header": {"cve_id": "CVE-2023-4863"}} That is all.', "JSON with prose"),
        
        # Malformed but extractable
        ('Some text {"header": {"cve_id": "CVE-2023-4863"} more text', "JSON in middle of text"),
    ]
    
    for test_input, description in test_cases:
        print(f"\n  {description}:")
        result = extractor.extract_with_context(test_input)
        print(f"    Success: {result['success']}")
        print(f"    Method: {result['metadata'].get('extraction_method', 'N/A')}")
        if result['extracted_json']:
            print(f"    Extracted: {result['extracted_json'][:50]}...")


def test_json_repair():
    """Test JSON repair functionality."""
    print("\nTesting JSON Repair...")
    repair = JSONRepair()
    
    test_cases = [
        # Trailing comma
        ('{"header": {"cve_id": "CVE-2023-4863"},}', "Trailing comma"),
        
        # Single quotes
        ("{'header': {'cve_id': 'CVE-2023-4863'}}", "Single quotes"),
        
        # Unquoted keys (limited repair)
        ('{header: {"cve_id": "CVE-2023-4863"}}', "Unquoted key"),
    ]
    
    for test_input, description in test_cases:
        print(f"\n  {description}:")
        result = repair.repair_with_context(test_input)
        print(f"    Success: {result['success']}")
        print(f"    Methods: {result['metadata'].get('repair_methods', [])}")
        if result['repaired_json']:
            print(f"    Repaired: {result['repaired_json'][:50]}...")


def test_schema_normalizer():
    """Test schema normalization."""
    print("\nTesting Schema Normalizer...")
    normalizer = SchemaNormalizer()
    
    test_cases = [
        # Canonical format (should not change)
        ({
            "header": {"cve_id": "CVE-2023-4863"},
            "pre_remediation_checks": [],
            "workflows": [{"name": "test"}],
            "post_remediation_validation": [],
            "additional_recommendations": [],
            "retrieval_metadata": {}
        }, "Canonical format"),
        
        # Alternative wrapper names
        ({
            "vulnerability_info": {"cve_id": "CVE-2023-4863"},
            "remediation_workflows": [{"name": "test"}],
            "pre_checks": [],
            "post_validation": [],
            "recommendations": [],
            "metadata": {}
        }, "Alternative names"),
        
        # Nested playbook
        ({
            "playbook": {
                "header": {"cve_id": "CVE-2023-4863"},
                "workflows": [{"name": "test"}]
            }
        }, "Nested playbook"),
    ]
    
    for test_input, description in test_cases:
        print(f"\n  {description}:")
        result = normalizer.normalize_with_context(test_input)
        print(f"    Success: {result['success']}")
        print(f"    Normalization applied: {result['metadata'].get('normalization_applied', False)}")
        print(f"    Mappings: {result['metadata'].get('mappings_applied', [])}")
        
        # Check semantic utility
        if result['normalized_json']:
            utility = normalizer.get_semantic_utility(result['normalized_json'])
            print(f"    Utility: {utility['assessment']}")
            print(f"    Workflow count: {utility['workflow_count']}")


def test_validation_grader():
    """Test validation grading."""
    print("\nTesting Validation Grader...")
    grader = ValidationGrader()
    
    test_cases = [
        # STRICT_PASS scenario
        {
            "parse_passed": True,
            "repair_applied": False,
            "normalization_applied": False,
            "canonical_validation_passed": True,
            "semantic_utility": {"has_useful_content": True, "missing_critical_sections": []}
        },
        
        # NORMALIZED_PASS scenario
        {
            "parse_passed": True,
            "repair_applied": False,
            "normalization_applied": True,
            "canonical_validation_passed": True,
            "semantic_utility": {"has_useful_content": True, "missing_critical_sections": []}
        },
        
        # REPAIR_PASS scenario
        {
            "parse_passed": False,
            "repair_applied": True,
            "normalization_applied": False,
            "canonical_validation_passed": True,
            "semantic_utility": {"has_useful_content": True, "missing_critical_sections": []}
        },
        
        # SEMANTIC_PARTIAL scenario
        {
            "parse_passed": True,
            "repair_applied": False,
            "normalization_applied": True,
            "canonical_validation_passed": False,
            "semantic_utility": {"has_useful_content": True, "missing_critical_sections": ["workflows"]}
        },
        
        # HARD_FAIL scenario
        {
            "parse_passed": False,
            "repair_applied": False,
            "normalization_applied": False,
            "canonical_validation_passed": False,
            "semantic_utility": {"has_useful_content": False, "missing_critical_sections": ["header", "workflows"]}
        },
    ]
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n  Test case {i}:")
        grade = grader.grade_validation(
            raw_response="test",
            extracted_response="{}",
            repaired_response=None,
            normalized_response={},
            **test_case
        )
        print(f"    Grade: {grade['grade']}")
        print(f"    Reason: {grade['grade_reason']}")


def main():
    """Run all tests."""
    print("=" * 80)
    print("v0.3.1 VALIDATION MODULES TEST")
    print("=" * 80)
    
    try:
        test_json_extractor()
        test_json_repair()
        test_schema_normalizer()
        test_validation_grader()
        
        print("\n" + "=" * 80)
        print("All tests completed successfully!")
        print("=" * 80)
        
    except Exception as e:
        print(f"\nTest failed with error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()