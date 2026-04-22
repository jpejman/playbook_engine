"""
Validation Grader for Continuous Pipeline v0.3.1
Version: v0.3.1

Purpose:
- Assign validation grades to model outputs
- Support graded validation levels
- Provide detailed grading metadata
"""

import logging
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)


class ValidationGrader:
    """
    Grade validation results with multiple levels.
    """
    
    # Grade definitions
    GRADES = {
        "STRICT_PASS": {
            "description": "Raw output parses directly, no repair or normalization needed",
            "requirements": [
                "parse_passed",
                "no_repair_applied",
                "no_normalization_applied",
                "canonical_validation_passed"
            ]
        },
        "NORMALIZED_PASS": {
            "description": "Raw output parses but normalization required",
            "requirements": [
                "parse_passed",
                "no_repair_applied",
                "normalization_applied",
                "canonical_validation_passed"
            ]
        },
        "REPAIR_PASS": {
            "description": "Output required extraction or repair",
            "requirements": [
                "parse_failed_initially",
                "repair_applied",
                "canonical_validation_passed"
            ]
        },
        "SEMANTIC_PARTIAL": {
            "description": "Output contains useful structured content but missing required sections",
            "requirements": [
                "has_useful_content",
                "missing_critical_sections"
            ]
        },
        "HARD_FAIL": {
            "description": "Unusable response, cannot extract or normalize",
            "requirements": [
                "no_useful_content"
            ]
        }
    }
    
    def __init__(self):
        pass
    
    def grade_validation(
        self,
        raw_response: str,
        extracted_response: Optional[str],
        repaired_response: Optional[str],
        normalized_response: Optional[Dict[str, Any]],
        parse_passed: bool,
        repair_applied: bool,
        normalization_applied: bool,
        canonical_validation_passed: bool,
        semantic_utility: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Assign validation grade based on processing results.
        
        Args:
            raw_response: Raw model output
            extracted_response: Extracted JSON string (if any)
            repaired_response: Repaired JSON string (if any)
            normalized_response: Normalized JSON dictionary (if any)
            parse_passed: Whether initial parse succeeded
            repair_applied: Whether repair was applied
            normalization_applied: Whether normalization was applied
            canonical_validation_passed: Whether canonical validation passed
            semantic_utility: Semantic utility assessment
            
        Returns:
            Dictionary with grade and metadata
        """
        grade_metadata = {
            "raw_response_length": len(raw_response) if raw_response else 0,
            "extracted_response_present": extracted_response is not None,
            "repaired_response_present": repaired_response is not None,
            "normalized_response_present": normalized_response is not None,
            "parse_passed": parse_passed,
            "repair_applied": repair_applied,
            "normalization_applied": normalization_applied,
            "canonical_validation_passed": canonical_validation_passed,
            "semantic_utility": semantic_utility,
            "grade": None,
            "grade_reason": None,
            "requirements_met": [],
            "requirements_failed": []
        }
        
        # Check for STRICT_PASS
        if (parse_passed and 
            not repair_applied and 
            not normalization_applied and 
            canonical_validation_passed):
            grade_metadata["grade"] = "STRICT_PASS"
            grade_metadata["grade_reason"] = "Direct parse succeeded with canonical validation"
            grade_metadata["requirements_met"] = self.GRADES["STRICT_PASS"]["requirements"]
            return grade_metadata
        
        # Check for NORMALIZED_PASS
        if (parse_passed and 
            not repair_applied and 
            normalization_applied and 
            canonical_validation_passed):
            grade_metadata["grade"] = "NORMALIZED_PASS"
            grade_metadata["grade_reason"] = "Parse succeeded but normalization was required"
            grade_metadata["requirements_met"] = self.GRADES["NORMALIZED_PASS"]["requirements"]
            return grade_metadata
        
        # Check for REPAIR_PASS
        if (not parse_passed and 
            repair_applied and 
            canonical_validation_passed):
            grade_metadata["grade"] = "REPAIR_PASS"
            grade_metadata["grade_reason"] = "Repair was required and succeeded"
            grade_metadata["requirements_met"] = self.GRADES["REPAIR_PASS"]["requirements"]
            return grade_metadata
        
        # Check for SEMANTIC_PARTIAL
        has_useful_content = semantic_utility.get("has_useful_content", False)
        missing_critical = semantic_utility.get("missing_critical_sections", [])
        
        if has_useful_content and missing_critical:
            grade_metadata["grade"] = "SEMANTIC_PARTIAL"
            grade_metadata["grade_reason"] = f"Useful content present but missing critical sections: {missing_critical}"
            grade_metadata["requirements_met"] = self.GRADES["SEMANTIC_PARTIAL"]["requirements"]
            return grade_metadata
        
        # Check for partial with normalization but failed validation
        if (normalized_response is not None and 
            has_useful_content and 
            not canonical_validation_passed):
            grade_metadata["grade"] = "SEMANTIC_PARTIAL"
            grade_metadata["grade_reason"] = "Useful content extracted but canonical validation failed"
            grade_metadata["requirements_met"] = self.GRADES["SEMANTIC_PARTIAL"]["requirements"]
            return grade_metadata
        
        # Default to HARD_FAIL
        grade_metadata["grade"] = "HARD_FAIL"
        grade_metadata["grade_reason"] = "No useful content could be extracted or validated"
        grade_metadata["requirements_met"] = self.GRADES["HARD_FAIL"]["requirements"]
        
        return grade_metadata
    
    def get_grade_summary(self, grade_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate summary statistics for multiple grade results.
        
        Args:
            grade_results: List of grade result dictionaries
            
        Returns:
            Summary dictionary
        """
        if not grade_results:
            return {
                "total": 0,
                "grades": {},
                "success_rate": 0.0,
                "partial_rate": 0.0
            }
        
        grade_counts = {}
        for grade in self.GRADES.keys():
            grade_counts[grade] = 0
        
        for result in grade_results:
            grade = result.get("grade")
            if grade in grade_counts:
                grade_counts[grade] += 1
        
        total = len(grade_results)
        passing_grades = ["STRICT_PASS", "NORMALIZED_PASS", "REPAIR_PASS"]
        partial_grades = ["SEMANTIC_PARTIAL"]
        
        passing_count = sum(grade_counts[grade] for grade in passing_grades)
        partial_count = sum(grade_counts[grade] for grade in partial_grades)
        
        return {
            "total": total,
            "grades": grade_counts,
            "success_rate": passing_count / total if total > 0 else 0.0,
            "partial_rate": partial_count / total if total > 0 else 0.0,
            "passing_count": passing_count,
            "partial_count": partial_count,
            "fail_count": grade_counts.get("HARD_FAIL", 0)
        }
    
    def explain_grade(self, grade: str) -> Dict[str, Any]:
        """
        Get detailed explanation of a grade.
        
        Args:
            grade: Grade string
            
        Returns:
            Grade explanation dictionary
        """
        if grade not in self.GRADES:
            return {
                "grade": grade,
                "valid": False,
                "description": "Unknown grade",
                "requirements": []
            }
        
        grade_info = self.GRADES[grade]
        return {
            "grade": grade,
            "valid": True,
            "description": grade_info["description"],
            "requirements": grade_info["requirements"]
        }
    
    def get_all_grades(self) -> List[Dict[str, Any]]:
        """
        Get information about all available grades.
        
        Returns:
            List of grade information dictionaries
        """
        grades = []
        for grade_name, grade_info in self.GRADES.items():
            grades.append({
                "name": grade_name,
                "description": grade_info["description"],
                "requirements": grade_info["requirements"]
            })
        
        return grades