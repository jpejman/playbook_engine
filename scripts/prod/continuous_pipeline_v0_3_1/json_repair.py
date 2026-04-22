"""
JSON Repair for Continuous Pipeline v0.3.1
Version: v0.3.1

Purpose:
- Perform minimal, safe JSON cleanup
- Fix common malformed JSON issues
- Never fabricate semantic content
"""

import json
import re
import logging
from typing import Optional, Tuple, Dict, Any

logger = logging.getLogger(__name__)


class JSONRepair:
    """
    Repair common JSON malformations safely.
    """
    
    def __init__(self):
        self.repair_methods = [
            self._repair_trailing_commas,
            self._repair_unquoted_keys,
            self._repair_single_quotes,
            self._repair_missing_commas,
            self._repair_unclosed_braces,
        ]
    
    def repair_json(self, json_text: str) -> Tuple[Optional[str], Dict[str, Any]]:
        """
        Attempt to repair malformed JSON.
        
        Args:
            json_text: JSON text (may be malformed)
            
        Returns:
            Tuple of (repaired_json_string, metadata)
        """
        metadata = {
            "repair_applied": False,
            "repair_methods": [],
            "original_text": json_text,
            "error": None,
            "success": False
        }
        
        if not json_text or not isinstance(json_text, str):
            metadata["error"] = "Invalid input: empty or non-string"
            return None, metadata
        
        # Try direct parse first
        try:
            parsed = json.loads(json_text)
            metadata["success"] = True
            return json_text, metadata
        except json.JSONDecodeError as e:
            metadata["parse_error"] = str(e)
            metadata["parse_error_position"] = e.pos
        
        # Apply repair methods in sequence
        repaired_text = json_text
        applied_methods = []
        
        for method in self.repair_methods:
            try:
                result, method_name = method(repaired_text)
                if result != repaired_text:
                    repaired_text = result
                    applied_methods.append(method_name)
                    
                    # Try parse after each repair
                    try:
                        json.loads(repaired_text)
                        metadata["repair_applied"] = True
                        metadata["repair_methods"] = applied_methods
                        metadata["success"] = True
                        return repaired_text, metadata
                    except json.JSONDecodeError:
                        continue
            except Exception as e:
                logger.debug(f"Repair method {method.__name__} failed: {e}")
                continue
        
        # If we get here, repair failed
        metadata["error"] = "All repair attempts failed"
        return None, metadata
    
    def _repair_trailing_commas(self, text: str) -> Tuple[str, str]:
        """
        Remove trailing commas in objects and arrays.
        
        Args:
            text: JSON text
            
        Returns:
            Tuple of (repaired_text, method_name)
        """
        # Remove trailing commas in objects: { "key": "value", }
        pattern1 = r',(\s*[}\]])'
        repaired = re.sub(pattern1, r'\1', text)
        
        # Remove trailing commas in arrays: [ "item", ]
        pattern2 = r',(\s*\])'
        repaired = re.sub(pattern2, r'\1', repaired)
        
        method_name = "trailing_commas" if repaired != text else None
        return repaired, method_name
    
    def _repair_unquoted_keys(self, text: str) -> Tuple[str, str]:
        """
        Add quotes to unquoted object keys.
        
        Args:
            text: JSON text
            
        Returns:
            Tuple of (repaired_text, method_name)
        """
        # Pattern for unquoted keys: { key: "value" }
        # Be careful not to match JavaScript object shorthand
        pattern = r'(\{|\,\s*)([a-zA-Z_][a-zA-Z0-9_]*)\s*:'
        
        def replace_key(match):
            prefix = match.group(1)
            key = match.group(2)
            return f'{prefix}"{key}":'
        
        repaired = re.sub(pattern, replace_key, text)
        method_name = "unquoted_keys" if repaired != text else None
        return repaired, method_name
    
    def _repair_single_quotes(self, text: str) -> Tuple[str, str]:
        """
        Convert single quotes to double quotes for JSON compatibility.
        
        Args:
            text: JSON text
            
        Returns:
            Tuple of (repaired_text, method_name)
        """
        # Convert single-quoted strings to double-quoted
        # This is a simple approach - more complex would handle escaped quotes
        in_string = False
        result = []
        i = 0
        
        while i < len(text):
            char = text[i]
            
            if char == "'" and (i == 0 or text[i-1] != '\\'):
                # Check if this is likely a string delimiter
                # Look ahead for matching single quote
                j = i + 1
                while j < len(text):
                    if text[j] == "'" and (j == 0 or text[j-1] != '\\'):
                        # Found matching single quote - replace both with double quotes
                        result.append('"')
                        # Copy content between quotes
                        result.append(text[i+1:j])
                        result.append('"')
                        i = j
                        break
                    j += 1
                else:
                    # No matching quote found, leave as is
                    result.append(char)
            else:
                result.append(char)
            
            i += 1
        
        repaired = ''.join(result)
        method_name = "single_quotes" if repaired != text else None
        return repaired, method_name
    
    def _repair_missing_commas(self, text: str) -> Tuple[str, str]:
        """
        Add missing commas between object/array elements.
        
        Args:
            text: JSON text
            
        Returns:
            Tuple of (repaired_text, method_name)
        """
        # This is complex and potentially dangerous
        # We'll only attempt in very specific cases
        
        # Pattern: } { (missing comma between objects in array)
        pattern1 = r'\}\s*\{'
        repaired = re.sub(pattern1, '},{', text)
        
        # Pattern: ] [ (missing comma between arrays)
        pattern2 = r'\]\s*\['
        repaired = re.sub(pattern2, '],[', repaired)
        
        # Pattern: value { (missing comma before object)
        pattern3 = r'("(?:[^"\\]|\\.)*"|\d+|true|false|null)\s*\{'
        repaired = re.sub(pattern3, r'\1,{', repaired)
        
        method_name = "missing_commas" if repaired != text else None
        return repaired, method_name
    
    def _repair_unclosed_braces(self, text: str) -> Tuple[str, str]:
        """
        Attempt to close unclosed braces/brackets.
        
        Args:
            text: JSON text
            
        Returns:
            Tuple of (repaired_text, method_name)
        """
        # Count braces and brackets
        open_braces = text.count('{') - text.count('}')
        open_brackets = text.count('[') - text.count(']')
        
        repaired = text
        
        # Add missing closing braces
        if open_braces > 0:
            repaired += '}' * open_braces
        
        # Add missing closing brackets
        if open_brackets > 0:
            repaired += ']' * open_brackets
        
        method_name = "unclosed_braces" if repaired != text else None
        return repaired, method_name
    
    def repair_with_context(self, json_text: str) -> Dict[str, Any]:
        """
        Repair JSON with full context metadata.
        
        Args:
            json_text: JSON text (may be malformed)
            
        Returns:
            Dictionary with repair results and metadata
        """
        repaired_json, metadata = self.repair_json(json_text)
        
        result = {
            "original_json": json_text,
            "repaired_json": repaired_json,
            "metadata": metadata,
            "success": repaired_json is not None
        }
        
        return result