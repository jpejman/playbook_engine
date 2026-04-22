"""
JSON Extractor for Continuous Pipeline v0.3.1
Version: v0.3.1

Purpose:
- Extract JSON from raw model output
- Handle markdown code fences, leading/trailing prose
- Support wrapper text around JSON
"""

import json
import re
import logging
from typing import Optional, Tuple, Dict, Any

logger = logging.getLogger(__name__)


class JSONExtractor:
    """
    Extract JSON from raw model output with various wrapper formats.
    """
    
    def __init__(self):
        self.json_patterns = [
            # JSON object with potential wrapper
            r'(\{.*\})',
            # JSON array with potential wrapper  
            r'(\[.*\])',
        ]
        
    def extract_json(self, raw_text: str) -> Tuple[Optional[str], Dict[str, Any]]:
        """
        Extract JSON from raw text.
        
        Args:
            raw_text: Raw model output text
            
        Returns:
            Tuple of (extracted_json_string, metadata)
        """
        metadata = {
            "extraction_applied": False,
            "extraction_method": None,
            "original_length": len(raw_text),
            "stripped_markdown": False,
            "stripped_prose": False,
            "error": None
        }
        
        if not raw_text or not isinstance(raw_text, str):
            metadata["error"] = "Invalid input: empty or non-string"
            return None, metadata
            
        text = raw_text.strip()
        
        # Try direct JSON parse first
        try:
            json.loads(text)
            metadata["extraction_method"] = "direct_parse"
            metadata["extraction_applied"] = True
            return text, metadata
        except json.JSONDecodeError:
            pass
        
        # Try to strip markdown code fences
        stripped_text = self._strip_markdown_fences(text)
        if stripped_text != text:
            metadata["stripped_markdown"] = True
            text = stripped_text
            
            # Try parse after markdown stripping
            try:
                json.loads(text.strip())
                metadata["extraction_method"] = "markdown_stripped"
                metadata["extraction_applied"] = True
                return text.strip(), metadata
            except json.JSONDecodeError:
                pass
        
        # Try to find JSON in text using patterns
        for pattern in self.json_patterns:
            matches = re.findall(pattern, text, re.DOTALL)
            if matches:
                # Find the longest match (most likely to be complete JSON)
                longest_match = max(matches, key=len)
                
                # Clean up the match
                cleaned = longest_match.strip()
                
                # Try to parse
                try:
                    json.loads(cleaned)
                    metadata["extraction_method"] = f"pattern_match_{pattern}"
                    metadata["extraction_applied"] = True
                    metadata["stripped_prose"] = True
                    return cleaned, metadata
                except json.JSONDecodeError:
                    # Try to find JSON boundaries more precisely
                    json_start = text.find('{')
                    json_end = text.rfind('}')
                    
                    if json_start != -1 and json_end != -1 and json_end > json_start:
                        candidate = text[json_start:json_end + 1]
                        try:
                            json.loads(candidate)
                            metadata["extraction_method"] = "boundary_match"
                            metadata["extraction_applied"] = True
                            metadata["stripped_prose"] = True
                            return candidate, metadata
                        except json.JSONDecodeError:
                            pass
        
        # Try to extract from common wrapper patterns
        wrapper_patterns = [
            r'```(?:json)?\s*\n(.*?)\n```',
            r'Here.*?JSON.*?:\s*\n?(.*?)(?:\n\n|\Z)',
            r'The.*?response.*?:\s*\n?(.*?)(?:\n\n|\Z)',
            r'Output.*?:\s*\n?(.*?)(?:\n\n|\Z)',
        ]
        
        for pattern in wrapper_patterns:
            match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
            if match:
                candidate = match.group(1).strip()
                try:
                    json.loads(candidate)
                    metadata["extraction_method"] = f"wrapper_pattern_{pattern[:20]}"
                    metadata["extraction_applied"] = True
                    metadata["stripped_prose"] = True
                    return candidate, metadata
                except json.JSONDecodeError:
                    pass
        
        metadata["error"] = "No valid JSON found in text"
        return None, metadata
    
    def _strip_markdown_fences(self, text: str) -> str:
        """
        Strip markdown code fences from text.
        
        Args:
            text: Input text
            
        Returns:
            Text with markdown fences removed
        """
        # Remove ```json ... ```
        text = re.sub(r'^```(?:json)?\s*\n', '', text, flags=re.MULTILINE)
        text = re.sub(r'\n```\s*$', '', text, flags=re.MULTILINE)
        
        # Remove ``` ... ```
        text = re.sub(r'^```\s*\n', '', text, flags=re.MULTILINE)
        text = re.sub(r'\n```\s*$', '', text, flags=re.MULTILINE)
        
        # Remove ~~~ ... ~~~
        text = re.sub(r'^~~~\s*\n', '', text, flags=re.MULTILINE)
        text = re.sub(r'\n~~~\s*$', '', text, flags=re.MULTILINE)
        
        return text.strip()
    
    def extract_with_context(self, raw_text: str) -> Dict[str, Any]:
        """
        Extract JSON with full context metadata.
        
        Args:
            raw_text: Raw model output
            
        Returns:
            Dictionary with extraction results and metadata
        """
        extracted_json, metadata = self.extract_json(raw_text)
        
        result = {
            "raw_text": raw_text,
            "extracted_json": extracted_json,
            "metadata": metadata,
            "success": extracted_json is not None
        }
        
        return result