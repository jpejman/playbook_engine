#!/usr/bin/env python3
"""Debug parser markdown fence issue"""

import re

def strip_markdown_fences(text: str) -> str:
    """
    Strip markdown code fences from text.
    
    Args:
        text: Text potentially containing markdown fences
        
    Returns:
        Text with fences removed
    """
    # Pattern for ```json ... ``` or ``` ... ```
    pattern = r'^```(?:json)?\s*\n?(.*?)\n?```$'
    
    # Check if entire text is wrapped in fences
    match = re.match(pattern, text, re.DOTALL)
    if match:
        print(f"Matched with DOTALL: '{match.group(1)}'")
        return match.group(1).strip()
    
    # Also handle cases where fences might be at start/end but not both
    # Remove leading ```json or ```
    text = re.sub(r'^```(?:json)?\s*\n?', '', text, flags=re.MULTILINE)
    # Remove trailing ```
    text = re.sub(r'\n?```$', '', text, flags=re.MULTILINE)
    
    return text.strip()

# Test case
json_with_fences = '''```json
{
    "playbook": {
        "title": "Fenced Playbook",
        "cve_id": "CVE-TEST-0002",
        "remediation_steps": []
    }
}
```'''

print("Original text:")
print(repr(json_with_fences))
print("\nAfter stripping fences:")
result = strip_markdown_fences(json_with_fences)
print(repr(result))