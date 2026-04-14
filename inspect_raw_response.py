#!/usr/bin/env python3
"""
VS.ai — Playbook Engine Gen-3
Malformed JSON Response Inspection
Timestamp (UTC): 2026-04-13

Inspect failed raw response for dual failure:
1. Non-JSON prefix (markdown/code fence)
2. Invalid escape sequence inside JSON body
"""

import json
import re

def inspect_raw_response(raw_response: str):
    """
    Inspect raw response for JSON parsing issues.
    
    Args:
        raw_response: Raw LLM response text
    """
    print("=" * 80)
    print("RAW RESPONSE INSPECTION")
    print("=" * 80)
    
    # 1. Extract and print first 150 characters
    print("\n1. FIRST 150 CHARACTERS OF RAW RESPONSE:")
    print("-" * 40)
    first_150 = raw_response[:150]
    print(first_150)
    print(f"Length: {len(first_150)} chars")
    
    # 2. Strip leading markdown fences and show first 150 chars again
    print("\n2. AFTER STRIPPING MARKDOWN FENCES:")
    print("-" * 40)
    
    # Pattern for ```json ... ``` or ``` ... ```
    pattern = r'^```(?:json)?\s*\n?(.*?)\n?```$'
    
    # Check if entire text is wrapped in fences
    match = re.match(pattern, raw_response, re.DOTALL)
    if match:
        stripped = match.group(1).strip()
        print("Found complete markdown fence wrapper")
    else:
        # Also handle cases where fences might be at start/end but not both
        # Remove leading ```json or ```
        stripped = re.sub(r'^```(?:json)?\s*\n?', '', raw_response, flags=re.MULTILINE)
        # Remove trailing ```
        stripped = re.sub(r'\n?```$', '', stripped, flags=re.MULTILINE)
        stripped = stripped.strip()
    
    print(f"First 150 chars after stripping: {stripped[:150]}")
    print(f"Length after stripping: {len(stripped)} chars")
    
    # 3. Identify prefix issue
    print("\n3. PREFIX ISSUE ANALYSIS:")
    print("-" * 40)
    
    # Check for markdown/code fences
    has_markdown_fence = raw_response.strip().startswith('```')
    print(f"Starts with markdown fence (```): {has_markdown_fence}")
    
    # Check for text before first {
    first_brace_index = raw_response.find('{')
    if first_brace_index > 0:
        text_before_brace = raw_response[:first_brace_index]
        print(f"Text before first '{{' (char {first_brace_index}): '{text_before_brace}'")
        print(f"Length of text before first '{{': {len(text_before_brace)} chars")
    else:
        print("No '{' found in response")
    
    # 4. Deep inspection at failure point (char ~5037)
    print("\n4. DEEP INSPECTION AT CHAR ~5037:")
    print("-" * 40)
    
    target_char = 5037
    if len(raw_response) > target_char:
        # Print 200 chars before and after
        start = max(0, target_char - 200)
        end = min(len(raw_response), target_char + 200)
        
        context = raw_response[start:end]
        print(f"Context around char {target_char} (chars {start}-{end}):")
        print("-" * 40)
        print(context)
        print("-" * 40)
        
        # Try to identify invalid escape sequence
        # Look for common invalid escape patterns
        invalid_escape_patterns = [
            r'\\[^"\\/bfnrtu]',  # Invalid escape sequence
            r'\\x[^0-9a-fA-F]',  # Invalid hex escape
            r'\\u[^0-9a-fA-F]{4}',  # Invalid unicode escape
            r'\\[cghijklmopqsvwxyz]',  # Invalid single-letter escapes
        ]
        
        print("\nSearching for invalid escape sequences...")
        for i, pattern in enumerate(invalid_escape_patterns):
            matches = list(re.finditer(pattern, raw_response[max(0, target_char-100):target_char+100]))
            if matches:
                print(f"Pattern {i+1} matches found:")
                for match in matches:
                    print(f"  Position ~{target_char-100+match.start()}: '{match.group()}'")
        
        # Also check for Windows paths (C:\)
        windows_path_pattern = r'[A-Za-z]:\\[^"]'
        windows_matches = list(re.finditer(windows_path_pattern, raw_response[max(0, target_char-100):target_char+100]))
        if windows_matches:
            print(f"\nWindows path patterns found:")
            for match in windows_matches:
                print(f"  Position ~{target_char-100+match.start()}: '{match.group()}'")
        
        # Check for shell commands with backslashes
        shell_pattern = r'\\[ntr]'
        shell_matches = list(re.finditer(shell_pattern, raw_response[max(0, target_char-100):target_char+100]))
        if shell_matches:
            print(f"\nShell command patterns found:")
            for match in shell_matches:
                print(f"  Position ~{target_char-100+match.start()}: '{match.group()}'")
    else:
        print(f"Response too short for char {target_char} inspection")
        print(f"Response length: {len(raw_response)} chars")
    
    # 5. Try to parse JSON to get exact error
    print("\n5. JSON PARSING ATTEMPT:")
    print("-" * 40)
    
    try:
        parsed = json.loads(raw_response)
        print("Direct parse SUCCESSFUL")
    except json.JSONDecodeError as e:
        print(f"Direct parse FAILED: {e}")
        print(f"Error at position: {e.pos}")
        print(f"Error message: {e.msg}")
        
        # Try parsing stripped version
        try:
            parsed = json.loads(stripped)
            print("Stripped parse SUCCESSFUL")
        except json.JSONDecodeError as e2:
            print(f"Stripped parse FAILED: {e2}")
            print(f"Error at position: {e2.pos}")
            print(f"Error message: {e2.msg}")
    
    # 6. Classify root cause
    print("\n6. ROOT CAUSE CLASSIFICATION:")
    print("-" * 40)
    
    print("Prefix issue classification:")
    if has_markdown_fence:
        print("  - markdown_fence: YES")
    if first_brace_index > 0 and raw_response[:first_brace_index].strip():
        print("  - commentary_prefix: YES")
    if raw_response.startswith((' ', '\t', '\n', '\r')):
        print("  - whitespace/control: YES")
    
    print("\nEscape issue classification (based on patterns found):")
    # Check for specific patterns in the context
    context_area = raw_response[max(0, target_char-50):min(len(raw_response), target_char+50)]
    
    if re.search(r'[A-Za-z]:\\', context_area):
        print("  - windows_path: YES")
    if re.search(r'\\[ntr]', context_area):
        print("  - shell_command: YES")
    if re.search(r'\\[^"\\/bfnrtu]', context_area):
        print("  - regex: YES")
    
    # Check for unknown patterns
    if re.search(r'\\[cghijklmopqsvwxyz]', context_area):
        print("  - unknown: YES (invalid single-letter escape)")
    
    print("\n" + "=" * 80)
    print("INSPECTION COMPLETE")
    print("=" * 80)

def main():
    """Main function with test cases."""
    
    # Test case 1: Response with markdown fence and invalid escape
    test_response = '''```json
{
  "header": {
    "title": "Remediation Playbook for CVE-2025-12593",
    "cve_id": "CVE-2025-12593",
    "vendor": "Example Vendor",
    "product": "Example Product",
    "severity": "HIGH",
    "description": "This is a test vulnerability with Windows path C:\\Users\\test\\file.txt and shell command with \\n newline",
    "vulnerability_type": "Buffer Overflow"
  },
  "workflows": [
    {
      "description": "Apply patch from C:\\patches\\fix.exe",
      "commands": ["cd C:\\program files\\app", "run fix.exe \\quiet"],
      "verification": "Check version with app.exe --version",
      "evidence_based": true
    }
  ],
  "references": ["https://example.com/cve/CVE-2025-12593"]
}
```'''
    
    print("TEST CASE 1: Response with markdown fence and Windows paths")
    inspect_raw_response(test_response)
    
    # Test case 2: Response with commentary prefix
    test_response2 = '''Here is the playbook you requested:

{
  "playbook": {
    "title": "Test Playbook",
    "cve_id": "CVE-2025-12593",
    "severity": "High",
    "affected_components": ["Component 1"],
    "remediation_steps": [
      {
        "step_number": 1,
        "description": "Run command with \\t tab",
        "commands": ["echo 'test' > file.txt"],
        "verification": "Check output",
        "evidence_based": false
      }
    ]
  }
}

Please let me know if you need any changes.'''
    
    print("\n\nTEST CASE 2: Response with commentary prefix")
    inspect_raw_response(test_response2)

if __name__ == "__main__":
    main()