#!/usr/bin/env python3
"""
Test the fixes made to phase1_continuous_execution_system_v0_2_0_fixed_terminal_dedup.py
"""

import sys
from pathlib import Path

# Add to path
sys.path.insert(0, str(Path(__file__).parent))

def test_imports():
    """Test that the file can be imported without syntax errors."""
    print("Testing imports...")
    try:
        # Try to import the module
        import scripts.prod.phase1_continuous_execution_system_v0_2_0_fixed_terminal_dedup as module
        print("[OK] File imports successfully")
        return True
    except SyntaxError as e:
        print(f"✗ Syntax error: {e}")
        return False
    except ImportError as e:
        print(f"✗ Import error: {e}")
        return False
    except Exception as e:
        print(f"[ERROR] Other error: {e}")
        return False

def test_has_terminal_success_method():
    """Test that the _has_terminal_success method has correct indentation."""
    print("\nTesting _has_terminal_success method...")
    
    # Read the file
    file_path = Path("scripts/prod/phase1_continuous_execution_system_v0_2_0_fixed_terminal_dedup.py")
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Find the method
    import re
    method_pattern = r'def _has_terminal_success\(self, cve_id: str\) -> bool:(.*?)(?=\n    def|\nclass|\Z)'
    match = re.search(method_pattern, content, re.DOTALL)
    
    if not match:
        print("[ERROR] Could not find _has_terminal_success method")
        return False
    
    method_body = match.group(1)
    
    # Check indentation
    lines = method_body.strip().split('\n')
    if not lines:
        print("✗ Method body is empty")
        return False
    
    # First line should be the docstring with proper indentation
    first_line = lines[0]
    if not first_line.startswith('        """'):
        print(f"[ERROR] Docstring not properly indented: {first_line[:50]}...")
        return False
    
    # Check that try: is properly indented
    for i, line in enumerate(lines):
        if 'try:' in line and not line.startswith('        try:'):
            print(f"[ERROR] 'try:' not properly indented on line {i}: {line}")
            return False
    
    print("[OK] _has_terminal_success method has correct indentation")
    return True

def test_sql_query():
    """Test that the SQL query in _has_terminal_success is correct."""
    print("\nTesting SQL query...")
    
    # Read the file
    file_path = Path("scripts/prod/phase1_continuous_execution_system_v0_2_0_fixed_terminal_dedup.py")
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Find the SQL query
    import re
    sql_pattern = r'SELECT EXISTS \(\s*SELECT 1\s*FROM generation_runs gr\s*LEFT JOIN qa_runs qa ON gr\.id = qa\.generation_run_id\s*WHERE gr\.cve_id = %s\s*AND gr\.status = \'completed\'\s*AND gr\.response IS NOT NULL\s*AND btrim\(gr\.response\) <> \'\'\s*AND qa\.qa_result = \'approved\''
    
    if re.search(sql_pattern, content, re.DOTALL | re.IGNORECASE):
        print("[OK] SQL query correctly checks for QA approval")
        return True
    else:
        print("[ERROR] SQL query might not be correct")
        return False

def main():
    """Run all tests."""
    print("=" * 80)
    print("TESTING FIXES FOR phase1_continuous_execution_system_v0_2_0_fixed_terminal_dedup.py")
    print("=" * 80)
    
    tests = [
        test_imports,
        test_has_terminal_success_method,
        test_sql_query,
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
    
    print("\n" + "=" * 80)
    print(f"RESULTS: {passed}/{total} tests passed")
    print("=" * 80)
    
    if passed == total:
        print("[OK] All tests passed!")
        return 0
    else:
        print("[ERROR] Some tests failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())