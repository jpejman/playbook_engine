#!/usr/bin/env python3
from pathlib import Path
import subprocess
import sys

# Simulate what phase1_single_cve_continuous_runner.py does
def test_paths():
    # First, let's simulate being in the scripts/prod directory
    # like phase1_single_cve_continuous_runner.py is
    original_file = "scripts/prod/phase1_single_cve_continuous_runner.py"
    
    # This is what the code does
    cwd_path = Path(original_file).parent.parent.parent.resolve()
    print(f"Original file: {original_file}")
    print(f"cwd_path: {cwd_path}")
    print(f"cwd_path type: {type(cwd_path)}")
    
    # Check the file path that the code checks
    script_path = cwd_path / 'scripts/prod/02_85_build_context_snapshot_v0_1_0.py'
    print(f"\nscript_path (as checked in code): {script_path}")
    print(f"script_path exists: {script_path.exists()}")
    
    # What should the correct path be?
    correct_path = cwd_path / 'agents/playbook_engine/scripts/prod/02_85_build_context_snapshot_v0_1_0.py'
    print(f"\ncorrect_path (should be): {correct_path}")
    print(f"correct_path exists: {correct_path.exists()}")
    
    # Check what the actual current directory is
    print(f"\nCurrent working directory: {Path.cwd()}")
    
    # The actual file location
    actual_file = Path.cwd() / 'scripts/prod/02_85_build_context_snapshot_v0_1_0.py'
    print(f"\nactual_file (from cwd): {actual_file}")
    print(f"actual_file exists: {actual_file.exists()}")

if __name__ == "__main__":
    test_paths()