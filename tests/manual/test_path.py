#!/usr/bin/env python3
from pathlib import Path
import sys

print(f"File: {__file__}")
print(f"Parent: {Path(__file__).parent}")
print(f"Parent parent: {Path(__file__).parent.parent}")
print(f"Parent parent parent: {Path(__file__).parent.parent.parent}")
print(f"Current dir: {Path.cwd()}")
print(f"sys.path[0]: {sys.path[0]}")