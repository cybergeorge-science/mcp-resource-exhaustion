"""Ensures the experiments/ directory (parent of this tests/ package) is on
sys.path regardless of how/where pytest is invoked from, so `import common`
resolves without needing experiments/ installed as a package. Mirrors
harness/tests/conftest.py's pattern.
"""
import os
import sys

_EXPERIMENTS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _EXPERIMENTS_DIR not in sys.path:
    sys.path.insert(0, _EXPERIMENTS_DIR)
