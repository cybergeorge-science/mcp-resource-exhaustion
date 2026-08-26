"""Ensures the harness/ directory (parent of this tests/ package) is on
sys.path regardless of how/where pytest is invoked from, so `import
dos_module` / `import measure` resolve without needing harness installed as
a package."""
import os
import sys

_HARNESS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _HARNESS_DIR not in sys.path:
    sys.path.insert(0, _HARNESS_DIR)
