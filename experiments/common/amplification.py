"""
Amplification-factor formulas.

P3.3 unification: the implementation now lives in ONE place,
`harness/measure/amplification.py`, and this module re-exports it so the
experiments pipeline and the harness (and the harness test suite) all run the
exact same code. The channel definitions (memory channel for vectors 1/2/3/6,
CPU channel for 4/5/7) are documented there and in paper Section 4.2.
"""
from __future__ import annotations

import os
import sys

# make the harness package importable regardless of caller cwd
_HARNESS = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "harness"))
if _HARNESS not in sys.path:
    sys.path.insert(0, _HARNESS)

from measure.amplification import EPS, cpu_amplification, mem_amplification, ratio  # noqa: E402,F401
