#!/usr/bin/env python3
"""
Root-level unittest forwarder for Threat Intelligence tests.
Enables running `python -m unittest tests/test_threat_intel.py` from project root.
"""
import sys
import importlib.util
from pathlib import Path

root_dir = Path(__file__).resolve().parent.parent
backend_dir = root_dir / "backend"

if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

backend_test_file = backend_dir / "tests" / "test_threat_intel.py"
spec = importlib.util.spec_from_file_location("backend_test_threat_intel", backend_test_file)
mod = importlib.util.module_from_spec(spec)
sys.modules["backend_test_threat_intel"] = mod
spec.loader.exec_module(mod)

TestThreatIntel = mod.TestThreatIntel

__all__ = ["TestThreatIntel"]
