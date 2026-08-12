#!/usr/bin/env python3
"""Repository-local entry point for the Control Plane CLI."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from regex_conformance_control_plane.cli import main

raise SystemExit(main())
