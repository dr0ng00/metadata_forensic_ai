#!/usr/bin/env python3
"""
MetaForensicAI - Compatibility launcher
Allows running the CLI as:
    python forensic.py
"""

import sys
from pathlib import Path


root_dir = str(Path(__file__).parent)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from src.main import main


if __name__ == "__main__":
    main()
