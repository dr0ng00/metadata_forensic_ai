#!/usr/bin/env python3
"""
MetaForensicAI - Execution Wrapper

Primary launch commands:
    python forensicai.py
    python forensicai.py --gui
"""

import subprocess
import sys
from pathlib import Path

# Ensure root directory is in python path
root_dir = Path(__file__).parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))


def _launch_gui(argv: list[str]) -> int:
    """Launch the Streamlit GUI through the project wrapper."""
    app_path = root_dir / "app.py"
    streamlit_args = [arg for arg in argv if arg != "--gui"]
    cmd = [sys.executable, "-m", "streamlit", "run", str(app_path), *streamlit_args]
    return subprocess.call(cmd)


def _print_wrapper_help() -> None:
    print(
        "Usage:\n"
        "  python forensicai.py [CLI options]\n"
        "  python forensicai.py --gui [streamlit options]\n\n"
        "Examples:\n"
        "  python forensicai.py --image evidence.jpg\n"
        "  python forensicai.py --gui\n"
        "  python forensicai.py --gui --server.port 8502\n"
    )


try:
    from src.main import main
except ImportError:
    raise


if __name__ == "__main__":
    if "--gui" in sys.argv[1:]:
        try:
            sys.exit(_launch_gui(sys.argv[1:]))
        except KeyboardInterrupt:
            sys.exit(130)
    if any(arg in {"--wrapper-help", "--gui-help"} for arg in sys.argv[1:]):
        _print_wrapper_help()
        sys.exit(0)
    main()



