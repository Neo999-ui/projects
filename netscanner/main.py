"""
NetPulse Pro - Main Application Entrypoint
Launches the Graphical User Interface (GUI) by default, or routes to CLI if flags are supplied.
"""

import sys
import os

from cli import main_cli
from gui import launch_gui


def main():
    """Main application entry point."""
    # Check if CLI flags were passed (e.g. -t, --target, --cli, --help, etc.)
    if len(sys.argv) > 1 and sys.argv[1] not in ["--gui", "-g"]:
        main_cli()
    else:
        launch_gui()


if __name__ == "__main__":
    main()
