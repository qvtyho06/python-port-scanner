"""Allow ``python -m port_scanner_project``."""

import sys

from .scanner import cli

sys.exit(cli())
