"""Точка входа SecCheck: запуск `sudo python3 main.py` (см. `python3 main.py --help`)."""

from __future__ import annotations

import sys

from ui.cli import main

if __name__ == "__main__":
    sys.exit(main())
