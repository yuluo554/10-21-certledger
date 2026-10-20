"""Entry point for ``python -m certledger``.

Both this and the ``certledger`` console script must go through the same
``certledger.cli.main``; having two entry points with different exit-code
semantics is a known drift source (see plan/02 §五).
"""

from __future__ import annotations

import sys

from certledger.cli import main

if __name__ == "__main__":
    sys.exit(main())
