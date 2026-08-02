"""Allow ``python -m rbw_qr_pinentry``."""

from __future__ import annotations

import sys

from rbw_qr_pinentry.pinentry import main

if __name__ == "__main__":
    sys.exit(main())
