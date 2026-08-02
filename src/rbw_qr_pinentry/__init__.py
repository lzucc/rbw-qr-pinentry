"""rbw-qr-pinentry — QR-code pinentry for the rbw Bitwarden CLI."""

from __future__ import annotations

try:
    from importlib.metadata import PackageNotFoundError, version

    try:
        __version__ = version("rbw-qr-pinentry")
    except PackageNotFoundError:
        __version__ = "1.0.0"
except ImportError:  # pragma: no cover - Python < 3.8
    __version__ = "1.0.0"

__all__ = ["__version__"]
