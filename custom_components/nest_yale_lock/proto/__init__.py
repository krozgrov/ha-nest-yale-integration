"""Integration-local proto package without global aliasing.

This package exposes the generated protobuf modules under
`custom_components.nest_yale_lock.proto` only, avoiding any top-level
`proto` module alias that could clash with third-party libraries
such as the `proto` (proto-plus) package used by Google clients.
"""

from importlib import import_module
from pathlib import Path

PACKAGE_PATH = Path(__file__).resolve().parent

__all__ = ["PACKAGE_PATH", "const"]

try:
    const = import_module(".const", __name__)
except ModuleNotFoundError:  # optional helper module
    const = None
