"""Expose generated protobuf modules and helpers for the Nest Yale integration."""

from importlib import import_module
from pathlib import Path

PACKAGE_PATH = Path(__file__).resolve().parent

__all__ = ["PACKAGE_PATH", "const"]

try:
    const = import_module(".const", __name__)
except ModuleNotFoundError:  # pragma: no cover - optional helper module
    const = None
