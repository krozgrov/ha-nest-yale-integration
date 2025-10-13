"""Nest Labs gateway protobuf package."""

from importlib import import_module

__all__ = ["gateway"]

# Lazily import the nested gateway package when available.
try:  # pragma: no cover - optional nested package
    gateway = import_module(".gateway", __name__)
except ModuleNotFoundError:
    gateway = None
