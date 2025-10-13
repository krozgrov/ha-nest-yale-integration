"""Constants for working with local protobuf assets."""

from pathlib import Path

PACKAGE_PATH = Path(__file__).resolve().parent

# Default Observe payload filenames that ship with the integration.
OBSERVE_TRAITS_BIN = PACKAGE_PATH / "ObserveTraits.bin"
ALT_OBSERVE_TRAITS_BIN = PACKAGE_PATH / "aObserveTraits.bin"

__all__ = [
    "PACKAGE_PATH",
    "OBSERVE_TRAITS_BIN",
    "ALT_OBSERVE_TRAITS_BIN",
]
