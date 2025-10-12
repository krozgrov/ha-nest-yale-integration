import asyncio
import logging
import os

_LOGGER = logging.getLogger(__name__)

async def read_protobuf_file(file_path):
    """Read a protobuf file asynchronously to prevent blocking the event loop."""
    if not os.path.exists(file_path):
        _LOGGER.error(f"Protobuf file not found: {file_path}")
        return None  # Return None if the file doesn't exist

    try:
        return await asyncio.to_thread(_read_protobuf, file_path)
    except Exception as e:
        _LOGGER.error(f"Error reading protobuf file {file_path}: {e}")
        return None  # Return None if there's an error

def _read_protobuf(file_path):
    """Actual file reading function (runs in a separate thread)."""
    with open(file_path, "rb") as f:
        return f.read()