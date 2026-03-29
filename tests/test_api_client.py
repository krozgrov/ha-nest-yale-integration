"""Unit tests for Nest API client metadata helpers."""

from __future__ import annotations

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys
import types
import unittest

try:
    from google.protobuf.any_pb2 import Any  # noqa: F401
except Exception:
    HAS_PROTOBUF = False
else:
    HAS_PROTOBUF = True

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = REPO_ROOT / "custom_components"
MODULE_PATH = PACKAGE_ROOT / "nest_yale_lock" / "api_client.py"

custom_components_pkg = sys.modules.setdefault("custom_components", types.ModuleType("custom_components"))
custom_components_pkg.__path__ = [str(PACKAGE_ROOT)]

nest_pkg = sys.modules.setdefault(
    "custom_components.nest_yale_lock",
    types.ModuleType("custom_components.nest_yale_lock"),
)
nest_pkg.__path__ = [str(PACKAGE_ROOT / "nest_yale_lock")]

homeassistant_pkg = sys.modules.setdefault("homeassistant", types.ModuleType("homeassistant"))
helpers_pkg = sys.modules.setdefault("homeassistant.helpers", types.ModuleType("homeassistant.helpers"))
aiohttp_client_pkg = sys.modules.setdefault(
    "homeassistant.helpers.aiohttp_client",
    types.ModuleType("homeassistant.helpers.aiohttp_client"),
)
exceptions_pkg = sys.modules.setdefault(
    "homeassistant.exceptions",
    types.ModuleType("homeassistant.exceptions"),
)
aiohttp_pkg = sys.modules.setdefault("aiohttp", types.ModuleType("aiohttp"))
jwt_pkg = sys.modules.setdefault("jwt", types.ModuleType("jwt"))


class _ClientError(Exception):
    pass


class _ClientResponseError(_ClientError):
    def __init__(self, *args, status: int | None = None, message: str = "", headers=None, **kwargs):
        super().__init__(message or f"status={status}")
        self.status = status
        self.message = message
        self.headers = headers


class _ClientTimeout:
    def __init__(self, total=None):
        self.total = total


class _ClientSession:
    pass


def _async_get_clientsession(_hass):
    return None


class _ConfigEntryAuthFailed(Exception):
    pass


aiohttp_client_pkg.async_get_clientsession = _async_get_clientsession
exceptions_pkg.ConfigEntryAuthFailed = _ConfigEntryAuthFailed
homeassistant_pkg.helpers = helpers_pkg
helpers_pkg.aiohttp_client = aiohttp_client_pkg
homeassistant_pkg.exceptions = exceptions_pkg
aiohttp_pkg.ClientError = _ClientError
aiohttp_pkg.ClientResponseError = _ClientResponseError
aiohttp_pkg.ClientTimeout = _ClientTimeout
aiohttp_pkg.ClientSession = _ClientSession
jwt_pkg.decode = lambda *args, **kwargs: {}

SPEC = spec_from_file_location("custom_components.nest_yale_lock.api_client", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Unable to load API client from {MODULE_PATH}")
if HAS_PROTOBUF:
    API_CLIENT = module_from_spec(SPEC)
    sys.modules[SPEC.name] = API_CLIENT
    SPEC.loader.exec_module(API_CLIENT)

    NestAPIClient = API_CLIENT.NestAPIClient


class TestApiClientMetadata(unittest.TestCase):
    def setUp(self) -> None:
        if not HAS_PROTOBUF:
            self.skipTest("google.protobuf runtime is required")

    def _make_client(self) -> NestAPIClient:
        client = NestAPIClient.__new__(NestAPIClient)
        client._structure_id = "018C86E39308F29F"
        client.current_state = {
            "devices": {"locks": {}},
            "all_traits": {},
        }
        client.auth_data = {}
        return client

    def test_get_device_metadata_accepts_software_version_keys(self) -> None:
        client = self._make_client()
        client.current_state["devices"]["locks"]["DEVICE_1"] = {
            "device_id": "DEVICE_1",
            "serial_number": "SERIAL123",
            "softwareVersion": "1.2-7",
        }

        metadata = client.get_device_metadata("DEVICE_1")

        self.assertEqual("1.2-7", metadata["firmware_revision"])

    def test_get_device_metadata_falls_back_to_auth_data_software_version(self) -> None:
        client = self._make_client()
        client.current_state["devices"]["locks"]["DEVICE_1"] = {
            "device_id": "DEVICE_1",
            "serial_number": "SERIAL123",
        }
        client.auth_data = {
            "devices": [
                {
                    "device_id": "DEVICE_1",
                    "serial_number": "SERIAL123",
                    "softwareVersion": "1.2-7",
                }
            ]
        }

        metadata = client.get_device_metadata("DEVICE_1")

        self.assertEqual("1.2-7", metadata["firmware_revision"])


if __name__ == "__main__":
    unittest.main()
