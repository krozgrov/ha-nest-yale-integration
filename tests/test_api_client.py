"""Unit tests for Nest API client helper logic."""

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
    weave_security_pb2 = API_CLIENT.weave_security_pb2
    v1_pb2 = API_CLIENT.v1_pb2


class TestApiClientHelpers(unittest.TestCase):
    def setUp(self) -> None:
        if not HAS_PROTOBUF:
            self.skipTest("google.protobuf runtime is required")

    def _make_client(self) -> NestAPIClient:
        client = NestAPIClient.__new__(NestAPIClient)
        client._structure_id = "018C86E39308F29F"
        client.current_state = {
            "all_traits": {},
            "trait_labels": {
                "STRUCTURE_018C86E39308F29F": {
                    "weave.trait.security.UserPincodesSettingsTrait": "user_pincodes",
                }
            },
            "trait_states": {},
        }
        return client

    def test_extract_command_response_hints_collects_resource_ids_and_types(self) -> None:
        raw_data = (
            b"\x00type.googleapis.com/nest.trait.guest.GuestsTrait.CreateGuestResponse"
            b"\x00GUEST_01957D1DC308C4AE\x00DEVICE_00177A0000060303"
        )

        hints = NestAPIClient._extract_command_response_hints(raw_data)

        self.assertEqual(
            ["DEVICE_00177A0000060303", "GUEST_01957D1DC308C4AE"],
            hints["resource_ids"],
        )
        self.assertIn("CreateGuestResponse", hints["type_hints"])
        self.assertIn("GuestsTrait.CreateGuestResponse", hints["type_hints"])

    def test_summarize_send_command_response_extracts_operation_details(self) -> None:
        response = v1_pb2.SendCommandResponse()
        command_group = response.sendCommandResponse.add()
        command_group.resourceRequest.resourceId = "STRUCTURE_018C86E39308F29F"
        command_group.resourceRequest.requestId = "request-1"

        operation = command_group.traitOperations.add()
        operation.traitRequest.resourceId = "STRUCTURE_018C86E39308F29F"
        operation.traitRequest.traitLabel = "guests"
        operation.traitRequest.requestId = "request-1"
        operation.progress = 4
        operation.status.code = 0
        operation.status.message = "ok"
        operation.publisherAcceptedStateVersion = 321
        operation.command.traitRequest.resourceId = "STRUCTURE_018C86E39308F29F"
        operation.command.traitRequest.traitLabel = "guests"
        operation.command.command.type_url = (
            "type.googleapis.com/nest.trait.guest.GuestsTrait.CreateGuestResponse"
        )
        operation.command.command.value = b"\x00GUEST_019CF39791A93D05"
        detail = operation.status.details.add()
        detail.type_url = "type.googleapis.com/nest.trait.guest.GuestsTrait.CreateGuestResponse"
        detail.value = b"\x00GUEST_019CF39791A93D05"

        summary = NestAPIClient._summarize_send_command_response(
            response.SerializeToString()
        )

        self.assertEqual(1, len(summary["operations"]))
        self.assertEqual(
            "STRUCTURE_018C86E39308F29F",
            summary["operations"][0]["resource_id"],
        )
        self.assertEqual("guests", summary["operations"][0]["trait_label"])
        self.assertEqual("COMPLETE", summary["operations"][0]["progress"])
        self.assertEqual(321, summary["operations"][0]["publisher_accepted_state_version"])
        self.assertEqual(
            "type.googleapis.com/nest.trait.guest.GuestsTrait.CreateGuestResponse",
            summary["operations"][0]["command_type_url"],
        )
        self.assertEqual(
            ["GUEST_019CF39791A93D05"],
            summary["operations"][0]["command_resource_ids"],
        )
        self.assertEqual(
            ["type.googleapis.com/nest.trait.guest.GuestsTrait.CreateGuestResponse"],
            summary["operations"][0]["status_detail_types"],
        )
        self.assertEqual(
            ["GUEST_019CF39791A93D05"],
            summary["operations"][0]["status_detail_resource_ids"],
        )

    def test_snapshot_user_pincodes_collects_fingerprints(self) -> None:
        client = self._make_client()
        trait = weave_security_pb2.UserPincodesSettingsTrait()
        slot = trait.userPincodes[4]
        slot.userId.resourceId = "GUEST_01957D1DC308C4AE"
        slot.pincode = b"\x02\x01\x44\x00\x00abcdef"
        slot.pincodeCredentialEnabled.value = True
        client.current_state["trait_states"] = {
            "STRUCTURE_018C86E39308F29F": {
                "weave.trait.security.UserPincodesSettingsTrait": trait,
            }
        }

        snapshot = client._snapshot_user_pincodes("STRUCTURE_018C86E39308F29F")

        self.assertEqual(1, len(snapshot))
        self.assertEqual(4, snapshot[0]["slot"])
        self.assertEqual("GUEST_01957D1DC308C4AE", snapshot[0]["user_id"])
        self.assertTrue(snapshot[0]["has_passcode"])
        self.assertEqual(11, snapshot[0]["pincode_len"])
        self.assertIsInstance(snapshot[0]["pincode_fingerprint"], str)
        self.assertEqual(12, len(snapshot[0]["pincode_fingerprint"]))

    def test_diff_experimental_guest_snapshot_detects_new_guest_and_pincode_change(self) -> None:
        client = self._make_client()
        before = {
            "guests": [{"name": "Nelly", "guest_id": "GUEST_OLD"}],
            "user_access_records": [{"user_id": "GUEST_OLD"}],
            "structure_pincodes": [
                {
                    "slot": 3,
                    "user_id": "GUEST_OLD",
                    "enabled": True,
                    "has_passcode": True,
                    "pincode_fingerprint": "aaaabbbbcccc",
                }
            ],
            "device_pincodes": [],
        }
        after = {
            "guests": [
                {"name": "Nelly", "guest_id": "GUEST_OLD"},
                {"name": "Probe", "guest_id": "GUEST_NEW"},
            ],
            "user_access_records": [
                {"user_id": "GUEST_OLD"},
                {"user_id": "GUEST_NEW"},
            ],
            "structure_pincodes": [
                {
                    "slot": 3,
                    "user_id": "GUEST_OLD",
                    "enabled": True,
                    "has_passcode": True,
                    "pincode_fingerprint": "dddd1111eeee",
                },
                {
                    "slot": 4,
                    "user_id": "GUEST_NEW",
                    "enabled": True,
                    "has_passcode": True,
                    "pincode_fingerprint": "ffff2222gggg",
                },
            ],
            "device_pincodes": [],
        }

        diff = client._diff_experimental_guest_snapshot(
            before=before,
            after=after,
            guest_name="Probe",
        )

        self.assertTrue(diff["observable_change"])
        self.assertEqual(["GUEST_NEW"], diff["new_guest_ids"])
        self.assertEqual(["GUEST_NEW"], diff["new_user_access_ids"])
        self.assertEqual(["GUEST_NEW"], diff["matching_guest_ids_after"])
        self.assertEqual(1, len(diff["structure_pincode_diff"]["added"]))
        self.assertEqual(1, len(diff["structure_pincode_diff"]["changed"]))


if __name__ == "__main__":
    unittest.main()
