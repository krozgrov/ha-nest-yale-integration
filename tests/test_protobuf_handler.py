"""Unit tests for protobuf handler compatibility helpers."""

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
MODULE_PATH = PACKAGE_ROOT / "nest_yale_lock" / "protobuf_handler.py"

if HAS_PROTOBUF:
    custom_components_pkg = sys.modules.setdefault("custom_components", types.ModuleType("custom_components"))
    custom_components_pkg.__path__ = [str(PACKAGE_ROOT)]

    nest_pkg = sys.modules.setdefault(
        "custom_components.nest_yale_lock",
        types.ModuleType("custom_components.nest_yale_lock"),
    )
    nest_pkg.__path__ = [str(PACKAGE_ROOT / "nest_yale_lock")]

    SPEC = spec_from_file_location("custom_components.nest_yale_lock.protobuf_handler", MODULE_PATH)
    if SPEC is None or SPEC.loader is None:
        raise RuntimeError(f"Unable to load protobuf handler from {MODULE_PATH}")
    PROTOBUF_HANDLER = module_from_spec(SPEC)
    sys.modules[SPEC.name] = PROTOBUF_HANDLER
    SPEC.loader.exec_module(PROTOBUF_HANDLER)

    NestProtobufHandler = PROTOBUF_HANDLER.NestProtobufHandler


class TestProtobufHandler(unittest.TestCase):
    def setUp(self) -> None:
        if not HAS_PROTOBUF:
            self.skipTest("google.protobuf runtime is required")
        self.handler = NestProtobufHandler()

    def test_decode_device_identity_data_supports_camel_case_fields(self) -> None:
        class _Wrapper:
            def __init__(self, value):
                self.value = value

        class _Trait:
            serialNumber = "SERIAL123"
            fwVersion = "1.2.3"
            manufacturer = _Wrapper("Yale")
            modelName = _Wrapper("Nest x Yale")

            def HasField(self, name):
                return name in {"manufacturer", "modelName"}

        decoded = PROTOBUF_HANDLER._decode_device_identity_data(_Trait())

        self.assertEqual(
            {
                "serial_number": "SERIAL123",
                "firmware_version": "1.2.3",
                "manufacturer": "Yale",
                "model": "Nest x Yale",
            },
            decoded,
        )

    def test_decode_device_identity_data_supports_software_version_field(self) -> None:
        class _Wrapper:
            def __init__(self, value):
                self.value = value

        class _Trait:
            serialNumber = "SERIAL123"
            softwareVersion = "1.2-7"
            manufacturer = _Wrapper("Yale")
            modelName = _Wrapper("Nest x Yale")

            def HasField(self, name):
                return name in {"manufacturer", "modelName"}

        decoded = PROTOBUF_HANDLER._decode_device_identity_data(_Trait())

        self.assertEqual("1.2-7", decoded["firmware_version"])

    def test_apply_structure_info_trait_supports_camel_case_legacy_id(self) -> None:
        class _Structure:
            legacyId = "STRUCTURE.018C86E39308F29F"

        locks_data = {"yale": {}}

        self.handler._apply_structure_info_trait(
            "STRUCTURE_018C86E39308F29F",
            _Structure(),
            locks_data,
        )

        self.assertEqual("018C86E39308F29F", locks_data["structure_id"])

    def test_apply_bolt_lock_trait_supports_snake_case_fields(self) -> None:
        class _Timestamp:
            def ToJsonString(self):
                return "2026-03-28T13:00:00Z"

        class _Originator:
            resource_id = "USER_123"

        class _Actor:
            method = PROTOBUF_HANDLER.weave_security_pb2.BoltLockTrait.BOLT_LOCK_ACTOR_METHOD_PHYSICAL
            originator = _Originator()

        class _BoltLock:
            locked_state = PROTOBUF_HANDLER.weave_security_pb2.BoltLockTrait.BOLT_LOCKED_STATE_LOCKED
            actuator_state = PROTOBUF_HANDLER.weave_security_pb2.BoltLockTrait.BOLT_ACTUATOR_STATE_OK
            bolt_lock_actor = _Actor()
            locked_state_last_changed_at = _Timestamp()

            def HasField(self, name):
                return name == "locked_state_last_changed_at"

        locks_data = {"yale": {}, "user_id": None}

        self.handler._apply_bolt_lock_trait("DEVICE_1", _BoltLock(), locks_data)

        device = locks_data["yale"]["DEVICE_1"]
        self.assertTrue(device["bolt_locked"])
        self.assertFalse(device["bolt_moving"])
        self.assertEqual("Physical", device["last_action"])
        self.assertEqual("2026-03-28T13:00:00Z", device["last_action_timestamp"])
        self.assertEqual("USER_123", locks_data["user_id"])

    def test_apply_bolt_lock_settings_trait_supports_snake_case_fields(self) -> None:
        class _Duration:
            seconds = 60

        class _Settings:
            auto_relock_on = True
            auto_relock_duration = _Duration()

            def HasField(self, name):
                return name == "auto_relock_duration"

        locks_data = {"yale": {}}
        self.handler._apply_bolt_lock_settings_trait("DEVICE_1", _Settings(), locks_data)

        device = locks_data["yale"]["DEVICE_1"]
        self.assertTrue(device["auto_relock_on"])
        self.assertEqual(60, device["auto_relock_duration"])

    def test_apply_tamper_trait_supports_snake_case_fields(self) -> None:
        class _Tamper:
            tamper_state = 2

        locks_data = {"yale": {}}
        self.handler._apply_tamper_trait("DEVICE_1", _Tamper(), locks_data)

        device = locks_data["yale"]["DEVICE_1"]
        self.assertEqual(2, device["tamper_state"])
        self.assertTrue(device["tamper_detected"])
        self.assertEqual("Tampered", device["tamper"])


if __name__ == "__main__":
    unittest.main()
