"""Unit tests for protobuf handler manual trait decoders."""

from __future__ import annotations

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys
import types
import unittest

try:
    from google.protobuf.any_pb2 import Any
except Exception:  # pragma: no cover - dependency may be unavailable in lightweight test envs
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


def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        part = value & 0x7F
        value >>= 7
        if value:
            out.append(part | 0x80)
        else:
            out.append(part)
            return bytes(out)


def _tag(field_number: int, wire_type: int) -> bytes:
    return _varint((field_number << 3) | wire_type)


def _len_field(field_number: int, payload: bytes) -> bytes:
    return _tag(field_number, 2) + _varint(len(payload)) + payload


def _uint_field(field_number: int, value: int) -> bytes:
    return _tag(field_number, 0) + _varint(value)


def _resource_id(value: str) -> bytes:
    return _len_field(1, value.encode("utf-8"))


class TestProtobufHandler(unittest.TestCase):
    def setUp(self) -> None:
        if not HAS_PROTOBUF:
            self.skipTest("google.protobuf runtime is required")
        self.handler = NestProtobufHandler()

    def test_trait_state_rank_label(self) -> None:
        self.assertEqual("confirmed", self.handler._trait_state_rank_label(1))
        self.assertEqual("accepted", self.handler._trait_state_rank_label(2))
        self.assertEqual("unranked", self.handler._trait_state_rank_label(0))
        self.assertEqual("unranked", self.handler._trait_state_rank_label(None))
        self.assertEqual("rank_7", self.handler._trait_state_rank_label(7))

    def test_decode_user_access_trait_payload(self) -> None:
        timestamp = b"".join(
            [
                _uint_field(1, 1_700_000_000),
                _uint_field(2, 123_000_000),
            ]
        )
        record = b"".join(
            [
                _len_field(1, _resource_id("GUEST_01957D1DC308C4AE")),
                _uint_field(2, 1),
                _len_field(3, _resource_id("DEVICE_00177A0000060303")),
                _len_field(4, timestamp),
            ]
        )

        decoded = self.handler._decode_user_access_trait_payload(_len_field(1, record))

        self.assertEqual(1, len(decoded["records"]))
        self.assertEqual("GUEST_01957D1DC308C4AE", decoded["records"][0]["user_id"])
        self.assertEqual("DEVICE_00177A0000060303", decoded["records"][0]["device_id"])
        self.assertEqual(1, decoded["records"][0]["access_type"])
        self.assertEqual(1_700_000_000, decoded["records"][0]["last_used_seconds"])
        self.assertEqual(123_000_000, decoded["records"][0]["last_used_nanos"])
        self.assertEqual("2023-11-14T22:13:20.123000Z", decoded["records"][0]["last_used_time"])

    def test_decode_basic_user_schedules_trait_payload(self) -> None:
        window = b"".join(
            [
                _uint_field(1, 1_700_000_000),
                _uint_field(2, 1_700_003_600),
            ]
        )
        schedule_value = b"".join(
            [
                _len_field(1, _resource_id("GUEST_01957D1DC308C4AE")),
                _len_field(3, _len_field(1, window)),
            ]
        )
        map_entry = b"".join(
            [
                _uint_field(1, 4),
                _len_field(2, schedule_value),
            ]
        )

        decoded = self.handler._decode_basic_user_schedules_trait_payload(_len_field(1, map_entry))

        self.assertEqual(1, len(decoded["schedules"]))
        self.assertEqual(4, decoded["schedules"][0]["slot"])
        self.assertEqual("GUEST_01957D1DC308C4AE", decoded["schedules"][0]["user_id"])
        self.assertEqual(1, decoded["schedules"][0]["schedule_count"])
        self.assertEqual(1_700_000_000, decoded["schedules"][0]["schedule_windows"][0]["start_seconds"])
        self.assertEqual(1_700_003_600, decoded["schedules"][0]["schedule_windows"][0]["end_seconds"])

    def test_parse_v2_observe_keeps_user_access_trait(self) -> None:
        any_msg = Any(
            type_url="type.googleapis.com/nest.trait.user.UserAccessTrait",
            value=_len_field(1, b""),
        )
        patch = _len_field(1, any_msg.SerializeToString())
        trait_id = b"".join(
            [
                _len_field(1, b"STRUCTURE_018C86E39308F29F"),
                _len_field(2, b"user_access_records"),
            ]
        )
        trait_state = b"".join(
            [
                _len_field(1, trait_id),
                _uint_field(2, 1),
                _len_field(3, patch),
            ]
        )
        inner = _len_field(3, trait_state)
        message = _len_field(1, inner)

        updates = self.handler._parse_v2_observe(message)

        self.assertIn("STRUCTURE_018C86E39308F29F", updates)
        self.assertIn(
            "nest.trait.user.UserAccessTrait",
            updates["STRUCTURE_018C86E39308F29F"],
        )

    def test_parse_v2_observe_keeps_accepted_and_confirmed_trait_entries(self) -> None:
        any_msg = Any(
            type_url="type.googleapis.com/nest.trait.guest.GuestsTrait",
            value=_len_field(1, b""),
        )
        patch = _len_field(1, any_msg.SerializeToString())
        trait_id = b"".join(
            [
                _len_field(1, b"STRUCTURE_018C86E39308F29F"),
                _len_field(2, b"guests"),
            ]
        )
        accepted_trait_state = b"".join(
            [
                _len_field(1, trait_id),
                _uint_field(2, 2),
                _len_field(3, patch),
            ]
        )
        confirmed_trait_state = b"".join(
            [
                _len_field(1, trait_id),
                _uint_field(2, 1),
                _len_field(3, patch),
            ]
        )
        inner = b"".join(
            [
                _len_field(3, accepted_trait_state),
                _len_field(3, confirmed_trait_state),
            ]
        )
        message = _len_field(1, inner)

        updates = self.handler._parse_v2_observe(message)

        entries = updates["STRUCTURE_018C86E39308F29F"]["nest.trait.guest.GuestsTrait"]
        self.assertEqual({1, 2}, {entry["rank"] for entry in entries})

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
