"""Unit tests for passcode helper utilities."""

from __future__ import annotations

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import unittest

MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "custom_components"
    / "nest_yale_lock"
    / "passcode_utils.py"
)
SPEC = spec_from_file_location("passcode_utils", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Unable to load passcode utils from {MODULE_PATH}")
PASSCODE_UTILS = module_from_spec(SPEC)
SPEC.loader.exec_module(PASSCODE_UTILS)

extract_guest_user_slots = PASSCODE_UTILS.extract_guest_user_slots
passcode_limits = PASSCODE_UTILS.passcode_limits
resolve_guest_user_id = PASSCODE_UTILS.resolve_guest_user_id
validate_guest_passcode = PASSCODE_UTILS.validate_guest_passcode
validate_guest_slot = PASSCODE_UTILS.validate_guest_slot


def _device_data() -> dict:
    return {
        "traits": {
            "UserPincodesCapabilitiesTrait": {
                "min_pincode_length": 4,
                "max_pincode_length": 8,
                "max_pincodes_supported": 3,
            },
            "UserPincodesSettingsTrait": {
                "user_pincodes": {
                    "2": {
                        "user_id": "USER_0002",
                        "enabled": True,
                        "has_passcode": True,
                    },
                    "1": {
                        "user_id": "USER_0001",
                        "enabled": False,
                        "has_passcode": False,
                    },
                }
            },
        }
    }


class TestPasscodeUtils(unittest.TestCase):
    def test_extract_guest_user_slots_sorted(self) -> None:
        slots = extract_guest_user_slots(_device_data())
        self.assertEqual([1, 2], list(slots.keys()))
        self.assertEqual("USER_0001", slots[1]["user_id"])
        self.assertFalse(slots[1]["enabled"])
        self.assertFalse(slots[1]["has_passcode"])

    def test_resolve_guest_user_id_prefers_explicit(self) -> None:
        resolved = resolve_guest_user_id("  USER_CUSTOM  ", slot=2, device_data=_device_data())
        self.assertEqual("USER_CUSTOM", resolved)

    def test_resolve_guest_user_id_from_slot(self) -> None:
        resolved = resolve_guest_user_id(None, slot=2, device_data=_device_data())
        self.assertEqual("USER_0002", resolved)

    def test_resolve_guest_user_id_requires_slot_or_id(self) -> None:
        with self.assertRaisesRegex(ValueError, "either guest_user_id or slot"):
            resolve_guest_user_id(None, slot=None, device_data=_device_data())

    def test_resolve_guest_user_id_missing_slot_mapping(self) -> None:
        with self.assertRaisesRegex(ValueError, "No user mapping"):
            resolve_guest_user_id(None, slot=3, device_data=_device_data())

    def test_resolve_guest_user_id_missing_user_id(self) -> None:
        data = _device_data()
        data["traits"]["UserPincodesSettingsTrait"]["user_pincodes"]["3"] = {
            "enabled": True,
            "has_passcode": True,
        }
        with self.assertRaisesRegex(ValueError, "has no user_id mapping"):
            resolve_guest_user_id(None, slot=3, device_data=data)

    def test_validate_guest_slot_accepts_none(self) -> None:
        validate_guest_slot(None, _device_data())

    def test_validate_guest_slot_rejects_non_positive(self) -> None:
        with self.assertRaisesRegex(ValueError, "positive integer"):
            validate_guest_slot(0, _device_data())

    def test_validate_guest_slot_rejects_over_max(self) -> None:
        with self.assertRaisesRegex(ValueError, "between 1 and 3"):
            validate_guest_slot(4, _device_data())

    def test_validate_guest_passcode_rejects_non_digits(self) -> None:
        with self.assertRaisesRegex(ValueError, "digits only"):
            validate_guest_passcode("12a4", _device_data(), default_min_len=4, default_max_len=8)

    def test_validate_guest_passcode_rejects_short(self) -> None:
        with self.assertRaisesRegex(ValueError, "between 4 and 8"):
            validate_guest_passcode("123", _device_data(), default_min_len=4, default_max_len=8)

    def test_validate_guest_passcode_accepts_valid(self) -> None:
        validate_guest_passcode("1234", _device_data(), default_min_len=4, default_max_len=8)

    def test_passcode_limits_falls_back_when_invalid_capabilities(self) -> None:
        data = _device_data()
        data["traits"]["UserPincodesCapabilitiesTrait"]["min_pincode_length"] = 9
        data["traits"]["UserPincodesCapabilitiesTrait"]["max_pincode_length"] = 4
        min_len, max_len = passcode_limits(data, default_min_len=4, default_max_len=8)
        self.assertEqual((4, 8), (min_len, max_len))


if __name__ == "__main__":
    unittest.main()
