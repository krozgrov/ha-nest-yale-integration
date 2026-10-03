"""Tests for action actor and event data exposed to Home Assistant."""

from __future__ import annotations

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import unittest


MODULE_PATH = Path(__file__).resolve().parents[1] / "custom_components/nest_yale_lock/action.py"
SPEC = spec_from_file_location("nest_yale_action", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Unable to load action module from {MODULE_PATH}")
ACTION = module_from_spec(SPEC)
SPEC.loader.exec_module(ACTION)


class TestActionExposure(unittest.TestCase):
    def test_attributes_preserve_pin_slots_without_passcodes(self):
        device = {
            "last_action_user_id": "USER_CLEANER",
            "traits": {
                "UserPincodesSettingsTrait": {
                    "user_pincodes": {
                        "2": {"user_id": "USER_CLEANER", "has_passcode": True, "pincode": "1234"},
                        "7": {"user_id": "USER_GUEST", "enabled": False},
                        "8": {"user_id": None},
                    }
                }
            },
        }

        attrs = ACTION.last_action_attributes(device)

        self.assertEqual("USER_CLEANER", attrs["user_id"])
        self.assertEqual({"2": "USER_CLEANER", "7": "USER_GUEST"}, attrs["code_users"])
        self.assertNotIn("1234", str(attrs))

    def test_events_distinguish_repeated_actions_and_multiple_locks(self):
        previous = {
            "DEVICE_1": {"last_action_timestamp": "2026-09-25T10:00:00Z"},
            "DEVICE_2": {"last_action_timestamp": "2026-09-25T10:00:00Z"},
        }
        update = {
            "DEVICE_1": {
                "last_action": "Keypad",
                "last_action_user_id": "USER_CLEANER",
                "last_action_timestamp": "2026-09-25T10:01:00Z",
                "bolt_moving": False,
            },
            "DEVICE_2": {
                "last_action": "Keypad",
                "last_action_user_id": "USER_GUEST",
                "last_action_timestamp": "2026-09-25T10:00:00Z",
            },
        }

        events = ACTION.new_lock_action_events(update, previous)

        self.assertEqual([{
            "device_id": "DEVICE_1",
            "method": "Keypad",
            "user_id": "USER_CLEANER",
            "agent_id": None,
            "timestamp": "2026-09-25T10:01:00Z",
        }], events)
        self.assertEqual([], ACTION.new_lock_action_events(update, {"DEVICE_1": update["DEVICE_1"]}))
        self.assertEqual([], ACTION.new_lock_action_events(update, {}))

        second = {"DEVICE_1": {**update["DEVICE_1"], "last_action_timestamp": "2026-09-25T10:02:00Z"}}
        self.assertEqual(1, len(ACTION.new_lock_action_events(second, {"DEVICE_1": update["DEVICE_1"]})))

        second["DEVICE_1"]["bolt_moving"] = True
        self.assertEqual([], ACTION.new_lock_action_events(second, {"DEVICE_1": update["DEVICE_1"]}))
