"""Unit tests for passcode crypto helpers."""

from __future__ import annotations

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys
import unittest

MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "custom_components"
    / "nest_yale_lock"
    / "passcode_crypto.py"
)
SPEC = spec_from_file_location("passcode_crypto", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Unable to load passcode crypto from {MODULE_PATH}")
PASSCODE_CRYPTO = module_from_spec(SPEC)
sys.modules[SPEC.name] = PASSCODE_CRYPTO
SPEC.loader.exec_module(PASSCODE_CRYPTO)

parse_application_keys_trait = PASSCODE_CRYPTO.parse_application_keys_trait


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


class TestPasscodeCrypto(unittest.TestCase):
    def test_parse_application_keys_trait_collects_candidates(self) -> None:
        epoch_key = bytes([0x11] * 32)
        master_key = bytes([0x22] * 32)
        candidate_32 = bytes([0x33] * 32)
        candidate_36 = bytes([0x44] * 36)
        nested_32 = bytes([0x55] * 32)
        nested_36 = bytes([0x66] * 36)

        timestamp = _uint_field(1, 1)
        epoch_entry = b"".join(
            [
                _uint_field(1, 1),
                _len_field(2, timestamp),
                _len_field(3, epoch_key),
            ]
        )
        master_entry = b"".join(
            [
                _uint_field(1, 1234),
                _uint_field(2, 5),
                _len_field(3, master_key),
            ]
        )
        nested_unknown = b"".join(
            [
                _len_field(1, nested_32),
                _len_field(2, nested_36),
            ]
        )

        payload = b"".join(
            [
                _len_field(1, epoch_entry),
                _len_field(2, master_entry),
                _len_field(3, candidate_32),
                _len_field(4, candidate_36),
                _len_field(5, nested_unknown),
            ]
        )

        parsed = parse_application_keys_trait(payload)

        self.assertEqual(1, len(parsed["epoch_keys"]))
        self.assertEqual(1, parsed["epoch_keys"][0]["key_id"])
        self.assertEqual(epoch_key.hex(), parsed["epoch_keys"][0]["key_hex"])
        self.assertEqual(5, parsed["master_keys"][0]["application_group_short_id"])
        self.assertEqual(master_key.hex(), parsed["master_keys"][0]["key_hex"])

        candidate_hex_32 = {entry["key_hex"] for entry in parsed["candidate_keys_32"]}
        candidate_hex_36 = {entry["key_hex"] for entry in parsed["candidate_keys_36"]}
        self.assertTrue({candidate_32.hex(), nested_32.hex()}.issubset(candidate_hex_32))
        self.assertEqual({candidate_36.hex(), nested_36.hex()}, candidate_hex_36)

    def test_parse_application_keys_trait_empty_payload(self) -> None:
        parsed = parse_application_keys_trait(b"")
        self.assertEqual([], parsed["epoch_keys"])
        self.assertEqual([], parsed["master_keys"])
        self.assertEqual([], parsed["candidate_keys_32"])
        self.assertEqual([], parsed["candidate_keys_36"])

    def test_parse_application_keys_trait_collects_deep_nested_candidates(self) -> None:
        deep_32 = bytes([0x77] * 32)
        deep_36 = bytes([0x88] * 36)

        deep_nested = _len_field(1, _len_field(1, _len_field(1, deep_32) + _len_field(2, deep_36)))
        payload = b"".join(
            [
                _len_field(1, deep_nested),
                _len_field(2, deep_nested),
            ]
        )

        parsed = parse_application_keys_trait(payload)

        candidate_hex_32 = {entry["key_hex"] for entry in parsed["candidate_keys_32"]}
        candidate_hex_36 = {entry["key_hex"] for entry in parsed["candidate_keys_36"]}
        self.assertIn(deep_32.hex(), candidate_hex_32)
        self.assertIn(deep_36.hex(), candidate_hex_36)


if __name__ == "__main__":
    unittest.main()
