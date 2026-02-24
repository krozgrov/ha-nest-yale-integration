"""Unit tests for passcode crypto helpers."""

from __future__ import annotations

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys
import unittest

try:
    import cryptography  # noqa: F401
except Exception:  # pragma: no cover - dependency may be unavailable in lightweight test envs
    HAS_CRYPTOGRAPHY = False
else:
    HAS_CRYPTOGRAPHY = True

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
derive_passcode_config2_keys = PASSCODE_CRYPTO.derive_passcode_config2_keys
encrypt_passcode_config2 = PASSCODE_CRYPTO.encrypt_passcode_config2
verify_encrypted_passcode_config2 = PASSCODE_CRYPTO.verify_encrypted_passcode_config2


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
    @unittest.skipUnless(HAS_CRYPTOGRAPHY, "cryptography dependency is required")
    def test_config2_authenticator_binds_key_id_header(self) -> None:
        key_id = 0x00004401
        nonce = 0x12345678
        client_root_key = bytes([0xA1] * 32)
        master_key = bytes([0xB2] * 32)
        enc_key, auth_key, fingerprint_key = derive_passcode_config2_keys(
            key_id=key_id,
            nonce=nonce,
            master_key=master_key,
            epoch_key=None,
            fabric_secret=None,
            client_root_key=client_root_key,
            service_root_key=None,
        )
        encrypted = bytearray(
            encrypt_passcode_config2(
                passcode="1234",
                key_id=key_id,
                nonce=nonce,
                enc_key=enc_key,
                auth_key=auth_key,
                fingerprint_key=fingerprint_key,
            )
        )

        tampered_key_id = 0x00004402
        encrypted[1:5] = tampered_key_id.to_bytes(4, "little")

        self.assertFalse(
            verify_encrypted_passcode_config2(
                encrypted_passcode=bytes(encrypted),
                key_id=tampered_key_id,
                enc_key=enc_key,
                auth_key=auth_key,
                fingerprint_key=fingerprint_key,
            )
        )

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

    def test_parse_application_keys_trait_keeps_epoch_key_without_id(self) -> None:
        epoch_key = bytes([0x99] * 32)
        timestamp = _uint_field(1, 1)
        epoch_entry = b"".join(
            [
                _len_field(2, timestamp),
                _len_field(3, epoch_key),
            ]
        )
        payload = _len_field(1, epoch_entry)

        parsed = parse_application_keys_trait(payload)

        self.assertEqual(1, len(parsed["epoch_keys"]))
        self.assertEqual(epoch_key.hex(), parsed["epoch_keys"][0]["key_hex"])
        self.assertNotIn("key_id", parsed["epoch_keys"][0])


if __name__ == "__main__":
    unittest.main()
