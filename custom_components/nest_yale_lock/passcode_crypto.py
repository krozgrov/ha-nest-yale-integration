"""Helpers for Weave/Nest passcode encryption (Config2)."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
from typing import Any

PASSCODE_CONFIG2 = 0x02
PASSCODE_PADDED_LEN = 16
PASSCODE_AUTH_LEN = 8
PASSCODE_FINGERPRINT_LEN = 8
PASSCODE_ENCRYPTED_LEN = 1 + 4 + 4 + PASSCODE_PADDED_LEN + PASSCODE_AUTH_LEN + PASSCODE_FINGERPRINT_LEN

PASSCODE_ENC_DIVERSIFIER = bytes.fromhex("1a655d96")
PASSCODE_FINGERPRINT_DIVERSIFIER = bytes.fromhex("d1a1d96c")
APP_INTERMEDIATE_DIVERSIFIER = bytes.fromhex("bcaa95ad")
FABRIC_ROOT_DIVERSIFIER = bytes.fromhex("21fa8f6a")
CLIENT_ROOT_DIVERSIFIER = bytes.fromhex("53e3ffe5")

ROOT_KEY_FABRIC = 0x00010000
ROOT_KEY_CLIENT = 0x00010400
ROOT_KEY_SERVICE = 0x00010800

KEY_TYPE_APP_STATIC = 0x00004000
KEY_TYPE_APP_ROTATING = 0x00005000
KEY_TYPE_APP_ROOT = 0x00010000

KEY_FLAG_USE_CURRENT_EPOCH = 0x80000000

KEY_MASK_TYPE = 0x0FFFF000
KEY_MASK_ROOT = 0x00000C00
KEY_MASK_EPOCH = 0x00000380
KEY_MASK_GROUP_LOCAL = 0x0000007F


class PasscodeCryptoError(RuntimeError):
    """Raised when passcode cryptographic material is missing/invalid."""


@dataclass(frozen=True)
class EncryptedPasscodeMetadata:
    """Header metadata carried in encrypted passcode bytes."""

    config: int
    key_id: int
    nonce: int


def _read_varint(data: bytes, pos: int) -> tuple[int | None, int]:
    value = 0
    shift = 0
    start = pos
    while pos < len(data):
        byte = data[pos]
        value |= (byte & 0x7F) << shift
        pos += 1
        if not (byte & 0x80):
            return value, pos
        shift += 7
        if shift >= 64 or (pos - start) >= 10:
            return None, pos
    return None, pos


def _read_length_delimited(data: bytes, pos: int) -> tuple[bytes | None, int]:
    length, pos = _read_varint(data, pos)
    if length is None:
        return None, pos
    end = pos + length
    if end > len(data):
        return None, pos
    return data[pos:end], end


def _skip_field(data: bytes, pos: int, wire_type: int) -> int:
    if wire_type == 0:
        _, pos = _read_varint(data, pos)
        return pos
    if wire_type == 1:
        return min(len(data), pos + 8)
    if wire_type == 2:
        length, pos = _read_varint(data, pos)
        if length is None:
            return len(data)
        return min(len(data), pos + length)
    if wire_type == 5:
        return min(len(data), pos + 4)
    return len(data)


def _decode_timestamp_seconds(payload: bytes) -> int | None:
    pos = 0
    seconds = None
    while pos < len(payload):
        tag, pos = _read_varint(payload, pos)
        if tag is None:
            break
        field = tag >> 3
        wire_type = tag & 0x07
        if field == 1 and wire_type == 0:
            value, pos = _read_varint(payload, pos)
            if value is not None:
                seconds = int(value)
            continue
        pos = _skip_field(payload, pos, wire_type)
    return seconds


def _decode_epoch_key(payload: bytes) -> dict[str, int | str] | None:
    pos = 0
    key_id = None
    start_time = None
    key_bytes = None
    while pos < len(payload):
        tag, pos = _read_varint(payload, pos)
        if tag is None:
            break
        field = tag >> 3
        wire_type = tag & 0x07
        if field == 1 and wire_type == 0:
            value, pos = _read_varint(payload, pos)
            if value is not None:
                key_id = int(value)
            continue
        if field == 2 and wire_type == 2:
            value, pos = _read_length_delimited(payload, pos)
            if value is None:
                break
            start_time = _decode_timestamp_seconds(value)
            continue
        if field == 3 and wire_type == 2:
            value, pos = _read_length_delimited(payload, pos)
            if value is None:
                break
            key_bytes = value
            continue
        pos = _skip_field(payload, pos, wire_type)

    if key_id is None or not key_bytes:
        return None
    result: dict[str, int | str] = {
        "key_id": key_id,
        "key_hex": key_bytes.hex(),
    }
    if start_time is not None:
        result["start_time"] = start_time
    return result


def _decode_master_key(payload: bytes) -> dict[str, int | str] | None:
    pos = 0
    global_id = None
    short_id = None
    key_bytes = None
    while pos < len(payload):
        tag, pos = _read_varint(payload, pos)
        if tag is None:
            break
        field = tag >> 3
        wire_type = tag & 0x07
        if field == 1 and wire_type == 0:
            value, pos = _read_varint(payload, pos)
            if value is not None:
                global_id = int(value)
            continue
        if field == 2 and wire_type == 0:
            value, pos = _read_varint(payload, pos)
            if value is not None:
                short_id = int(value)
            continue
        if field == 3 and wire_type == 2:
            value, pos = _read_length_delimited(payload, pos)
            if value is None:
                break
            key_bytes = value
            continue
        pos = _skip_field(payload, pos, wire_type)

    if short_id is None or not key_bytes:
        return None
    result: dict[str, int | str] = {
        "application_group_short_id": short_id,
        "key_hex": key_bytes.hex(),
    }
    if global_id is not None:
        result["application_group_global_id"] = global_id
    return result


def parse_application_keys_trait(payload: bytes) -> dict[str, list[dict[str, int | str]]]:
    """Decode weave.trait.auth.ApplicationKeysTrait from raw protobuf bytes."""
    decoded: dict[str, list[dict[str, int | str]]] = {
        "epoch_keys": [],
        "master_keys": [],
        "candidate_keys_32": [],
        "candidate_keys_36": [],
    }
    if not payload:
        return decoded

    candidate_32: set[str] = set()
    candidate_36: set[str] = set()

    def _record_candidate(value: bytes) -> None:
        if len(value) == 32:
            candidate_32.add(value.hex())
        elif len(value) == 36:
            candidate_36.add(value.hex())

    def _scan_length_delimited_keys(data: bytes) -> None:
        scan_pos = 0
        while scan_pos < len(data):
            scan_tag, scan_pos = _read_varint(data, scan_pos)
            if scan_tag is None:
                break
            scan_wire = scan_tag & 0x07
            if scan_wire != 2:
                scan_pos = _skip_field(data, scan_pos, scan_wire)
                continue
            scan_value, scan_pos = _read_length_delimited(data, scan_pos)
            if scan_value is None:
                break
            _record_candidate(scan_value)

    pos = 0
    while pos < len(payload):
        tag, pos = _read_varint(payload, pos)
        if tag is None:
            break
        field = tag >> 3
        wire_type = tag & 0x07
        if wire_type != 2:
            pos = _skip_field(payload, pos, wire_type)
            continue
        value, pos = _read_length_delimited(payload, pos)
        if value is None:
            break
        if field == 1:
            entry = _decode_epoch_key(value)
            if entry:
                decoded["epoch_keys"].append(entry)
        elif field == 2:
            entry = _decode_master_key(value)
            if entry:
                decoded["master_keys"].append(entry)
        else:
            _record_candidate(value)
            # Some variants can wrap key bytes in an unknown nested message.
            if len(value) not in (32, 36):
                _scan_length_delimited_keys(value)
    if candidate_32:
        decoded["candidate_keys_32"] = [{"key_hex": key_hex} for key_hex in sorted(candidate_32)]
    if candidate_36:
        decoded["candidate_keys_36"] = [{"key_hex": key_hex} for key_hex in sorted(candidate_36)]
    return decoded


def parse_encrypted_passcode_metadata(payload: bytes | None) -> EncryptedPasscodeMetadata | None:
    """Return encrypted passcode metadata if bytes look valid enough."""
    if not payload or len(payload) < 9:
        return None
    return EncryptedPasscodeMetadata(
        config=payload[0],
        key_id=int.from_bytes(payload[1:5], "little"),
        nonce=int.from_bytes(payload[5:9], "little"),
    )


def get_root_key_id(key_id: int) -> int:
    return KEY_TYPE_APP_ROOT | (key_id & KEY_MASK_ROOT)


def get_epoch_key_number(key_id: int) -> int:
    return (key_id & KEY_MASK_EPOCH) >> 7


def get_app_group_local_number(key_id: int) -> int:
    return key_id & KEY_MASK_GROUP_LOCAL


def is_app_rotating_key(key_id: int) -> bool:
    return (key_id & KEY_MASK_TYPE) == KEY_TYPE_APP_ROTATING


def uses_current_epoch_key(key_id: int) -> bool:
    return (key_id & KEY_FLAG_USE_CURRENT_EPOCH) != 0


def convert_to_static_app_key_id(key_id: int) -> int:
    return KEY_TYPE_APP_STATIC | ((get_root_key_id(key_id) | get_app_group_local_number(key_id)) & 0x0FFF)


def update_epoch_key_id(key_id: int, epoch_key_number: int) -> int:
    """Resolve a logical/current app key id to a concrete epoch key number."""
    return (key_id & ~(KEY_FLAG_USE_CURRENT_EPOCH | KEY_MASK_EPOCH)) | (
        (int(epoch_key_number) << 7) & KEY_MASK_EPOCH
    )


def _hkdf_sha1(
    salt: bytes | None,
    key_material_1: bytes,
    key_material_2: bytes,
    info: bytes,
    out_len: int,
) -> bytes:
    """RFC5869 HKDF-SHA1 with concatenated key material inputs."""
    if out_len <= 0:
        return b""
    h_len = hashlib.sha1().digest_size
    if not salt:
        salt = b"\x00" * h_len
    prk = hmac.new(salt, key_material_1 + key_material_2, hashlib.sha1).digest()

    output = bytearray()
    block = b""
    counter = 1
    while len(output) < out_len:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha1).digest()
        output.extend(block)
        counter += 1
    return bytes(output[:out_len])


def _derive_root_key(
    root_key_id: int,
    *,
    fabric_secret: bytes | None,
    client_root_key: bytes | None,
    service_root_key: bytes | None,
) -> bytes:
    if root_key_id == ROOT_KEY_CLIENT:
        if fabric_secret:
            return _hkdf_sha1(None, fabric_secret, b"", CLIENT_ROOT_DIVERSIFIER, 32)
        if client_root_key:
            return client_root_key
        raise PasscodeCryptoError("Client root key is required to derive passcode keys")

    if root_key_id == ROOT_KEY_FABRIC:
        if fabric_secret:
            return _hkdf_sha1(None, fabric_secret, b"", FABRIC_ROOT_DIVERSIFIER, 32)
        raise PasscodeCryptoError("Fabric secret is required to derive fabric root key")

    if root_key_id == ROOT_KEY_SERVICE:
        if service_root_key:
            return service_root_key
        raise PasscodeCryptoError("Service root key is required to derive passcode keys")

    raise PasscodeCryptoError(f"Unsupported root key id: 0x{root_key_id:08x}")


def derive_passcode_config2_keys(
    *,
    key_id: int,
    nonce: int,
    master_key: bytes,
    epoch_key: bytes | None,
    fabric_secret: bytes | None,
    client_root_key: bytes | None,
    service_root_key: bytes | None,
) -> tuple[bytes, bytes, bytes]:
    """Derive Config2 encryption/auth/fingerprint keys from Weave key material."""
    root_key_id = get_root_key_id(key_id)
    root_key = _derive_root_key(
        root_key_id,
        fabric_secret=fabric_secret,
        client_root_key=client_root_key,
        service_root_key=service_root_key,
    )

    if len(master_key) != 32:
        raise PasscodeCryptoError("Master key must be 32 bytes")

    if is_app_rotating_key(key_id):
        if not epoch_key or len(epoch_key) != 32:
            raise PasscodeCryptoError("Epoch key is required for rotating passcode key ids")
        base_key = _hkdf_sha1(None, root_key, epoch_key, APP_INTERMEDIATE_DIVERSIFIER, 32)
    else:
        base_key = root_key

    nonce_le = int(nonce & 0xFFFFFFFF).to_bytes(4, "little")
    enc_diversifier = PASSCODE_ENC_DIVERSIFIER + bytes([PASSCODE_CONFIG2])
    enc_auth = _hkdf_sha1(nonce_le, base_key, master_key, enc_diversifier, 36)
    enc_key = enc_auth[:16]
    auth_key = enc_auth[16:36]

    static_key_id = convert_to_static_app_key_id(key_id)
    static_root = _derive_root_key(
        get_root_key_id(static_key_id),
        fabric_secret=fabric_secret,
        client_root_key=client_root_key,
        service_root_key=service_root_key,
    )
    fingerprint_key = _hkdf_sha1(
        None,
        static_root,
        master_key,
        PASSCODE_FINGERPRINT_DIVERSIFIER,
        20,
    )
    return enc_key, auth_key, fingerprint_key


def encrypt_passcode_config2(
    *,
    passcode: str,
    key_id: int,
    nonce: int,
    enc_key: bytes,
    auth_key: bytes,
    fingerprint_key: bytes,
) -> bytes:
    """Build a Weave Config2 encrypted passcode payload (41 bytes)."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    if not isinstance(passcode, str):
        raise PasscodeCryptoError("Passcode must be a string")
    passcode_bytes = passcode.encode("ascii")
    if not passcode_bytes or len(passcode_bytes) > PASSCODE_PADDED_LEN:
        raise PasscodeCryptoError("Passcode length must be between 1 and 16 bytes")
    if len(enc_key) != 16:
        raise PasscodeCryptoError("Encryption key must be 16 bytes")
    if len(auth_key) != 20:
        raise PasscodeCryptoError("Auth key must be 20 bytes")
    if len(fingerprint_key) != 20:
        raise PasscodeCryptoError("Fingerprint key must be 20 bytes")

    padded_passcode = passcode_bytes + (b"\x00" * (PASSCODE_PADDED_LEN - len(passcode_bytes)))

    fingerprint_full = hmac.new(fingerprint_key, padded_passcode, hashlib.sha1).digest()
    fingerprint = fingerprint_full[:PASSCODE_FINGERPRINT_LEN]

    cipher = Cipher(algorithms.AES(enc_key), modes.ECB())
    encryptor = cipher.encryptor()
    encrypted_block = encryptor.update(padded_passcode) + encryptor.finalize()

    nonce_le = int(nonce & 0xFFFFFFFF).to_bytes(4, "little")
    auth_input = bytes([PASSCODE_CONFIG2]) + nonce_le + encrypted_block
    authenticator_full = hmac.new(auth_key, auth_input, hashlib.sha1).digest()
    authenticator = authenticator_full[:PASSCODE_AUTH_LEN]

    output = bytearray(PASSCODE_ENCRYPTED_LEN)
    output[0] = PASSCODE_CONFIG2
    output[1:5] = int(key_id & 0xFFFFFFFF).to_bytes(4, "little")
    output[5:9] = nonce_le
    output[9:25] = encrypted_block
    output[25:33] = authenticator
    output[33:41] = fingerprint
    return bytes(output)


def decrypt_passcode_config2(
    *,
    encrypted_passcode: bytes,
    key_id: int,
    enc_key: bytes,
    auth_key: bytes,
    fingerprint_key: bytes,
) -> str:
    """Decrypt and verify a Weave Config2 passcode payload."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    if len(encrypted_passcode) != PASSCODE_ENCRYPTED_LEN:
        raise PasscodeCryptoError(
            f"Encrypted passcode must be {PASSCODE_ENCRYPTED_LEN} bytes"
        )
    if encrypted_passcode[0] != PASSCODE_CONFIG2:
        raise PasscodeCryptoError("Unsupported passcode config")
    if int.from_bytes(encrypted_passcode[1:5], "little") != int(key_id & 0xFFFFFFFF):
        raise PasscodeCryptoError("Encrypted passcode key id mismatch")
    if len(enc_key) != 16:
        raise PasscodeCryptoError("Encryption key must be 16 bytes")
    if len(auth_key) != 20:
        raise PasscodeCryptoError("Auth key must be 20 bytes")
    if len(fingerprint_key) != 20:
        raise PasscodeCryptoError("Fingerprint key must be 20 bytes")

    nonce_le = encrypted_passcode[5:9]
    encrypted_block = encrypted_passcode[9:25]
    authenticator = encrypted_passcode[25:33]
    fingerprint = encrypted_passcode[33:41]

    auth_input = bytes([PASSCODE_CONFIG2]) + nonce_le + encrypted_block
    expected_auth = hmac.new(auth_key, auth_input, hashlib.sha1).digest()[:PASSCODE_AUTH_LEN]
    if not hmac.compare_digest(authenticator, expected_auth):
        raise PasscodeCryptoError("Encrypted passcode authenticator mismatch")

    cipher = Cipher(algorithms.AES(enc_key), modes.ECB())
    decryptor = cipher.decryptor()
    padded_passcode = decryptor.update(encrypted_block) + decryptor.finalize()

    expected_fingerprint = hmac.new(
        fingerprint_key, padded_passcode, hashlib.sha1
    ).digest()[:PASSCODE_FINGERPRINT_LEN]
    if not hmac.compare_digest(fingerprint, expected_fingerprint):
        raise PasscodeCryptoError("Encrypted passcode fingerprint mismatch")

    passcode_end = padded_passcode.find(b"\x00")
    if passcode_end < 0:
        passcode_end = len(padded_passcode)
    passcode_bytes = padded_passcode[:passcode_end]
    if not passcode_bytes:
        raise PasscodeCryptoError("Decrypted passcode is empty")
    try:
        return passcode_bytes.decode("ascii")
    except UnicodeDecodeError as err:
        raise PasscodeCryptoError("Decrypted passcode is not valid ASCII") from err


def decode_hex_bytes(value: Any, *, expected_len: int | None = None) -> bytes | None:
    """Decode optional hex input. Returns None for empty input."""
    if not isinstance(value, str):
        return None
    cleaned = value.strip().lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    if not cleaned:
        return None
    try:
        raw = bytes.fromhex(cleaned)
    except ValueError as err:
        raise PasscodeCryptoError(f"Invalid hex value: {value}") from err
    if expected_len is not None and len(raw) != expected_len:
        raise PasscodeCryptoError(
            f"Expected {expected_len} bytes but received {len(raw)} bytes"
        )
    return raw
