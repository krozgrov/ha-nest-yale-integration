import logging
from google.protobuf.message import DecodeError
from google.protobuf.any_pb2 import Any
from base64 import b64decode
import binascii

from .proto.weave.trait import security_pb2 as weave_security_pb2
from .proto.nest.trait import structure_pb2 as nest_structure_pb2
from .proto.nest.trait import security_pb2 as nest_security_pb2
from .proto.nest.trait import located_pb2 as nest_located_pb2
from .proto.nest import rpc_pb2 as rpc_pb2
_LOGGER = logging.getLogger(__name__)

# Import HomeKit trait decoders
try:
    from .proto.weave.trait import description_pb2
    from .proto.weave.trait import power_pb2
    PROTO_AVAILABLE = True
except ImportError:
    PROTO_AVAILABLE = False
    _LOGGER.warning("HomeKit trait proto files not available - DeviceIdentityTrait and BatteryPowerSourceTrait decoding disabled")

MAX_BUFFER_SIZE = 4194304  # 4MB
CATALOG_THRESHOLD = 20000  # 20KB
_LOCK_TRAIT_HINTS = (
    "BoltLockTrait",
    "BoltLockSettingsTrait",
    "BoltLockCapabilitiesTrait",
    "TamperTrait",
    "PincodeInputTrait",
)

_NEST_TYPE_PREFIX = "type.nestlabs.com/"
_GOOGLE_TYPE_PREFIX = "type.googleapis.com/"

_V2_STATE_CONFIRMED = 1
_V2_STATE_ACCEPTED = 2

_USE_STREAMBODY_FALLBACK = False

_V2_TRAIT_CLASS_MAP = {
    "weave.trait.security.BoltLockTrait": weave_security_pb2.BoltLockTrait,
    "weave.trait.security.BoltLockSettingsTrait": weave_security_pb2.BoltLockSettingsTrait,
    "weave.trait.security.BoltLockCapabilitiesTrait": weave_security_pb2.BoltLockCapabilitiesTrait,
    "weave.trait.security.UserPincodesSettingsTrait": weave_security_pb2.UserPincodesSettingsTrait,
    "weave.trait.security.UserPincodesCapabilitiesTrait": weave_security_pb2.UserPincodesCapabilitiesTrait,
    "weave.trait.security.TamperTrait": weave_security_pb2.TamperTrait,
    "weave.trait.security.PincodeInputTrait": weave_security_pb2.PincodeInputTrait,
    "nest.trait.security.EnhancedBoltLockSettingsTrait": nest_security_pb2.EnhancedBoltLockSettingsTrait,
    "nest.trait.structure.StructureInfoTrait": nest_structure_pb2.StructureInfoTrait,
    "nest.trait.located.DeviceLocatedSettingsTrait": nest_located_pb2.DeviceLocatedSettingsTrait,
    "nest.trait.located.LocatedAnnotationsTrait": nest_located_pb2.LocatedAnnotationsTrait,
}

if PROTO_AVAILABLE:
    _V2_TRAIT_CLASS_MAP.update(
        {
            "weave.trait.description.DeviceIdentityTrait": description_pb2.DeviceIdentityTrait,
            "weave.trait.power.BatteryPowerSourceTrait": power_pb2.BatteryPowerSourceTrait,
        }
    )


def _normalize_any_type(any_message: Any) -> Any:
    """Map legacy Nest type URLs onto googleapis prefix so Unpack succeeds."""
    if not isinstance(any_message, Any):
        return any_message
    type_url = any_message.type_url or ""
    if type_url.startswith("type.nestlabs.com/"):
        normalized = Any()
        normalized.value = any_message.value
        normalized.type_url = type_url.replace("type.nestlabs.com/", "type.googleapis.com/", 1)
        return normalized
    return any_message


def _strip_type_prefix(type_url: str) -> str:
    if not type_url:
        return ""
    if type_url.startswith(_NEST_TYPE_PREFIX):
        return type_url[len(_NEST_TYPE_PREFIX):]
    if type_url.startswith(_GOOGLE_TYPE_PREFIX):
        return type_url[len(_GOOGLE_TYPE_PREFIX):]
    return type_url


def _pick_object_id(obj) -> str | None:
    """Best-effort object id for messages that populate key/uuid instead of id."""
    if obj is None:
        return None
    candidates = [
        getattr(obj, "id", None),
        getattr(obj, "key", None),
        getattr(obj, "uuid", None),
    ]
    for value in candidates:
        if isinstance(value, str) and value.startswith(("DEVICE_", "STRUCTURE_", "USER_")):
            return value
    for value in candidates:
        if isinstance(value, str) and value:
            return value
    return None


def _is_device_lock_id(object_id: str | None) -> bool:
    return isinstance(object_id, str) and object_id.startswith("DEVICE_")


class NestProtobufHandler:
    def __init__(self):
        self.buffer = bytearray()
        self.pending_length = None
        self.stream_body = rpc_pb2.StreamBody()
        self._decode_warned = False
        self._last_parse_failed_len = None
        self._last_parse_failed_head = None
        self._last_parse_failed_buffer_len = None

    def reset_stream_state(self):
        """Clear stream parsing buffers between connections."""
        self.buffer.clear()
        self.pending_length = None
        self.stream_body.Clear()
        # Allow DecodeError warnings again after a fresh connection
        self._decode_warned = False
        self._last_parse_failed_len = None
        self._last_parse_failed_head = None
        self._last_parse_failed_buffer_len = None

    def prepend_chunk(self, chunk: bytes):
        """Push a raw chunk back into the buffer so we can wait for more data."""
        if chunk:
            # Prepend while preserving any buffered bytes that already exist
            self.buffer = bytearray(chunk) + self.buffer

    def _decode_varint(self, buffer, pos):
        value = 0
        shift = 0
        start = pos
        max_bytes = 10
        while pos < len(buffer):
            byte = buffer[pos]
            value |= (byte & 0x7F) << shift
            pos += 1
            if not (byte & 0x80):
                _LOGGER.debug("Decoded varint: %s from position %s using %s bytes", value, start, pos - start)
                return value, pos
            shift += 7
            if shift >= 64 or pos - start >= max_bytes:
                _LOGGER.error("Varint too long at pos %s", start)
                return None, pos
        # Not enough bytes yet to decode the varint; wait for more data.
        _LOGGER.debug("Incomplete varint at pos %s; awaiting additional data", start)
        return None, start

    def _read_varint(self, data: bytes, pos: int):
        value = 0
        shift = 0
        start = pos
        max_bytes = 10
        while pos < len(data):
            byte = data[pos]
            value |= (byte & 0x7F) << shift
            pos += 1
            if not (byte & 0x80):
                return value, pos
            shift += 7
            if shift >= 64 or pos - start >= max_bytes:
                return None, pos
        return None, pos

    def _read_length_delimited(self, data: bytes, pos: int):
        length, pos = self._read_varint(data, pos)
        if length is None:
            return None, pos
        end = pos + length
        if end > len(data):
            return None, pos
        return data[pos:end], end

    def _skip_field(self, data: bytes, pos: int, wire_type: int):
        if wire_type == 0:
            _, pos = self._read_varint(data, pos)
            return pos
        if wire_type == 1:
            return min(len(data), pos + 8)
        if wire_type == 2:
            length, pos = self._read_varint(data, pos)
            if length is None:
                return len(data)
            return min(len(data), pos + length)
        if wire_type == 5:
            return min(len(data), pos + 4)
        return len(data)

    def _parse_v2_trait_id(self, data: bytes):
        resource_id = None
        trait_label = None
        pos = 0
        while pos < len(data):
            tag, pos = self._read_varint(data, pos)
            if tag is None:
                break
            field = tag >> 3
            wire_type = tag & 0x07
            if wire_type != 2:
                pos = self._skip_field(data, pos, wire_type)
                continue
            value, pos = self._read_length_delimited(data, pos)
            if value is None:
                break
            try:
                decoded = value.decode("utf-8")
            except Exception:
                decoded = None
            if field == 1:
                resource_id = decoded
            elif field == 2:
                trait_label = decoded
        return resource_id, trait_label

    def _parse_v2_patch_any(self, data: bytes):
        candidates = self._collect_patch_any_candidates(data, depth=2)
        if not candidates:
            return None

        def _score(candidate: Any) -> tuple[int, int, int]:
            descriptor = _strip_type_prefix(candidate.type_url)
            is_known = descriptor in _V2_TRAIT_CLASS_MAP or descriptor in {
                "weave.trait.description.LabelSettingsTrait",
                "nest.trait.located.CustomLocatedAnnotationsTrait",
            }
            has_value = bool(candidate.value)
            return (1 if is_known else 0, 1 if has_value else 0, len(candidate.value))

        return max(candidates, key=_score)

    def _collect_patch_any_candidates(self, payload: bytes, depth: int) -> list[Any]:
        candidates: list[Any] = []
        seen: set[tuple[str, bytes]] = set()

        def _scan(data: bytes, remaining_depth: int) -> None:
            pos = 0
            while pos < len(data):
                tag, pos = self._read_varint(data, pos)
                if tag is None:
                    break
                wire_type = tag & 0x07
                if wire_type != 2:
                    pos = self._skip_field(data, pos, wire_type)
                    continue

                value, pos = self._read_length_delimited(data, pos)
                if value is None:
                    break

                candidate = Any()
                try:
                    candidate.ParseFromString(value)
                except DecodeError:
                    candidate = None

                if candidate and candidate.type_url:
                    normalized = _normalize_any_type(candidate)
                    key = (normalized.type_url, normalized.value)
                    if key not in seen:
                        seen.add(key)
                        candidates.append(normalized)

                if remaining_depth > 0 and value:
                    _scan(value, remaining_depth - 1)

        _scan(payload, depth)
        return candidates

    def _parse_v2_trait_state(self, data: bytes):
        resource_id = None
        trait_label = None
        state_types = []
        any_msg = None
        pos = 0
        while pos < len(data):
            tag, pos = self._read_varint(data, pos)
            if tag is None:
                break
            field = tag >> 3
            wire_type = tag & 0x07
            if field == 1 and wire_type == 2:
                trait_id_bytes, pos = self._read_length_delimited(data, pos)
                if trait_id_bytes is None:
                    break
                resource_id, trait_label = self._parse_v2_trait_id(trait_id_bytes)
            elif field == 2 and wire_type == 0:
                value, pos = self._read_varint(data, pos)
                if value is not None:
                    state_types.append(int(value))
            elif field == 2 and wire_type == 2:
                packed, pos = self._read_length_delimited(data, pos)
                if packed is None:
                    break
                inner_pos = 0
                while inner_pos < len(packed):
                    value, inner_pos = self._read_varint(packed, inner_pos)
                    if value is None:
                        break
                    state_types.append(int(value))
            elif field == 3 and wire_type == 2:
                patch_bytes, pos = self._read_length_delimited(data, pos)
                if patch_bytes is None:
                    break
                any_msg = self._parse_v2_patch_any(patch_bytes)
            else:
                pos = self._skip_field(data, pos, wire_type)
        return {
            "resource_id": resource_id,
            "trait_label": trait_label,
            "state_types": state_types,
            "any_msg": any_msg,
        }

    def _parse_v2_inner(self, data: bytes, updates: dict):
        pos = 0
        while pos < len(data):
            tag, pos = self._read_varint(data, pos)
            if tag is None:
                break
            field = tag >> 3
            wire_type = tag & 0x07
            if field == 3 and wire_type == 2:
                trait_state_bytes, pos = self._read_length_delimited(data, pos)
                if trait_state_bytes is None:
                    break
                trait_state = self._parse_v2_trait_state(trait_state_bytes)
                resource_id = trait_state.get("resource_id")
                trait_label = trait_state.get("trait_label")
                any_msg = trait_state.get("any_msg")
                if not resource_id or not any_msg or not any_msg.type_url:
                    continue
                descriptor = _strip_type_prefix(any_msg.type_url)
                if not descriptor:
                    continue
                if (
                    descriptor != "weave.trait.description.LabelSettingsTrait"
                    and descriptor != "nest.trait.located.CustomLocatedAnnotationsTrait"
                    and descriptor not in _V2_TRAIT_CLASS_MAP
                ):
                    continue
                state_types = trait_state.get("state_types") or []
                state_ranks: list[int] = []
                if _V2_STATE_ACCEPTED in state_types:
                    state_ranks.append(_V2_STATE_ACCEPTED)
                if _V2_STATE_CONFIRMED in state_types:
                    state_ranks.append(_V2_STATE_CONFIRMED)
                if not state_ranks:
                    state_ranks = [0]
                trait_entries = updates.setdefault(resource_id, {}).setdefault(descriptor, [])
                for state_rank in state_ranks:
                    replaced = False
                    for idx, entry in enumerate(trait_entries):
                        if entry.get("rank") == state_rank:
                            trait_entries[idx] = {
                                "rank": state_rank,
                            "any_msg": any_msg,
                            "type_url": any_msg.type_url,
                            "trait_label": trait_label,
                        }
                        replaced = True
                        break
                    if replaced:
                        continue
                    trait_entries.append({
                        "rank": state_rank,
                        "any_msg": any_msg,
                        "type_url": any_msg.type_url,
                        "trait_label": trait_label,
                    })
                continue
            pos = self._skip_field(data, pos, wire_type)

    def _parse_v2_observe(self, message: bytes):
        updates = {}
        pos = 0
        while pos < len(message):
            tag, pos = self._read_varint(message, pos)
            if tag is None:
                return None
            field = tag >> 3
            wire_type = tag & 0x07
            if field == 1 and wire_type == 2:
                inner_bytes, pos = self._read_length_delimited(message, pos)
                if inner_bytes is None:
                    return None
                self._parse_v2_inner(inner_bytes, updates)
                continue
            pos = self._skip_field(message, pos, wire_type)
        return updates

    def _merge_trait_message(self, existing, incoming):
        if existing is None:
            return incoming
        if incoming is None:
            return existing
        if existing.__class__ is not incoming.__class__:
            return incoming
        merged = existing.__class__()
        merged.CopyFrom(existing)
        for field, value in incoming.ListFields():
            if field.label == field.LABEL_REPEATED:
                target = getattr(merged, field.name)
                target.clear()
                if self._is_map_field(field):
                    value_field = field.message_type.fields_by_name.get("value")
                    value_is_message = bool(
                        value_field and value_field.type == value_field.TYPE_MESSAGE
                    )
                    for map_key, map_value in value.items():
                        if value_is_message:
                            target[map_key].CopyFrom(map_value)
                        else:
                            target[map_key] = map_value
                elif field.type == field.TYPE_MESSAGE:
                    for item in value:
                        target.add().CopyFrom(item)
                else:
                    target.extend(list(value))
            elif field.type == field.TYPE_MESSAGE:
                getattr(merged, field.name).CopyFrom(value)
            else:
                setattr(merged, field.name, value)
        return merged

    @staticmethod
    def _is_map_field(field) -> bool:
        if field.label != field.LABEL_REPEATED or field.type != field.TYPE_MESSAGE:
            return False
        message_type = getattr(field, "message_type", None)
        if message_type is None:
            return False
        try:
            return bool(message_type.GetOptions().map_entry)
        except Exception:
            return False

    def _apply_bolt_lock_trait(self, obj_id, bolt_lock, locks_data):
        # Only publish bolt_locked when the stream explicitly reports LOCKED or UNLOCKED.
        locked_state = bolt_lock.lockedState
        bolt_locked_value = None
        if locked_state == weave_security_pb2.BoltLockTrait.BOLT_LOCKED_STATE_LOCKED:
            bolt_locked_value = True
        elif locked_state == weave_security_pb2.BoltLockTrait.BOLT_LOCKED_STATE_UNLOCKED:
            bolt_locked_value = False

        device = locks_data["yale"].setdefault(obj_id, {"device_id": obj_id})
        device["device_id"] = obj_id
        actuator_state = bolt_lock.actuatorState
        moving_states = {
            weave_security_pb2.BoltLockTrait.BOLT_ACTUATOR_STATE_LOCKING,
            weave_security_pb2.BoltLockTrait.BOLT_ACTUATOR_STATE_UNLOCKING,
            weave_security_pb2.BoltLockTrait.BOLT_ACTUATOR_STATE_MOVING,
        }
        device["actuator_state"] = actuator_state
        device["bolt_moving"] = actuator_state in moving_states
        if bolt_locked_value is not None:
            device["bolt_locked"] = bolt_locked_value
        else:
            _LOGGER.debug(
                "Skipping bolt_locked update for %s due to ambiguous lockedState=%s",
                obj_id,
                locked_state,
            )
        if bolt_lock.boltLockActor.originator.resourceId:
            locks_data["user_id"] = bolt_lock.boltLockActor.originator.resourceId

        # Capture last action (who/what caused the change).
        try:
            method = bolt_lock.boltLockActor.method
            method_map = {
                weave_security_pb2.BoltLockTrait.BOLT_LOCK_ACTOR_METHOD_PHYSICAL: "Physical",
                weave_security_pb2.BoltLockTrait.BOLT_LOCK_ACTOR_METHOD_KEYPAD_PIN: "Keypad",
                weave_security_pb2.BoltLockTrait.BOLT_LOCK_ACTOR_METHOD_VOICE_ASSISTANT: "Voice Assistant",
                weave_security_pb2.BoltLockTrait.BOLT_LOCK_ACTOR_METHOD_REMOTE_USER_EXPLICIT: "Remote",
                weave_security_pb2.BoltLockTrait.BOLT_LOCK_ACTOR_METHOD_REMOTE_USER_IMPLICIT: "Remote",
                weave_security_pb2.BoltLockTrait.BOLT_LOCK_ACTOR_METHOD_REMOTE_USER_OTHER: "Remote",
                weave_security_pb2.BoltLockTrait.BOLT_LOCK_ACTOR_METHOD_REMOTE_DELEGATE: "Remote",
            }
            device["last_action"] = method_map.get(method, "Other")
            device["last_action_method"] = int(method)
        except Exception:
            pass
        try:
            if bolt_lock.HasField("lockedStateLastChangedAt"):
                ts = bolt_lock.lockedStateLastChangedAt
                device["last_action_timestamp"] = ts.ToJsonString()
        except Exception:
            pass
        _LOGGER.debug(
            "Parsed BoltLockTrait for %s: %s, user_id=%s",
            obj_id,
            device,
            locks_data["user_id"],
        )

    def _apply_bolt_lock_settings_trait(self, obj_id, settings, locks_data):
        device = locks_data["yale"].setdefault(obj_id, {"device_id": obj_id})
        if hasattr(settings, "autoRelockOn"):
            device["auto_relock_on"] = bool(getattr(settings, "autoRelockOn", False))
        duration = getattr(settings, "autoRelockDuration", None)
        if settings.HasField("autoRelockDuration") and duration is not None:
            device["auto_relock_duration"] = int(getattr(duration, "seconds", 0) or 0)

    def _apply_bolt_lock_capabilities_trait(self, obj_id, caps, locks_data):
        device = locks_data["yale"].setdefault(obj_id, {"device_id": obj_id})
        max_dur = getattr(caps, "maxAutoRelockDuration", None)
        device["max_auto_relock_duration"] = int(getattr(max_dur, "seconds", 0) or 0) if max_dur else 0

    def _apply_tamper_trait(self, obj_id, tamper, locks_data):
        device = locks_data["yale"].setdefault(obj_id, {"device_id": obj_id})
        # tamperState enum: CLEAR=1, TAMPERED=2, UNKNOWN=3 (0=UNSPECIFIED)
        state_val = int(getattr(tamper, "tamperState", 0) or 0)
        device["tamper_state"] = state_val
        device["tamper"] = "Clear" if state_val == 1 else ("Tampered" if state_val == 2 else "Unknown")
        device["tamper_detected"] = state_val == 2

    def _apply_structure_info_trait(self, obj_id, structure, locks_data):
        if structure.legacy_id:
            legacy_id = structure.legacy_id
            parts = legacy_id.split(".")
            resolved = parts[-1] if len(parts) > 1 else legacy_id
            if "-" in resolved:
                locks_data["structure_id_v2"] = resolved
            else:
                locks_data["structure_id"] = resolved

        if obj_id.startswith("STRUCTURE_"):
            resolved = obj_id.replace("STRUCTURE_", "")
            if "-" in resolved:
                if not locks_data.get("structure_id_v2"):
                    locks_data["structure_id_v2"] = resolved
            else:
                if not locks_data.get("structure_id"):
                    locks_data["structure_id"] = resolved

    def _apply_label_settings_trait(self, obj_id, label_trait, locks_data):
        label = self._normalize_label_value(label_trait if isinstance(label_trait, str) else None)
        if not label:
            return
        device = locks_data["yale"].setdefault(obj_id, {"device_id": obj_id})
        device["label_name"] = label
        self._update_name_from_components(device)

    def _compose_lock_name(self, door_label: str | None, label_name: str | None) -> str | None:
        door = self._normalize_label_value(door_label)
        label = self._normalize_label_value(label_name)
        if door and label:
            if door.casefold() == label.casefold():
                return door
            return f"{door} ({label})"
        if door:
            return door
        if label:
            return label
        return None

    def _update_name_from_components(self, device: dict) -> None:
        if not isinstance(device, dict):
            return
        door_label = self._normalize_label_value(device.get("door_label"))
        label_name = self._normalize_label_value(device.get("label_name"))
        composed = self._compose_lock_name(door_label, label_name)
        if composed:
            device["name"] = composed

    def _annotation_id_variants(self, annotation_id: str | None) -> list[str]:
        base = self._normalize_label_value(annotation_id)
        if not base:
            return []

        variants: list[str] = [base]
        upper = base.upper()
        if upper not in variants:
            variants.append(upper)

        if not upper.startswith("ANNOTATION_"):
            return variants

        suffix = upper.split("ANNOTATION_", 1)[1]
        if len(suffix) != 16:
            return variants
        try:
            value = int(suffix, 16)
        except ValueError:
            return variants

        # Some payloads encode fixture IDs with a 0x01000000 flag in the low
        # 32 bits (for example ANNOTATION_0000000001000007). Try canonical
        # aliases so they resolve against the located annotation catalog.
        if suffix.startswith("0000000001") and value >= 0x01000000:
            canonical = value - 0x01000000
            alias = f"ANNOTATION_{canonical:016X}"
            if alias not in variants:
                variants.append(alias)

        return variants

    def _lookup_annotation_label(self, annotation_id: str | None, *maps: dict[str, str]) -> str | None:
        for candidate in self._annotation_id_variants(annotation_id):
            for mapping in maps:
                if not mapping:
                    continue
                value = mapping.get(candidate)
                normalized = self._normalize_label_value(value)
                if normalized:
                    return normalized
        return None

    def _is_door_fixture_type(self, located_settings) -> bool:
        try:
            if not hasattr(located_settings, "fixtureType") or not located_settings.HasField("fixtureType"):
                return False
            major = int(getattr(located_settings.fixtureType, "majorType", 0) or 0)
            door_major = int(
                getattr(
                    nest_located_pb2.LocatedTrait,
                    "LOCATED_MAJOR_FIXTURE_TYPE_DOOR",
                    1,
                )
                or 1
            )
            return major == door_major
        except Exception:
            return False

    def _door_label_from_fixture_type(self, located_settings) -> str | None:
        if not self._is_door_fixture_type(located_settings):
            return None
        try:
            minor = int(getattr(located_settings.fixtureType, "minorTypeDoor", 0) or 0)
        except Exception:
            return "Door"

        enum = nest_located_pb2.LocatedTrait
        garage_segmented = int(
            getattr(enum, "LOCATED_MINOR_FIXTURE_TYPE_DOOR_GARAGE_SEGMENTED", -1) or -1
        )
        garage_single = int(
            getattr(enum, "LOCATED_MINOR_FIXTURE_TYPE_DOOR_GARAGE_SINGLE_PANEL", -1) or -1
        )
        french = int(getattr(enum, "LOCATED_MINOR_FIXTURE_TYPE_DOOR_FRENCH", -1) or -1)
        sliding = int(getattr(enum, "LOCATED_MINOR_FIXTURE_TYPE_DOOR_SLIDING", -1) or -1)
        hinged = int(getattr(enum, "LOCATED_MINOR_FIXTURE_TYPE_DOOR_HINGED", -1) or -1)

        if minor in (garage_segmented, garage_single):
            return "Garage door"
        if minor == french:
            return "French door"
        if minor == sliding:
            return "Sliding door"
        if minor == hinged:
            return "Door"
        return "Door"

    def _normalize_door_label(self, value: str | None, *, is_door_fixture: bool) -> str | None:
        label = self._normalize_label_value(value)
        if not label:
            return None
        if not is_door_fixture:
            return label
        low = label.casefold()
        if "door" in low:
            return label
        if low in {"garage", "front", "side", "back"}:
            return f"{label} door"
        return label

    @staticmethod
    def _normalize_label_value(value: str | None) -> str | None:
        if not isinstance(value, str):
            return None
        value = value.strip()
        if not value or value.lower() == "undefined":
            return None
        return value

    def _extract_where_map(self, located) -> dict[str, str]:
        where_map: dict[str, str] = {}
        for field_name in ("annotations", "custom_annotations"):
            annotations = getattr(located, field_name, None)
            if not annotations:
                continue
            for annotation in annotations:
                info = getattr(annotation, "info", None)
                if not info:
                    continue
                id_field = getattr(info, "id", None)
                name_field = getattr(info, "name", None)
                where_id = getattr(id_field, "value", None) if id_field else None
                where_name = getattr(name_field, "value", None) if name_field else None
                if isinstance(where_id, str):
                    where_id = where_id.strip()
                if isinstance(where_name, str):
                    where_name = where_name.strip()
                if not where_id or not where_name:
                    continue
                if where_name.lower() == "undefined":
                    continue
                where_map[where_id] = where_name
        return where_map

    def _decode_label_settings(self, payload: bytes) -> str | None:
        pos = 0
        while pos < len(payload):
            tag, pos = self._read_varint(payload, pos)
            if tag is None:
                return None
            field = tag >> 3
            wire_type = tag & 0x07
            if field == 1 and wire_type == 2:
                value, pos = self._read_length_delimited(payload, pos)
                if value is None:
                    return None
                indirect = self._normalize_label_value(self._decode_string_ref(value))
                if indirect:
                    return indirect
                try:
                    direct = self._normalize_label_value(value.decode("utf-8"))
                except Exception:
                    direct = None
                if direct:
                    return direct
            pos = self._skip_field(payload, pos, wire_type)

        for candidate in self._scan_text_candidates(payload, depth=2):
            if self._is_probable_label(candidate):
                return candidate
        return None

    @staticmethod
    def _is_probable_label(value: str | None) -> bool:
        if not isinstance(value, str):
            return False
        if len(value) > 80:
            return False
        if value.startswith(
            (
                "type.googleapis.com/",
                "type.nestlabs.com/",
                "weave.",
                "nest.",
                "google.",
                "proto.",
                "DEVICE_",
                "STRUCTURE_",
                "USER_",
                "GUEST_",
                "ANNOTATION_",
            )
        ):
            return False
        if not any(ch.isalpha() for ch in value):
            return False
        return all(ch.isprintable() for ch in value)

    def _scan_text_candidates(self, payload: bytes, depth: int) -> list[str]:
        results: list[str] = []
        seen: set[str] = set()

        def _scan(data: bytes, remaining_depth: int) -> None:
            pos = 0
            while pos < len(data):
                tag, pos = self._read_varint(data, pos)
                if tag is None:
                    break
                wire_type = tag & 0x07
                if wire_type != 2:
                    pos = self._skip_field(data, pos, wire_type)
                    continue

                value, pos = self._read_length_delimited(data, pos)
                if value is None:
                    break

                try:
                    text = value.decode("utf-8")
                except Exception:
                    text = None
                normalized = self._normalize_label_value(text) if text else None
                if normalized and normalized not in seen:
                    seen.add(normalized)
                    results.append(normalized)

                if remaining_depth > 0 and value:
                    _scan(value, remaining_depth - 1)

        _scan(payload, depth)
        return results

    def _decode_label_settings_any(self, any_msg: Any) -> str | None:
        if (
            any_msg
            and any_msg.value
            and PROTO_AVAILABLE
            and hasattr(description_pb2, "LabelSettingsTrait")
        ):
            trait = description_pb2.LabelSettingsTrait()
            normalized_any = _normalize_any_type(any_msg)
            try:
                unpacked = normalized_any.Unpack(trait)
            except DecodeError:
                unpacked = False
            if unpacked:
                raw_label = getattr(trait, "label", None)
                label = self._normalize_label_value(raw_label)
                if not label and hasattr(raw_label, "value"):
                    label = self._normalize_label_value(getattr(raw_label, "value", None))
                if label:
                    return label
        if any_msg and any_msg.value:
            return self._normalize_label_value(self._decode_label_settings(any_msg.value))
        return None

    def _decode_string_ref(self, payload: bytes) -> str | None:
        pos = 0
        while pos < len(payload):
            tag, pos = self._read_varint(payload, pos)
            if tag is None:
                return None
            field = tag >> 3
            wire_type = tag & 0x07
            if field == 1 and wire_type == 2:
                value, pos = self._read_length_delimited(payload, pos)
                if value is None:
                    return None
                try:
                    return value.decode("utf-8")
                except Exception:
                    return None
            pos = self._skip_field(payload, pos, wire_type)
        return None

    def _decode_resource_id(self, payload: bytes) -> str | None:
        pos = 0
        while pos < len(payload):
            tag, pos = self._read_varint(payload, pos)
            if tag is None:
                return None
            field = tag >> 3
            wire_type = tag & 0x07
            if field == 1 and wire_type == 2:
                value, pos = self._read_length_delimited(payload, pos)
                if value is None:
                    return None
                try:
                    return value.decode("utf-8")
                except Exception:
                    return None
            pos = self._skip_field(payload, pos, wire_type)
        return None

    def _decode_device_located_payload(
        self,
        payload: bytes,
    ) -> tuple[str | None, str | None, str | None, str | None]:
        where_label = None
        fixture_label = None
        where_id = None
        fixture_id = None
        pos = 0
        while pos < len(payload):
            tag, pos = self._read_varint(payload, pos)
            if tag is None:
                break
            field = tag >> 3
            wire_type = tag & 0x07
            if field in (2, 3) and wire_type == 2:
                value, pos = self._read_length_delimited(payload, pos)
                if value is None:
                    break
                decoded = self._decode_resource_id(value)
                if decoded:
                    if field == 2:
                        where_id = decoded
                    else:
                        fixture_id = decoded
                continue
            if field in (5, 7) and wire_type == 2:
                value, pos = self._read_length_delimited(payload, pos)
                if value is None:
                    break
                label = self._decode_string_ref(value)
                if label:
                    if field == 5:
                        where_label = label
                    elif field == 7:
                        fixture_label = label
                continue
            pos = self._skip_field(payload, pos, wire_type)

        if not where_id or not fixture_id or not where_label or not fixture_label:
            ids, labels = self._scan_located_strings(payload)
            if not where_id and ids:
                where_id = ids[0]
            if not fixture_id and len(ids) > 1:
                fixture_id = ids[1]
            if not where_label and labels:
                where_label = labels[0]
            if not fixture_label and len(labels) > 1:
                fixture_label = labels[1]
        return where_label, fixture_label, where_id, fixture_id

    def _scan_located_strings(self, payload: bytes) -> tuple[list[str], list[str]]:
        ids: list[str] = []
        labels: list[str] = []
        pos = 0
        while pos < len(payload):
            tag, pos = self._read_varint(payload, pos)
            if tag is None:
                break
            wire_type = tag & 0x07
            if wire_type == 2:
                value, pos = self._read_length_delimited(payload, pos)
                if value is None:
                    break
                try:
                    text = value.decode("utf-8").strip()
                except Exception:
                    text = ""
                if not text:
                    continue
                if text.startswith("ANNOTATION_"):
                    if text not in ids:
                        ids.append(text)
                    continue
                if text.lower() == "undefined":
                    continue
                if text not in labels:
                    labels.append(text)
                continue
            pos = self._skip_field(payload, pos, wire_type)
        return ids, labels

    def _decode_custom_located_map_entry(self, payload: bytes) -> bytes | None:
        pos = 0
        value_payload = None
        while pos < len(payload):
            tag, pos = self._read_varint(payload, pos)
            if tag is None:
                break
            field = tag >> 3
            wire_type = tag & 0x07
            if field == 2 and wire_type == 2:
                value_payload, pos = self._read_length_delimited(payload, pos)
                continue
            pos = self._skip_field(payload, pos, wire_type)
        return value_payload

    def _decode_custom_where_item(self, payload: bytes) -> tuple[str | None, str | None]:
        where_id = None
        label = None
        pos = 0
        while pos < len(payload):
            tag, pos = self._read_varint(payload, pos)
            if tag is None:
                break
            field = tag >> 3
            wire_type = tag & 0x07
            if field == 1 and wire_type == 2:
                value, pos = self._read_length_delimited(payload, pos)
                if value is None:
                    break
                label = self._decode_string_ref(value)
                continue
            if field == 3 and wire_type == 2:
                value, pos = self._read_length_delimited(payload, pos)
                if value is None:
                    break
                where_id = self._decode_resource_id(value)
                continue
            pos = self._skip_field(payload, pos, wire_type)
        return self._normalize_label_value(where_id), self._normalize_label_value(label)

    def _decode_custom_fixture_item(self, payload: bytes) -> tuple[str | None, str | None]:
        fixture_id = None
        label = None
        pos = 0
        while pos < len(payload):
            tag, pos = self._read_varint(payload, pos)
            if tag is None:
                break
            field = tag >> 3
            wire_type = tag & 0x07
            if field == 1 and wire_type == 2:
                value, pos = self._read_length_delimited(payload, pos)
                if value is None:
                    break
                label = self._decode_string_ref(value)
                continue
            if field == 2 and wire_type == 2:
                value, pos = self._read_length_delimited(payload, pos)
                if value is None:
                    break
                fixture_id = self._decode_resource_id(value)
                continue
            pos = self._skip_field(payload, pos, wire_type)
        return self._normalize_label_value(fixture_id), self._normalize_label_value(label)

    def _decode_custom_located_annotations(self, payload: bytes) -> tuple[dict[str, str], dict[str, str]]:
        fixtures: dict[str, str] = {}
        wheres: dict[str, str] = {}
        pos = 0
        while pos < len(payload):
            tag, pos = self._read_varint(payload, pos)
            if tag is None:
                break
            field = tag >> 3
            wire_type = tag & 0x07
            if field in (1, 2) and wire_type == 2:
                entry, pos = self._read_length_delimited(payload, pos)
                if entry is None:
                    break
                value_payload = self._decode_custom_located_map_entry(entry)
                if not value_payload:
                    continue
                if field == 1:
                    where_id, label = self._decode_custom_where_item(value_payload)
                    if where_id and label:
                        wheres[where_id] = label
                else:
                    fixture_id, label = self._decode_custom_fixture_item(value_payload)
                    if fixture_id and label:
                        fixtures[fixture_id] = label
                continue
            pos = self._skip_field(payload, pos, wire_type)
        return fixtures, wheres

    def _process_v2_observe(self, message: bytes):
        updates = self._parse_v2_observe(message)
        if not updates:
            return None

        locks_data = {
            "yale": {},
            "user_id": None,
            "structure_id": None,
            "structure_id_v2": None,
            "all_traits": {},
            "trait_states": {},
        }
        all_traits = {}
        trait_states = {}
        trait_labels = {}
        lock_device_ids = set()
        where_map: dict[str, str] = {}
        custom_where_map: dict[str, str] = {}
        fixture_map: dict[str, str] = {}
        device_wheres: dict[str, str] = {}
        device_fixtures: dict[str, str] = {}

        for obj_id, trait_map in updates.items():
            if not obj_id:
                continue
            if obj_id.startswith("STRUCTURE_"):
                resolved = obj_id.replace("STRUCTURE_", "")
                if "-" in resolved:
                    if not locks_data.get("structure_id_v2"):
                        locks_data["structure_id_v2"] = resolved
                else:
                    if not locks_data.get("structure_id"):
                        locks_data["structure_id"] = resolved
            if obj_id.startswith("USER_"):
                locks_data["user_id"] = obj_id

            is_lock = False
            if isinstance(trait_map, dict):
                for descriptor in trait_map.keys():
                    if any(hint in descriptor for hint in _LOCK_TRAIT_HINTS):
                        is_lock = True
                        break

            for descriptor_name, entries in trait_map.items():
                if isinstance(entries, dict):
                    entries = [entries]
                if not entries:
                    continue

                if descriptor_name == "weave.trait.description.LabelSettingsTrait":
                    label = None
                    for entry in sorted(entries, key=lambda item: item.get("rank", 0)):
                        any_msg = entry.get("any_msg")
                        if not any_msg or not any_msg.value:
                            continue
                        label = self._decode_label_settings_any(any_msg)
                        if label:
                            break
                    if label:
                        type_url = ""
                        for entry in entries:
                            if entry.get("type_url"):
                                type_url = entry["type_url"]
                                break
                        if not type_url:
                            type_url = "type.googleapis.com/weave.trait.description.LabelSettingsTrait"
                        trait_key = f"{obj_id}:{type_url}"
                        all_traits[trait_key] = {
                            "object_id": obj_id,
                            "type_url": type_url,
                            "decoded": True,
                            "data": {"label": label},
                        }
                        if is_lock:
                            self._apply_label_settings_trait(obj_id, label, locks_data)
                    continue

                if descriptor_name == "nest.trait.located.CustomLocatedAnnotationsTrait":
                    for entry in sorted(entries, key=lambda item: item.get("rank", 0)):
                        any_msg = entry.get("any_msg")
                        if not any_msg or not any_msg.value:
                            continue
                        fixtures, wheres = self._decode_custom_located_annotations(any_msg.value)
                        if fixtures:
                            fixture_map.update(fixtures)
                        if wheres:
                            custom_where_map.update(wheres)
                    continue

                trait_cls = _V2_TRAIT_CLASS_MAP.get(descriptor_name)
                if not trait_cls:
                    continue

                merged_msg = None
                merged_type_url = ""
                located_payload = None
                prefer_confirmed = descriptor_name != "weave.trait.security.BoltLockTrait"
                for entry in sorted(
                    entries,
                    key=lambda item: item.get("rank", 0),
                    reverse=prefer_confirmed,
                ):
                    any_msg = entry.get("any_msg")
                    if not any_msg:
                        continue
                    if located_payload is None and any_msg.value:
                        located_payload = any_msg.value
                    normalized_any = _normalize_any_type(any_msg)
                    trait_msg = trait_cls()
                    try:
                        unpacked = normalized_any.Unpack(trait_msg)
                    except DecodeError:
                        continue
                    if not unpacked:
                        continue
                    merged_msg = self._merge_trait_message(merged_msg, trait_msg)
                    if not merged_type_url:
                        merged_type_url = normalized_any.type_url or entry.get("type_url") or ""

                if merged_msg is None:
                    continue
                type_url = merged_type_url
                if not type_url:
                    type_url = f"type.googleapis.com/{descriptor_name}"
                entry_label = None
                for entry in entries:
                    if entry.get("trait_label"):
                        entry_label = entry["trait_label"]
                        break
                if entry_label:
                    trait_labels.setdefault(obj_id, {})[descriptor_name] = entry_label

                trait_states.setdefault(obj_id, {})[descriptor_name] = merged_msg

                if "BoltLockTrait" in descriptor_name:
                    if not _is_device_lock_id(obj_id):
                        continue
                    lock_device_ids.add(obj_id)
                    self._apply_bolt_lock_trait(obj_id, merged_msg, locks_data)
                elif "BoltLockSettingsTrait" in descriptor_name or "EnhancedBoltLockSettingsTrait" in descriptor_name:
                    if not _is_device_lock_id(obj_id):
                        continue
                    lock_device_ids.add(obj_id)
                    self._apply_bolt_lock_settings_trait(obj_id, merged_msg, locks_data)
                elif "BoltLockCapabilitiesTrait" in descriptor_name:
                    if not _is_device_lock_id(obj_id):
                        continue
                    lock_device_ids.add(obj_id)
                    self._apply_bolt_lock_capabilities_trait(obj_id, merged_msg, locks_data)
                elif "UserPincodesCapabilitiesTrait" in descriptor_name:
                    if not _is_device_lock_id(obj_id):
                        continue
                    lock_device_ids.add(obj_id)
                    trait_key = f"{obj_id}:{type_url}"
                    all_traits[trait_key] = {
                        "object_id": obj_id,
                        "type_url": type_url,
                        "decoded": True,
                        "data": {
                            "min_pincode_length": int(getattr(merged_msg, "minPincodeLength", 0) or 0),
                            "max_pincode_length": int(getattr(merged_msg, "maxPincodeLength", 0) or 0),
                            "max_pincodes_supported": int(getattr(merged_msg, "maxPincodesSupported", 0) or 0),
                        },
                    }
                elif "UserPincodesSettingsTrait" in descriptor_name:
                    if not _is_device_lock_id(obj_id):
                        continue
                    lock_device_ids.add(obj_id)
                    sanitized_pincodes = {}
                    try:
                        for slot, user_pincode in merged_msg.userPincodes.items():
                            user_id = None
                            if user_pincode.HasField("userId"):
                                user_id = getattr(user_pincode.userId, "resourceId", None)
                            enabled = None
                            if user_pincode.HasField("pincodeCredentialEnabled"):
                                enabled = bool(user_pincode.pincodeCredentialEnabled.value)
                            has_passcode = bool(getattr(user_pincode, "pincode", b""))
                            sanitized_pincodes[str(int(slot))] = {
                                "user_id": user_id,
                                "enabled": enabled,
                                "has_passcode": has_passcode,
                            }
                    except Exception:
                        sanitized_pincodes = {}
                    trait_key = f"{obj_id}:{type_url}"
                    all_traits[trait_key] = {
                        "object_id": obj_id,
                        "type_url": type_url,
                        "decoded": True,
                        "data": {
                            "user_pincodes": sanitized_pincodes,
                        },
                    }
                elif "TamperTrait" in descriptor_name:
                    if not _is_device_lock_id(obj_id):
                        continue
                    lock_device_ids.add(obj_id)
                    self._apply_tamper_trait(obj_id, merged_msg, locks_data)
                elif "StructureInfoTrait" in descriptor_name:
                    self._apply_structure_info_trait(obj_id, merged_msg, locks_data)
                elif "LocatedAnnotationsTrait" in descriptor_name:
                    where_map.update(self._extract_where_map(merged_msg))
                elif "DeviceIdentityTrait" in descriptor_name and PROTO_AVAILABLE:
                    trait_key = f"{obj_id}:{type_url}"
                    all_traits[trait_key] = {
                        "object_id": obj_id,
                        "type_url": type_url,
                        "decoded": True,
                        "data": {
                            "serial_number": merged_msg.serial_number if merged_msg.serial_number else None,
                            "firmware_version": merged_msg.fw_version if merged_msg.fw_version else None,
                            "manufacturer": merged_msg.manufacturer.value if merged_msg.HasField("manufacturer") else None,
                            "model": merged_msg.model_name.value if merged_msg.HasField("model_name") else None,
                        },
                    }
                elif "BatteryPowerSourceTrait" in descriptor_name and PROTO_AVAILABLE:
                    trait_key = f"{obj_id}:{type_url}"
                    all_traits[trait_key] = {
                        "object_id": obj_id,
                        "type_url": type_url,
                        "decoded": True,
                        "data": {
                            "battery_level": merged_msg.remaining.remainingPercent.value
                            if merged_msg.HasField("remaining") and merged_msg.remaining.HasField("remainingPercent")
                            else None,
                            "voltage": merged_msg.assessedVoltage.value if merged_msg.HasField("assessedVoltage") else None,
                            "condition": merged_msg.condition,
                            "status": merged_msg.status,
                            "replacement_indicator": merged_msg.replacementIndicator,
                        },
                    }
                elif "DeviceLocatedSettingsTrait" in descriptor_name:
                    where_id = None
                    if hasattr(merged_msg, "where_id") and merged_msg.HasField("where_id"):
                        where_id = getattr(merged_msg.where_id, "value", None)
                    if isinstance(where_id, str):
                        where_id = where_id.strip()
                    where_label = None
                    fixture_label = None
                    raw_where_id = None
                    raw_fixture_id = None
                    if located_payload:
                        (
                            where_label,
                            fixture_label,
                            raw_where_id,
                            raw_fixture_id,
                        ) = self._decode_device_located_payload(located_payload)
                    raw_where_id = self._normalize_label_value(raw_where_id)
                    raw_fixture_id = self._normalize_label_value(raw_fixture_id)
                    if not where_id and raw_where_id:
                        where_id = raw_where_id
                    where_label = self._normalize_label_value(where_label)
                    fixture_label = self._normalize_label_value(fixture_label)
                    if is_lock:
                        is_door_fixture = self._is_door_fixture_type(merged_msg)
                        door_label = None
                        if raw_fixture_id:
                            door_label = self._lookup_annotation_label(
                                raw_fixture_id,
                                fixture_map,
                                where_map,
                                custom_where_map,
                            )
                        if not door_label:
                            door_label = fixture_label
                        door_label = self._normalize_door_label(
                            door_label,
                            is_door_fixture=is_door_fixture,
                        )
                        if not door_label:
                            door_label = self._door_label_from_fixture_type(merged_msg)
                        if door_label:
                            device = locks_data["yale"].setdefault(obj_id, {"device_id": obj_id})
                            device["door_label"] = door_label
                            self._update_name_from_components(device)
                        area_label = where_label or self._lookup_annotation_label(
                            where_id,
                            where_map,
                            custom_where_map,
                        )
                        if area_label:
                            device = locks_data["yale"].setdefault(obj_id, {"device_id": obj_id})
                            device["where_label"] = area_label
                    if where_id:
                        device_wheres[obj_id] = where_id
                    if raw_fixture_id:
                        device_fixtures[obj_id] = raw_fixture_id

        if custom_where_map:
            where_map.update(custom_where_map)
        locks_data["all_traits"] = all_traits
        locks_data["trait_states"] = trait_states
        locks_data["trait_labels"] = trait_labels
        if device_fixtures:
            for device_id, fixture_id in device_fixtures.items():
                if device_id not in lock_device_ids:
                    continue
                device = locks_data["yale"].setdefault(device_id, {"device_id": device_id})
                door_label = self._lookup_annotation_label(
                    fixture_id,
                    fixture_map,
                    where_map,
                    custom_where_map,
                )
                if door_label:
                    device["door_label"] = door_label
                    self._update_name_from_components(device)
        if where_map and device_wheres:
            for device_id, where_id in device_wheres.items():
                if device_id not in lock_device_ids:
                    continue
                device = locks_data["yale"].setdefault(device_id, {"device_id": device_id})
                if device.get("where_label"):
                    continue
                where_name = self._lookup_annotation_label(
                    where_id,
                    where_map,
                    custom_where_map,
                )
                if where_name:
                    device["where_label"] = where_name
        for obj_id in lock_device_ids:
            if not _is_device_lock_id(obj_id):
                continue
            locks_data["yale"].setdefault(
                obj_id,
                {
                    "device_id": obj_id,
                    "bolt_locked": True,
                    "actuator_state": weave_security_pb2.BoltLockTrait.BOLT_ACTUATOR_STATE_OK,
                },
            )
        if _LOGGER.isEnabledFor(logging.DEBUG) and locks_data.get("yale"):
            _LOGGER.debug(
                "Parsed v2 ObserveResponse: locks=%d, traits=%d",
                len(locks_data["yale"]),
                sum(len(traits) for traits in updates.values()),
            )
        return locks_data

    async def _ingest_chunk(self, payload):
        results = []

        if not payload:
            return results

        stripped = payload.strip()
        if stripped and all(b < 128 for b in stripped):
            try:
                decoded = b64decode(stripped, validate=True)
                if decoded:
                    payload = decoded
            except binascii.Error:
                pass

        self.buffer.extend(payload)

        while True:
            if self.pending_length is None:
                if len(self.buffer) >= 5 and self.buffer[0] in (0x00, 0x80):
                    frame_type = self.buffer[0]
                    frame_len = int.from_bytes(self.buffer[1:5], "big")
                    if len(self.buffer) < 5 + frame_len:
                        break
                    del self.buffer[:5]
                    if frame_type == 0x80:
                        del self.buffer[:frame_len]
                        continue
                    if frame_len == 0:
                        continue
                    self.pending_length = frame_len
                elif self.buffer and self.buffer[0] == 0x0A:
                    # Nest streams often deliver a StreamBody message that begins with a length-delimited
                    # field tag (0x0A) followed by a varint length. This is NOT a standalone length prefix;
                    # it's part of the protobuf encoding. We use it to find frame boundaries (similar to
                    # nest_legacy's observe framing) to avoid parsing stray trailing bytes as new messages.
                    message_length, end_pos = self._decode_varint(self.buffer, 1)
                    if message_length is None:
                        break
                    frame_size = end_pos + message_length
                    if len(self.buffer) < frame_size:
                        break
                    self.pending_length = frame_size
                else:
                    length, offset = self._decode_varint(self.buffer, 0)
                    if length is None or offset > len(self.buffer):
                        break
                    del self.buffer[:offset]
                    if length == 0:
                        continue
                    self.pending_length = length

            if self.pending_length is None or len(self.buffer) < self.pending_length:
                break

            message = self.buffer[:self.pending_length]
            del self.buffer[:self.pending_length]
            self.pending_length = None
            locks_data = await self._process_message(message)
            if locks_data.get("parse_failed"):
                # Put data back and wait for more bytes (likely partial frame).
                # If we keep seeing the same unparseable frame without new data,
                # drop it to avoid stalling the stream indefinitely.
                head = message[:32]
                if (
                    self._last_parse_failed_len == len(message)
                    and self._last_parse_failed_head == head
                    and self._last_parse_failed_buffer_len is not None
                    and len(self.buffer) <= self._last_parse_failed_buffer_len
                ):
                    _LOGGER.debug(
                        "Dropping repeated unparseable frame (len=%d) to avoid stream stall",
                        len(message),
                    )
                    self._last_parse_failed_len = None
                    self._last_parse_failed_head = None
                    self._last_parse_failed_buffer_len = None
                    continue
                self._last_parse_failed_len = len(message)
                self._last_parse_failed_head = head
                self._last_parse_failed_buffer_len = len(self.buffer)
                self.buffer = message + self.buffer
                # Avoid runaway growth
                if len(self.buffer) > MAX_BUFFER_SIZE:
                    _LOGGER.warning("Buffer exceeded MAX_BUFFER_SIZE while waiting for complete frame; resetting buffer")
                    self.buffer.clear()
                    self.pending_length = None
                    break
                break
            if locks_data.get("yale"):
                self._last_parse_failed_len = None
                self._last_parse_failed_head = None
                self._last_parse_failed_buffer_len = None
                results.append(locks_data)

        if (
            self.pending_length
            and len(self.buffer) >= self.pending_length
            and len(self.buffer) >= CATALOG_THRESHOLD
        ):
            message = self.buffer[:self.pending_length]
            del self.buffer[:self.pending_length]
            self.pending_length = None
            locks_data = await self._process_message(message)
            if locks_data.get("parse_failed"):
                head = message[:32]
                if (
                    self._last_parse_failed_len == len(message)
                    and self._last_parse_failed_head == head
                    and self._last_parse_failed_buffer_len is not None
                    and len(self.buffer) <= self._last_parse_failed_buffer_len
                ):
                    _LOGGER.debug(
                        "Dropping repeated unparseable frame (len=%d) to avoid stream stall",
                        len(message),
                    )
                    self._last_parse_failed_len = None
                    self._last_parse_failed_head = None
                    self._last_parse_failed_buffer_len = None
                else:
                    self._last_parse_failed_len = len(message)
                    self._last_parse_failed_head = head
                    self._last_parse_failed_buffer_len = len(self.buffer)
                    self.buffer = message + self.buffer
            elif locks_data.get("yale"):
                self._last_parse_failed_len = None
                self._last_parse_failed_head = None
                self._last_parse_failed_buffer_len = None
                results.append(locks_data)

        return results

    async def _process_message(self, message):
        if _LOGGER.isEnabledFor(logging.DEBUG):
            _LOGGER.debug("Raw chunk (length=%d): %s", len(message), message.hex())

        if not message:
            _LOGGER.error("Empty protobuf message received.")
            return {"yale": {}, "user_id": None, "structure_id": None}

        v2_result = self._process_v2_observe(message)
        if v2_result is not None:
            return v2_result
        if not _USE_STREAMBODY_FALLBACK:
            return {"yale": {}, "user_id": None, "structure_id": None, "all_traits": {}}

        locks_data = {"yale": {}, "user_id": None, "structure_id": None, "all_traits": {}}
        all_traits = {}
        # Track which device IDs are locks (identified by BoltLockTrait)
        # This allows us to skip processing traits for non-lock devices
        lock_device_ids = set()

        try:
            self.stream_body.Clear()
            self.stream_body.ParseFromString(message)
            if _LOGGER.isEnabledFor(logging.DEBUG):
                # Avoid dumping massive protobufs into logs; summarize instead.
                try:
                    msg_count = len(self.stream_body.message)
                    get_count = 0
                    set_count = 0
                    type_urls: list[str] = []
                    for m in self.stream_body.message[:10]:
                        get_count += len(getattr(m, "get", []))
                        set_count += len(getattr(m, "set", []))
                        for g in getattr(m, "get", [])[:10]:
                            prop = getattr(getattr(g, "data", None), "property", None)
                            if prop and getattr(prop, "type_url", None):
                                type_urls.append(prop.type_url)
                        for s in getattr(m, "set", [])[:10]:
                            trait_type = getattr(getattr(s, "property_key", None), "trait_type", None)
                            if trait_type:
                                type_urls.append(trait_type)
                    # De-dupe while preserving order (first 15 only)
                    seen = set()
                    uniq = []
                    for t in type_urls:
                        if t in seen:
                            continue
                        seen.add(t)
                        uniq.append(t)
                        if len(uniq) >= 15:
                            break
                    _LOGGER.debug(
                        "Parsed StreamBody: messages=%d get=%d set=%d types=%s",
                        msg_count,
                        get_count,
                        set_count,
                        uniq,
                    )
                except Exception:
                    _LOGGER.debug("Parsed StreamBody (summary unavailable)")

            # Check for authentication failure (status code 7)
            if self.stream_body.HasField("status") and self.stream_body.status.code == 7:
                _LOGGER.warning("Authentication failed detected in stream (status code 7): %s", self.stream_body.status.message)
                locks_data["auth_failed"] = True
                return locks_data

            # First pass: Identify lock devices by BoltLockTrait or Linus lock resource hints (set operations)
            for msg in self.stream_body.message:
                for set_op in msg.set:
                    obj_id = getattr(set_op, "resource_id", None) or getattr(getattr(set_op, "object", None), "id", None)
                    resource_type = getattr(set_op, "resource_type", "") or ""
                    trait_type = getattr(getattr(set_op, "property_key", None), "trait_type", "") if hasattr(set_op, "property_key") else ""
                    if obj_id and (
                        "LinusLock" in resource_type
                        or any(hint in trait_type for hint in _LOCK_TRAIT_HINTS)
                        or resource_type.lower().startswith("yale.resource")
                    ):
                        lock_device_ids.add(obj_id)
                        _LOGGER.debug("Identified lock device via set: %s (%s)", obj_id, resource_type or trait_type)
                    if obj_id and trait_type and "DeviceIdentityTrait" in trait_type:
                        trait_key = f"{obj_id}:{trait_type}"
                        all_traits[trait_key] = {"object_id": obj_id, "type_url": trait_type, "decoded": False}
                for get_op in msg.get:
                    obj_id = _pick_object_id(get_op.object)
                    property_any = getattr(get_op.data, "property", None)
                    property_any = _normalize_any_type(property_any) if property_any else None
                    type_url = getattr(property_any, "type_url", None) if property_any else None
                    if not type_url and 7 in get_op:
                        type_url = "weave.trait.security.BoltLockTrait"
                    
                    # Track devices with BoltLockTrait as locks
                    if obj_id and any(hint in (type_url or "") for hint in _LOCK_TRAIT_HINTS):
                        lock_device_ids.add(obj_id)
                        _LOGGER.debug("Identified lock device: %s", obj_id)

            # Second pass: Process traits only for lock devices, structures, and users
            for msg in self.stream_body.message:
                for set_op in msg.set:
                    obj_id = getattr(set_op, "resource_id", None) or getattr(getattr(set_op, "object", None), "id", None)
                    obj_key = getattr(getattr(set_op, "property_key", None), "property_key", None) or "unknown"
                    trait_type = getattr(getattr(set_op, "property_key", None), "trait_type", None)
                    should_process = obj_id and (obj_id in lock_device_ids or obj_id.startswith("STRUCTURE_") or obj_id.startswith("USER_"))
                    # Capture structure/user ids from set frames so commands have IDs early
                    if obj_id and obj_id.startswith("STRUCTURE_"):
                        locks_data["structure_id"] = obj_id.replace("STRUCTURE_", "")
                    if obj_id and obj_id.startswith("USER_"):
                        locks_data["user_id"] = obj_id
                    if should_process and trait_type:
                        trait_key = f"{obj_id}:{trait_type}"
                        if trait_key not in all_traits:
                            all_traits[trait_key] = {"object_id": obj_id, "type_url": trait_type, "decoded": False}
                        _LOGGER.debug("Processing set-op trait hint `%s` for `%s` with key `%s`", trait_type, obj_id, obj_key)

                for get_op in msg.get:
                    obj_id = _pick_object_id(get_op.object)
                    obj_key = get_op.object.key if get_op.object.key else "unknown"
                    if not obj_id and isinstance(obj_key, str) and obj_key:
                        obj_id = obj_key
                        _LOGGER.debug("Using object key as id for trait decode: %s", obj_key)

                    property_any = getattr(get_op.data, "property", None)
                    property_any = _normalize_any_type(property_any) if property_any else None
                    type_url = getattr(property_any, "type_url", None) if property_any else None
                    if not type_url and 7 in get_op:
                        type_url = "weave.trait.security.BoltLockTrait"

                    # Determine if this is a lock device, structure, or user (all should be processed)
                    # Skip processing traits for non-lock devices (thermostats, cameras, etc.)
                    is_lock_device = obj_id in lock_device_ids if obj_id else False
                    is_structure_or_user = obj_id and (obj_id.startswith("STRUCTURE_") or obj_id.startswith("USER_"))
                    should_process = is_lock_device or is_structure_or_user or not obj_id
                    
                    # Only log and process traits for devices we care about
                    if should_process:
                        _LOGGER.debug("Extracting `%s` for `%s` with key `%s`", type_url, obj_id, obj_key)
                    elif obj_id and obj_id.startswith("DEVICE_"):
                        # Silently skip non-lock devices (reduce log noise)
                        continue
                    
                    # Only process HomeKit traits (DeviceIdentityTrait, BatteryPowerSourceTrait) for lock devices
                    # Also process StructureInfoTrait and UserInfoTrait for metadata
                    # Skip all other traits for non-lock devices
                    if property_any and type_url and should_process:
                        trait_key = f"{obj_id}:{type_url}" if obj_id and type_url else None
                        trait_info = {"object_id": obj_id, "type_url": type_url, "decoded": False}
                        
                        try:
                            # DeviceIdentityTrait
                            if "DeviceIdentityTrait" in type_url and PROTO_AVAILABLE:
                                trait = description_pb2.DeviceIdentityTrait()
                                property_any.Unpack(trait)
                                trait_info["decoded"] = True
                                trait_info["data"] = {
                                    "serial_number": trait.serial_number if trait.serial_number else None,
                                    "firmware_version": trait.fw_version if trait.fw_version else None,
                                    "manufacturer": trait.manufacturer.value if trait.HasField("manufacturer") else None,
                                    "model": trait.model_name.value if trait.HasField("model_name") else None,
                                }
                                _LOGGER.info("✅ Decoded DeviceIdentityTrait for %s: serial=%s, fw=%s", 
                                           obj_id, trait_info["data"].get("serial_number"), trait_info["data"].get("firmware_version"))
                            
                            # BatteryPowerSourceTrait
                            elif "BatteryPowerSourceTrait" in type_url and PROTO_AVAILABLE:
                                trait = power_pb2.BatteryPowerSourceTrait()
                                property_any.Unpack(trait)
                                trait_info["decoded"] = True
                                trait_info["data"] = {
                                    "battery_level": trait.remaining.remainingPercent.value if trait.HasField("remaining") and trait.remaining.HasField("remainingPercent") else None,
                                    "voltage": trait.assessedVoltage.value if trait.HasField("assessedVoltage") else None,
                                    "condition": trait.condition,
                                    "status": trait.status,
                                    "replacement_indicator": trait.replacementIndicator,
                                }
                                _LOGGER.info("✅ Decoded BatteryPowerSourceTrait for %s: level=%s, voltage=%s", 
                                           obj_id, trait_info["data"].get("battery_level"), trait_info["data"].get("voltage"))
                        except Exception as e:
                            trait_info["error"] = str(e)
                            _LOGGER.debug("Error decoding trait %s: %s", type_url, e)
                        
                        # Store trait info (only for lock devices, structures, and users)
                        if trait_key and should_process:
                            all_traits[trait_key] = trait_info

                    # Only process BoltLockTrait for lock devices
                    if "BoltLockTrait" in (type_url or "") and obj_id:
                        bolt_lock = weave_security_pb2.BoltLockTrait()
                        try:
                            if not property_any:
                                _LOGGER.warning("No property payload for %s, skipping BoltLockTrait decode", obj_id)
                                continue
                            unpacked = property_any.Unpack(bolt_lock)
                            if not unpacked:
                                _LOGGER.warning("Unpacking BoltLockTrait failed for %s, skipping", obj_id)
                                continue
                            self._apply_bolt_lock_trait(obj_id, bolt_lock, locks_data)

                        except DecodeError as err:
                            _LOGGER.error("Failed to decode BoltLockTrait for %s: %s", obj_id, err)
                            continue
                        except Exception as err:
                            _LOGGER.error("Unexpected error unpacking BoltLockTrait for %s: %s", obj_id, err, exc_info=True)
                            continue

                    elif "BoltLockSettingsTrait" in (type_url or "") and obj_id:
                        try:
                            if not property_any:
                                continue
                            settings = weave_security_pb2.BoltLockSettingsTrait()
                            unpacked = property_any.Unpack(settings)
                            if not unpacked:
                                continue
                            self._apply_bolt_lock_settings_trait(obj_id, settings, locks_data)
                        except Exception as err:
                            _LOGGER.debug("Failed to decode BoltLockSettingsTrait for %s: %s", obj_id, err)

                    elif "BoltLockCapabilitiesTrait" in (type_url or "") and obj_id:
                        try:
                            if not property_any:
                                continue
                            caps = weave_security_pb2.BoltLockCapabilitiesTrait()
                            unpacked = property_any.Unpack(caps)
                            if not unpacked:
                                continue
                            self._apply_bolt_lock_capabilities_trait(obj_id, caps, locks_data)
                        except Exception as err:
                            _LOGGER.debug("Failed to decode BoltLockCapabilitiesTrait for %s: %s", obj_id, err)

                    elif "TamperTrait" in (type_url or "") and obj_id:
                        try:
                            if not property_any:
                                continue
                            tamper = weave_security_pb2.TamperTrait()
                            unpacked = property_any.Unpack(tamper)
                            if not unpacked:
                                continue
                            self._apply_tamper_trait(obj_id, tamper, locks_data)
                        except Exception as err:
                            _LOGGER.debug("Failed to decode TamperTrait for %s: %s", obj_id, err)

                    elif "StructureInfoTrait" in (type_url or "") and obj_id:
                        try:
                            if not property_any:
                                _LOGGER.warning("No StructureInfo payload for %s", obj_id)
                                continue
                            structure = nest_structure_pb2.StructureInfoTrait()
                            unpacked = property_any.Unpack(structure)
                            if not unpacked:
                                _LOGGER.warning("Unpacking StructureInfoTrait failed for %s, skipping", obj_id)
                                continue
                            self._apply_structure_info_trait(obj_id, structure, locks_data)
                        except Exception as err:
                            _LOGGER.error("Failed to parse StructureInfoTrait for %s: %s", obj_id, err, exc_info=True)

                    elif "UserInfoTrait" in (type_url or ""):
                        try:
                            locks_data["user_id"] = obj_id
                        except Exception as err:
                            _LOGGER.error("Failed to parse UserInfoTrait: %s", err, exc_info=True)

            locks_data["all_traits"] = all_traits
            # If we saw a lock device but no BoltLockTrait yet, seed a placeholder so entities can initialize
            for obj_id in lock_device_ids:
                locks_data["yale"].setdefault(
                    obj_id,
                    {
                        "device_id": obj_id,
                        "bolt_locked": True,
                        "actuator_state": weave_security_pb2.BoltLockTrait.BOLT_ACTUATOR_STATE_OK,
                    },
                )
            _LOGGER.debug(f"Final lock data: {locks_data}")
            return locks_data

        except DecodeError as e:
            # These occur for currently-unmapped message types and are expected, but
            # during startup we may see partial frames; signal caller to retry with more data.
            locks_data["parse_failed"] = True
            if not self._decode_warned:
                _LOGGER.warning(
                    "Some protobuf messages could not be decoded; this is expected and harmless. "
                    "Enable DEBUG to see details."
                )
                self._decode_warned = True
            if _LOGGER.isEnabledFor(logging.DEBUG):
                _LOGGER.debug("DecodeError in StreamBody: %s", e)
                if message:
                    _LOGGER.debug(
                        "Failed StreamBody payload (hex, first 200 bytes): %s",
                        message[:200].hex(),
                    )
            return locks_data
        except Exception as e:
            _LOGGER.error(f"Unexpected error processing message: {e}", exc_info=True)
            return locks_data

    # Note: streaming and refresh helpers are handled by api_client
