import logging
from google.protobuf.message import DecodeError
from google.protobuf.any_pb2 import Any
from base64 import b64decode
import binascii

from .proto.weave.trait import security_pb2 as weave_security_pb2
from .proto.nest.trait import structure_pb2 as nest_structure_pb2
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


class NestProtobufHandler:
    def __init__(self):
        self.buffer = bytearray()
        self.pending_length = None
        self.stream_body = rpc_pb2.StreamBody()
        self._decode_warned = False

    def reset_stream_state(self):
        """Clear stream parsing buffers between connections."""
        self.buffer.clear()
        self.pending_length = None
        self.stream_body.Clear()
        # Allow DecodeError warnings again after a fresh connection
        self._decode_warned = False

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
                # Put data back and wait for more bytes (likely partial frame)
                self.buffer = message + self.buffer
                # Avoid runaway growth
                if len(self.buffer) > MAX_BUFFER_SIZE:
                    _LOGGER.warning("Buffer exceeded MAX_BUFFER_SIZE while waiting for complete frame; resetting buffer")
                    self.buffer.clear()
                    self.pending_length = None
                    break
                break
            if locks_data.get("yale"):
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
                self.buffer = message + self.buffer
            elif locks_data.get("yale"):
                results.append(locks_data)

        return results

    async def _process_message(self, message):
        if _LOGGER.isEnabledFor(logging.DEBUG):
            _LOGGER.debug("Raw chunk (length=%d): %s", len(message), message.hex())

        if not message:
            _LOGGER.error("Empty protobuf message received.")
            return {"yale": {}, "user_id": None, "structure_id": None}

        locks_data = {"yale": {}, "user_id": None, "structure_id": None, "all_traits": {}}
        all_traits = {}
        # Track which device IDs are locks (identified by BoltLockTrait)
        # This allows us to skip processing traits for non-lock devices
        lock_device_ids = set()

        try:
            self.stream_body.Clear()
            self.stream_body.ParseFromString(message)
            _LOGGER.debug(f"Parsed StreamBody: {self.stream_body}")

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
                        or "BoltLockTrait" in trait_type
                        or resource_type.lower().startswith("yale.resource")
                    ):
                        lock_device_ids.add(obj_id)
                        _LOGGER.debug("Identified lock device via set: %s (%s)", obj_id, resource_type or trait_type)
                    if obj_id and trait_type and "DeviceIdentityTrait" in trait_type:
                        trait_key = f"{obj_id}:{trait_type}"
                        all_traits[trait_key] = {"object_id": obj_id, "type_url": trait_type, "decoded": False}
                for get_op in msg.get:
                    obj_id = get_op.object.id if get_op.object.id else None
                    property_any = getattr(get_op.data, "property", None)
                    property_any = _normalize_any_type(property_any) if property_any else None
                    type_url = getattr(property_any, "type_url", None) if property_any else None
                    if not type_url and 7 in get_op:
                        type_url = "weave.trait.security.BoltLockTrait"
                    
                    # Track devices with BoltLockTrait as locks
                    if obj_id and "BoltLockTrait" in (type_url or ""):
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
                    obj_id = get_op.object.id if get_op.object.id else None
                    obj_key = get_op.object.key if get_op.object.key else "unknown"

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

                            # Only publish bolt_locked when the stream explicitly reports LOCKED or UNLOCKED.
                            # The API can transiently emit UNKNOWN/UNSPECIFIED during reconnects/motion;
                            # treating those as "unlocked" causes phantom HA state flips.
                            locked_state = bolt_lock.lockedState
                            bolt_locked_value = None
                            if locked_state == weave_security_pb2.BoltLockTrait.BOLT_LOCKED_STATE_LOCKED:
                                bolt_locked_value = True
                            elif locked_state == weave_security_pb2.BoltLockTrait.BOLT_LOCKED_STATE_UNLOCKED:
                                bolt_locked_value = False

                            locks_data["yale"][obj_id] = {
                                "device_id": obj_id,
                                "bolt_moving": bolt_lock.actuatorState
                                not in [weave_security_pb2.BoltLockTrait.BOLT_ACTUATOR_STATE_OK],
                                "actuator_state": bolt_lock.actuatorState,
                            }
                            if bolt_locked_value is not None:
                                locks_data["yale"][obj_id]["bolt_locked"] = bolt_locked_value
                            else:
                                _LOGGER.debug(
                                    "Skipping bolt_locked update for %s due to ambiguous lockedState=%s",
                                    obj_id,
                                    locked_state,
                                )
                            if bolt_lock.boltLockActor.originator.resourceId:
                                locks_data["user_id"] = bolt_lock.boltLockActor.originator.resourceId
                            _LOGGER.debug("Parsed BoltLockTrait for %s: %s, user_id=%s", obj_id, locks_data["yale"][obj_id], locks_data["user_id"])

                        except DecodeError as err:
                            _LOGGER.error("Failed to decode BoltLockTrait for %s: %s", obj_id, err)
                            continue
                        except Exception as err:
                            _LOGGER.error("Unexpected error unpacking BoltLockTrait for %s: %s", obj_id, err, exc_info=True)
                            continue

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
                            if structure.legacy_id:
                                locks_data["structure_id"] = structure.legacy_id.split(".")[1]
                            elif obj_id.startswith("STRUCTURE_"):
                                locks_data["structure_id"] = obj_id.replace("STRUCTURE_", "")
                            _LOGGER.debug("Parsed StructureInfoTrait for %s: structure_id=%s", obj_id, locks_data["structure_id"])
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
