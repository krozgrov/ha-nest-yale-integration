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
        self._accumulator = bytearray()  # For accumulating chunks until parseable

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
            if locks_data.get("yale"):
                results.append(locks_data)

        return results

    def clear_accumulator(self):
        """Clear the accumulator buffer (call on new connections)."""
        self._accumulator.clear()
    
    async def accumulate_and_parse(self, chunk):
        """Accumulate chunk data and try to parse as StreamBody.
        
        Returns:
            dict: Parsed lock data if successful, or empty dict if more data needed.
        """
        if not chunk:
            return {"yale": {}, "user_id": None, "structure_id": None, "all_traits": {}}
        
        self._accumulator.extend(chunk)
        
        # Try to parse the accumulated data
        try:
            self.stream_body.Clear()
            self.stream_body.ParseFromString(bytes(self._accumulator))
            
            # Success! Process the message and clear accumulator
            result = await self._extract_lock_data()
            self._accumulator.clear()
            return result
        except Exception as e:
            # Not enough data yet, or parse error
            # If accumulator is very large (>1MB), something is wrong - clear it
            if len(self._accumulator) > 1048576:
                _LOGGER.warning("Accumulator exceeded 1MB without successful parse, clearing")
                self._accumulator.clear()
            return {"yale": {}, "user_id": None, "structure_id": None, "all_traits": {}}
    
    async def _extract_lock_data(self):
        """Extract lock data from the already-parsed stream_body."""
        locks_data = {"yale": {}, "user_id": None, "structure_id": None, "all_traits": {}}
        all_traits = {}
        lock_device_ids = set()

        # Check for authentication failure (status code 7)
        if self.stream_body.HasField("status") and self.stream_body.status.code == 7:
            _LOGGER.warning("Authentication failed detected in stream (status code 7): %s", self.stream_body.status.message)
            locks_data["auth_failed"] = True
            return locks_data

        # First pass: Identify lock devices by BoltLockTrait
        for msg in self.stream_body.message:
            for get_op in msg.get:
                obj_id = get_op.object.id if get_op.object.id else None
                property_any = getattr(get_op.data, "property", None)
                property_any = _normalize_any_type(property_any) if property_any else None
                type_url = getattr(property_any, "type_url", None) if property_any else None
                if not type_url and 7 in get_op:
                    type_url = "weave.trait.security.BoltLockTrait"
                
                if obj_id and "BoltLockTrait" in (type_url or ""):
                    lock_device_ids.add(obj_id)
                    _LOGGER.debug("Identified lock device: %s", obj_id)

        # Second pass: Process traits
        for msg in self.stream_body.message:
            for get_op in msg.get:
                obj_id = get_op.object.id if get_op.object.id else None
                obj_key = get_op.object.key if get_op.object.key else "unknown"

                property_any = getattr(get_op.data, "property", None)
                property_any = _normalize_any_type(property_any) if property_any else None
                type_url = getattr(property_any, "type_url", None) if property_any else None
                if not type_url and 7 in get_op:
                    type_url = "weave.trait.security.BoltLockTrait"

                is_lock_device = obj_id in lock_device_ids if obj_id else False
                is_structure_or_user = obj_id and (obj_id.startswith("STRUCTURE_") or obj_id.startswith("USER_"))
                should_process = is_lock_device or is_structure_or_user or not obj_id
                
                if not should_process and obj_id and obj_id.startswith("DEVICE_"):
                    continue
                
                if property_any and type_url and should_process:
                    self._process_trait(obj_id, type_url, property_any, locks_data, all_traits, lock_device_ids)

        locks_data["all_traits"] = all_traits
        
        # Log final state
        if locks_data.get("yale"):
            _LOGGER.info("Extracted %d lock device(s): %s", len(locks_data["yale"]), list(locks_data["yale"].keys()))
        
        return locks_data
    
    def _process_trait(self, obj_id, type_url, property_any, locks_data, all_traits, lock_device_ids):
        """Process a single trait and update locks_data."""
        trait_key = f"{obj_id}:{type_url}" if obj_id and type_url else None
        trait_info = {"object_id": obj_id, "type_url": type_url, "decoded": False}
        
        try:
            # BoltLockTrait - core lock state
            if "BoltLockTrait" in type_url:
                trait = weave_security_pb2.BoltLockTrait()
                property_any.Unpack(trait)
                state_val = trait.state
                # actuatorState is an enum field, use direct access (0 = UNSPECIFIED)
                actuator_state = trait.actuatorState if trait.actuatorState != 0 else None
                _LOGGER.info("✅ Decoded BoltLockTrait for %s: state=%s actuator_state=%s", obj_id, state_val, actuator_state)
                if obj_id and obj_id.startswith("DEVICE_"):
                    if obj_id not in locks_data["yale"]:
                        locks_data["yale"][obj_id] = {}
                    locks_data["yale"][obj_id]["locked"] = (state_val == 2)
                    if actuator_state is not None:
                        locks_data["yale"][obj_id]["actuator_state"] = actuator_state
                trait_info["decoded"] = True
                trait_info["data"] = {"state": state_val, "actuator_state": actuator_state}
            
            # DeviceIdentityTrait
            elif "DeviceIdentityTrait" in type_url and PROTO_AVAILABLE:
                trait = description_pb2.DeviceIdentityTrait()
                property_any.Unpack(trait)
                trait_info["decoded"] = True
                trait_info["data"] = {
                    "serial_number": trait.serial_number if trait.serial_number else None,
                    "firmware_version": trait.fw_version if trait.fw_version else None,
                }
                _LOGGER.info("✅ Decoded DeviceIdentityTrait for %s: serial=%s", obj_id, trait_info["data"].get("serial_number"))
            
            # BatteryPowerSourceTrait
            elif "BatteryPowerSourceTrait" in type_url and PROTO_AVAILABLE:
                trait = power_pb2.BatteryPowerSourceTrait()
                property_any.Unpack(trait)
                trait_info["decoded"] = True
                battery_level = trait.remaining.remainingPercent.value if trait.HasField("remaining") and trait.remaining.HasField("remainingPercent") else None
                trait_info["data"] = {"battery_level": battery_level}
                _LOGGER.info("✅ Decoded BatteryPowerSourceTrait for %s: battery=%s%%", obj_id, battery_level)
            
            # StructureInfoTrait
            elif "StructureInfoTrait" in type_url:
                trait = nest_structure_pb2.StructureInfoTrait()
                property_any.Unpack(trait)
                trait_info["decoded"] = True
                trait_info["data"] = {"structure_name": trait.name if trait.name else None}
                if obj_id and obj_id.startswith("STRUCTURE_"):
                    locks_data["structure_id"] = obj_id
                    _LOGGER.info("✅ Decoded StructureInfoTrait: structure_id=%s", obj_id)
            
            # UserInfoTrait
            elif "UserInfoTrait" in type_url:
                if obj_id and obj_id.startswith("USER_"):
                    locks_data["user_id"] = obj_id
                    _LOGGER.info("✅ Found UserInfoTrait: user_id=%s", obj_id)
                trait_info["decoded"] = True
                trait_info["data"] = {"user_id": obj_id}
            
            if trait_key:
                all_traits[trait_key] = trait_info
                
        except Exception as e:
            _LOGGER.debug("Could not decode trait %s: %s", type_url, e)

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

            # First pass: Identify lock devices by BoltLockTrait
            for msg in self.stream_body.message:
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

                            locks_data["yale"][obj_id] = {
                                "device_id": obj_id,
                                "bolt_locked": bolt_lock.lockedState == weave_security_pb2.BoltLockTrait.BOLT_LOCKED_STATE_LOCKED,
                                "bolt_moving": bolt_lock.actuatorState
                                not in [weave_security_pb2.BoltLockTrait.BOLT_ACTUATOR_STATE_OK],
                                "actuator_state": bolt_lock.actuatorState,
                            }
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
            _LOGGER.debug(f"Final lock data: {locks_data}")
            return locks_data

        except DecodeError as e:
            # These occur for currently-unmapped message types and are expected.
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
