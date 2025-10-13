import logging
from google.protobuf import any_pb2
from custom_components.nest_yale.proto.weave.trait import security_pb2 as weave_security_pb2
from custom_components.nest_yale.proto.weave.trait import power_pb2 as weave_power_pb2
from custom_components.nest_yale.proto.nest.trait import user_pb2 as nest_user_pb2
from custom_components.nest_yale.proto.weave.trait import description_pb2 as weave_description_pb2
from custom_components.nest_yale.proto.nest.trait import security_pb2 as nest_security_pb2

_LOGGER = logging.getLogger(__name__)

def clone_object(obj):
    """Simple deep clone using repr/eval – adjust as needed."""
    # For simple dicts, you might use:
    import copy
    return copy.deepcopy(obj)

class DeviceParser:
    @staticmethod
    def parse_locks(message):
        """
        Parse a StreamBody message for Yale lock data and user ID.
        This mirrors the Homebridge JS logic.
        """
        body = {"yale": {}, "user_id": None}
        _LOGGER.debug(f"Attempting to parse Protobuf message: {message}")

        if not hasattr(message, "message"):
            _LOGGER.error("Invalid protobuf message structure: 'message' field missing")
            return body

        try:
            for msg in message.message:
                if not hasattr(msg, "get"):
                    _LOGGER.warning("Skipping message: Missing 'get' attribute")
                    continue

                _LOGGER.debug(f"Processing message with get: {msg.get}")
                # In JS, msg.get is iterated over; here we assume it is a list-like field.
                for trait in msg.get:
                    if not hasattr(trait, "object") or not hasattr(trait, "data") or not hasattr(trait.data, "property"):
                        _LOGGER.warning("Skipping trait: Missing 'object' or 'data.property' attribute")
                        continue

                    resource_id = getattr(trait.object, "id", None)
                    trait_key = getattr(trait.object, "key", None)
                    if not resource_id or not trait_key:
                        _LOGGER.warning(f"Skipping trait with missing data: {trait}")
                        continue

                    _LOGGER.debug(f"Found trait: {resource_id} - {trait_key}")

                    property_any = trait.data.property
                    property_value = None

                    # BoltLockTrait
                    if (property_any.type_url == "type.nestlabs.com/weave.trait.security.BoltLockTrait" or
                        (trait_key and trait_key.lower() == "bolt_lock")):
                        property_value = weave_security_pb2.BoltLockTrait()
                        if property_any.Unpack(property_value):
                            if resource_id.startswith("DEVICE_"):
                                device_id = resource_id.replace("DEVICE_", "")
                                body["yale"][device_id] = DeviceParser._parse_bolt_lock(property_value, device_id)
                                _LOGGER.debug(f"Parsed bolt_lock for {device_id}: {body['yale'][device_id]}")
                    # BatteryPowerSourceTrait
                    elif (property_any.type_url == "type.nestlabs.com/weave.trait.power.BatteryPowerSourceTrait" or
                          (trait_key and trait_key.lower() == "battery_power_source")):
                        property_value = weave_power_pb2.BatteryPowerSourceTrait()
                        if property_any.Unpack(property_value):
                            if resource_id.startswith("DEVICE_"):
                                device_id = resource_id.replace("DEVICE_", "")
                                if device_id not in body["yale"]:
                                    body["yale"][device_id] = {"device_id": device_id, "using_protobuf": True}
                                DeviceParser._parse_battery_power_source(property_value, body["yale"][device_id])
                                _LOGGER.debug(f"Parsed battery_power_source for {device_id}: {body['yale'][device_id]}")
                    # UserInfoTrait – extract user_id
                    elif (property_any.type_url == "type.nestlabs.com/nest.trait.user.UserInfoTrait" or
                          (trait_key and trait_key.lower() == "user_info")):
                        property_value = nest_user_pb2.UserInfoTrait()
                        if property_any.Unpack(property_value):
                            body["user_id"] = getattr(property_value, "legacyId", None)
                            _LOGGER.debug(f"Extracted user_id: {body['user_id']}")
                    # DeviceIdentityTrait
                    elif (property_any.type_url == "type.nestlabs.com/weave.trait.description.DeviceIdentityTrait" or
                          (trait_key and trait_key.lower() == "device_identity")):
                        property_value = weave_description_pb2.DeviceIdentityTrait()
                        if property_any.Unpack(property_value):
                            if resource_id.startswith("DEVICE_"):
                                device_id = resource_id.replace("DEVICE_", "")
                                if device_id not in body["yale"]:
                                    body["yale"][device_id] = {"device_id": device_id, "using_protobuf": True}
                                DeviceParser._parse_device_identity(property_value, body["yale"][device_id])
                                _LOGGER.debug(f"Parsed device_identity for {device_id}: {body['yale'][device_id]}")
                    # EnhancedBoltLockSettingsTrait
                    elif (property_any.type_url == "type.nestlabs.com/nest.trait.security.EnhancedBoltLockSettingsTrait" or
                          (trait_key and trait_key.lower() == "enhanced_bolt_lock_settings")):
                        property_value = nest_security_pb2.EnhancedBoltLockSettingsTrait()
                        if property_any.Unpack(property_value):
                            if resource_id.startswith("DEVICE_"):
                                device_id = resource_id.replace("DEVICE_", "")
                                if device_id not in body["yale"]:
                                    body["yale"][device_id] = {"device_id": device_id, "using_protobuf": True}
                                DeviceParser._parse_enhanced_bolt_lock(property_value, body["yale"][device_id])
                                _LOGGER.debug(f"Parsed enhanced_bolt_lock_settings for {device_id}: {body['yale'][device_id]}")
                    else:
                        _LOGGER.debug(f"Unhandled trait: type_url={property_any.type_url}, key={trait_key}")
        except Exception as e:
            _LOGGER.error(f"Error parsing protobuf data: {e}")

        if not body["yale"] and not body["user_id"]:
            _LOGGER.warning("No lock data or user_id parsed from message")
        else:
            _LOGGER.debug(f"Final parsed body: {body}")
        return body

    @staticmethod
    def _parse_bolt_lock(property_value, device_id):
        """Parse lock data from BoltLockTrait."""
        return {
            "device_id": device_id,
            "bolt_locked": property_value.lockedState == weave_security_pb2.BoltLockTrait.BoltLockedState.BOLT_LOCKED_STATE_LOCKED,
            "bolt_moving": property_value.actuatorState in (
                weave_security_pb2.BoltLockTrait.BoltActuatorState.BOLT_ACTUATOR_STATE_LOCKING,
                weave_security_pb2.BoltLockTrait.BoltActuatorState.BOLT_ACTUATOR_STATE_UNLOCKING,
                weave_security_pb2.BoltLockTrait.BoltActuatorState.BOLT_ACTUATOR_STATE_MOVING
            ),
            "bolt_moving_to": property_value.actuatorState == weave_security_pb2.BoltLockTrait.BoltActuatorState.BOLT_ACTUATOR_STATE_LOCKING,
            "using_protobuf": True
        }

    @staticmethod
    def _parse_battery_power_source(property_value, lock_info):
        """Parse battery data from BatteryPowerSourceTrait."""
        lock_info["battery_status"] = getattr(property_value, "replacementIndicator", None)
        if hasattr(property_value, "assessedVoltage") and hasattr(property_value.assessedVoltage, "value"):
            lock_info["battery_voltage"] = getattr(property_value.assessedVoltage, "value", None)

    @staticmethod
    def _parse_device_identity(property_value, lock_info):
        """Parse identity data from DeviceIdentityTrait."""
        lock_info["serial_number"] = getattr(property_value, "serialNumber", None)
        lock_info["software_version"] = getattr(property_value, "fwVersion", None)

    @staticmethod
    def _parse_enhanced_bolt_lock(property_value, lock_info):
        """Parse settings from EnhancedBoltLockSettingsTrait."""
        lock_info["auto_relock_on"] = getattr(property_value, "autoRelockOn", False)
        if hasattr(property_value, "autoRelockDuration"):
            lock_info["auto_relock_duration"] = property_value.autoRelockDuration.seconds
        lock_info["one_touch_lock"] = getattr(property_value, "oneTouchLock", False)
        lock_info["home_away_assist_lock_on"] = getattr(property_value, "homeAwayAssistLockOn", False)

def transform_traits(object_list, proto):
    """
    Iterates over a list of traits and unpacks them using the appropriate proto type.
    """
    for el in object_list:
        type_url = el.data.property.type_url
        buffer = el.data.property.value
        pbuf_trait = lookup_trait(proto, type_url)
        if pbuf_trait and buffer:
            el.data.property.value = pbuf_trait.toObject(pbuf_trait.decode(buffer), { "enums": str, "defaults": True })

def lookup_trait(proto, type_url):
    """
    Attempts to look up a trait type in the proto object.
    Splits the type_url and returns the corresponding type.
    """
    pbuf_trait = None
    for trait_key in proto:
        try:
            pbuf_trait = pbuf_trait or proto[trait_key].lookupType(type_url.split('/')[1])
        except Exception:
            continue
    return pbuf_trait

def get_proto_object(object_list, key):
    """Return all objects where object.key equals key."""
    return [el for el in object_list if el.object.key == key]

def get_proto_keys(object_list):
    """Return a list of tuples: (object.key, object.id, data.property.type_url)."""
    return [(el.object.key, el.object.id, el.data.property.type_url if hasattr(el.data, "property") else None) for el in object_list]

def uuid_v4():
    """Generate a UUID version 4."""
    import uuid
    return str(uuid.uuid4())

# For use in updates (legacy code conversion)
def clone_object(obj):
    """Perform a deep clone of an object."""
    import copy
    return copy.deepcopy(obj)

def create_api_object(node_id, value):
    """Create an API object structure for updates."""
    return {
        "object_key": node_id,
        "op": "MERGE",
        "value": clone_object(value)
    }

# Export the Connection constructor for compatibility with the rest of the integration.
# In the original JS, the Connection constructor is exported.
# Here, you might import this file as a module in your connection handler.
Connection = None  # Placeholder; this file focuses on device parsing.