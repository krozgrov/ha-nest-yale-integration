import logging

_LOGGER = logging.getLogger(__name__)

class DeviceParser:
    @staticmethod
    def parse_locks(message):
        """Parse StreamBody for lock states and user ID."""
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

                    # Lock State Parsing from BoltLockTrait
                    if trait_key == "weave.trait.security.BoltLockTrait" and resource_id.startswith("DEVICE_"):
                        device_id = resource_id.split("_")[1]
                        property_value = getattr(trait.data.property, "value", None)
                        if not property_value:
                            _LOGGER.warning(f"Skipping lock {device_id}: Missing 'value' field in property")
                            continue
                        body["yale"][device_id] = DeviceParser._parse_bolt_lock(property_value, device_id)
                        _LOGGER.debug(f"Parsed lock from BoltLockTrait {device_id}: {body['yale'][device_id]}")

                    # Lock State Parsing from EnhancedBoltLockSettingsTrait
                    elif trait_key == "nest.trait.security.EnhancedBoltLockSettingsTrait" and resource_id.startswith("DEVICE_"):
                        device_id = resource_id.split("_")[1]
                        property_value = getattr(trait.data.property, "value", None)
                        if not property_value:
                            _LOGGER.warning(f"Skipping lock {device_id}: Missing 'value' field in EnhancedBoltLockSettings")
                            continue
                        _LOGGER.debug(f"Raw EnhancedBoltLockSettings value for {device_id}: {property_value.hex()}")
                        body["yale"][device_id] = DeviceParser._parse_enhanced_bolt_lock(property_value, device_id)
                        _LOGGER.debug(f"Parsed lock from EnhancedBoltLockSettings {device_id}: {body['yale'][device_id]}")

                    # User ID Parsing
                    elif trait_key == "user_info":
                        property_value = getattr(trait.data.property, "value", None)
                        if property_value:
                            body["user_id"] = getattr(property_value, "legacyId", None)
                            _LOGGER.debug(f"Extracted user_id: {body['user_id']}")

                    # Annotation Parsing
                    elif trait_key == "located_annotated_settings" or resource_id.startswith("ANNOTATION_"):
                        property_value = getattr(trait.data.property, "value", None)
                        if property_value:
                            _LOGGER.debug(f"Annotation data for {resource_id}: {property_value}")

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
            "bolt_locked": (
                getattr(property_value, "lockedState", "") == "BOLT_LOCKED_STATE_LOCKED"
            ),
            "bolt_moving": (
                getattr(property_value, "actuatorState", "") != "BOLT_ACTUATOR_STATE_OK"
            ),
            "bolt_moving_to": (
                getattr(property_value, "actuatorState", "") == "BOLT_ACTUATOR_STATE_LOCKING"
            ),
            "battery_status": getattr(property_value, "replacementIndicator", None),
            "battery_voltage": (
                getattr(property_value.assessedVoltage, "value", None)
                if hasattr(property_value, "assessedVoltage") else None
            ),
            "using_protobuf": True
        }

    @staticmethod
    def _parse_enhanced_bolt_lock(property_value, device_id):
        """Parse lock data from EnhancedBoltLockSettingsTrait."""
        # Placeholder: Decode value like "\022\002\010<\210\002\001" (needs schema)
        return {
            "device_id": device_id,
            "bolt_locked": None,  # Unknown field; debug raw value
            "bolt_moving": None,
            "bolt_moving_to": None,
            "using_protobuf": True,
            "raw_value": property_value.hex()  # Preserve for debugging
        }