import logging
import asyncio
from homeassistant.components.lock import LockEntity, LockState
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from .const import DOMAIN, GRPC_CODE_INTERNAL
from .entity import NestYaleEntity
from .proto.weave.trait import security_pb2 as weave_security_pb2
from .proto.nest import rpc_pb2
from .proto.nestlabs.gateway import v1_pb2

_LOGGER = logging.getLogger(__name__)

# Errors that indicate the connection to the lock is stale and needs reconnection
RECONNECT_ERROR_CODES = {GRPC_CODE_INTERNAL}  # "Internal error encountered"

# TraitOperation progress states
PROGRESS_STATE_NAMES = {0: "UNSPECIFIED", 1: "QUEUED", 2: "PENDING", 3: "STARTED", 4: "COMPLETE"}

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback):
    _LOGGER.debug("Starting async_setup_entry for lock platform, entry_id: %s", entry.entry_id)
    coordinator = hass.data[DOMAIN][entry.entry_id]

    # Use a per-entry tracker so removing/re-adding the integration does not
    # suppress rediscovery due to stale in-memory state.
    added_map = hass.data[DOMAIN].setdefault("added_lock_ids", {})
    added: set[str] = added_map.setdefault(entry.entry_id, set())

    @callback
    def _process_devices():
        data = coordinator.data or {}
        new_entities = []
        for device_id, device in data.items():
            if not isinstance(device, dict):
                continue
            # Backfill device_id from key when missing
            device.setdefault("device_id", device_id)
            unique_id = f"{DOMAIN}_{device_id}"
            if unique_id in added:
                continue
            new_entities.append(NestYaleLock(coordinator, device))
            added.add(unique_id)
            _LOGGER.debug("Prepared new lock entity: %s", unique_id)
        if new_entities:
            _LOGGER.info("Adding %d Nest Yale locks", len(new_entities))
            async_add_entities(new_entities)

    # Add whatever we have now, then subscribe for future updates
    _process_devices()
    cancel = coordinator.async_add_listener(_process_devices)
    # Ensure listener removal on unload
    entry.async_on_unload(cancel)

class NestYaleLock(NestYaleEntity, LockEntity):
    """Representation of a Nest Yale Lock."""
    
    def __init__(self, coordinator, device):
        """Initialize the lock entity."""
        device_id = device.get("device_id")
        super().__init__(coordinator, device_id, device)
        # Store internal state as entity attributes, not in device dict
        self._bolt_moving = False
        self._bolt_moving_to: bool | None = None
        self._attr_has_entity_name = False
        self._attr_should_poll = False
        self._state: LockState | None = None
        # Note: user_id and structure_id are now accessed via _get_device_attributes() in base class
        # Keeping these for backward compatibility with existing code that references them
        self._user_id = self._coordinator.api_client.user_id
        self._structure_id = self._coordinator.api_client.structure_id
        _LOGGER.debug(
            "Initialized lock with user_id: %s, structure_id: %s, device_id=%s, unique_id=%s, device=%s",
            self._user_id,
            self._structure_id,
            self._device_id,
            self._attr_unique_id,
            self._device_data,
        )

    @property
    def is_locked(self):
        state = self._device_data.get("bolt_locked", False)
        _LOGGER.debug("is_locked check for %s: %s", self._attr_unique_id, state)
        return state

    @property
    def is_locking(self):
        """Return true if lock is currently locking."""
        state = self._bolt_moving and self._bolt_moving_to is True
        _LOGGER.debug("is_locking check for %s: %s", self._attr_unique_id, state)
        return state

    @property
    def is_unlocking(self):
        """Return true if lock is currently unlocking."""
        state = self._bolt_moving and self._bolt_moving_to is False
        _LOGGER.debug("is_unlocking check for %s: %s", self._attr_unique_id, state)
        return state

    @property
    def extra_state_attributes(self):
        """Return extra state attributes in logical order.
        
        Follows HA best practices:
        - Entity-specific attributes (bolt_moving) in entity class
        - Device-level attributes from base class
        - Battery info grouped together
        """
        # Get common device-level attributes from base class
        attrs = self._get_device_attributes()
        
        # Build attributes in logical order:
        # 1. Bolt Moving (lock-specific)
        # 2. Battery info (all battery-related attributes grouped)
        # 3-7. Device-level attributes (from base class)
        
        # 1. Bolt Moving - lock-specific attribute
        attrs = {
            "bolt_moving": self._bolt_moving,
            **attrs,  # Merge device-level attributes
        }
        
        # 2. Battery info - group all battery attributes together
        traits = self._device_data.get("traits", {})
        battery_trait = traits.get("BatteryPowerSourceTrait", {})
        if battery_trait:
            if battery_trait.get("battery_level") is not None:
                # Convert to percentage (0.0-1.0 -> 0-100) and round to whole number
                battery_level = battery_trait["battery_level"]
                if isinstance(battery_level, float):
                    attrs["battery_level"] = round(battery_level * 100)
                elif isinstance(battery_level, (int, float)):
                    attrs["battery_level"] = int(round(battery_level * 100 if battery_level <= 1.0 else battery_level))
                else:
                    attrs["battery_level"] = battery_level
            if battery_trait.get("voltage") is not None:
                attrs["battery_voltage"] = battery_trait["voltage"]
            if battery_trait.get("condition") is not None:
                attrs["battery_condition"] = battery_trait["condition"]
            if battery_trait.get("status") is not None:
                attrs["battery_status"] = battery_trait["status"]
            if battery_trait.get("replacement_indicator") is not None:
                attrs["battery_replacement_indicator"] = battery_trait["replacement_indicator"]
        
        # Reorder to match requested order:
        # 1. Bolt Moving, 2. Battery info, 3. Structure ID, 4. Device ID, 5. User ID, 6. Firmware, 7. Serial Number
        ordered_attrs = {
            "bolt_moving": attrs.pop("bolt_moving"),
        }
        
        # Add battery attributes if present
        battery_keys = ["battery_level", "battery_voltage", "battery_condition", "battery_status", "battery_replacement_indicator"]
        for key in battery_keys:
            if key in attrs:
                ordered_attrs[key] = attrs.pop(key)
        
        # Add remaining device-level attributes in order
        for key in ["structure_id", "device_id", "user_id", "firmware_revision", "serial_number"]:
            if key in attrs:
                ordered_attrs[key] = attrs.pop(key)
        
        # Add any remaining attributes (manufacturer, model, etc.)
        ordered_attrs.update(attrs)
        
        _LOGGER.debug("Extra state attributes for %s: %s", self._attr_unique_id, ordered_attrs)
        return ordered_attrs

    async def async_lock(self, **kwargs):
        _LOGGER.debug("UI triggered async_lock for %s, kwargs: %s, current state: %s",
                      self._attr_unique_id, kwargs, self.state)
        await self._send_command(True)

    async def async_unlock(self, **kwargs):
        _LOGGER.debug("UI triggered async_unlock for %s, kwargs: %s, current state: %s",
                      self._attr_unique_id, kwargs, self.state)
        await self._send_command(False)

    def _parse_command_response(self, response: bytes):
        """Parse command response to check for errors.
        
        Returns:
            tuple: (success: bool, error_code: int | None, error_message: str | None)
        """
        if not response:
            return True, None, None
        
        # Log response for debugging
        _LOGGER.debug("Parsing command response (%d bytes): %s", len(response), response[:50].hex() if len(response) > 50 else response.hex())
        
        # Try to parse as StreamBody which wraps Status (field 2)
        # The error response format is: 12 1f 08 0d 12 1b ... (StreamBody with status)
        try:
            stream_body = rpc_pb2.StreamBody()
            stream_body.ParseFromString(response)
            _LOGGER.debug("StreamBody parse: has_status=%s, status.code=%s, status.message=%s",
                         stream_body.HasField("status") if hasattr(stream_body, 'HasField') else 'N/A',
                         stream_body.status.code if stream_body.status else 'N/A',
                         stream_body.status.message if stream_body.status else 'N/A')
            
            # Check status - don't use HasField, just check the code directly
            if stream_body.status.code != 0:
                error_code = stream_body.status.code
                error_message = stream_body.status.message or f"Error code {error_code}"
                _LOGGER.warning("StreamBody error detected: %s (code=%s)", error_message, error_code)
                return False, error_code, error_message
        except Exception as e:
            _LOGGER.debug("Could not parse as StreamBody: %s", e)
        
        # Try parsing as Status directly (in case it's not wrapped)
        try:
            status = rpc_pb2.Status()
            status.ParseFromString(response)
            _LOGGER.debug("Status parse: code=%s, message=%s", status.code, status.message)
            if status.code != 0:
                error_code = status.code
                error_message = status.message or f"Error code {error_code}"
                _LOGGER.warning("Status error detected: %s (code=%s)", error_message, error_code)
                return False, error_code, error_message
        except Exception as e:
            _LOGGER.debug("Could not parse as Status: %s", e)
        
        # Try ResourceCommandResponseFromAPI for successful command responses
        try:
            api_response = v1_pb2.ResourceCommandResponseFromAPI()
            api_response.ParseFromString(response)
            
            # Only process if we actually have response data
            if api_response.resouceCommandResponse:
                for cmd_response in api_response.resouceCommandResponse:
                    for trait_op in cmd_response.traitOperations:
                        progress = trait_op.progress
                        progress_name = PROGRESS_STATE_NAMES.get(progress, f"UNKNOWN({progress})")
                        _LOGGER.info("Command progress: %s", progress_name)
                        
                        # Check for status error in the TraitOperation
                        if trait_op.HasField("status") and trait_op.status.code != 0:
                            error_code = trait_op.status.code
                            error_message = trait_op.status.message or f"Error code {error_code}"
                            _LOGGER.warning("TraitOperation error: %s (code=%s)", error_message, error_code)
                            return False, error_code, error_message
                        
                        # If progress is QUEUED or PENDING, the command might not reach the lock
                        if progress in (1, 2):  # QUEUED or PENDING
                            _LOGGER.warning("Command is %s - lock may be unreachable", progress_name)
                
                # If we got here with actual response data, command succeeded
                return True, None, None
        except Exception as e:
            _LOGGER.debug("Could not parse as ResourceCommandResponseFromAPI: %s", e)
        
        # If we couldn't parse anything meaningful, assume success
        # (better to fail on the timeout than block commands)
        _LOGGER.debug("Could not parse command response, assuming success")
        return True, None, None

    async def _send_command(self, lock: bool):
        """Send lock/unlock command with auto-retry on stale session."""
        await self._send_command_internal(lock, is_retry=False)

    async def _send_command_internal(self, lock: bool, is_retry: bool = False):
        """Internal command sender that handles retry logic."""
        # Refresh identifiers before issuing the command to keep payload accurate.
        self._user_id = self._coordinator.api_client.user_id
        self._structure_id = self._coordinator.api_client.structure_id

        state = weave_security_pb2.BoltLockTrait.BOLT_STATE_EXTENDED if lock else weave_security_pb2.BoltLockTrait.BOLT_STATE_RETRACTED
        request = weave_security_pb2.BoltLockTrait.BoltLockChangeRequest()
        request.state = state
        request.boltLockActor.method = weave_security_pb2.BoltLockTrait.BOLT_LOCK_ACTOR_METHOD_REMOTE_USER_EXPLICIT
        request.boltLockActor.originator.resourceId = str(self._user_id) if self._user_id else "UNKNOWN_USER_ID"

        cmd_any = {
            "traitLabel": "bolt_lock",
            "command": {
                "type_url": "type.nestlabs.com/weave.trait.security.BoltLockTrait.BoltLockChangeRequest",
                "value": request.SerializeToString(),
            }
        }

        try:
            retry_prefix = "[RETRY] " if is_retry else ""
            _LOGGER.info("%sSending %s command to %s (user_id=%s, structure_id=%s, device_id=%s)",
                          retry_prefix, "lock" if lock else "unlock", self._attr_unique_id, self._user_id, self._structure_id, self._device_id)
            response = await self._coordinator.api_client.send_command(cmd_any, self._device_id, structure_id=self._structure_id)
            response_hex = response.hex() if isinstance(response, bytes) else None
            if response_hex is not None:
                _LOGGER.debug("Lock command response: %s", response_hex)
            else:
                _LOGGER.debug("Lock command response (non-bytes): %s", response)
            
            # Parse the response to check for errors
            success, error_code, error_message = self._parse_command_response(response)
            if not success:
                _LOGGER.warning("%sCommand %s failed for %s: %s (code=%s)", 
                               retry_prefix, "lock" if lock else "unlock", self._attr_unique_id, error_message, error_code)
                
                # Check if this error indicates a stale connection that needs reconnection
                if error_code in RECONNECT_ERROR_CODES and not is_retry:
                    _LOGGER.info("Triggering session reset and auto-retry due to connection error")
                    await self._trigger_observe_reconnect()
                    
                    # Wait for observe stream to reconnect and get fresh structure_id
                    _LOGGER.info("Waiting 5 seconds for observe stream to reconnect...")
                    await asyncio.sleep(5)
                    
                    # Refresh identifiers from the reconnected stream
                    self._user_id = self._coordinator.api_client.user_id
                    self._structure_id = self._coordinator.api_client.structure_id
                    _LOGGER.info("After reconnect: user_id=%s, structure_id=%s", self._user_id, self._structure_id)
                    
                    _LOGGER.info("Auto-retrying %s command...", "lock" if lock else "unlock")
                    await self._send_command_internal(lock, is_retry=True)
                elif is_retry:
                    _LOGGER.error("Retry also failed - the lock may be offline or there's a persistent issue")
                return

            # Set optimistic state - the observe stream will confirm the actual state
            self._bolt_moving = True
            self._bolt_moving_to = lock
            self.async_write_ha_state()
            _LOGGER.info("%sCommand %s sent successfully for %s, waiting for observe stream to confirm state change",
                         retry_prefix, "lock" if lock else "unlock", self._attr_unique_id)

        except Exception as e:
            _LOGGER.error("Command failed for %s: %s", self._attr_unique_id, e, exc_info=True)
            self._bolt_moving = False
            self._bolt_moving_to = None
            self.async_schedule_update_ha_state()
            raise

    async def _trigger_observe_reconnect(self):
        """Trigger a full reconnection by closing HTTP session and re-authenticating.
        
        This is called when a command fails with an error indicating the
        connection to the lock is stale (e.g., "Internal error encountered").
        Since the Nest app still works, our session is stale and needs refresh.
        """
        try:
            _LOGGER.info("Triggering full session reset and re-authentication")
            
            api_client = self._coordinator.api_client
            
            # Close the existing HTTP session to force fresh TCP connections
            if api_client.session and not api_client.session.closed:
                _LOGGER.info("Closing existing HTTP session...")
                await api_client.session.close()
            
            # Create a fresh HTTP session
            import aiohttp
            api_client.session = aiohttp.ClientSession()
            _LOGGER.info("Created fresh HTTP session")
            
            # Clear credentials to force full re-authentication
            api_client.access_token = None
            api_client.connection.connected = False
            
            # Cancel the current observer task - it will reconnect with fresh session
            coordinator = self._coordinator
            if hasattr(coordinator, '_observer_task') and coordinator._observer_task:
                coordinator._observer_task.cancel()
                _LOGGER.info("Observer task cancelled, will reconnect with fresh session")
            
            _LOGGER.info("Session reset complete - retry your command")
        except Exception as e:
            _LOGGER.warning("Failed to trigger reconnect: %s", e)

    async def async_added_to_hass(self):
        _LOGGER.debug("Entity %s added to HA", self._attr_unique_id)
        await super().async_added_to_hass()

    def _handle_coordinator_update(self) -> None:
        new_data = self._coordinator.data.get(self._device_id)
        if new_data:
            old_state = self._device_data.copy()
            old_bolt_locked = self._device_data.get("bolt_locked", False)
            
            # Update device data
            self._device_data.update(new_data)
            self._user_id = self._coordinator.api_client.user_id
            self._structure_id = self._coordinator.api_client.structure_id
            
            # Update device_info from traits (handled by base class)
            self._update_device_info_from_traits()
            
            # Update bolt_moving based on actuator state
            if "actuator_state" in new_data:
                actuator_state = new_data["actuator_state"]
                self._bolt_moving = actuator_state not in [weave_security_pb2.BoltLockTrait.BOLT_ACTUATOR_STATE_OK]
            else:
                # Clear optimistic state when we get a real update
                self._bolt_moving = False
            
            # Clear optimistic state when we get a real update
            if old_bolt_locked != self._device_data.get("bolt_locked", False):
                # State actually changed, clear optimistic flags
                self._bolt_moving = False
                self._bolt_moving_to = None
                _LOGGER.info("Lock state changed for %s: %s -> %s", self._attr_unique_id, 
                            "locked" if old_bolt_locked else "unlocked",
                            "locked" if self._device_data.get("bolt_locked", False) else "unlocked")
            
            # Set HA state based on actual lock state
            if self.is_locked:
                self._state = LockState.LOCKED
            elif self.is_unlocking:
                self._state = LockState.UNLOCKING
            elif self.is_locking:
                self._state = LockState.LOCKING
            else:
                self._state = LockState.UNLOCKED
            
            self.async_write_ha_state()
            _LOGGER.debug("Updated lock state for %s: old=%s, new=%s", self._attr_unique_id, old_state, self._device_data)
        else:
            _LOGGER.debug("No updated data for lock %s in coordinator", self._attr_unique_id)
            self._bolt_moving = False
            self._bolt_moving_to = None
            self.async_write_ha_state()

    async def _clear_bolt_moving(self):
        """Clear bolt_moving state after delay."""
        await asyncio.sleep(5)
        self._bolt_moving = False
        self.async_schedule_update_ha_state()
        _LOGGER.debug("Cleared bolt_moving for %s after delay", self._attr_unique_id)

    @property
    def available(self) -> bool:
        """Return if entity is available."""
        available = bool(self._device_data) and self._coordinator.last_update_success
        _LOGGER.debug("Availability check for %s: %s", self._attr_unique_id, available)
        return available

    @property
    def state(self) -> LockState:
        """Return the current lock state."""
        if self.is_locking:
            return LockState.LOCKING
        elif self.is_unlocking:
            return LockState.UNLOCKING
        elif self.is_locked:
            return LockState.LOCKED
        return LockState.UNLOCKED

    async def async_update(self) -> None:
        """Update entity state."""
        _LOGGER.debug("Forcing update for %s", self._attr_unique_id)
        await self._coordinator.async_request_refresh()

    async def async_will_remove_from_hass(self) -> None:
        """Run when entity will be removed from Home Assistant."""
        _LOGGER.debug("Removing entity %s from HA", self._attr_unique_id)
        await super().async_will_remove_from_hass()
