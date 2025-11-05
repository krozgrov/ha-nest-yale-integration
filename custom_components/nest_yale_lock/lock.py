import logging
import asyncio
from homeassistant.components.lock import LockEntity, LockState
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from .const import DOMAIN
from .proto.weave.trait import security_pb2 as weave_security_pb2

_LOGGER = logging.getLogger(__name__)

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

class NestYaleLock(CoordinatorEntity, LockEntity):
    def __init__(self, coordinator, device):
        super().__init__(coordinator)
        self._coordinator = coordinator
        self._device = device.copy()
        self._device["bolt_moving"] = False
        self._device["bolt_moving_to"] = None
        self._device_id = device.get("device_id")
        self._attr_unique_id = f"{DOMAIN}_{self._device_id}"
        metadata = self._coordinator.api_client.get_device_metadata(self._device_id)
        serial_number = metadata.get("serial_number") or self._device_id
        identifiers = {(DOMAIN, self._device_id)}
        if serial_number and serial_number != self._device_id:
            identifiers.add((DOMAIN, serial_number))
        self._attr_name = metadata["name"]
        self._attr_device_info = {
            "identifiers": identifiers,
            "manufacturer": "Nest",
            "model": "Nest x Yale Lock",
            "name": self._attr_name,
            "sw_version": metadata["firmware_revision"],
            "serial_number": serial_number,
        }
        # Don't set supported_features - LockEntity provides lock/unlock by default
        # Setting it to 0 would make the entity read-only
        self._attr_has_entity_name = False
        self._attr_should_poll = False
        self._state = None
        self._user_id = self._coordinator.api_client.user_id
        self._structure_id = self._coordinator.api_client.structure_id
        _LOGGER.debug(
            "Initialized lock with user_id: %s, structure_id: %s, device_id=%s, unique_id=%s, device=%s",
            self._user_id,
            self._structure_id,
            self._device_id,
            self._attr_unique_id,
            self._device,
        )

    @property
    def is_locked(self):
        state = self._device.get("bolt_locked", False)
        _LOGGER.debug("is_locked check for %s: %s", self._attr_unique_id, state)
        return state

    @property
    def is_locking(self):
        state = self._device.get("bolt_moving", False) and self._device.get("bolt_moving_to", False)
        _LOGGER.debug("is_locking check for %s: %s", self._attr_unique_id, state)
        return state

    @property
    def is_unlocking(self):
        state = self._device.get("bolt_moving", False) and not self._device.get("bolt_moving_to", True)
        _LOGGER.debug("is_unlocking check for %s: %s", self._attr_unique_id, state)
        return state

    @property
    def extra_state_attributes(self):
        attrs = {
            "bolt_moving": self._device.get("bolt_moving", False),
            "bolt_moving_to": self._device.get("bolt_moving_to"),
            "battery_status": self._device.get("battery_status"),
            "battery_voltage": self._device.get("battery_voltage"),
            "serial_number": self._attr_device_info.get("serial_number", self._device_id),
            "firmware_revision": self._attr_device_info["sw_version"],
            "user_id": self._user_id,
            "structure_id": self._structure_id,
        }
        _LOGGER.debug("Extra state attributes for %s: %s", self._attr_unique_id, attrs)
        return attrs

    async def async_lock(self, **kwargs):
        _LOGGER.debug("UI triggered async_lock for %s, kwargs: %s, current state: %s",
                      self._attr_unique_id, kwargs, self.state)
        await self._send_command(True)

    async def async_unlock(self, **kwargs):
        _LOGGER.debug("UI triggered async_unlock for %s, kwargs: %s, current state: %s",
                      self._attr_unique_id, kwargs, self.state)
        await self._send_command(False)

    async def _send_command(self, lock: bool):
        """Send lock/unlock command following Home Assistant best practices.
        
        - Optimistically updates state for immediate UI feedback
        - Relies on coordinator/observe stream for actual state updates
        - Proper error handling with state consistency
        """
        # Refresh identifiers before issuing the command to keep payload accurate
        self._user_id = self._coordinator.api_client.user_id
        self._structure_id = self._coordinator.api_client.structure_id

        if not self._user_id:
            _LOGGER.error("Cannot send command: user_id not available")
            raise RuntimeError("User ID not available for command")

        # Build the protobuf command request
        state = weave_security_pb2.BoltLockTrait.BOLT_STATE_EXTENDED if lock else weave_security_pb2.BoltLockTrait.BOLT_STATE_RETRACTED
        request = weave_security_pb2.BoltLockTrait.BoltLockChangeRequest()
        request.state = state
        request.boltLockActor.method = weave_security_pb2.BoltLockTrait.BOLT_LOCK_ACTOR_METHOD_REMOTE_USER_EXPLICIT
        request.boltLockActor.originator.resourceId = str(self._user_id)

        cmd_any = {
            "traitLabel": "bolt_lock",
            "command": {
                "type_url": "type.nestlabs.com/weave.trait.security.BoltLockTrait.BoltLockChangeRequest",
                "value": request.SerializeToString(),
            }
        }

        # Optimistically update state for immediate UI feedback
        # The observe stream will provide the actual state confirmation
        self._device["bolt_moving"] = True
        self._device["bolt_moving_to"] = lock
        self._state = LockState.LOCKING if lock else LockState.UNLOCKING
        self.async_write_ha_state()

        try:
            _LOGGER.info(
                "Sending %s command to %s (user_id=%s, structure_id=%s, device_id=%s)",
                "lock" if lock else "unlock",
                self._attr_unique_id,
                self._user_id,
                self._structure_id,
                self._device_id,
            )
            
            # Send command - this may raise an exception
            result = await self._coordinator.api_client.send_command(cmd_any, self._device_id, self._structure_id)
            
            _LOGGER.info(
                "Command %s sent successfully for %s, result=%s. Waiting for observe stream to confirm state.",
                "lock" if lock else "unlock",
                self._attr_unique_id,
                result,
            )
            # Note: We don't wait here - the observe stream will update state automatically
            # The optimistic update above provides immediate feedback
            
        except Exception as e:
            _LOGGER.error("Command failed for %s: %s", self._attr_unique_id, e, exc_info=True)
            # Revert optimistic state on error
            self._device["bolt_moving"] = False
            self.async_write_ha_state()
            # Re-raise to let Home Assistant handle the error appropriately
            raise

    async def async_added_to_hass(self):
        _LOGGER.debug("Entity %s added to HA", self._attr_unique_id)
        await super().async_added_to_hass()

    def _handle_coordinator_update(self) -> None:
        """Handle coordinator updates from observe stream.
        
        Preserves optimistic state updates during command execution.
        """
        new_data = self._coordinator.data.get(self._device_id)
        if new_data:
            old_state = self._device.copy()
            old_bolt_locked = self._device.get("bolt_locked")
            
            # Update device data
            self._device.update(new_data)
            self._user_id = self._coordinator.api_client.user_id
            self._structure_id = self._coordinator.api_client.structure_id
            
            # Handle bolt_moving flag from stream
            # Only update if stream explicitly provides it, otherwise preserve local state
            if "bolt_moving" in new_data:
                stream_bolt_moving = new_data["bolt_moving"]
                # If stream says it's moving, create task to clear it
                if stream_bolt_moving:
                    self._device["bolt_moving"] = True
                    asyncio.create_task(self._clear_bolt_moving())
                else:
                    # Stream says not moving - only clear if we're not in the middle of a command
                    # Check if lock state actually changed - if not, preserve moving state briefly
                    new_bolt_locked = self._device.get("bolt_locked")
                    if old_bolt_locked != new_bolt_locked:
                        # State changed, command completed
                        self._device["bolt_moving"] = False
                    # If state didn't change, keep moving flag for a bit longer (command might still be processing)
            
            # Set HA state based on actual lock state
            if self.is_locked:
                self._state = LockState.LOCKED
            else:
                self._state = LockState.UNLOCKED
                
            self.async_write_ha_state()
            
            if old_state != self._device:
                _LOGGER.info(
                    "Updated lock state for %s: bolt_locked=%s->%s, bolt_moving=%s",
                    self._attr_unique_id,
                    old_state.get("bolt_locked"),
                    self._device.get("bolt_locked"),
                    self._device.get("bolt_moving"),
                )
        else:
            _LOGGER.debug("No updated data for lock %s in coordinator", self._attr_unique_id)
            # Don't clear bolt_moving if we have no data - might be mid-command

    async def _clear_bolt_moving(self):
        """Clear bolt_moving flag after delay."""
        await asyncio.sleep(5)
        self._device["bolt_moving"] = False
        self.async_write_ha_state()
        _LOGGER.debug("Cleared bolt_moving for %s after delay", self._attr_unique_id)

    @property
    def available(self):
        """Check if entity is available."""
        # Check coordinator health and connection status
        coordinator_healthy = self._coordinator.last_update_success
        has_device_data = bool(self._device)
        # Check if API client connection is healthy
        api_healthy = getattr(self._coordinator.api_client, '_connection_healthy', True)
        available = has_device_data and coordinator_healthy and api_healthy
        if not available:
            _LOGGER.debug(
                "Availability check for %s: device_data=%s, coordinator=%s, api=%s",
                self._attr_unique_id, has_device_data, coordinator_healthy, api_healthy
            )
        return available

    @property
    def device_info(self):
        return self._attr_device_info

    @property
    def state(self):
        if self.is_locking:
            return LockState.LOCKING
        elif self.is_unlocking:
            return LockState.UNLOCKING
        elif self.is_locked:
            return LockState.LOCKED
        return LockState.UNLOCKED

    async def async_update(self):
        _LOGGER.debug("Forcing update for %s", self._attr_unique_id)
        await self._coordinator.async_request_refresh()

    async def async_will_remove_from_hass(self):
        _LOGGER.debug("Removing entity %s from HA", self._attr_unique_id)
