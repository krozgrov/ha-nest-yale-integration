import logging
import asyncio
from homeassistant.components.lock import LockEntity, LockState
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import device_registry as dr
from .const import DOMAIN, COMMAND_ERROR_CODE_FAILED
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
    """Representation of a Nest Yale Lock."""
    
    def __init__(self, coordinator, device):
        """Initialize the lock entity."""
        super().__init__(coordinator)
        self._coordinator = coordinator
        self._device = device.copy()
        # Store internal state as entity attributes, not in device dict
        self._bolt_moving = False
        self._bolt_moving_to: bool | None = None
        self._device_id = device.get("device_id")
        self._attr_unique_id = f"{DOMAIN}_{self._device_id}"
        metadata = self._coordinator.api_client.get_device_metadata(self._device_id)
        self._attr_name = metadata["name"]
        # Use device_id as stable identifier (never change it)
        # Serial number will be added as secondary identifier when trait data arrives
        self._attr_device_info = {
            "identifiers": {(DOMAIN, self._device_id)},
            "manufacturer": "Nest",
            "model": "Nest x Yale Lock",
            "name": self._attr_name,
            "sw_version": metadata["firmware_revision"],
        }
        self._attr_has_entity_name = False
        self._attr_should_poll = False
        self._state: LockState | None = None
        self._user_id = self._coordinator.api_client.user_id
        self._structure_id = self._coordinator.api_client.structure_id
        self._device_info_updated = False  # Track if we've updated device_info from traits
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
        """Return extra state attributes."""
        # Get serial number from identifiers (may be device_id initially, serial_number when trait data arrives)
        serial_number = next(iter(self._attr_device_info["identifiers"]))[1]
        attrs = {
            "bolt_moving": self._bolt_moving,
            "serial_number": serial_number,
            "firmware_revision": self._attr_device_info.get("sw_version", "unknown"),
            "user_id": self._user_id,
            "structure_id": self._structure_id,
        }
        
        # Extract trait data from device
        traits = self._device.get("traits", {})
        
        # DeviceIdentityTrait data
        device_identity = traits.get("DeviceIdentityTrait", {})
        if device_identity:
            if device_identity.get("serial_number"):
                attrs["serial_number"] = device_identity["serial_number"]
            if device_identity.get("firmware_version"):
                attrs["firmware_revision"] = device_identity["firmware_version"]
            if device_identity.get("manufacturer"):
                attrs["manufacturer"] = device_identity["manufacturer"]
            if device_identity.get("model"):
                attrs["model"] = device_identity["model"]
        
        # BatteryPowerSourceTrait data - only include if we have actual values
        battery_trait = traits.get("BatteryPowerSourceTrait", {})
        if battery_trait:
            if battery_trait.get("battery_level") is not None:
                # Convert to percentage (0.0-1.0 -> 0-100)
                battery_level = battery_trait["battery_level"]
                if isinstance(battery_level, float):
                    attrs["battery_level"] = round(battery_level * 100, 1)
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
            _LOGGER.info("Sending %s command to %s (user_id=%s, structure_id=%s, device_id=%s)",
                          "lock" if lock else "unlock", self._attr_unique_id, self._user_id, self._structure_id, self._device_id)
            response = await self._coordinator.api_client.send_command(cmd_any, self._device_id, structure_id=self._structure_id)
            response_hex = response.hex() if isinstance(response, bytes) else None
            if response_hex is not None:
                _LOGGER.debug("Lock command response: %s", response_hex)
            else:
                _LOGGER.debug("Lock command response (non-bytes): %s", response)
            if response_hex == COMMAND_ERROR_CODE_FAILED:
                _LOGGER.warning("Command failed with error code %s, not updating local state", COMMAND_ERROR_CODE_FAILED)
                return

            # Set optimistic state - the observe stream will confirm the actual state
            self._bolt_moving = True
            self._bolt_moving_to = lock
            self.async_write_ha_state()
            _LOGGER.info("Command %s sent successfully for %s, waiting for observe stream to confirm state change",
                         "lock" if lock else "unlock", self._attr_unique_id)

        except Exception as e:
            _LOGGER.error("Command failed for %s: %s", self._attr_unique_id, e, exc_info=True)
            self._bolt_moving = False
            self._bolt_moving_to = None
            self.async_schedule_update_ha_state()
            raise

    async def async_added_to_hass(self):
        _LOGGER.debug("Entity %s added to HA", self._attr_unique_id)
        await super().async_added_to_hass()

    def _handle_coordinator_update(self) -> None:
        new_data = self._coordinator.data.get(self._device_id)
        if new_data:
            old_state = self._device.copy()
            old_bolt_locked = self._device.get("bolt_locked", False)
            
            # Update device data
            self._device.update(new_data)
            self._user_id = self._coordinator.api_client.user_id
            self._structure_id = self._coordinator.api_client.structure_id
            
            # Update device_info if we have trait data with better metadata (only once)
            if not self._device_info_updated:
                traits = self._device.get("traits", {})
                device_identity = traits.get("DeviceIdentityTrait", {})
                if device_identity:
                    new_serial = device_identity.get("serial_number")
                    new_firmware = device_identity.get("firmware_version")
                    new_manufacturer = device_identity.get("manufacturer")
                    new_model = device_identity.get("model")
                    
                    if new_serial or new_firmware:
                        # Update _attr_device_info (but keep device_id as identifier to prevent duplicates)
                        if new_firmware:
                            self._attr_device_info["sw_version"] = new_firmware
                        if new_manufacturer:
                            self._attr_device_info["manufacturer"] = new_manufacturer
                        if new_model:
                            self._attr_device_info["model"] = new_model
                        
                        _LOGGER.info("Updated device_info for %s with trait data: serial=%s, fw=%s", 
                                   self._attr_unique_id, new_serial, new_firmware)
                        
                        # Update device registry so HA UI reflects the changes
                        # Best practice: Keep device_id as primary identifier, add serial as secondary
                        try:
                            device_registry = dr.async_get(self.hass)
                            # Find device by device_id (our stable identifier)
                            device = device_registry.async_get_device(identifiers={(DOMAIN, self._device_id)})
                            
                            if device:
                                update_kwargs = {}
                                # Add serial number as secondary identifier (Home Assistant supports multiple identifiers)
                                if new_serial:
                                    current_identifiers = set(device.identifiers)
                                    new_identifiers = current_identifiers | {(DOMAIN, new_serial)}
                                    if new_identifiers != current_identifiers:
                                        update_kwargs["new_identifiers"] = new_identifiers
                                if new_firmware and device.sw_version != new_firmware:
                                    update_kwargs["sw_version"] = new_firmware
                                if new_manufacturer and device.manufacturer != new_manufacturer:
                                    update_kwargs["manufacturer"] = new_manufacturer
                                if new_model and device.model != new_model:
                                    update_kwargs["model"] = new_model
                                
                                if update_kwargs:
                                    device_registry.async_update_device(device.id, **update_kwargs)
                                    _LOGGER.info("Updated device registry for %s: %s", self._attr_unique_id, update_kwargs)
                                    # Update _attr_device_info to match registry (for device_info property)
                                    if new_serial:
                                        self._attr_device_info["identifiers"] = {(DOMAIN, self._device_id), (DOMAIN, new_serial)}
                                    if new_firmware:
                                        self._attr_device_info["sw_version"] = new_firmware
                                    if new_manufacturer:
                                        self._attr_device_info["manufacturer"] = new_manufacturer
                                    if new_model:
                                        self._attr_device_info["model"] = new_model
                            else:
                                _LOGGER.warning("Could not find device in registry for %s (device_id=%s, serial=%s)", 
                                              self._attr_unique_id, self._device_id, new_serial)
                        except Exception as e:
                            _LOGGER.error("Error updating device registry for %s: %s", self._attr_unique_id, e, exc_info=True)
                        
                        self._device_info_updated = True
            
            # Update bolt_moving based on actuator state
            if "actuator_state" in new_data:
                actuator_state = new_data["actuator_state"]
                self._bolt_moving = actuator_state not in [weave_security_pb2.BoltLockTrait.BOLT_ACTUATOR_STATE_OK]
            else:
                # Clear optimistic state when we get a real update
                self._bolt_moving = False
            
            # Clear optimistic state when we get a real update
            if old_bolt_locked != self._device.get("bolt_locked", False):
                # State actually changed, clear optimistic flags
                self._bolt_moving = False
                self._bolt_moving_to = None
                _LOGGER.info("Lock state changed for %s: %s -> %s", self._attr_unique_id, 
                            "locked" if old_bolt_locked else "unlocked",
                            "locked" if self._device.get("bolt_locked", False) else "unlocked")
            
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
            _LOGGER.debug("Updated lock state for %s: old=%s, new=%s", self._attr_unique_id, old_state, self._device)
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
        available = bool(self._device) and self._coordinator.last_update_success
        _LOGGER.debug("Availability check for %s: %s", self._attr_unique_id, available)
        return available

    @property
    def device_info(self) -> dict:
        """Return device information."""
        return self._attr_device_info.copy()

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
