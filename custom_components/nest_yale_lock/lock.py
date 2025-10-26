import logging
import asyncio
from homeassistant.components.lock import LockEntity, LockState
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.helpers.dispatcher import async_dispatcher_send
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from .const import DOMAIN, DATA_KNOWN_DEVICE_IDS, SIGNAL_DEVICE_DISCOVERED
from .device_helpers import ensure_device_registered
from .proto.weave.trait import security_pb2 as weave_security_pb2

_LOGGER = logging.getLogger(__name__)

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback):
    _LOGGER.debug("Starting async_setup_entry for lock platform, entry_id: %s", entry.entry_id)
    coordinator = hass.data[DOMAIN][entry.entry_id]
    known_devices = hass.data[DOMAIN].setdefault(DATA_KNOWN_DEVICE_IDS, {}).setdefault(entry.entry_id, set())

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
            metadata = coordinator.api_client.get_device_metadata(device_id)
            ensure_device_registered(hass, entry.entry_id, device_id, metadata)
            new_entities.append(NestYaleLock(coordinator, device))
            added.add(unique_id)
            known_devices.add(device_id)
            _LOGGER.debug("Prepared new lock entity: %s", unique_id)
            async_dispatcher_send(hass, SIGNAL_DEVICE_DISCOVERED, entry.entry_id, device_id)
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
        self._attr_supported_features = 0
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
            _LOGGER.debug("Sending %s command to %s with cmd_any (user_id=%s, structure_id=%s): %s",
                          "lock" if lock else "unlock", self._attr_unique_id, self._user_id, self._structure_id, cmd_any)
            response = await self._coordinator.api_client.send_command(cmd_any, self._device_id)
            response_hex = response.hex() if isinstance(response, bytes) else None
            if response_hex is not None:
                _LOGGER.debug("Lock command response: %s", response_hex)
            else:
                _LOGGER.debug("Lock command response (non-bytes): %s", response)
            if response_hex == "12020802":  # Updated to match actual response
                _LOGGER.warning("Command failed with 12020802, not updating local state")
                return

            self._device["bolt_moving"] = True
            self._device["bolt_moving_to"] = lock
            self._state = LockState.LOCKING if lock else LockState.UNLOCKING
            self.async_schedule_update_ha_state()  # Replace force_refresh
            await asyncio.sleep(5)
            self._device["bolt_moving"] = False
            await self._coordinator.async_request_refresh()
            _LOGGER.debug("Refresh successful, updated state: %s", self._device)

        except Exception as e:
            _LOGGER.error("Command failed for %s: %s", self._attr_unique_id, e, exc_info=True)
            self._device["bolt_moving"] = False
            self.async_schedule_update_ha_state()  # Replace force_refresh
            raise

    async def async_added_to_hass(self):
        _LOGGER.debug("Entity %s added to HA", self._attr_unique_id)
        await super().async_added_to_hass()

    def _handle_coordinator_update(self) -> None:
        new_data = self._coordinator.data.get(self._device_id)
        if new_data:
            old_state = self._device.copy()
            self._device.update(new_data)
            self._user_id = self._coordinator.api_client.user_id
            self._structure_id = self._coordinator.api_client.structure_id
            # Normalize movement flag
            if "bolt_moving" in new_data and new_data["bolt_moving"]:
                self._device["bolt_moving"] = True
                asyncio.create_task(self._clear_bolt_moving())
            else:
                self._device["bolt_moving"] = False
            # Set HA state
            if self.is_locked:
                self._state = LockState.LOCKED
            else:
                self._state = LockState.UNLOCKED
            self.async_write_ha_state()
            _LOGGER.debug("Updated lock state for %s: old=%s, new=%s", self._attr_unique_id, old_state, self._device)
        else:
            _LOGGER.debug("No updated data for lock %s in coordinator", self._attr_unique_id)
            self._device["bolt_moving"] = False
            self.async_write_ha_state()

    async def _clear_bolt_moving(self):
        await asyncio.sleep(5)
        self._device["bolt_moving"] = False
        self.async_schedule_update_ha_state()  # Replace force_refresh
        _LOGGER.debug("Cleared bolt_moving for %s after delay", self._attr_unique_id)

    @property
    def available(self):
        available = bool(self._device) and self._coordinator.last_update_success
        _LOGGER.debug("Availability check for %s: %s", self._attr_unique_id, available)
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
