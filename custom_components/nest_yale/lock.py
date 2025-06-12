#!/usr/bin/env python3
import logging
import asyncio
from homeassistant.components.lock import LockEntity, LockState
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from .const import DOMAIN
from .proto import weave_security_pb2

_LOGGER = logging.getLogger(__name__)

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback):
    _LOGGER.debug("Starting async_setup_entry for lock platform, entry_id: %s", entry.entry_id)
    coordinator = hass.data[DOMAIN][entry.entry_id]
    locks_data = coordinator.data
    _LOGGER.debug("Coordinator data at setup: %s", locks_data)

    if locks_data is None or not locks_data:
        _LOGGER.warning("No lock data available yet, waiting for observer updates.")
        await asyncio.sleep(5)
        locks_data = coordinator.data
        if not locks_data:
            _LOGGER.error("Still no lock data after waiting, setup failed.")
            return

    locks = []
    existing_entities = hass.data[DOMAIN].get("entities", [])
    existing_ids = {entity.unique_id for entity in existing_entities}
    _LOGGER.debug("Existing entity IDs: %s", existing_ids)

    for device_id, device in locks_data.items():
        _LOGGER.debug("Processing device_id: %s, device: %s", device_id, device)
        if not isinstance(device, dict):
            _LOGGER.warning("Invalid device entry for %s: %s", device_id, device)
            continue
        if "device_id" not in device:
            _LOGGER.warning("Skipping device without 'device_id': %s", device)
            continue
        unique_id = f"{DOMAIN}_{device_id}"
        if unique_id not in existing_ids:
            lock = NestYaleLock(coordinator, device)
            locks.append(lock)
            hass.data[DOMAIN]["entities"].append(lock)
            _LOGGER.debug("Added new lock entity: %s", unique_id)

    if locks:
        _LOGGER.info("Adding %d Nest Yale locks", len(locks))
        async_add_entities(locks)
    else:
        _LOGGER.warning("No valid locks found to add.")

class NestYaleLock(LockEntity):
    def __init__(self, coordinator, device):
        self._coordinator = coordinator
        self._device = device.copy()
        self._device["bolt_moving"] = False
        self._device["bolt_moving_to"] = None
        self._device_id = device.get("device_id")
        self._attr_unique_id = f"{DOMAIN}_{self._device_id}"
        metadata = self._coordinator.api_client.get_device_metadata(self._device_id)
        self._attr_name = metadata["name"]
        self._attr_device_info = {
            "identifiers": {(DOMAIN, metadata["serial_number"])},
            "manufacturer": "Nest",
            "model": "Nest x Yale Lock",
            "name": self._attr_name,
            "sw_version": metadata["firmware_revision"],
        }
        self._attr_entity_id = f"lock.{self._attr_unique_id.replace(':', '_').lower()}"
        self._attr_supported_features = 0
        self._attr_has_entity_name = False
        self._attr_should_poll = False
        self._state = None
        self._user_id = self._coordinator.api_client.user_id
        self._structure_id = self._coordinator.api_client.structure_id
        _LOGGER.debug("Initialized lock with user_id: %s, structure_id: %s, device_id=%s, unique_id=%s, entity_id=%s, device=%s",
                      self._user_id, self._structure_id, self._device_id, self._attr_unique_id, self._attr_entity_id, self._device)

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
        serial_number = next(iter(self._attr_device_info["identifiers"]))[1]
        attrs = {
            "bolt_moving": self._device.get("bolt_moving", False),
            "bolt_moving_to": self._device.get("bolt_moving_to"),
            "battery_status": self._device.get("battery_status"),
            "battery_voltage": self._device.get("battery_voltage"),
            "serial_number": serial_number,
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
            if not self._structure_id:
                _LOGGER.warning(
                    "Structure ID missing for %s, refreshing state before command",
                    self._attr_unique_id,
                )
                await self._coordinator.async_request_refresh()
                self._structure_id = self._coordinator.api_client.structure_id
                if not self._structure_id:
                    _LOGGER.error(
                        "Structure ID is not available for %s, cannot send command.",
                        self._attr_entity_id,
                    )
                    return

            _LOGGER.debug(
                "Sending %s command to %s with cmd_any (user_id=%s, structure_id=%s): %s",
                "lock" if lock else "unlock",
                self._attr_unique_id,
                self._user_id,
                self._structure_id,
                cmd_any,
            )
            response = await self._coordinator.api_client.send_command(cmd_any, self._device_id)
            _LOGGER.debug("Lock command response: %s", response.hex())
            if response.hex() == "12020802":  # Updated to match actual response
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
        @callback
        def update_listener():
            new_data = self._coordinator.data.get(self._device_id)
            if new_data:
                old_state = self._device.copy()
                self._device.update(new_data)
                if "bolt_moving" in new_data and new_data["bolt_moving"]:
                    self._device["bolt_moving"] = True
                    asyncio.create_task(self._clear_bolt_moving())
                else:
                    self._device["bolt_moving"] = False
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

        self.async_on_remove(self._coordinator.async_add_listener(update_listener))

    async def _clear_bolt_moving(self):
        await asyncio.sleep(5)
        self._device["bolt_moving"] = False
        self.async_schedule_update_ha_state()  # Replace force_refresh
        _LOGGER.debug("Cleared bolt_moving for %s after delay", self._attr_unique_id)

    @property
    def available(self):
        available = bool(self._device)
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
        self.async_schedule_update_ha_state()  # Replace force_refresh

    async def async_update_ha_state(self):
        self.async_write_ha_state()
        await asyncio.sleep(0.1)

    async def async_will_remove_from_hass(self):
        _LOGGER.debug("Removing entity %s from HA", self._attr_unique_id)