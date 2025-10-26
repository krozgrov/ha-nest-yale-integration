from __future__ import annotations

import logging
from collections.abc import Callable

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import (
    DATA_DIAGNOSTIC_STATUS,
    DEFAULT_DIAGNOSTIC_STATUS,
    DIAGNOSTIC_STATUS_OPTIONS,
    DOMAIN,
    SIGNAL_DIAGNOSTIC_STATUS_UPDATED,
)

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator = hass.data[DOMAIN][entry.entry_id]

    status_store = hass.data[DOMAIN].setdefault(DATA_DIAGNOSTIC_STATUS, {})
    status_store.setdefault(entry.entry_id, {})

    tracked: set[str] = set()

    def _gather_devices() -> dict[str, dict]:
        devices: dict[str, dict] = {}
        data = coordinator.data or {}
        if isinstance(data, dict):
            devices.update({device_id: device for device_id, device in data.items() if isinstance(device, dict)})
        current_state = coordinator.api_client.current_state.get("devices", {}).get("locks", {})
        if isinstance(current_state, dict):
            for device_id, device in current_state.items():
                if isinstance(device, dict):
                    devices.setdefault(device_id, device)
        return devices

    def _process_devices() -> None:
        devices = _gather_devices()
        _LOGGER.debug("Diagnostic sensor setup processing devices: %s", list(devices.keys()))
        new_entities: list[NestYaleDiagnosticStatusSensor] = []
        for device_id in devices:
            if device_id in tracked:
                continue
            tracked.add(device_id)
            new_entities.append(NestYaleDiagnosticStatusSensor(hass, coordinator, entry.entry_id, device_id))
            _LOGGER.debug("Prepared diagnostic status sensor for device_id=%s", device_id)
        if new_entities:
            async_add_entities(new_entities)
            _LOGGER.debug("Added %d diagnostic sensor entities", len(new_entities))

    _process_devices()
    cancel = coordinator.async_add_listener(_process_devices)
    entry.async_on_unload(cancel)


class NestYaleDiagnosticStatusSensor(SensorEntity):
    _attr_has_entity_name = True
    _attr_name = "Diagnostic Status"
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_device_class = SensorDeviceClass.ENUM
    _attr_options = DIAGNOSTIC_STATUS_OPTIONS
    _attr_should_poll = False
    _attr_entity_registry_enabled_default = True

    def __init__(self, hass: HomeAssistant, coordinator, entry_id: str, device_id: str) -> None:
        self.hass = hass
        self._coordinator = coordinator
        self._entry_id = entry_id
        self._device_id = device_id
        self._unsub_dispatcher: Callable[[], None] | None = None
        self._attr_unique_id = f"{DOMAIN}_{device_id}_diagnostic_status"
        metadata = coordinator.api_client.get_device_metadata(device_id)
        serial_number = metadata.get("serial_number") or device_id
        identifiers = {(DOMAIN, device_id)}
        if serial_number and serial_number != device_id:
            identifiers.add((DOMAIN, serial_number))
        self._attr_device_info = {
            "identifiers": identifiers,
            "manufacturer": "Nest",
            "model": "Nest x Yale Lock",
            "name": metadata["name"],
            "sw_version": metadata["firmware_revision"],
            "serial_number": serial_number,
        }

        status_store = hass.data[DOMAIN].setdefault(DATA_DIAGNOSTIC_STATUS, {})
        entry_store = status_store.setdefault(entry_id, {})
        self._attr_native_value = entry_store.get(device_id, DEFAULT_DIAGNOSTIC_STATUS)

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self._unsub_dispatcher = async_dispatcher_connect(
            self.hass,
            SIGNAL_DIAGNOSTIC_STATUS_UPDATED,
            self._handle_status_update,
        )

    async def async_will_remove_from_hass(self) -> None:
        if self._unsub_dispatcher:
            self._unsub_dispatcher()
            self._unsub_dispatcher = None
        await super().async_will_remove_from_hass()

    def _handle_status_update(self, entry_id: str, device_id: str, status: str) -> None:
        if entry_id != self._entry_id or device_id != self._device_id:
            return
        if status != self._attr_native_value:
            self._attr_native_value = status
            self.async_write_ha_state()
            _LOGGER.debug(
                "Diagnostic status sensor updated for device_id=%s to %s", self._device_id, status
            )
