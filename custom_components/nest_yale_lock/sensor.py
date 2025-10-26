from __future__ import annotations

from collections.abc import Callable

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import (
    DATA_ADDED_SENSOR_IDS,
    DATA_DIAGNOSTIC_STATUS,
    DEFAULT_DIAGNOSTIC_STATUS,
    DIAGNOSTIC_STATUS_OPTIONS,
    DOMAIN,
    SIGNAL_DIAGNOSTIC_STATUS_UPDATED,
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator = hass.data[DOMAIN][entry.entry_id]

    added_map = hass.data[DOMAIN].setdefault(DATA_ADDED_SENSOR_IDS, {})
    added: set[str] = added_map.setdefault(entry.entry_id, set())

    def _process_devices() -> None:
        data = coordinator.data or {}
        new_entities: list[NestYaleDiagnosticStatusSensor] = []
        for device_id in data:
            unique_id = f"{DOMAIN}_{device_id}_diagnostic_status"
            if unique_id in added:
                continue
            new_entities.append(NestYaleDiagnosticStatusSensor(hass, coordinator, entry.entry_id, device_id))
            added.add(unique_id)
        if new_entities:
            async_add_entities(new_entities)

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

    def __init__(self, hass: HomeAssistant, coordinator, entry_id: str, device_id: str) -> None:
        self.hass = hass
        self._coordinator = coordinator
        self._entry_id = entry_id
        self._device_id = device_id
        self._unsub_dispatcher: Callable[[], None] | None = None
        self._attr_unique_id = f"{DOMAIN}_{device_id}_diagnostic_status"
        metadata = coordinator.api_client.get_device_metadata(device_id)
        self._attr_device_info = {
            "identifiers": {(DOMAIN, metadata["serial_number"])},
            "manufacturer": "Nest",
            "model": "Nest x Yale Lock",
            "name": metadata["name"],
            "sw_version": metadata["firmware_revision"],
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
