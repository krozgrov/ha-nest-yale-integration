from __future__ import annotations

import logging
from collections.abc import Callable

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers import entity_registry as er

from .const import (
    DATA_DIAGNOSTIC_STATUS,
    DATA_KNOWN_DEVICE_IDS,
    DEFAULT_DIAGNOSTIC_STATUS,
    DIAGNOSTIC_STATUS_OPTIONS,
    DOMAIN,
    SIGNAL_DEVICE_DISCOVERED,
    SIGNAL_DIAGNOSTIC_STATUS_UPDATED,
)
from .device_helpers import ensure_device_registered

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator = hass.data[DOMAIN][entry.entry_id]

    status_store = hass.data[DOMAIN].setdefault(DATA_DIAGNOSTIC_STATUS, {})
    status_store.setdefault(entry.entry_id, {})

    added: set[str] = set()

    def _add_entity(device_id: str) -> None:
        if device_id in added:
            return
        added.add(device_id)
        _LOGGER.debug("Prepared diagnostic sensor for device_id=%s", device_id)
        metadata = coordinator.api_client.get_device_metadata(device_id)
        ensure_device_registered(hass, entry.entry_id, device_id, metadata)
        async_add_entities([NestYaleDiagnosticStatusSensor(hass, coordinator, entry.entry_id, device_id, metadata)])

    def _handle_device(entry_id: str, device_id: str) -> None:
        if entry_id != entry.entry_id:
            return
        _add_entity(device_id)

    for device_id in hass.data[DOMAIN].get(DATA_KNOWN_DEVICE_IDS, {}).get(entry.entry_id, set()):
        _add_entity(device_id)

    if isinstance(coordinator.data, dict):
        for device_id in coordinator.data.keys():
            _add_entity(device_id)

    unsubscribe = async_dispatcher_connect(hass, SIGNAL_DEVICE_DISCOVERED, _handle_device)
    entry.async_on_unload(unsubscribe)


class NestYaleDiagnosticStatusSensor(SensorEntity):
    _attr_has_entity_name = True
    _attr_name = "Diagnostic Status"
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_device_class = SensorDeviceClass.ENUM
    _attr_options = DIAGNOSTIC_STATUS_OPTIONS
    _attr_should_poll = False
    _attr_entity_registry_enabled_default = True

    def __init__(self, hass: HomeAssistant, coordinator, entry_id: str, device_id: str, metadata: dict) -> None:
        self.hass = hass
        self._coordinator = coordinator
        self._entry_id = entry_id
        self._device_id = device_id
        self._unsub_dispatcher: Callable[[], None] | None = None
        self._attr_unique_id = f"{DOMAIN}_{device_id}_diagnostic_status"
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

        self._device_registry_id = ensure_device_registered(hass, entry_id, device_id, metadata)
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
        if self._device_registry_id:
            ent_reg = er.async_get(self.hass)
            entry = ent_reg.async_update_entity(self.entity_id, device_id=self._device_registry_id)
            _LOGGER.debug(
                "Diagnostic sensor linked entity %s to device %s (registry entry=%s)",
                self.entity_id,
                self._device_registry_id,
                entry and entry.id,
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
