from __future__ import annotations

import logging

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.dispatcher import async_dispatcher_send, async_dispatcher_connect
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers import entity_registry as er

from .const import (
    DOMAIN,
    DATA_DIAGNOSTIC_STATUS,
    DATA_KNOWN_DEVICE_IDS,
    DEFAULT_DIAGNOSTIC_STATUS,
    DIAGNOSTIC_STATUS_AVAILABLE,
    DIAGNOSTIC_STATUS_UNAVAILABLE,
    SIGNAL_DEVICE_DISCOVERED,
    SIGNAL_DIAGNOSTIC_STATUS_UPDATED,
)
from .device_helpers import ensure_device_registered

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback) -> None:
    coordinator = hass.data[DOMAIN][entry.entry_id]
    status_store = hass.data[DOMAIN].setdefault(DATA_DIAGNOSTIC_STATUS, {})
    status_store.setdefault(entry.entry_id, {})

    added: set[str] = set()

    def _add_entity(device_id: str) -> None:
        if device_id in added:
            return
        added.add(device_id)
        _LOGGER.debug("Prepared diagnostic button for device_id=%s", device_id)
        metadata = coordinator.api_client.get_device_metadata(device_id)
        ensure_device_registered(hass, entry.entry_id, device_id, metadata)
        async_add_entities([NestYaleDiagnosticButton(hass, coordinator, entry.entry_id, device_id, metadata)])

    def _handle_device(entry_id: str, device_id: str) -> None:
        if entry_id != entry.entry_id:
            return
        _add_entity(device_id)

    # Prime with any previously-known devices
    known_devices = hass.data[DOMAIN].get(DATA_KNOWN_DEVICE_IDS, {}).get(entry.entry_id, set())
    for device_id in known_devices:
        _add_entity(device_id)

    # Include devices already present in coordinator snapshot
    if isinstance(coordinator.data, dict):
        for device_id in coordinator.data.keys():
            _add_entity(device_id)

    unsubscribe = async_dispatcher_connect(hass, SIGNAL_DEVICE_DISCOVERED, _handle_device)
    entry.async_on_unload(unsubscribe)


class NestYaleDiagnosticButton(ButtonEntity):
    _attr_has_entity_name = True
    _attr_name = "Diagnostic: Request Platform API State"
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_entity_registry_enabled_default = True

    def __init__(self, hass: HomeAssistant, coordinator, entry_id: str, device_id: str, metadata: dict) -> None:
        self.hass = hass
        self._coordinator = coordinator
        self._entry_id = entry_id
        self._device_id = device_id
        self._attr_unique_id = f"{DOMAIN}_{device_id}_diagnostic_button"
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
        entry_store.setdefault(device_id, DEFAULT_DIAGNOSTIC_STATUS)

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        ent_reg = er.async_get(self.hass)
        if self._device_registry_id:
            entry = ent_reg.async_update_entity(self.entity_id, device_id=self._device_registry_id)
            _LOGGER.debug(
                "Diagnostic button linked entity %s to device %s (registry entry=%s)",
                self.entity_id,
                self._device_registry_id,
                entry and entry.id,
            )

    async def async_press(self) -> None:
        api = self._coordinator.api_client
        status_store = self.hass.data[DOMAIN][DATA_DIAGNOSTIC_STATUS][self._entry_id]
        # Try a quick ephemeral auth to validate state
        new_status = DIAGNOSTIC_STATUS_UNAVAILABLE
        try:
            session = api.session.__class__(timeout=api.session.timeout)  # type: ignore
            try:
                auth_data = await api.authenticator.authenticate(session)
                if auth_data and auth_data.get("access_token"):
                    new_status = DIAGNOSTIC_STATUS_AVAILABLE
            finally:
                await session.close()
        except Exception:
            new_status = DIAGNOSTIC_STATUS_UNAVAILABLE

        status_store[self._device_id] = new_status
        async_dispatcher_send(
            self.hass,
            SIGNAL_DIAGNOSTIC_STATUS_UPDATED,
            self._entry_id,
            self._device_id,
            new_status,
        )
        _LOGGER.debug(
            "Diagnostic button updated status for device_id=%s to %s", self._device_id, new_status
        )
        # Create a persistent notification with the status
        await self.hass.services.async_call(
            "persistent_notification",
            "create",
            {
                "title": "Nest Yale Platform API State",
                "message": f"Status: {new_status}",
                "notification_id": f"{DOMAIN}_diagnostic_status",
            },
            blocking=True,
        )
