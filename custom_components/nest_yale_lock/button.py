from __future__ import annotations

import logging

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.dispatcher import async_dispatcher_send
from homeassistant.helpers.entity import EntityCategory

from .const import (
    DOMAIN,
    DATA_ADDED_BUTTON_IDS,
    DATA_DIAGNOSTIC_STATUS,
    DEFAULT_DIAGNOSTIC_STATUS,
    DIAGNOSTIC_STATUS_AVAILABLE,
    DIAGNOSTIC_STATUS_UNAVAILABLE,
    SIGNAL_DIAGNOSTIC_STATUS_UPDATED,
)

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback) -> None:
    coordinator = hass.data[DOMAIN][entry.entry_id]

    added_map = hass.data[DOMAIN].setdefault(DATA_ADDED_BUTTON_IDS, {})
    added: set[str] = added_map.setdefault(entry.entry_id, set())

    def _process_devices() -> None:
        data = coordinator.data or {}
        if _LOGGER.isEnabledFor(logging.DEBUG):
            _LOGGER.debug("Diagnostic button setup processing devices: %s", list(data.keys()))
        new_entities: list[NestYaleDiagnosticButton] = []
        for device_id in data:
            unique_id = f"{DOMAIN}_{device_id}_diagnostic_button"
            if unique_id in added:
                continue
            new_entities.append(NestYaleDiagnosticButton(hass, coordinator, entry.entry_id, device_id))
            added.add(unique_id)
            _LOGGER.debug("Prepared diagnostic button for device_id=%s, unique_id=%s", device_id, unique_id)
        if new_entities:
            async_add_entities(new_entities)
            _LOGGER.debug("Added %d diagnostic button entities", len(new_entities))

    _process_devices()
    cancel = coordinator.async_add_listener(_process_devices)
    entry.async_on_unload(cancel)


class NestYaleDiagnosticButton(ButtonEntity):
    _attr_has_entity_name = True
    _attr_name = "Diagnostic: Request Platform API State"
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_entity_registry_enabled_default = True

    def __init__(self, hass: HomeAssistant, coordinator, entry_id: str, device_id: str) -> None:
        self.hass = hass
        self._coordinator = coordinator
        self._entry_id = entry_id
        self._device_id = device_id
        self._attr_unique_id = f"{DOMAIN}_{device_id}_diagnostic_button"
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
        entry_store.setdefault(device_id, DEFAULT_DIAGNOSTIC_STATUS)

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
