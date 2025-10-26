from __future__ import annotations

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback) -> None:
    coordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([NestYaleDiagnosticButton(hass, coordinator)])


class NestYaleDiagnosticButton(ButtonEntity):
    _attr_has_entity_name = True
    _attr_name = "Diagnostic: Request Platform API State"

    def __init__(self, hass: HomeAssistant, coordinator) -> None:
        self.hass = hass
        self._coordinator = coordinator
        self._attr_unique_id = f"{DOMAIN}_diagnostic_button"

    async def async_press(self) -> None:
        api = self._coordinator.api_client
        # Try a quick ephemeral auth to validate state
        status = "Unavailable"
        try:
            session = api.session.__class__(timeout=api.session.timeout)  # type: ignore
            try:
                auth_data = await api.authenticator.authenticate(session)
                if auth_data and auth_data.get("access_token"):
                    status = "Available"
            finally:
                await session.close()
        except Exception:
            status = "Unavailable"
        # Create a persistent notification with the status
        await self.hass.services.async_call(
            "persistent_notification",
            "create",
            {
                "title": "Nest Yale Platform API State",
                "message": f"Status: {status}",
                "notification_id": f"{DOMAIN}_diagnostic_status",
            },
            blocking=True,
        )

