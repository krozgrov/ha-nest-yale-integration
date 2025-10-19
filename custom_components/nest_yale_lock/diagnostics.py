from __future__ import annotations

from homeassistant.core import HomeAssistant
from homeassistant.config_entries import ConfigEntry

from .const import DOMAIN


def _mask(value: str, keep: int = 4) -> str:
    try:
        if not value or len(value) <= keep * 2:
            return "***"
        return f"{value[:keep]}***{value[-keep:]}"
    except Exception:
        return "***"


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: ConfigEntry
):
    coordinator = hass.data.get(DOMAIN, {}).get(entry.entry_id)
    data = coordinator.data if coordinator else {}
    api = coordinator.api_client if coordinator else None

    return {
        "entry": {
            "entry_id": entry.entry_id,
            "title": entry.title,
        },
        "coordinator": {
            "last_update_success": getattr(coordinator, "last_update_success", None),
            "device_count": len(data) if isinstance(data, dict) else 0,
        },
        "api": {
            "user_id": _mask(str(getattr(api, "user_id", ""))),
            "structure_id": str(getattr(api, "structure_id", "")),
            "transport_url": getattr(api, "transport_url", None),
        },
    }

