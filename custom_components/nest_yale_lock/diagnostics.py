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
    age = coordinator.last_good_update_age() if coordinator and hasattr(coordinator, "last_good_update_age") else None

    # Compute observe age in seconds when possible
    observe_age = None
    try:
        if api and getattr(api, "_last_observe_data_ts", None):
            # _last_observe_data_ts uses loop time()
            observe_age = __import__("asyncio").get_event_loop().time() - api._last_observe_data_ts
    except Exception:
        observe_age = None

    return {
        "entry": {
            "entry_id": entry.entry_id,
            "title": entry.title,
        },
        "coordinator": {
            "last_update_success": getattr(coordinator, "last_update_success", None),
            "device_count": len(data) if isinstance(data, dict) else 0,
            "observer_healthy": getattr(coordinator, "_observer_healthy", None),
            "last_good_update_age_seconds": age,
            "empty_refresh_attempts": getattr(coordinator, "_empty_refresh_attempts", None),
            "watchdog_recovery_attempts": getattr(coordinator, "_recovery_attempts", None),
            "reload_scheduled": bool(getattr(coordinator, "_reload_task", None)),
        },
        "api": {
            "user_id": _mask(str(getattr(api, "user_id", ""))),
            "structure_id": str(getattr(api, "structure_id", "")),
            "transport_url": getattr(api, "transport_url", None),
            "connection_connected": getattr(getattr(api, "connection", None), "connected", None),
            "observe_last_yale_age_seconds": observe_age,
            "access_token_present": bool(getattr(api, "access_token", None)),
            "last_command": getattr(api, "_last_command_info", None),
        },
    }

