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


def _auth_trait_summaries(api) -> list[dict]:
    all_traits = getattr(api, "current_state", {}).get("all_traits", {}) if api else {}
    if not isinstance(all_traits, dict):
        return []
    summaries: list[dict] = []
    for trait_info in all_traits.values():
        if not isinstance(trait_info, dict):
            continue
        type_url = trait_info.get("type_url")
        if not isinstance(type_url, str) or "/weave.trait.auth." not in type_url:
            continue
        data = trait_info.get("data")
        if not isinstance(data, dict):
            data = {}
        payload_lens = data.get("payload_lens")
        summaries.append(
            {
                "object_id": trait_info.get("object_id"),
                "type_url": type_url,
                "payload_lens": payload_lens if isinstance(payload_lens, list) else [],
                "candidate32": len(data.get("candidate_keys_32", []))
                if isinstance(data.get("candidate_keys_32"), list)
                else 0,
                "candidate36": len(data.get("candidate_keys_36", []))
                if isinstance(data.get("candidate_keys_36"), list)
                else 0,
            }
        )
    return summaries


def _guest_trait_summaries(api) -> list[dict]:
    all_traits = getattr(api, "current_state", {}).get("all_traits", {}) if api else {}
    if not isinstance(all_traits, dict):
        return []
    summaries: list[dict] = []
    for trait_info in all_traits.values():
        if not isinstance(trait_info, dict):
            continue
        type_url = trait_info.get("type_url")
        if not isinstance(type_url, str) or not type_url.endswith("/nest.trait.guest.GuestsTrait"):
            continue
        data = trait_info.get("data")
        if not isinstance(data, dict):
            data = {}
        guests = data.get("guests")
        guest_rows = guests if isinstance(guests, list) else []
        summaries.append(
            {
                "object_id": trait_info.get("object_id"),
                "type_url": type_url,
                "guest_count": len(guest_rows),
                "guest_ids": [
                    _mask(str(guest.get("guest_id")))
                    for guest in guest_rows
                    if isinstance(guest, dict) and guest.get("guest_id")
                ],
                "guest_names": [
                    guest.get("name")
                    for guest in guest_rows
                    if isinstance(guest, dict) and guest.get("name")
                ],
                "payload_lens": data.get("payload_lens", []),
                "max_guests_per_structure": data.get("max_guests_per_structure"),
            }
        )
    return summaries


def _pincode_trait_summaries(api) -> list[dict]:
    all_traits = getattr(api, "current_state", {}).get("all_traits", {}) if api else {}
    if not isinstance(all_traits, dict):
        return []
    summaries: list[dict] = []
    for trait_info in all_traits.values():
        if not isinstance(trait_info, dict):
            continue
        type_url = trait_info.get("type_url")
        if (
            not isinstance(type_url, str)
            or not type_url.endswith("/weave.trait.security.UserPincodesSettingsTrait")
        ):
            continue
        data = trait_info.get("data")
        if not isinstance(data, dict):
            data = {}
        pincodes = data.get("user_pincodes")
        rows = pincodes if isinstance(pincodes, dict) else {}
        slots_with_passcodes = sorted(
            [
                int(slot)
                for slot, row in rows.items()
                if isinstance(row, dict) and row.get("has_passcode")
            ]
        )
        summaries.append(
            {
                "object_id": trait_info.get("object_id"),
                "type_url": type_url,
                "slot_count": len(rows),
                "slots_with_passcodes": slots_with_passcodes,
                "guest_user_ids": [
                    _mask(str(row.get("user_id")))
                    for row in rows.values()
                    if isinstance(row, dict) and row.get("user_id")
                ],
            }
        )
    return summaries


def _user_access_trait_summaries(api) -> list[dict]:
    all_traits = getattr(api, "current_state", {}).get("all_traits", {}) if api else {}
    if not isinstance(all_traits, dict):
        return []
    summaries: list[dict] = []
    for trait_info in all_traits.values():
        if not isinstance(trait_info, dict):
            continue
        type_url = trait_info.get("type_url")
        if not isinstance(type_url, str) or not type_url.endswith("/nest.trait.user.UserAccessTrait"):
            continue
        data = trait_info.get("data")
        if not isinstance(data, dict):
            data = {}
        records = data.get("records")
        rows = records if isinstance(records, list) else []
        summaries.append(
            {
                "object_id": trait_info.get("object_id"),
                "type_url": type_url,
                "record_count": len(rows),
                "user_ids": [
                    _mask(str(row.get("user_id")))
                    for row in rows
                    if isinstance(row, dict) and row.get("user_id")
                ],
                "device_ids": sorted(
                    {
                        str(row.get("device_id"))
                        for row in rows
                        if isinstance(row, dict) and row.get("device_id")
                    }
                ),
                "access_types": sorted(
                    {
                        int(row.get("access_type"))
                        for row in rows
                        if isinstance(row, dict) and isinstance(row.get("access_type"), int)
                    }
                ),
                "payload_lens": data.get("payload_lens", []),
            }
        )
    return summaries


def _schedule_trait_summaries(api) -> list[dict]:
    all_traits = getattr(api, "current_state", {}).get("all_traits", {}) if api else {}
    if not isinstance(all_traits, dict):
        return []
    summaries: list[dict] = []
    for trait_info in all_traits.values():
        if not isinstance(trait_info, dict):
            continue
        type_url = trait_info.get("type_url")
        if (
            not isinstance(type_url, str)
            or not type_url.endswith("/weave.trait.schedule.BasicUserSchedulesSettingsTrait")
        ):
            continue
        data = trait_info.get("data")
        if not isinstance(data, dict):
            data = {}
        schedules = data.get("schedules")
        rows = schedules if isinstance(schedules, list) else []
        summaries.append(
            {
                "object_id": trait_info.get("object_id"),
                "type_url": type_url,
                "schedule_count": len(rows),
                "slots": sorted(
                    [
                        int(row.get("slot"))
                        for row in rows
                        if isinstance(row, dict) and isinstance(row.get("slot"), int)
                    ]
                ),
                "user_ids": [
                    _mask(str(row.get("user_id")))
                    for row in rows
                    if isinstance(row, dict) and row.get("user_id")
                ],
                "window_counts": [
                    int(row.get("schedule_count", 0))
                    for row in rows
                    if isinstance(row, dict)
                ],
                "payload_lens": data.get("payload_lens", []),
            }
        )
    return summaries


def _trait_inventory_summaries(api) -> dict[str, list[str]]:
    inventory = getattr(api, "current_state", {}).get("trait_inventory", {}) if api else {}
    if not isinstance(inventory, dict):
        return {}
    normalized: dict[str, list[str]] = {}
    for object_id, descriptors in inventory.items():
        if not isinstance(object_id, str) or not isinstance(descriptors, list):
            continue
        normalized[object_id] = [str(descriptor) for descriptor in descriptors if descriptor]
    return normalized


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: ConfigEntry
):
    coordinator = hass.data.get(DOMAIN, {}).get(entry.entry_id)
    data = coordinator.data if coordinator else {}
    api = coordinator.api_client if coordinator else None
    age = coordinator.last_good_update_age() if coordinator and hasattr(coordinator, "last_good_update_age") else None
    last_command = getattr(api, "_last_command_info", None)
    last_command_status = None
    if isinstance(last_command, dict):
        last_command_status = {
            "status_code": last_command.get("status_code"),
            "status_message": last_command.get("status_message"),
        }

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
            "structure_id": _mask(str(getattr(api, "structure_id", ""))),
            "transport_url": getattr(api, "transport_url", None),
            "connection_connected": getattr(getattr(api, "connection", None), "connected", None),
            "observe_last_yale_age_seconds": observe_age,
            "access_token_present": bool(getattr(api, "access_token", None)),
            "last_command": last_command,
            "last_command_status": last_command_status,
            "observed_auth_traits": _auth_trait_summaries(api),
            "observed_guest_traits": _guest_trait_summaries(api),
            "observed_pincode_traits": _pincode_trait_summaries(api),
            "observed_user_access_traits": _user_access_trait_summaries(api),
            "observed_schedule_traits": _schedule_trait_summaries(api),
            "trait_inventory": _trait_inventory_summaries(api),
        },
    }
