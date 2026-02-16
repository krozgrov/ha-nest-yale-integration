#!/usr/bin/env python3
import logging
import asyncio
import voluptuous as vol
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.exceptions import (
    ConfigEntryNotReady,
    ConfigEntryAuthFailed,
    HomeAssistantError,
)
from .const import (
    DOMAIN,
    PLATFORMS,
    CONF_DEBUG_ATTRIBUTES,
    CONF_STALE_STATE_MAX_SECONDS,
    DEFAULT_DEBUG_ATTRIBUTES,
    DEFAULT_STALE_STATE_MAX_SECONDS,
    SERVICE_RESET_CONNECTION,
    SERVICE_SET_GUEST_PASSCODE,
    SERVICE_DELETE_GUEST_PASSCODE,
    DEFAULT_MIN_PASSCODE_LENGTH,
    DEFAULT_MAX_PASSCODE_LENGTH,
)
from .api_client import NestAPIClient
from .coordinator import NestCoordinator

_LOGGER = logging.getLogger(__name__)

# This integration is config-entry only (no YAML options)
CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)

SERVICE_RESET_CONNECTION_SCHEMA = vol.Schema(
    {
        vol.Optional("entry_id"): cv.string,
    }
)

SERVICE_SET_GUEST_PASSCODE_SCHEMA = vol.Schema(
    {
        vol.Optional("entry_id"): cv.string,
        vol.Optional("device_id"): cv.string,
        vol.Optional("guest_user_id"): cv.string,
        vol.Optional("slot"): vol.All(vol.Coerce(int), vol.Range(min=1)),
        vol.Required("passcode"): cv.string,
        vol.Optional("enabled", default=True): cv.boolean,
    }
)

SERVICE_DELETE_GUEST_PASSCODE_SCHEMA = vol.Schema(
    {
        vol.Optional("entry_id"): cv.string,
        vol.Optional("device_id"): cv.string,
        vol.Optional("guest_user_id"): cv.string,
        vol.Optional("slot"): vol.All(vol.Coerce(int), vol.Range(min=1)),
    }
)


def _active_coordinators(hass: HomeAssistant) -> dict[str, NestCoordinator]:
    """Return currently active coordinators keyed by config entry id."""
    domain_data = hass.data.get(DOMAIN, {})
    active: dict[str, NestCoordinator] = {}
    for key, value in domain_data.items():
        if isinstance(key, str) and isinstance(value, NestCoordinator):
            active[key] = value
    return active


def _cleanup_non_device_registry_entries(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Remove stale entities/devices that are not keyed by canonical DEVICE_* ids."""
    entity_registry = er.async_get(hass)
    entity_entries = er.async_entries_for_config_entry(entity_registry, entry.entry_id)
    has_device_style_entity_ids = any(
        isinstance(entity_entry.unique_id, str) and "DEVICE_" in entity_entry.unique_id
        for entity_entry in entity_entries
    )

    removed_entities = 0
    for entity_entry in entity_entries:
        unique_id = entity_entry.unique_id
        if not isinstance(unique_id, str):
            continue
        if not unique_id.startswith(f"{DOMAIN}_"):
            continue
        if unique_id.startswith(f"{DOMAIN}_USER_"):
            entity_registry.async_remove(entity_entry.entity_id)
            removed_entities += 1
            continue
        if has_device_style_entity_ids and "DEVICE_" not in unique_id:
            entity_registry.async_remove(entity_entry.entity_id)
            removed_entities += 1

    device_registry = dr.async_get(hass)
    device_entries = dr.async_entries_for_config_entry(device_registry, entry.entry_id)
    has_device_style_identifiers = any(
        domain == DOMAIN and isinstance(identifier, str) and identifier.startswith("DEVICE_")
        for device in device_entries
        for domain, identifier in device.identifiers
    )

    removed_devices = 0
    for device in device_entries:
        domain_identifiers = [
            identifier
            for domain, identifier in device.identifiers
            if domain == DOMAIN and isinstance(identifier, str)
        ]
        if not domain_identifiers:
            continue
        has_device_identifier = any(identifier.startswith("DEVICE_") for identifier in domain_identifiers)
        has_user_identifier = any(identifier.startswith("USER_") for identifier in domain_identifiers)
        stale_non_device = has_device_style_identifiers and not has_device_identifier
        if (has_user_identifier or stale_non_device) and device_registry.async_remove_device(device.id):
            removed_devices += 1

    if removed_entities or removed_devices:
        _LOGGER.warning(
            "Removed stale non-device Nest Yale registry entries for %s: entities=%d devices=%d",
            entry.entry_id,
            removed_entities,
            removed_devices,
        )


def _resolve_target_coordinators(
    hass: HomeAssistant,
    entry_id: str | None,
) -> dict[str, NestCoordinator]:
    """Resolve coordinators for an optional entry id filter."""
    coordinators = _active_coordinators(hass)
    if not coordinators:
        raise HomeAssistantError("No active Nest Yale config entries found.")
    if entry_id:
        coordinator = coordinators.get(entry_id)
        if coordinator is None:
            raise HomeAssistantError(f"Entry id '{entry_id}' is not active.")
        return {entry_id: coordinator}
    return coordinators


def _resolve_target_device_ids(
    coordinator: NestCoordinator,
    requested_device_id: str | None,
) -> list[str]:
    """Resolve device ids for a coordinator and optional device filter."""
    data = coordinator.data if isinstance(coordinator.data, dict) else {}
    lock_ids = [device_id for device_id, device in data.items() if isinstance(device, dict)]
    if requested_device_id:
        if requested_device_id not in lock_ids:
            raise HomeAssistantError(
                f"Device id '{requested_device_id}' was not found in this config entry."
            )
        return [requested_device_id]
    if len(lock_ids) == 1:
        return lock_ids
    if not lock_ids:
        raise HomeAssistantError("No lock devices are available yet; wait for initial sync.")
    raise HomeAssistantError(
        "Multiple lock devices found. Provide device_id to target a specific lock."
    )


def _passcode_limits(device_data: dict | None) -> tuple[int, int]:
    """Determine valid passcode length bounds for a device."""
    min_len = DEFAULT_MIN_PASSCODE_LENGTH
    max_len = DEFAULT_MAX_PASSCODE_LENGTH
    if isinstance(device_data, dict):
        traits = device_data.get("traits", {})
        if isinstance(traits, dict):
            caps = traits.get("UserPincodesCapabilitiesTrait", {})
            if isinstance(caps, dict):
                cap_min = caps.get("min_pincode_length")
                cap_max = caps.get("max_pincode_length")
                if isinstance(cap_min, int) and cap_min > 0:
                    min_len = cap_min
                if isinstance(cap_max, int) and cap_max > 0:
                    max_len = cap_max
    if min_len > max_len:
        return DEFAULT_MIN_PASSCODE_LENGTH, DEFAULT_MAX_PASSCODE_LENGTH
    return min_len, max_len


def _max_pincodes_supported(device_data: dict | None) -> int:
    """Determine max supported pincode slots for a device."""
    max_slots = 25
    if isinstance(device_data, dict):
        traits = device_data.get("traits", {})
        if isinstance(traits, dict):
            caps = traits.get("UserPincodesCapabilitiesTrait", {})
            if isinstance(caps, dict):
                raw_max = caps.get("max_pincodes_supported")
                if isinstance(raw_max, int) and raw_max > 0:
                    max_slots = raw_max
    return max_slots


def _extract_guest_user_slots(device_data: dict | None) -> dict[int, dict]:
    """Extract guest/user slot metadata from normalized trait data."""
    slots: dict[int, dict] = {}
    if not isinstance(device_data, dict):
        return slots

    traits = device_data.get("traits", {})
    if not isinstance(traits, dict):
        return slots

    pincode_trait = traits.get("UserPincodesSettingsTrait", {})
    if not isinstance(pincode_trait, dict):
        return slots

    user_pincodes = pincode_trait.get("user_pincodes", {})
    if not isinstance(user_pincodes, dict):
        return slots

    for raw_slot, details in user_pincodes.items():
        try:
            slot = int(raw_slot)
        except (TypeError, ValueError):
            continue
        if slot <= 0 or not isinstance(details, dict):
            continue

        slot_info: dict = {"slot": slot}
        user_id = details.get("user_id")
        if isinstance(user_id, str) and user_id.strip():
            slot_info["user_id"] = user_id.strip()

        enabled = details.get("enabled")
        if isinstance(enabled, bool):
            slot_info["enabled"] = enabled

        has_passcode = details.get("has_passcode")
        if isinstance(has_passcode, bool):
            slot_info["has_passcode"] = has_passcode

        slots[slot] = slot_info

    return dict(sorted(slots.items()))


def _validate_guest_slot(slot: int | None, device_data: dict | None) -> None:
    """Validate slot range against lock capabilities."""
    if slot is None:
        return
    if slot <= 0:
        raise HomeAssistantError("slot must be a positive integer.")
    max_slots = _max_pincodes_supported(device_data)
    if slot > max_slots:
        raise HomeAssistantError(
            f"slot must be between 1 and {max_slots} for this lock."
        )


def _resolve_guest_user_id(
    guest_user_id: str | None,
    slot: int | None,
    device_data: dict | None,
) -> str:
    """Resolve user id from explicit id or existing slot mapping."""
    if isinstance(guest_user_id, str):
        normalized = guest_user_id.strip()
        if normalized:
            return normalized

    if slot is None:
        raise HomeAssistantError("Provide either guest_user_id or slot.")

    slots = _extract_guest_user_slots(device_data)
    slot_info = slots.get(slot)
    if not slot_info:
        raise HomeAssistantError(
            "No user mapping was found for this slot. "
            "Create the guest in the Nest app first, then retry."
        )

    resolved_user_id = slot_info.get("user_id")
    if not isinstance(resolved_user_id, str) or not resolved_user_id.strip():
        raise HomeAssistantError(
            "Slot exists but has no user_id mapping. "
            "Create or sync the guest in the Nest app first."
        )
    return resolved_user_id.strip()


def _validate_guest_passcode(passcode: str, device_data: dict | None) -> None:
    """Validate guest passcode content and length."""
    if not isinstance(passcode, str):
        raise HomeAssistantError("Passcode must be a string of digits.")
    value = passcode.strip()
    if not value:
        raise HomeAssistantError("Passcode is required.")
    if not value.isdigit():
        raise HomeAssistantError("Passcode must contain digits only.")
    min_len, max_len = _passcode_limits(device_data)
    if len(value) < min_len or len(value) > max_len:
        raise HomeAssistantError(
            f"Passcode length must be between {min_len} and {max_len} digits for this lock."
        )


def _register_services(hass: HomeAssistant) -> None:
    """Register integration services once per running Home Assistant instance."""
    if hass.services.has_service(DOMAIN, SERVICE_RESET_CONNECTION):
        return

    async def handle_reset_connection(call: ServiceCall) -> None:
        entry_id = call.data.get("entry_id")
        coordinators = _resolve_target_coordinators(hass, entry_id)
        for target_entry_id in coordinators:
            _LOGGER.info("Reloading Nest Yale entry %s via service call", target_entry_id)
            await hass.config_entries.async_reload(target_entry_id)

    async def handle_set_guest_passcode(call: ServiceCall) -> None:
        entry_id = call.data.get("entry_id")
        requested_device_id = call.data.get("device_id")
        guest_user_id = call.data.get("guest_user_id")
        slot = call.data.get("slot")
        passcode = call.data["passcode"].strip()
        enabled = bool(call.data["enabled"])
        coordinators = _resolve_target_coordinators(hass, entry_id)
        for _, coordinator in coordinators.items():
            target_ids = _resolve_target_device_ids(coordinator, requested_device_id)
            for device_id in target_ids:
                device_data = coordinator.data.get(device_id) if isinstance(coordinator.data, dict) else None
                _validate_guest_slot(slot, device_data)
                _validate_guest_passcode(passcode, device_data)
                resolved_guest_user_id = _resolve_guest_user_id(guest_user_id, slot, device_data)
                try:
                    await coordinator.api_client.set_guest_passcode(
                        device_id,
                        resolved_guest_user_id,
                        passcode,
                        enabled=enabled,
                    )
                except ValueError as err:
                    raise HomeAssistantError(str(err)) from err
            await coordinator.async_refresh()

    async def handle_delete_guest_passcode(call: ServiceCall) -> None:
        entry_id = call.data.get("entry_id")
        requested_device_id = call.data.get("device_id")
        guest_user_id = call.data.get("guest_user_id")
        slot = call.data.get("slot")
        coordinators = _resolve_target_coordinators(hass, entry_id)
        for _, coordinator in coordinators.items():
            target_ids = _resolve_target_device_ids(coordinator, requested_device_id)
            for device_id in target_ids:
                device_data = coordinator.data.get(device_id) if isinstance(coordinator.data, dict) else None
                _validate_guest_slot(slot, device_data)
                resolved_guest_user_id = _resolve_guest_user_id(guest_user_id, slot, device_data)
                try:
                    await coordinator.api_client.delete_guest_passcode(
                        device_id,
                        resolved_guest_user_id,
                    )
                except ValueError as err:
                    raise HomeAssistantError(str(err)) from err
            await coordinator.async_refresh()

    hass.services.async_register(
        DOMAIN,
        SERVICE_RESET_CONNECTION,
        handle_reset_connection,
        schema=SERVICE_RESET_CONNECTION_SCHEMA,
    )
    hass.services.async_register(
        DOMAIN,
        SERVICE_SET_GUEST_PASSCODE,
        handle_set_guest_passcode,
        schema=SERVICE_SET_GUEST_PASSCODE_SCHEMA,
    )
    hass.services.async_register(
        DOMAIN,
        SERVICE_DELETE_GUEST_PASSCODE,
        handle_delete_guest_passcode,
        schema=SERVICE_DELETE_GUEST_PASSCODE_SCHEMA,
    )


def _unregister_services_if_idle(hass: HomeAssistant) -> None:
    """Remove integration services when no active config entries remain."""
    if _active_coordinators(hass):
        return
    for service_name in (
        SERVICE_RESET_CONNECTION,
        SERVICE_SET_GUEST_PASSCODE,
        SERVICE_DELETE_GUEST_PASSCODE,
    ):
        if hass.services.has_service(DOMAIN, service_name):
            hass.services.async_remove(DOMAIN, service_name)


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """Set up the Nest Yale component."""
    _LOGGER.debug("Starting async_setup for Nest Yale component")
    return True


async def _async_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Handle config entry updates (e.g., options)."""
    _LOGGER.debug("Reloading entry %s after options update", entry.entry_id)
    await hass.config_entries.async_reload(entry.entry_id)

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Nest Yale Lock from a config entry."""
    _LOGGER.debug("Starting async_setup_entry for entry_id: %s, title: %s", entry.entry_id, entry.title)
    # Normal behavior: avoid emitting extra startup diagnostics at WARNING

    issue_token = entry.data.get("issue_token")
    cookies = entry.data.get("cookies")

    if not issue_token or not cookies:
        _LOGGER.error("Missing required authentication credentials: issue_token=%s, cookies=%s",
                      issue_token, cookies)
        return False

    try:
        _LOGGER.debug("Creating NestAPIClient")
        conn = await NestAPIClient.create(
            hass,
            issue_token,
            None,
            cookies,
            auth_failure_raises=True,
        )
        _LOGGER.debug("Creating NestCoordinator")
        coordinator = NestCoordinator(hass, conn, entry.entry_id)
        options = entry.options
        coordinator._stale_max_seconds = options.get(
            CONF_STALE_STATE_MAX_SECONDS, DEFAULT_STALE_STATE_MAX_SECONDS
        )
        coordinator.debug_attributes_enabled = bool(
            options.get(CONF_DEBUG_ATTRIBUTES, DEFAULT_DEBUG_ATTRIBUTES)
        )
        _LOGGER.debug("Setting up coordinator")
        await coordinator.async_setup()
        # Best-effort initial refresh without blocking startup
        try:
            await asyncio.wait_for(coordinator.async_refresh(), timeout=5)
        except asyncio.TimeoutError:
            _LOGGER.warning("Initial refresh timed out after 5s; continuing with observer updates")
        except Exception as err:
            _LOGGER.debug("Initial refresh failed (non-blocking): %s", err)
        _LOGGER.debug("Coordinator setup complete, initial data: %s", coordinator.data)
        if not coordinator.data:
            _LOGGER.warning("Initial data still empty; waiting for observer updates (entities will use last-known state)")
    except ConfigEntryAuthFailed as err:
        _LOGGER.warning("Authentication failed for entry %s: %s", entry.entry_id, err)
        raise
    except Exception as e:
        _LOGGER.error("Failed to initialize API client or coordinator: %s", e, exc_info=True)
        raise ConfigEntryNotReady(f"Failed to initialize: {e}") from e

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator
    _cleanup_non_device_registry_entries(hass, entry)
    entry.async_on_unload(entry.add_update_listener(_async_update_listener))
    hass.data[DOMAIN].setdefault("entities", [])
    # Reset per-entry added ids on setup to avoid stale rediscovery state.
    added_map = hass.data[DOMAIN].setdefault("added_lock_ids", {})
    added_map[entry.entry_id] = set()
    added_map = hass.data[DOMAIN].setdefault("added_sensor_ids", {})
    added_map[entry.entry_id] = set()
    added_map = hass.data[DOMAIN].setdefault("added_binary_sensor_ids", {})
    added_map[entry.entry_id] = set()
    added_map = hass.data[DOMAIN].setdefault("added_switch_ids", {})
    added_map[entry.entry_id] = set()
    added_map = hass.data[DOMAIN].setdefault("added_select_ids", {})
    added_map[entry.entry_id] = set()
    _register_services(hass)

    _LOGGER.debug("Forwarding setup to platforms: %s", PLATFORMS)
    try:
        await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
        _LOGGER.debug("Successfully forwarded setup to platforms")
    except Exception as e:
        _LOGGER.error("Failed to forward entry setups to platforms: %s", e, exc_info=True)
        return False

    _LOGGER.info("Nest Yale Lock integration successfully set up for entry_id: %s", entry.entry_id)
    return True

async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    _LOGGER.debug("Unloading Nest Yale Lock integration for entry_id: %s", entry.entry_id)

    coordinator = hass.data[DOMAIN].pop(entry.entry_id, None)
    if coordinator:
        _LOGGER.debug("Unloading coordinator")
        await coordinator.async_unload()

    hass.data[DOMAIN]["entities"] = []
    # Clear per-entry added ids so re-adding the integration can discover devices
    try:
        added_map = hass.data[DOMAIN].get("added_lock_ids")
        if isinstance(added_map, dict) and entry.entry_id in added_map:
            added_map.pop(entry.entry_id, None)
        added_map = hass.data[DOMAIN].get("added_sensor_ids")
        if isinstance(added_map, dict) and entry.entry_id in added_map:
            added_map.pop(entry.entry_id, None)
        added_map = hass.data[DOMAIN].get("added_binary_sensor_ids")
        if isinstance(added_map, dict) and entry.entry_id in added_map:
            added_map.pop(entry.entry_id, None)
        added_map = hass.data[DOMAIN].get("added_switch_ids")
        if isinstance(added_map, dict) and entry.entry_id in added_map:
            added_map.pop(entry.entry_id, None)
        added_map = hass.data[DOMAIN].get("added_select_ids")
        if isinstance(added_map, dict) and entry.entry_id in added_map:
            added_map.pop(entry.entry_id, None)
    except Exception:
        pass
    try:
        result = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
        _unregister_services_if_idle(hass)
        _LOGGER.debug("Unload platforms result: %s", result)
        return result
    except Exception as e:
        _LOGGER.error("Failed to unload platforms: %s", e, exc_info=True)
        return False
