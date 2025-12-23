#!/usr/bin/env python3
import logging
import asyncio
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers import config_validation as cv
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady
from .const import DOMAIN, PLATFORMS
from .api_client import NestAPIClient
from .coordinator import NestCoordinator

_LOGGER = logging.getLogger(__name__)

# This integration is config-entry only (no YAML options)
CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)

async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """Set up the Nest Yale component."""
    _LOGGER.debug("Starting async_setup for Nest Yale component")
    return True

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
        conn = await NestAPIClient.create(hass, issue_token, None, cookies)
        _LOGGER.debug("Creating NestCoordinator")
        coordinator = NestCoordinator(hass, conn, entry.entry_id)
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
    except Exception as e:
        _LOGGER.error("Failed to initialize API client or coordinator: %s", e, exc_info=True)
        raise ConfigEntryNotReady(f"Failed to initialize: {e}") from e

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator
    hass.data[DOMAIN].setdefault("entities", [])
    # Track added entities per entry to allow clean re-add without restart
    hass.data[DOMAIN].setdefault("added_lock_ids", {})
    hass.data[DOMAIN]["added_lock_ids"].setdefault(entry.entry_id, set())
    hass.data[DOMAIN].setdefault("added_sensor_ids", {})
    hass.data[DOMAIN]["added_sensor_ids"].setdefault(entry.entry_id, set())
    hass.data[DOMAIN].setdefault("added_binary_sensor_ids", {})
    hass.data[DOMAIN]["added_binary_sensor_ids"].setdefault(entry.entry_id, set())
    hass.data[DOMAIN].setdefault("added_switch_ids", {})
    hass.data[DOMAIN]["added_switch_ids"].setdefault(entry.entry_id, set())
    hass.data[DOMAIN].setdefault("added_select_ids", {})
    hass.data[DOMAIN]["added_select_ids"].setdefault(entry.entry_id, set())

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
        _LOGGER.debug("Unload platforms result: %s", result)
        return result
    except Exception as e:
        _LOGGER.error("Failed to unload platforms: %s", e, exc_info=True)
        return False
