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
        coordinator = NestCoordinator(hass, conn)
        _LOGGER.debug("Setting up coordinator")
        await coordinator.async_setup()
        # Wait a moment for observer to start and potentially receive initial data
        await asyncio.sleep(1)
        # Retry initial data fetch if empty - try more times with longer waits
        max_retries = 5
        for attempt in range(max_retries):
            await coordinator.async_refresh()
            if coordinator.data:
                _LOGGER.info("Initial data fetched successfully after %d attempt(s)", attempt + 1)
                break
            if attempt < max_retries - 1:
                _LOGGER.warning("Coordinator data still empty, retrying... (attempt %d/%d)", attempt + 1, max_retries)
                # Increase wait time with each retry to give observer more time
                await asyncio.sleep(3 + attempt)
        _LOGGER.debug("Coordinator setup complete, initial data: %s", coordinator.data)
        if not coordinator.data:
            _LOGGER.warning("Initial data still empty after %d attempts; continuing setup and waiting for observer updates", max_retries)
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
    except Exception:
        pass
    try:
        result = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
        _LOGGER.debug("Unload platforms result: %s", result)
        return result
    except Exception as e:
        _LOGGER.error("Failed to unload platforms: %s", e, exc_info=True)
        return False
