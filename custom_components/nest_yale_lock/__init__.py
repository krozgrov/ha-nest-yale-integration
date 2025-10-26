#!/usr/bin/env python3
import logging
import asyncio
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers import config_validation as cv
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady
from .const import (
    DOMAIN,
    PLATFORMS,
    DATA_DIAGNOSTIC_STATUS,
    DATA_KNOWN_DEVICE_IDS,
)
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
        # Retry initial data fetch if empty
        for _ in range(3):
            await coordinator.async_refresh()
            if coordinator.data:
                break
            _LOGGER.warning("Coordinator data still empty, retrying...")
            await asyncio.sleep(2)
        _LOGGER.debug("Coordinator setup complete, initial data: %s", coordinator.data)
        if not coordinator.data:
            _LOGGER.warning("Initial data still empty; continuing setup and waiting for observer updates")
    except Exception as e:
        _LOGGER.error("Failed to initialize API client or coordinator: %s", e, exc_info=True)
        return False

    domain_data = hass.data.setdefault(DOMAIN, {})
    domain_data[entry.entry_id] = coordinator
    domain_data.setdefault("entities", [])
    # Track added entities per entry to allow clean re-add without restart
    domain_data.setdefault("added_lock_ids", {}).setdefault(entry.entry_id, set())
    domain_data.setdefault(DATA_DIAGNOSTIC_STATUS, {}).setdefault(entry.entry_id, {})
    domain_data.setdefault(DATA_KNOWN_DEVICE_IDS, {}).setdefault(entry.entry_id, set())

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

    domain_data = hass.data.setdefault(DOMAIN, {})
    domain_data["entities"] = []
    # Clear per-entry added ids so re-adding the integration can discover devices
    try:
        added_map = domain_data.get("added_lock_ids")
        if isinstance(added_map, dict) and entry.entry_id in added_map:
            added_map.pop(entry.entry_id, None)
    except Exception:
        pass
    try:
        diag_status = domain_data.get(DATA_DIAGNOSTIC_STATUS)
        if isinstance(diag_status, dict) and entry.entry_id in diag_status:
            diag_status.pop(entry.entry_id, None)
    except Exception:
        pass
    try:
        known_devices = domain_data.get(DATA_KNOWN_DEVICE_IDS)
        if isinstance(known_devices, dict) and entry.entry_id in known_devices:
            known_devices.pop(entry.entry_id, None)
    except Exception:
        pass
    try:
        result = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
        _LOGGER.debug("Unload platforms result: %s", result)
        return result
    except Exception as e:
        _LOGGER.error("Failed to unload platforms: %s", e, exc_info=True)
        return False
