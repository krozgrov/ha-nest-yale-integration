#!/usr/bin/env python3
import logging
import asyncio
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from .const import DOMAIN, PLATFORMS
from .api_client import NestAPIClient
from .coordinator import NestCoordinator

_LOGGER = logging.getLogger(__name__)

async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """Set up the Nest Yale component."""
    _LOGGER.debug("Starting async_setup for Nest Yale component")
    return True

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Nest Yale Lock from a config entry."""
    _LOGGER.debug("Starting async_setup_entry for entry_id: %s, title: %s", entry.entry_id, entry.title)

    issue_token = entry.data.get("issue_token")
    api_key = entry.data.get("api_key")
    cookies = entry.data.get("cookies")

    if not issue_token or not api_key or not cookies:
        _LOGGER.error("Missing required authentication credentials: issue_token=%s, api_key=%s, cookies=%s",
                      issue_token, api_key, cookies)
        return False

    try:
        _LOGGER.debug("Creating NestAPIClient")
        conn = await NestAPIClient.create(hass, issue_token, api_key, cookies)
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
            _LOGGER.error("Failed to fetch initial data after retries")
    except Exception as e:
        _LOGGER.error("Failed to initialize API client or coordinator: %s", e, exc_info=True)
        return False

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator
    hass.data[DOMAIN].setdefault("entities", [])

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
    try:
        result = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
        _LOGGER.debug("Unload platforms result: %s", result)
        return result
    except Exception as e:
        _LOGGER.error("Failed to unload platforms: %s", e, exc_info=True)
        return False