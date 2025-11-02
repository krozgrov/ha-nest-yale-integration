#!/usr/bin/env python3
import logging
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
from .const import DOMAIN, UPDATE_INTERVAL_SECONDS

_LOGGER = logging.getLogger(__name__)

class NestCoordinator(DataUpdateCoordinator):
    """Coordinator to manage Nest Yale Lock data via periodic refreshes."""

    def __init__(self, hass: HomeAssistant, api_client):
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=UPDATE_INTERVAL_SECONDS,
        )
        self.api_client = api_client
        self.data = {}
        _LOGGER.debug("Initialized NestCoordinator with initial data: %s", self.data)

    async def async_setup(self):
        _LOGGER.debug("Starting async_setup for coordinator")
        await self.api_client.async_setup()
        await self.async_refresh()
        if not self.data:
            _LOGGER.warning("Coordinator data is empty after initial refresh; waiting for next poll.")
        else:
            _LOGGER.debug("Initial data fetched: %s", self.data)

    async def _async_update_data(self):
        _LOGGER.debug("Starting _async_update_data")
        try:
            new_data = await self.api_client.refresh_state()
            if not new_data:
                _LOGGER.debug("Received empty lock data from refresh_state, keeping last known state")
                return self.data

            normalized_data = new_data.get("yale", new_data) if isinstance(new_data, dict) else {}
            for device_id, device in normalized_data.items():
                device.setdefault("device_id", device_id)
                device["bolt_moving"] = device.get("bolt_moving", False)
            _LOGGER.debug("Normalized data from refresh_state: %s", normalized_data)
            return normalized_data
        except Exception as exc:
            _LOGGER.error("Failed to update data: %s", exc, exc_info=True)
            for device in self.data.values():
                device["bolt_moving"] = False
            return self.data

    async def async_reset_connection(self, reason: str):
        _LOGGER.info("Resetting Nest Yale connection due to: %s", reason)
        await self.api_client.reset_connection(reason)
        await self.async_request_refresh()

    async def async_unload(self):
        _LOGGER.debug("Starting async_unload for coordinator")
        await self.api_client.close()
        _LOGGER.debug("Coordinator unloaded")
