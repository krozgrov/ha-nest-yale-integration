#!/usr/bin/env python3
import logging
import asyncio
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
from .const import DOMAIN, UPDATE_INTERVAL_SECONDS

_LOGGER = logging.getLogger(__name__)

class NestCoordinator(DataUpdateCoordinator):
    """Coordinator to manage Nest Yale Lock data via observe stream."""

    def __init__(self, hass: HomeAssistant, api_client):
        # Use a longer update interval since we're using push-based updates
        # This is mainly a fallback if the stream fails
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
        # Set up callback for observe stream updates
        self.api_client.set_state_callback(self._handle_stream_update)
        await self.api_client.async_setup()
        # Do initial refresh to get user_id and structure_id
        await self.async_refresh()
        if not self.data:
            _LOGGER.warning("Coordinator data is empty after initial refresh; waiting for stream updates.")
        else:
            _LOGGER.debug("Initial data fetched: %s", self.data)

    @callback
    def _handle_stream_update(self, locks_data):
        """Handle state updates from the observe stream.
        
        This callback is invoked by the API client when new data arrives
        from the observe stream. It processes the data and notifies
        all registered listeners (entities).
        """
        _LOGGER.info("Coordinator received stream update: %s", locks_data)
        try:
            normalized_data = locks_data.get("yale", {}) if isinstance(locks_data, dict) else {}
            if normalized_data:
                _LOGGER.info("Processing %d lock device(s) from stream update", len(normalized_data))
                for device_id, device in normalized_data.items():
                    if not isinstance(device, dict):
                        _LOGGER.warning("Invalid device data for %s: %s", device_id, type(device))
                        continue
                    device.setdefault("device_id", device_id)
                    device["bolt_moving"] = device.get("bolt_moving", False)
                    _LOGGER.info(
                        "Updating device %s: bolt_locked=%s, bolt_moving=%s",
                        device_id,
                        device.get("bolt_locked"),
                        device.get("bolt_moving"),
                    )
                
                # Update coordinator data and notify listeners
                old_data = self.data.copy()
                self.data.update(normalized_data)
                _LOGGER.info("Coordinator data updated, notifying %d listener(s)", len(self._listeners))
                self.async_update_listeners()
                _LOGGER.info("Listeners notified for devices: %s", list(normalized_data.keys()))
            else:
                _LOGGER.debug("Stream update had no yale data: %s", locks_data)
        except Exception as exc:
            _LOGGER.error("Failed to process stream update: %s", exc, exc_info=True)

    async def _async_update_data(self):
        """Periodic update fallback (used if stream fails)."""
        _LOGGER.debug("Starting _async_update_data (fallback)")
        try:
            new_data = await self.api_client.refresh_state()
            if not new_data:
                _LOGGER.debug("Received empty lock data from refresh_state, keeping last known state")
                return self.data

            normalized_data = new_data.get("yale", new_data) if isinstance(new_data, dict) else {}
            if isinstance(normalized_data, dict):
                for device_id, device in normalized_data.items():
                    device.setdefault("device_id", device_id)
                    device["bolt_moving"] = device.get("bolt_moving", False)
            _LOGGER.debug("Normalized data from refresh_state: %s", normalized_data)
            return normalized_data if isinstance(normalized_data, dict) else self.data
        except Exception as exc:
            _LOGGER.error("Failed to update data: %s", exc, exc_info=True)
            for device in self.data.values():
                if isinstance(device, dict):
                    device["bolt_moving"] = False
            return self.data

    async def async_reset_connection(self, reason: str):
        _LOGGER.info("Resetting Nest Yale connection due to: %s", reason)
        await self.api_client.reset_connection(reason)
        # Wait a moment for reconnection, then refresh
        await asyncio.sleep(2)
        await self.async_request_refresh()

    async def async_unload(self):
        _LOGGER.debug("Starting async_unload for coordinator")
        await self.api_client.close()
        _LOGGER.debug("Coordinator unloaded")
