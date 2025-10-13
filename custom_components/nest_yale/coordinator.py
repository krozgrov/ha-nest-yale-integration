#!/usr/bin/env python3
import logging
import asyncio
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
from .const import DOMAIN, UPDATE_INTERVAL_SECONDS

_LOGGER = logging.getLogger(__name__)

class NestCoordinator(DataUpdateCoordinator):
    """Coordinator to manage Nest Yale Lock data."""

    def __init__(self, hass: HomeAssistant, api_client):
        """Initialize the coordinator."""
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=UPDATE_INTERVAL_SECONDS,
        )
        self.api_client = api_client
        self._observer_task = None
        self.data = {}
        _LOGGER.debug("Initialized NestCoordinator with initial data: %s", self.data)

    async def async_setup(self):
        """Set up the coordinator."""
        _LOGGER.debug("Starting async_setup for coordinator")
        await self.api_client.async_setup()

        await self.async_refresh()
        if not self.data:
            _LOGGER.warning("Coordinator data is empty after initial refresh, waiting for observer updates.")
        else:
            _LOGGER.debug("Initial data fetched: %s", self.data)

        self._observer_task = self.hass.loop.create_task(self._run_observer())
        _LOGGER.debug("Observer task created: %s", self._observer_task)

    async def _async_update_data(self):
        """Fetch data from API client."""
        _LOGGER.debug("Starting _async_update_data")
        try:
            new_data = await self.api_client.refresh_state()
            if not new_data:
                _LOGGER.debug("Received empty lock data from refresh_state, keeping last known state")
                return self.data

            normalized_data = new_data.get("yale", new_data) if new_data else {}
            for device_id, device in normalized_data.items():
                device["bolt_moving"] = device.get("bolt_moving", False)
            _LOGGER.debug("Normalized data from refresh_state: %s", normalized_data)
            return normalized_data
        except Exception as e:
            _LOGGER.error("Failed to update data: %s", e, exc_info=True)
            for device in self.data.values():
                device["bolt_moving"] = False
            return self.data

    async def _run_observer(self):
        """Listen for real-time updates."""
        _LOGGER.debug("Starting _run_observer")
        try:
            async for update in self.api_client.observe():
                if update:
                    _LOGGER.debug("Received observer update: %s", update)
                    normalized_update = update.get("yale", update) if update else {}
                    if normalized_update:
                        for device_id, device in normalized_update.items():
                            if "actuatorState" in device:
                                device["actuator_state"] = device["actuatorState"]
                            device["bolt_moving"] = device.get("bolt_moving", False)
                        self.api_client.current_state["user_id"] = update.get("user_id")  # Persist user_id
                        self.async_set_updated_data(normalized_update)
                        _LOGGER.debug("Applied normalized observer update: %s, current_state user_id: %s",
                                      normalized_update, self.api_client.current_state["user_id"])
                    else:
                        _LOGGER.debug("Normalized observer update is empty: %s", normalized_update)
                        for device in self.data.values():
                            device["bolt_moving"] = False
                        self.async_set_updated_data(self.data)
                else:
                    _LOGGER.debug("Observer update received but is empty.")
                    for device in self.data.values():
                        device["bolt_moving"] = False
                    self.async_set_updated_data(self.data)
        except Exception as e:
            _LOGGER.error("Observer failed: %s", e, exc_info=True)
            await asyncio.sleep(5)
            self._observer_task = self.hass.loop.create_task(self._run_observer())

    async def async_unload(self):
        """Unload the coordinator."""
        _LOGGER.debug("Starting async_unload for coordinator")
        if self._observer_task:
            _LOGGER.debug("Cancelling observer task")
            self._observer_task.cancel()
            try:
                await self._observer_task
            except asyncio.CancelledError:
                _LOGGER.debug("Observer task cancelled")
        await self.api_client.close()
        _LOGGER.debug("Coordinator unloaded")