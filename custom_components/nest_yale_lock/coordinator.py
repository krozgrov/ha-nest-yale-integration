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
        self._observer_healthy = False  # Track if observe stream is working
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
        """Fetch data from API client (fallback only when observe stream is unhealthy)."""
        # Skip polling if observe stream is healthy - it provides real-time updates
        if self._observer_healthy:
            _LOGGER.debug("Skipping fallback poll - observe stream is healthy")
            return self.data
        
        _LOGGER.debug("Starting fallback _async_update_data (observe stream unhealthy)")
        try:
            new_data = await self.api_client.refresh_state()
            if not new_data:
                _LOGGER.debug("Received empty lock data from refresh_state, keeping last known state")
                return self.data

            normalized_data = new_data.get("yale", new_data) if new_data else {}
            for device_id, device in normalized_data.items():
                # Ensure required fields exist even if absent in payload
                device.setdefault("device_id", device_id)
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
                # Mark observer as healthy when we receive updates
                self._observer_healthy = True
                
                if update:
                    _LOGGER.debug("Received observer update: %s", update)
                    normalized_update = update.get("yale", update) if update else {}
                    all_traits = update.get("all_traits", {})
                    if normalized_update:
                        for device_id, device in normalized_update.items():
                            # Ensure required fields exist even if absent in payload
                            device.setdefault("device_id", device_id)
                            if "actuatorState" in device:
                                device["actuator_state"] = device["actuatorState"]
                            device["bolt_moving"] = device.get("bolt_moving", False)
                            
                            # Extract trait data for this device from all_traits
                            device_traits = {}
                            for trait_key, trait_info in all_traits.items():
                                if trait_key.startswith(f"{device_id}:"):
                                    trait_name = trait_info.get("type_url", "").split(".")[-1]
                                    if trait_info.get("decoded") and trait_info.get("data"):
                                        device_traits[trait_name] = trait_info["data"]
                            if device_traits:
                                device["traits"] = device_traits
                                _LOGGER.info("Added trait data to device %s: %s", device_id, list(device_traits.keys()))
                            else:
                                _LOGGER.debug("No trait data found for device %s in all_traits (keys: %s)", device_id, list(all_traits.keys())[:5])
                        
                        self.api_client.current_state["user_id"] = update.get("user_id")  # Persist user_id
                        self.api_client.current_state["all_traits"] = all_traits  # Persist trait data
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
            self._observer_healthy = False  # Mark as unhealthy on failure
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
