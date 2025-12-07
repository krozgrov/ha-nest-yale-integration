#!/usr/bin/env python3
import logging
import asyncio
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
from .const import DOMAIN, UPDATE_INTERVAL_SECONDS, STALE_STATE_MAX_SECONDS

_LOGGER = logging.getLogger(__name__)

class NestCoordinator(DataUpdateCoordinator):
    """Coordinator to manage Nest Yale Lock data."""

    def __init__(self, hass: HomeAssistant, api_client, entry_id: str | None = None):
        """Initialize the coordinator."""
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=UPDATE_INTERVAL_SECONDS,
        )
        self.api_client = api_client
        self.entry_id = entry_id
        self._observer_task = None
        self._observer_healthy = False  # Track if observe stream is working
        self.data = {}
        self._initial_data_event = asyncio.Event()
        self._reload_task = None
        self._empty_refresh_attempts = 0
        self._last_good_update = None
        self._stale_max_seconds = STALE_STATE_MAX_SECONDS
        _LOGGER.debug("Initialized NestCoordinator with initial data: %s", self.data)

    async def async_setup(self):
        """Set up the coordinator."""
        _LOGGER.debug("Starting async_setup for coordinator")
        await self.api_client.async_setup()

        await self.async_refresh()
        if self.data:
            _LOGGER.debug("Initial data fetched: %s", self.data)
            self._initial_data_event.set()
            self._last_good_update = asyncio.get_event_loop().time()
        else:
            _LOGGER.warning("Coordinator data is empty after initial refresh, waiting for observer updates.")

        self._observer_task = self.hass.loop.create_task(self._run_observer())
        _LOGGER.debug("Observer task created: %s", self._observer_task)

        if not self._initial_data_event.is_set():
            self.hass.loop.create_task(self._log_initial_data_ready())

    def schedule_reload(self, reason: str, delay: float = 0) -> None:
        """Schedule a config-entry reload similar to HA's GUI reload button."""
        if not self.entry_id:
            _LOGGER.debug("Cannot schedule reload without entry_id (reason: %s)", reason)
            return
        if self._reload_task and not self._reload_task.done():
            _LOGGER.debug("Reload already scheduled; ignoring new request (%s)", reason)
            return

        async def _do_reload():
            if delay:
                await asyncio.sleep(delay)
            _LOGGER.warning(
                "Automatically reloading Nest Yale Lock entry %s (%s)",
                self.entry_id,
                reason,
            )
            try:
                await self.hass.config_entries.async_reload(self.entry_id)
            except Exception as err:
                _LOGGER.error("Automatic reload failed: %s", err, exc_info=True)
            finally:
                self._reload_task = None

        self._reload_task = self.hass.loop.create_task(_do_reload())

    async def _async_update_data(self):
        """Fetch data from API client (fallback only when observe stream is unhealthy)."""
        # If observer claims healthy but we still have no data, force a fallback once
        if self._observer_healthy and not self.data:
            _LOGGER.warning("Observer marked healthy but data is empty; forcing fallback refresh")
            self._observer_healthy = False
        elif self._observer_healthy:
            _LOGGER.debug("Skipping fallback poll - observe stream is healthy")
            return self.data
        
        _LOGGER.debug("Starting fallback _async_update_data (observe stream unhealthy)")
        try:
            new_data = await self.api_client.refresh_state()
            if not new_data:
                _LOGGER.debug("Received empty lock data from refresh_state, keeping last known state")
                self._empty_refresh_attempts += 1
                if self._empty_refresh_attempts >= 3:
                    self.schedule_reload("No Yale data from refresh_state (fallback)")
                return self.data

            normalized_data = new_data.get("yale", new_data) if new_data else {}
            for device_id, device in normalized_data.items():
                # Ensure required fields exist even if absent in payload
                device.setdefault("device_id", device_id)
                # Remove bolt_moving from device dict - it's now entity state
                device.pop("bolt_moving", None)
            if normalized_data:
                self._initial_data_event.set()
                self._empty_refresh_attempts = 0
                self._last_good_update = asyncio.get_event_loop().time()
            _LOGGER.debug("Normalized data from refresh_state: %s", normalized_data)
            return normalized_data
        except Exception as e:
            _LOGGER.error("Failed to update data: %s", e, exc_info=True)
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
                            # Remove bolt_moving from device dict - it's now entity state
                            device.pop("bolt_moving", None)
                            
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
                        self._empty_refresh_attempts = 0
                        self._last_good_update = asyncio.get_event_loop().time()
                        self.async_set_updated_data(normalized_update)
                        self._initial_data_event.set()
                        _LOGGER.debug("Applied normalized observer update: %s, current_state user_id: %s",
                                      normalized_update, self.api_client.current_state["user_id"])
                    else:
                        _LOGGER.debug("Normalized observer update is empty: %s", normalized_update)
                        self._observer_healthy = False  # allow fallback polling if stream yields nothing
                        self.async_set_updated_data(self.data)
                else:
                    _LOGGER.debug("Observer update received but is empty.")
                    self._observer_healthy = False  # allow fallback polling if stream yields nothing
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
        if self._reload_task and not self._reload_task.done():
            _LOGGER.debug("Cancelling scheduled reload task")
            self._reload_task.cancel()
            try:
                await self._reload_task
            except asyncio.CancelledError:
                pass
            self._reload_task = None
        await self.api_client.close()
        _LOGGER.debug("Coordinator unloaded")

    def last_good_update_age(self) -> float | None:
        """Return age in seconds since last successful device payload."""
        if self._last_good_update is None:
            return None
        return asyncio.get_event_loop().time() - self._last_good_update

    async def _log_initial_data_ready(self):
        try:
            await asyncio.wait_for(self._initial_data_event.wait(), timeout=30)
            _LOGGER.info("Initial observer update received")
        except asyncio.TimeoutError:
            _LOGGER.warning("Timed out waiting for initial observer data; entities may start unavailable")
