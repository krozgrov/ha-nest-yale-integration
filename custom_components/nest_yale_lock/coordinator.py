#!/usr/bin/env python3
import logging
import asyncio
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
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
        self._watchdog_task: asyncio.Task | None = None
        self._last_recovery_ts: float | None = None
        self._recovery_attempts: int = 0
        self._known_lock_ids: set[str] = set()
        _LOGGER.debug("Initialized NestCoordinator with initial data: %s", self.data)

    async def async_setup(self):
        """Set up the coordinator."""
        _LOGGER.debug("Starting async_setup for coordinator")
        await self.api_client.async_setup()

        # Best-effort initial refresh but don't block HA startup
        try:
            await asyncio.wait_for(self.async_refresh(), timeout=10)
            if self.data:
                _LOGGER.debug("Initial data fetched: %s", self.data)
                self._initial_data_event.set()
                self._last_good_update = asyncio.get_event_loop().time()
        except asyncio.TimeoutError:
            _LOGGER.warning("Initial refresh timed out after 10s; continuing with observer")
        except Exception as err:
            _LOGGER.warning("Initial refresh failed (non-blocking): %s", err)

        self._observer_task = self.hass.loop.create_task(self._run_observer())
        _LOGGER.debug("Observer task created: %s", self._observer_task)

        # Watchdog: detect stale push updates and recover (refresh → reload) with rate limiting.
        if not self._watchdog_task or self._watchdog_task.done():
            self._watchdog_task = self.hass.loop.create_task(self._watchdog_loop())

        if not self._initial_data_event.is_set():
            self.hass.loop.create_task(self._log_initial_data_ready())

    def _merge_device_update(self, update: dict) -> dict:
        """Merge a partial device update into existing coordinator data.

        The observe stream can send partial device dicts; merging avoids dropping fields like
        traits/settings that were previously known.
        """
        if not isinstance(update, dict):
            return self.data or {}
        current = self.data or {}
        if not isinstance(current, dict):
            current = {}
        merged: dict = {**current}
        for device_id, device in update.items():
            if not isinstance(device, dict):
                continue
            prev = merged.get(device_id, {})
            if isinstance(prev, dict):
                merged[device_id] = {**prev, **device}
            else:
                merged[device_id] = device
        if self._known_lock_ids:
            merged = {
                device_id: device
                for device_id, device in merged.items()
                if device_id in self._known_lock_ids
            }
        return merged

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
                self._known_lock_ids = set(normalized_data.keys())
            if normalized_data:
                all_traits = self.api_client.current_state.get("all_traits", {}) or {}

                def _filter_traits_for_locks(traits: dict, lock_ids: set[str]) -> dict:
                    if not traits or not lock_ids:
                        return traits
                    filtered: dict = {}
                    for trait_key, trait_info in traits.items():
                        if not isinstance(trait_info, dict):
                            filtered[trait_key] = trait_info
                            continue
                        object_id = trait_info.get("object_id")
                        if object_id in lock_ids:
                            filtered[trait_key] = trait_info
                            continue
                        if isinstance(object_id, str) and (
                            object_id.startswith("STRUCTURE_") or object_id.startswith("USER_")
                        ):
                            filtered[trait_key] = trait_info
                    return filtered

                def _extract_device_traits(device_id: str, traits: dict) -> dict:
                    device_traits = {}
                    for trait_key, trait_info in traits.items():
                        if trait_key.startswith(f"{device_id}:"):
                            trait_name = trait_info.get("type_url", "").split(".")[-1]
                            if trait_info.get("decoded") and trait_info.get("data"):
                                device_traits[trait_name] = trait_info["data"]
                    return device_traits

                if all_traits:
                    if self._known_lock_ids:
                        all_traits = _filter_traits_for_locks(all_traits, self._known_lock_ids)
                        self.api_client.current_state["all_traits"] = all_traits
                    for device_id, device in normalized_data.items():
                        device_traits = _extract_device_traits(device_id, all_traits)
                        if device_traits:
                            device["traits"] = {**device.get("traits", {}), **device_traits}
            # Keep API client's cache in sync for metadata lookups (name/firmware fallbacks)
            try:
                self.api_client.current_state["devices"]["locks"].update(normalized_data)
            except Exception:
                pass
            if normalized_data:
                self._initial_data_event.set()
                self._empty_refresh_attempts = 0
                self._last_good_update = asyncio.get_event_loop().time()
            merged = self._merge_device_update(normalized_data) if normalized_data else self.data
            _LOGGER.debug("Normalized data from refresh_state: %s", merged)
            return merged
        except ConfigEntryAuthFailed as err:
            _LOGGER.warning("Authentication failed during refresh_state: %s", err)
            if self.entry_id:
                entry = self.hass.config_entries.async_get_entry(self.entry_id)
                if entry:
                    self.hass.config_entries.async_start_reauth(entry)
            raise
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
                    trait_states = update.get("trait_states", {})
                    lock_trait_markers = (
                        "BoltLockTrait",
                        "BoltLockSettingsTrait",
                        "BoltLockCapabilitiesTrait",
                        "TamperTrait",
                        "PincodeInputTrait",
                    )

                    def _extract_lock_ids_from_traits(states: dict) -> set[str]:
                        lock_ids: set[str] = set()
                        for device_id, traits in (states or {}).items():
                            if not isinstance(traits, dict):
                                continue
                            for trait_name in traits.keys():
                                if any(marker in trait_name for marker in lock_trait_markers):
                                    lock_ids.add(device_id)
                                    break
                        return lock_ids

                    def _is_lock_payload(device: dict) -> bool:
                        if not isinstance(device, dict):
                            return False
                        lock_keys = (
                            "bolt_locked",
                            "actuator_state",
                            "tamper_state",
                            "auto_relock_on",
                            "auto_relock_duration",
                            "max_auto_relock_duration",
                            "last_action",
                        )
                        return any(key in device for key in lock_keys)

                    def _filter_traits_for_locks(traits: dict, lock_ids: set[str]) -> dict:
                        if not traits or not lock_ids:
                            return traits
                        filtered: dict = {}
                        for trait_key, trait_info in traits.items():
                            if not isinstance(trait_info, dict):
                                filtered[trait_key] = trait_info
                                continue
                            object_id = trait_info.get("object_id")
                            if object_id in lock_ids:
                                filtered[trait_key] = trait_info
                                continue
                            if isinstance(object_id, str) and (
                                object_id.startswith("STRUCTURE_") or object_id.startswith("USER_")
                            ):
                                filtered[trait_key] = trait_info
                        return filtered
                    cached_traits = self.api_client.current_state.get("all_traits", {}) or {}
                    if all_traits:
                        merged_traits = {**cached_traits, **all_traits}
                        self.api_client.current_state["all_traits"] = merged_traits
                        all_traits = merged_traits
                    else:
                        all_traits = cached_traits
                    def _extract_device_traits(device_id: str) -> dict:
                        device_traits = {}
                        for trait_key, trait_info in all_traits.items():
                            if trait_key.startswith(f"{device_id}:"):
                                trait_name = trait_info.get("type_url", "").split(".")[-1]
                                if trait_info.get("decoded") and trait_info.get("data"):
                                    device_traits[trait_name] = trait_info["data"]
                        return device_traits

                    if normalized_update:
                        lock_ids_from_traits = _extract_lock_ids_from_traits(trait_states)
                        if lock_ids_from_traits:
                            self._known_lock_ids.update(lock_ids_from_traits)
                        if self._known_lock_ids:
                            normalized_update = {
                                device_id: device
                                for device_id, device in normalized_update.items()
                                if device_id in self._known_lock_ids
                            }
                        else:
                            normalized_update = {
                                device_id: device
                                for device_id, device in normalized_update.items()
                                if _is_lock_payload(device)
                            }
                        if normalized_update and not self._known_lock_ids:
                            self._known_lock_ids.update(normalized_update.keys())
                        if self._known_lock_ids:
                            all_traits = _filter_traits_for_locks(all_traits, self._known_lock_ids)
                        for device_id, device in normalized_update.items():
                            # Ensure required fields exist even if absent in payload
                            device.setdefault("device_id", device_id)
                            if "actuatorState" in device:
                                device["actuator_state"] = device["actuatorState"]
                            # Preserve bolt_moving if the stream sent it (used to clear optimistic state promptly)
                            if "bolt_moving" not in device:
                                device["bolt_moving"] = False
                            if device.get("bolt_moving"):
                                prior = self.data.get(device_id) or {}
                                for key in ("last_action", "last_action_method", "last_action_timestamp"):
                                    if key not in device:
                                        continue
                                    if key in prior:
                                        device[key] = prior[key]
                                    else:
                                        device.pop(key, None)
                            
                            # Extract trait data for this device from all_traits
                            device_traits = _extract_device_traits(device_id)
                            if device_traits:
                                device["traits"] = device_traits
                                _LOGGER.info("Added trait data to device %s: %s", device_id, list(device_traits.keys()))
                            else:
                                _LOGGER.debug("No trait data found for device %s in all_traits (keys: %s)", device_id, list(all_traits.keys())[:5])
                        
                        # Keep API client's cache in sync for metadata lookups (name/firmware fallbacks)
                        try:
                            self.api_client.current_state["devices"]["locks"].update(normalized_update)
                        except Exception:
                            pass

                        self.api_client.current_state["user_id"] = update.get("user_id")  # Persist user_id
                        self.api_client.current_state["all_traits"] = all_traits  # Persist trait data
                        self._empty_refresh_attempts = 0
                        self._last_good_update = asyncio.get_event_loop().time()
                        self.async_set_updated_data(self._merge_device_update(normalized_update))
                        self._initial_data_event.set()
                        _LOGGER.debug("Applied normalized observer update: %s, current_state user_id: %s",
                                      normalized_update, self.api_client.current_state["user_id"])
                    elif all_traits:
                        if self._known_lock_ids:
                            all_traits = _filter_traits_for_locks(all_traits, self._known_lock_ids)
                            self.api_client.current_state["all_traits"] = all_traits
                        updated = False
                        merged_data = {}
                        for device_id, device in (self.data or {}).items():
                            if not isinstance(device, dict):
                                merged_data[device_id] = device
                                continue
                            device_traits = _extract_device_traits(device_id)
                            if device_traits:
                                merged_device = {**device, "traits": {**device.get("traits", {}), **device_traits}}
                                merged_data[device_id] = merged_device
                                updated = True
                            else:
                                merged_data[device_id] = device
                        if self._known_lock_ids:
                            merged_data = {
                                device_id: device
                                for device_id, device in merged_data.items()
                                if device_id in self._known_lock_ids
                            }
                        if updated:
                            self._empty_refresh_attempts = 0
                            self._last_good_update = asyncio.get_event_loop().time()
                            self.async_set_updated_data(merged_data)
                            _LOGGER.debug("Applied trait-only observer update for %d device(s)", len(merged_data))
                        else:
                            self.async_set_updated_data(self.data)
                    else:
                        _LOGGER.debug("Normalized observer update is empty: %s", normalized_update)
                        self._observer_healthy = False  # allow fallback polling if stream yields nothing
                        self.async_set_updated_data(self.data)
                else:
                    _LOGGER.debug("Observer update received but is empty.")
                    self._observer_healthy = False  # allow fallback polling if stream yields nothing
                    self.async_set_updated_data(self.data)
        except ConfigEntryAuthFailed as err:
            _LOGGER.warning("Authentication failed in observe stream: %s", err)
            self._observer_healthy = False
            if self.entry_id:
                entry = self.hass.config_entries.async_get_entry(self.entry_id)
                if entry:
                    self.hass.config_entries.async_start_reauth(entry)
            return
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
        if self._watchdog_task:
            self._watchdog_task.cancel()
            try:
                await self._watchdog_task
            except asyncio.CancelledError:
                pass
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

    async def _watchdog_loop(self):
        """Background watchdog to recover if observe stream stalls for too long."""
        # Conservative defaults; can be tuned later via options.
        check_every = 60
        stale_refresh_after = 10 * 60  # 10 minutes without a good payload → force one fallback refresh
        stale_reload_after = 30 * 60   # 30 minutes without a good payload → reload entry (rate-limited)
        min_reload_interval = 30 * 60  # don't reload more often than every 30 minutes

        while True:
            await asyncio.sleep(check_every)
            try:
                age = self.last_good_update_age()
                if age is None:
                    continue

                # If the stream is healthy and we are receiving updates, do nothing.
                if age < stale_refresh_after:
                    self._recovery_attempts = 0
                    continue

                # First recovery step: force a fallback refresh (even if observer claims healthy).
                if self._recovery_attempts == 0:
                    _LOGGER.warning(
                        "Watchdog: no Yale updates for %.0fs; forcing fallback refresh_state",
                        age,
                    )
                    self._observer_healthy = False
                    try:
                        await asyncio.wait_for(self.async_refresh(), timeout=20)
                    except Exception as err:
                        _LOGGER.debug("Watchdog refresh attempt failed: %s", err)
                    self._last_recovery_ts = asyncio.get_event_loop().time()
                    self._recovery_attempts = 1
                    continue

                # Second step: if still stale long enough, reload (rate-limited).
                if age >= stale_reload_after:
                    now = asyncio.get_event_loop().time()
                    if self._last_recovery_ts and (now - self._last_recovery_ts) < min_reload_interval:
                        continue
                    _LOGGER.warning(
                        "Watchdog: still no Yale updates for %.0fs; scheduling entry reload",
                        age,
                    )
                    self._last_recovery_ts = now
                    self._recovery_attempts += 1
                    self.schedule_reload("Watchdog stale observe/updates", delay=0)
            except asyncio.CancelledError:
                raise
            except Exception as err:
                _LOGGER.debug("Watchdog loop error (ignored): %s", err, exc_info=True)
