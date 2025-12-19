"""Number entities for Nest Yale Lock."""
import logging

from homeassistant.components.number import NumberEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .entity import NestYaleEntity

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
):
    coordinator = hass.data[DOMAIN][entry.entry_id]

    added_map = hass.data[DOMAIN].setdefault("added_number_ids", {})
    added: set[str] = added_map.setdefault(entry.entry_id, set())

    @callback
    def _process_devices():
        data = coordinator.data or {}
        new_entities: list[NumberEntity] = []
        for device_id, device in data.items():
            if not isinstance(device, dict):
                continue
            device.setdefault("device_id", device_id)
            uid = f"{DOMAIN}_auto_relock_duration_{device_id}"
            if uid in added:
                continue
            try:
                new_entities.append(NestYaleAutoRelockDurationNumber(coordinator, device))
                added.add(uid)
            except Exception as err:
                _LOGGER.error("Failed to create auto-relock duration for %s: %s", device_id, err, exc_info=True)
        if new_entities:
            async_add_entities(new_entities)

    _process_devices()
    cancel = coordinator.async_add_listener(_process_devices)
    entry.async_on_unload(cancel)


class NestYaleAutoRelockDurationNumber(NestYaleEntity, NumberEntity):
    """Auto-relock duration (seconds)."""

    _attr_entity_category = EntityCategory.CONFIG
    _attr_native_unit_of_measurement = "s"
    _attr_step = 1

    def __init__(self, coordinator, device: dict):
        device_id = device.get("device_id")
        if not device_id:
            raise ValueError("device_id is required for auto-relock duration")
        super().__init__(coordinator, device_id, device)
        self._attr_unique_id = f"{DOMAIN}_auto_relock_duration_{device_id}"
        self._attr_name = "Auto-Relock Duration"
        self._attr_native_min_value = 0
        # Default to 300s if capabilities not yet present; update dynamically in native_max_value
        self._attr_native_max_value = 300

    @property
    def native_max_value(self) -> float:
        max_val = self._device_data.get("max_auto_relock_duration")
        if isinstance(max_val, (int, float)) and max_val > 0:
            return float(max_val)
        return float(self._attr_native_max_value or 300)

    @property
    def native_value(self) -> float | None:
        val = self._device_data.get("auto_relock_duration")
        if val is None:
            return None
        return float(val)

    async def async_set_native_value(self, value: float) -> None:
        await self._coordinator.api_client.update_bolt_lock_settings(
            self._device_id,
            auto_relock_duration=int(value),
            structure_id=self._coordinator.api_client.structure_id,
        )

    def _handle_coordinator_update(self) -> None:
        new_data = self._coordinator.data.get(self._device_id)
        if new_data:
            self._device_data.update(new_data)
            self._update_device_info_from_traits()
        self.async_write_ha_state()


