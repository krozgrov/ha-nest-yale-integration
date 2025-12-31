"""Select entities for Nest Yale Lock."""
import logging

from homeassistant.components.select import SelectEntity, SelectEntityDescription
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .entity import NestYaleEntity

_LOGGER = logging.getLogger(__name__)

_AUTO_LOCK_OPTIONS = {
    "10 seconds": 10,
    "1 minute": 60,
    "5 minutes": 300,
}
_AUTO_LOCK_OPTIONS_BY_SECONDS = {value: key for key, value in _AUTO_LOCK_OPTIONS.items()}

AUTO_LOCK_DURATION_DESC = SelectEntityDescription(
    key="auto_lock_duration",
    translation_key="auto_lock_duration",
)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
):
    coordinator = hass.data[DOMAIN][entry.entry_id]

    added_map = hass.data[DOMAIN].setdefault("added_select_ids", {})
    added: set[str] = added_map.setdefault(entry.entry_id, set())

    @callback
    def _process_devices():
        data = coordinator.data or {}
        new_entities: list[SelectEntity] = []
        for device_id, device in data.items():
            if not isinstance(device, dict):
                continue
            device.setdefault("device_id", device_id)
            uid = f"{DOMAIN}_auto_lock_duration_{device_id}"
            if uid in added:
                continue
            try:
                new_entities.append(NestYaleAutoLockDurationSelect(coordinator, device))
                added.add(uid)
            except Exception as err:
                _LOGGER.error("Failed to create auto-lock duration select for %s: %s", device_id, err, exc_info=True)
        if new_entities:
            async_add_entities(new_entities)

    _process_devices()
    cancel = coordinator.async_add_listener(_process_devices)
    entry.async_on_unload(cancel)


class NestYaleAutoLockDurationSelect(NestYaleEntity, SelectEntity):
    """Auto-lock duration presets."""

    _attr_entity_category = EntityCategory.CONFIG
    _attr_has_entity_name = True
    _attr_translation_key = "auto_lock_duration"
    _attr_options = list(_AUTO_LOCK_OPTIONS.keys())
    entity_description = AUTO_LOCK_DURATION_DESC

    def __init__(self, coordinator, device: dict):
        device_id = device.get("device_id")
        if not device_id:
            raise ValueError("device_id is required for auto-lock duration select")
        super().__init__(coordinator, device_id, device)
        self._attr_name = None
        self._attr_unique_id = f"{DOMAIN}_auto_lock_duration_{device_id}"

    @property
    def current_option(self) -> str | None:
        val = self._device_data.get("auto_relock_duration")
        if val is None:
            return None
        return _AUTO_LOCK_OPTIONS_BY_SECONDS.get(int(val))

    async def async_select_option(self, option: str) -> None:
        if option not in _AUTO_LOCK_OPTIONS:
            raise ValueError(f"Unsupported auto-lock option: {option}")
        await self._coordinator.api_client.update_bolt_lock_settings(
            self._device_id,
            auto_relock_on=True,
            auto_relock_duration=_AUTO_LOCK_OPTIONS[option],
            structure_id=self._coordinator.api_client.structure_id,
        )

    def _handle_coordinator_update(self) -> None:
        new_data = self._coordinator.data.get(self._device_id)
        if new_data:
            self._device_data.update(new_data)
            self._update_device_info_from_traits()
        self.async_write_ha_state()
