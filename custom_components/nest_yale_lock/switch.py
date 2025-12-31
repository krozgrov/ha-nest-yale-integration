"""Switch entities for Nest Yale Lock."""
import logging

from homeassistant.components.switch import SwitchEntity, SwitchEntityDescription
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .entity import NestYaleEntity

_LOGGER = logging.getLogger(__name__)

AUTO_LOCK_SWITCH_DESC = SwitchEntityDescription(
    key="auto_lock",
    translation_key="auto_lock",
)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
):
    coordinator = hass.data[DOMAIN][entry.entry_id]

    added_map = hass.data[DOMAIN].setdefault("added_switch_ids", {})
    added: set[str] = added_map.setdefault(entry.entry_id, set())

    @callback
    def _process_devices():
        data = coordinator.data or {}
        new_entities: list[SwitchEntity] = []
        for device_id, device in data.items():
            if not isinstance(device, dict):
                continue
            device.setdefault("device_id", device_id)
            uid = f"{DOMAIN}_auto_relock_{device_id}"
            if uid in added:
                continue
            try:
                new_entities.append(NestYaleAutoRelockSwitch(coordinator, device))
                added.add(uid)
            except Exception as err:
                _LOGGER.error("Failed to create auto-relock switch for %s: %s", device_id, err, exc_info=True)
        if new_entities:
            async_add_entities(new_entities)

    _process_devices()
    cancel = coordinator.async_add_listener(_process_devices)
    entry.async_on_unload(cancel)


class NestYaleAutoRelockSwitch(NestYaleEntity, SwitchEntity):
    """Auto-relock enable/disable."""

    _attr_entity_category = EntityCategory.CONFIG
    _attr_has_entity_name = True
    _attr_translation_key = "auto_lock"
    entity_description = AUTO_LOCK_SWITCH_DESC

    def __init__(self, coordinator, device: dict):
        device_id = device.get("device_id")
        if not device_id:
            raise ValueError("device_id is required for auto-relock switch")
        super().__init__(coordinator, device_id, device)
        self._attr_name = None
        self._attr_unique_id = f"{DOMAIN}_auto_relock_{device_id}"

    @property
    def is_on(self) -> bool | None:
        val = self._device_data.get("auto_relock_on")
        return None if val is None else bool(val)

    async def async_turn_on(self, **kwargs) -> None:
        duration = self._device_data.get("auto_relock_duration")
        if duration is None:
            duration = 60
        await self._coordinator.api_client.update_bolt_lock_settings(
            self._device_id,
            auto_relock_on=True,
            auto_relock_duration=int(duration),
            structure_id=self._coordinator.api_client.structure_id,
        )

    async def async_turn_off(self, **kwargs) -> None:
        await self._coordinator.api_client.update_bolt_lock_settings(
            self._device_id,
            auto_relock_on=False,
            structure_id=self._coordinator.api_client.structure_id,
        )

    def _handle_coordinator_update(self) -> None:
        new_data = self._coordinator.data.get(self._device_id)
        if new_data:
            self._device_data.update(new_data)
            self._update_device_info_from_traits()
        self.async_write_ha_state()
