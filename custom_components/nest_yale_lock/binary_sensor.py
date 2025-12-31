"""Binary sensors for Nest Yale Lock."""
import logging

from homeassistant.components.binary_sensor import (
    BinarySensorEntity,
    BinarySensorDeviceClass,
)
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

    added_map = hass.data[DOMAIN].setdefault("added_binary_sensor_ids", {})
    added: set[str] = added_map.setdefault(entry.entry_id, set())

    @callback
    def _process_devices():
        data = coordinator.data or {}
        new_entities: list[BinarySensorEntity] = []
        for device_id, device in data.items():
            if not isinstance(device, dict):
                continue
            device.setdefault("device_id", device_id)
            uid = f"{DOMAIN}_tamper_{device_id}"
            if uid in added:
                continue
            try:
                new_entities.append(NestYaleTamperBinarySensor(coordinator, device))
                added.add(uid)
            except Exception as err:
                _LOGGER.error("Failed to create tamper sensor for %s: %s", device_id, err, exc_info=True)
        if new_entities:
            async_add_entities(new_entities)

    _process_devices()
    cancel = coordinator.async_add_listener(_process_devices)
    entry.async_on_unload(cancel)


class NestYaleTamperBinarySensor(NestYaleEntity, BinarySensorEntity):
    """Tamper diagnostic sensor."""

    _attr_device_class = BinarySensorDeviceClass.TAMPER
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_has_entity_name = True
    _attr_translation_key = "tamper"

    def __init__(self, coordinator, device: dict):
        device_id = device.get("device_id")
        if not device_id:
            raise ValueError("device_id is required for tamper sensor")
        super().__init__(coordinator, device_id, device)
        self._attr_name = None
        self._attr_unique_id = f"{DOMAIN}_tamper_{device_id}"

    @property
    def is_on(self) -> bool | None:
        # Populated by protobuf_handler (TamperTrait)
        detected = self._device_data.get("tamper_detected")
        if detected is None:
            return None
        return bool(detected)

    def _handle_coordinator_update(self) -> None:
        new_data = self._coordinator.data.get(self._device_id)
        if new_data:
            self._device_data.update(new_data)
            self._update_device_info_from_traits()
        self.async_write_ha_state()
