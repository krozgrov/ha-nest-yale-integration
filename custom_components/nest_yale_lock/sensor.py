"""Battery sensor for Nest Yale Lock."""
import logging
from homeassistant.components.sensor import SensorEntity, SensorDeviceClass, SensorStateClass
from homeassistant.const import PERCENTAGE
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from .const import DOMAIN
from .entity import NestYaleEntity

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback):
    """Set up battery sensor entities."""
    _LOGGER.debug("Starting async_setup_entry for sensor platform, entry_id: %s", entry.entry_id)
    coordinator = hass.data[DOMAIN][entry.entry_id]

    # Use a per-entry tracker so removing/re-adding the integration does not
    # suppress rediscovery due to stale in-memory state.
    added_map = hass.data[DOMAIN].setdefault("added_sensor_ids", {})
    added: set[str] = added_map.setdefault(entry.entry_id, set())

    @callback
    def _process_devices():
        data = coordinator.data or {}
        new_entities = []
        for device_id, device in data.items():
            if not isinstance(device, dict):
                continue
            device.setdefault("device_id", device_id)
            unique_id = f"{DOMAIN}_battery_{device_id}"
            if unique_id in added:
                continue
            try:
                new_entities.append(NestYaleBatterySensor(coordinator, device))
                added.add(unique_id)
                _LOGGER.debug("Prepared new battery sensor entity: %s", unique_id)
            except Exception as e:
                _LOGGER.error("Failed to create battery sensor for %s: %s", device_id, e, exc_info=True)
        if new_entities:
            _LOGGER.info("Adding %d Nest Yale battery sensors", len(new_entities))
            async_add_entities(new_entities)

    # Add whatever we have now, then subscribe for future updates
    _process_devices()
    cancel = coordinator.async_add_listener(_process_devices)
    # Ensure listener removal on unload
    entry.async_on_unload(cancel)


class NestYaleBatterySensor(NestYaleEntity, SensorEntity):
    """Battery sensor for Nest Yale Lock."""

    def __init__(self, coordinator, device):
        """Initialize the battery sensor."""
        device_id = device.get("device_id")
        if not device_id:
            raise ValueError("device_id is required for battery sensor")
        super().__init__(coordinator, device_id, device)
        # Override unique_id to include "battery" prefix
        self._attr_unique_id = f"{DOMAIN}_battery_{device_id}"
        # Append "Battery" to the name
        self._attr_name = f"{self._attr_name} Battery"
        self._attr_device_class = SensorDeviceClass.BATTERY
        self._attr_state_class = SensorStateClass.MEASUREMENT
        self._attr_native_unit_of_measurement = PERCENTAGE
        _LOGGER.debug("Initialized battery sensor for %s", self._attr_unique_id)

    @property
    def native_value(self) -> float | None:
        """Return the battery level."""
        traits = self._device_data.get("traits", {})
        battery_trait = traits.get("BatteryPowerSourceTrait", {})
        if battery_trait and battery_trait.get("battery_level") is not None:
            battery_level = battery_trait["battery_level"]
            # Convert to percentage (0.0-1.0 -> 0-100)
            if isinstance(battery_level, float):
                return round(battery_level * 100, 1)
            return battery_level
        return None

    @property
    def extra_state_attributes(self):
        """Return extra state attributes."""
        attrs = {}
        traits = self._device_data.get("traits", {})
        battery_trait = traits.get("BatteryPowerSourceTrait", {})
        if battery_trait:
            if battery_trait.get("voltage") is not None:
                attrs["voltage"] = battery_trait["voltage"]
            if battery_trait.get("condition") is not None:
                attrs["condition"] = battery_trait["condition"]
            if battery_trait.get("status") is not None:
                attrs["status"] = battery_trait["status"]
            if battery_trait.get("replacement_indicator") is not None:
                attrs["replacement_indicator"] = battery_trait["replacement_indicator"]
        return attrs

    def _handle_coordinator_update(self) -> None:
        """Handle coordinator update."""
        new_data = self._coordinator.data.get(self._device_id)
        if new_data:
            self._device_data.update(new_data)
            # Update device_info from traits (handled by base class)
            self._update_device_info_from_traits()
        self.async_write_ha_state()

    @property
    def available(self) -> bool:
        """Return if entity is available."""
        available = bool(self._device_data) and self._coordinator.last_update_success
        return available

