"""Battery sensor for Nest Yale Lock."""
import logging
from homeassistant.components.sensor import (
    SensorEntity,
    SensorDeviceClass,
    SensorStateClass,
    SensorEntityDescription,
)
from homeassistant.const import PERCENTAGE
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from .const import DOMAIN
from .entity import NestYaleEntity

_LOGGER = logging.getLogger(__name__)

BATTERY_SENSOR_DESC = SensorEntityDescription(
    key="battery",
    translation_key="battery",
)
LAST_ACTION_SENSOR_DESC = SensorEntityDescription(
    key="last_action",
    translation_key="last_action",
)


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
            try:
                # Battery (diagnostic)
                battery_uid = f"{DOMAIN}_battery_{device_id}"
                if battery_uid not in added:
                    new_entities.append(NestYaleBatterySensor(coordinator, device))
                    added.add(battery_uid)
                    _LOGGER.debug("Prepared new battery sensor entity: %s", battery_uid)

                # Last Action (sensor)
                last_action_uid = f"{DOMAIN}_last_action_{device_id}"
                if last_action_uid not in added:
                    new_entities.append(NestYaleLastActionSensor(coordinator, device))
                    added.add(last_action_uid)
                    _LOGGER.debug("Prepared new last action sensor entity: %s", last_action_uid)
            except Exception as e:
                _LOGGER.error("Failed to create battery sensor for %s: %s", device_id, e, exc_info=True)
        if new_entities:
            _LOGGER.info("Adding %d Nest Yale sensors", len(new_entities))
            async_add_entities(new_entities)

    # Add whatever we have now, then subscribe for future updates
    _process_devices()
    cancel = coordinator.async_add_listener(_process_devices)
    # Ensure listener removal on unload
    entry.async_on_unload(cancel)


class NestYaleBatterySensor(NestYaleEntity, SensorEntity):
    """Battery sensor for Nest Yale Lock."""

    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_has_entity_name = True
    _attr_translation_key = "battery"
    entity_description = BATTERY_SENSOR_DESC

    def __init__(self, coordinator, device):
        """Initialize the battery sensor."""
        device_id = device.get("device_id")
        if not device_id:
            raise ValueError("device_id is required for battery sensor")
        super().__init__(coordinator, device_id, device)
        # Override unique_id to include "battery" prefix
        self._attr_unique_id = f"{DOMAIN}_battery_{device_id}"
        self._attr_device_class = SensorDeviceClass.BATTERY
        self._attr_state_class = SensorStateClass.MEASUREMENT
        self._attr_native_unit_of_measurement = PERCENTAGE
        _LOGGER.debug("Initialized battery sensor for %s", self._attr_unique_id)

    @property
    def native_value(self) -> int | None:
        """Return the battery level."""
        return self._battery_level_from_trait()

    @property
    def extra_state_attributes(self):
        """Return extra state attributes."""
        attrs = {}
        battery_trait = self._battery_trait()
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
        self._apply_coordinator_update()
        self.async_write_ha_state()

    @property
    def available(self) -> bool:
        """Return if entity is available."""
        # DataUpdateCoordinator.last_update_success is based on polling refreshes;
        # this integration is push-first. Mirror the lock entity behavior so the
        # battery sensor doesn't get stuck in UNKNOWN/UNAVAILABLE.
        if not self._device_data:
            return False
        age = self._coordinator.last_good_update_age() if hasattr(self._coordinator, "last_good_update_age") else None
        stale_limit = self._coordinator.hass.data.get(
            "nest_yale_lock_stale_max",  # optional override
            getattr(self._coordinator, "_stale_max_seconds", None) or 900,
        )
        if age is None:
            return True
        return age < stale_limit


class NestYaleLastActionSensor(NestYaleEntity, SensorEntity):
    """Last action sensor (Physical/Keypad/Remote/etc)."""

    _attr_has_entity_name = True
    _attr_translation_key = "last_action"
    entity_description = LAST_ACTION_SENSOR_DESC

    def __init__(self, coordinator, device):
        device_id = device.get("device_id")
        if not device_id:
            raise ValueError("device_id is required for last action sensor")
        super().__init__(coordinator, device_id, device)
        self._attr_unique_id = f"{DOMAIN}_last_action_{device_id}"
        _LOGGER.debug("Initialized last action sensor for %s", self._attr_unique_id)

    @property
    def native_value(self) -> str | None:
        # Populated by protobuf_handler (BoltLockTrait.boltLockActor.method mapping)
        return self._device_data.get("last_action")

    def _handle_coordinator_update(self) -> None:
        self._apply_coordinator_update()
        self.async_write_ha_state()
