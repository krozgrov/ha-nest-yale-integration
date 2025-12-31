"""Base entity class for Nest Yale Lock integration."""
import logging
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


class NestYaleEntity(CoordinatorEntity):
    """Base entity class for Nest Yale devices."""

    def __init__(self, coordinator, device_id, device_data):
        """Initialize the base entity."""
        super().__init__(coordinator)
        self._coordinator = coordinator
        self._device_id = device_id
        self._device_data = device_data.copy() if device_data else {}
        self._device_info_updated = False
        # If trait data arrives before the entity is added to HA, we may not be
        # able to update the device registry yet. Track that and retry once the
        # entity is fully added.
        self._device_registry_update_pending = False
        
        # Resolve entity naming/translation attributes after base init so they
        # are not overwritten by CoordinatorEntity/Entity defaults.
        entity_has_name = bool(
            getattr(self, "_attr_has_entity_name", False)
            or getattr(type(self), "_attr_has_entity_name", False)
        )
        self._attr_has_entity_name = entity_has_name

        translation_key = None
        if entity_has_name:
            candidate = getattr(self, "_attr_translation_key", None)
            if isinstance(candidate, str):
                translation_key = candidate
            if translation_key is None:
                candidate = getattr(type(self), "_attr_translation_key", None)
                if isinstance(candidate, str):
                    translation_key = candidate
            if translation_key is None:
                entity_description = getattr(self, "entity_description", None)
                if entity_description is None:
                    entity_description = getattr(type(self), "entity_description", None)
                if entity_description:
                    candidate = getattr(entity_description, "translation_key", None)
                    if isinstance(candidate, str):
                        translation_key = candidate
            if translation_key:
                self._attr_translation_key = translation_key

        # Get initial metadata
        metadata = self._coordinator.api_client.get_device_metadata(device_id)
        # Only set _attr_name for entities that opt out of entity naming.
        # Home Assistant skips translations when _attr_name is present.
        if not entity_has_name:
            self._attr_name = metadata["name"]
        
        # Log final state for debugging
        if entity_has_name:
            _LOGGER.debug(
                "Entity %s: has_entity_name=%s, translation_key=%s, name=%s",
                self.__class__.__name__,
                entity_has_name,
                translation_key,
                getattr(self, "_attr_name", None),
            )
        
        self._device_name = metadata.get("name")
        
        # Set up device info
        self._setup_device_info(metadata)

    async def async_added_to_hass(self) -> None:
        """Run when entity is added to Home Assistant."""
        await super().async_added_to_hass()
        # If we saw trait data early, retry registry update now that hass is available.
        if not self._device_info_updated or self._device_registry_update_pending:
            self._update_device_info_from_traits()
        # Ensure entity registry original_name reflects translated entity naming.
        self._ensure_entity_registry_name()

    def _ensure_entity_registry_name(self) -> None:
        """Normalize entity registry names for entity-named sub-entities."""
        if not getattr(self, "_attr_has_entity_name", False):
            return
        if not self.hass:
            return
        try:
            entity_registry = er.async_get(self.hass)
            entry = entity_registry.async_get(self.entity_id)
            if not entry:
                return
            # Respect user overrides.
            if entry.name is not None:
                return
            desired_name = self.name
            if not desired_name:
                return
            if entry.original_name != desired_name:
                entity_registry.async_update_entity(
                    self.entity_id,
                    original_name=desired_name,
                )
                _LOGGER.info(
                    "Updated entity registry name for %s: %s -> %s",
                    self.entity_id,
                    entry.original_name,
                    desired_name,
                )
        except Exception as err:
            _LOGGER.debug(
                "Failed to update entity registry name for %s: %s",
                self.entity_id,
                err,
            )
        
    def _setup_device_info(self, metadata):
        """Set up device info from metadata."""
        self._attr_unique_id = f"{DOMAIN}_{self._device_id}"  # Always use device_id for unique_id (stable)

        # Keep identifiers stable: use device_id only and store serial separately.
        identifiers = {(DOMAIN, self._device_id)}
        serial_number = metadata.get("serial_number") if metadata.get("serial_number") != self._device_id else None
        self._attr_device_info = {
            "identifiers": identifiers,
            "manufacturer": "Nest",
            "model": "Nest x Yale Lock",
            "name": self._device_name,
            "sw_version": metadata["firmware_revision"],
        }
        if serial_number:
            self._attr_device_info["serial_number"] = serial_number
        
        _LOGGER.debug("Initial device_info for %s: identifiers=%s, serial_number=%s, sw_version=%s", 
                     self._attr_unique_id, identifiers, serial_number, metadata["firmware_revision"])

    def _update_device_info_from_traits(self):
        """Update device_info when trait data arrives."""
        if self._device_info_updated:
            return
            
        traits = self._device_data.get("traits", {})
        device_identity = traits.get("DeviceIdentityTrait", {})
        if not device_identity:
            return
            
        new_serial = device_identity.get("serial_number")
        new_firmware = device_identity.get("firmware_version")
        new_manufacturer = device_identity.get("manufacturer")
        new_model = device_identity.get("model")
        
        _LOGGER.debug("Processing trait data for %s: serial=%s, fw=%s, manufacturer=%s, model=%s",
                     self._attr_unique_id, new_serial, new_firmware, new_manufacturer, new_model)
        
        if not (new_serial or new_firmware):
            return
        
        # Update _attr_device_info
        if new_firmware:
            self._attr_device_info["sw_version"] = new_firmware
        if new_manufacturer:
            self._attr_device_info["manufacturer"] = new_manufacturer
        if new_model:
            self._attr_device_info["model"] = new_model
        
        _LOGGER.info("Updated device_info for %s with trait data: serial=%s, fw=%s", 
                   self._attr_unique_id, new_serial, new_firmware)
        
        # Update device registry so HA UI reflects the changes
        # Only update registry if entity has been added to hass (self.hass is available)
        if not hasattr(self, 'hass') or self.hass is None:
            _LOGGER.debug("Entity %s not yet added to hass, skipping device registry update", self._attr_unique_id)
            # Still update _attr_device_info even if not in hass yet
            if new_serial:
                self._attr_device_info["serial_number"] = new_serial
            if new_firmware:
                self._attr_device_info["sw_version"] = new_firmware
            if new_manufacturer:
                self._attr_device_info["manufacturer"] = new_manufacturer
            if new_model:
                self._attr_device_info["model"] = new_model
            # IMPORTANT: don't mark as "updated" yet — we still need to update the
            # device registry once the entity is added to HA, otherwise firmware/
            # serial can remain "unknown" in the Device Info card.
            self._device_registry_update_pending = True
            return
        
        try:
            device_registry = dr.async_get(self.hass)
            _LOGGER.debug("Looking up device in registry for %s: device_id=%s, serial=%s", 
                         self._attr_unique_id, self._device_id, new_serial)
            
            # Find device by checking both device_id and serial number
            device = device_registry.async_get_device(identifiers={(DOMAIN, self._device_id)})
            if not device and new_serial:
                _LOGGER.debug("Device not found by device_id, trying serial number")
                device = device_registry.async_get_device(identifiers={(DOMAIN, new_serial)})
            
            if device:
                _LOGGER.debug("Found device in registry: id=%s, identifiers=%s, sw_version=%s", 
                             device.id, device.identifiers, device.sw_version)
                update_kwargs = {}

                # Ensure a device name is set when HA doesn't have one and the user hasn't overridden it.
                if self._device_name:
                    device_name_by_user = getattr(device, "name_by_user", None)
                    if not device_name_by_user and not device.name:
                        update_kwargs["name"] = self._device_name
                        _LOGGER.info("Setting device name: %s", self._device_name)
                
                # Always update firmware if we have it from trait data
                if new_firmware:
                    if device.sw_version != new_firmware:
                        update_kwargs["sw_version"] = new_firmware
                        _LOGGER.info("Updating device firmware: %s -> %s", device.sw_version, new_firmware)
                    elif device.sw_version is None or device.sw_version == "unknown":
                        update_kwargs["sw_version"] = new_firmware
                        _LOGGER.info("Setting device firmware: %s (was unknown)", new_firmware)
                
                if new_manufacturer and device.manufacturer != new_manufacturer:
                    update_kwargs["manufacturer"] = new_manufacturer
                    _LOGGER.info("Updating device manufacturer: %s -> %s", device.manufacturer, new_manufacturer)
                
                if new_model and device.model != new_model:
                    update_kwargs["model"] = new_model
                    _LOGGER.info("Updating device model: %s -> %s", device.model, new_model)
                
                # Update serial_number field (this is what shows in Device Info card per HA docs)
                if new_serial and device.serial_number != new_serial:
                    update_kwargs["serial_number"] = new_serial
                    _LOGGER.info("Updating device serial_number: %s -> %s", device.serial_number, new_serial)
                
                if update_kwargs:
                    device_registry.async_update_device(device.id, **update_kwargs)
                    _LOGGER.info("✅ Successfully updated device registry for %s: %s", self._attr_unique_id, update_kwargs)
                else:
                    _LOGGER.debug("No device registry updates needed for %s (already up to date)", self._attr_unique_id)
                
                # Always update _attr_device_info to match latest trait data
                if new_serial:
                    self._attr_device_info["serial_number"] = new_serial
                if new_firmware:
                    self._attr_device_info["sw_version"] = new_firmware
                if new_manufacturer:
                    self._attr_device_info["manufacturer"] = new_manufacturer
                if new_model:
                    self._attr_device_info["model"] = new_model
            else:
                _LOGGER.warning("Could not find device in registry for %s (device_id=%s, serial=%s). Device may not be registered yet.", 
                              self._attr_unique_id, self._device_id, new_serial)
                # Still update _attr_device_info even if device not found in registry
                if new_serial:
                    self._attr_device_info["serial_number"] = new_serial
                if new_firmware:
                    self._attr_device_info["sw_version"] = new_firmware
                if new_manufacturer:
                    self._attr_device_info["manufacturer"] = new_manufacturer
                if new_model:
                    self._attr_device_info["model"] = new_model
                # Retry on next update (or when entity is fully registered).
                self._device_registry_update_pending = True
                return
        except Exception as e:
            _LOGGER.error("Error updating device registry for %s: %s", self._attr_unique_id, e, exc_info=True)
            # Still update _attr_device_info even if registry update fails
            if new_serial:
                self._attr_device_info["serial_number"] = new_serial
            if new_firmware:
                self._attr_device_info["sw_version"] = new_firmware
            if new_manufacturer:
                self._attr_device_info["manufacturer"] = new_manufacturer
            if new_model:
                self._attr_device_info["model"] = new_model
            self._device_registry_update_pending = True
            return
        
        self._device_info_updated = True
        self._device_registry_update_pending = False

    @property
    def device_info(self) -> DeviceInfo:
        """Return device information."""
        # Always return current device_info, which is updated when trait data arrives
        device_info = self._attr_device_info.copy()
        
        # Also check for latest trait data in case it wasn't processed yet
        traits = self._device_data.get("traits", {})
        device_identity = traits.get("DeviceIdentityTrait", {})
        if device_identity:
            if device_identity.get("firmware_version"):
                device_info["sw_version"] = device_identity["firmware_version"]
            if device_identity.get("serial_number"):
                serial = device_identity["serial_number"]
                # Set serial_number field (this is what shows in Device Info card per HA docs)
                device_info["serial_number"] = serial
                _LOGGER.debug("device_info property for %s: serial_number=%s, identifiers=%s, sw_version=%s", 
                             self._attr_unique_id, serial, device_info["identifiers"], device_info.get("sw_version"))
            if device_identity.get("manufacturer"):
                device_info["manufacturer"] = device_identity["manufacturer"]
            if device_identity.get("model"):
                device_info["model"] = device_identity["model"]
        
        return device_info

    def _get_device_attributes(self):
        """Get common device-level attributes shared by all entities.
        
        This method provides device-level information that should be consistent
        across all entities for the same device (lock, sensor, etc.).
        
        Returns:
            dict: Dictionary of device-level attributes
        """
        serial_number = self._attr_device_info.get("serial_number") or self._device_id
        
        # Extract trait data from device
        traits = self._device_data.get("traits", {})
        
        # DeviceIdentityTrait data
        device_identity = traits.get("DeviceIdentityTrait", {})
        if device_identity:
            if device_identity.get("serial_number"):
                serial_number = device_identity["serial_number"]
            if device_identity.get("firmware_version"):
                firmware_revision = device_identity["firmware_version"]
            else:
                firmware_revision = self._attr_device_info.get("sw_version", "unknown")
        else:
            firmware_revision = self._attr_device_info.get("sw_version", "unknown")
        
        # Return device-level attributes in logical order.
        # Sensitive identifiers (user_id/structure_id) are diagnostics-only.
        # 3. Device ID
        # 4. Firmware
        # 5. Serial Number
        attrs = {
            "device_id": self._device_id,
            "firmware_revision": firmware_revision,
            "serial_number": serial_number,
        }
        
        # Additional device identity attributes (if available)
        if device_identity:
            if device_identity.get("manufacturer"):
                attrs["manufacturer"] = device_identity["manufacturer"]
            if device_identity.get("model"):
                attrs["model"] = device_identity["model"]
        
        return attrs
