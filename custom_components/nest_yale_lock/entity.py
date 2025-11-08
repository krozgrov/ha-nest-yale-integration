"""Base entity class for Nest Yale Lock integration."""
import logging
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers import device_registry as dr
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
        
        # Get initial metadata
        metadata = self._coordinator.api_client.get_device_metadata(device_id)
        self._attr_name = metadata["name"]
        
        # Set up device info
        self._setup_device_info(metadata)
        
    def _setup_device_info(self, metadata):
        """Set up device info from metadata."""
        # Use serial number as primary identifier if available (from trait data), otherwise use device_id
        primary_identifier = metadata.get("serial_number") if metadata.get("serial_number") != self._device_id else self._device_id
        self._attr_unique_id = f"{DOMAIN}_{self._device_id}"  # Always use device_id for unique_id (stable)
        
        # Device info uses serial number as primary identifier if available
        if primary_identifier != self._device_id:
            identifiers = {(DOMAIN, primary_identifier), (DOMAIN, self._device_id)}  # Serial first (primary)
        else:
            identifiers = {(DOMAIN, self._device_id)}  # Only device_id if no serial yet
        
        # Set serial_number if available (separate from identifiers - this is what shows in Device Info card)
        serial_number = metadata.get("serial_number") if metadata.get("serial_number") != self._device_id else None
        self._attr_device_info = {
            "identifiers": identifiers,
            "manufacturer": "Nest",
            "model": "Nest x Yale Lock",
            "name": self._attr_name,
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
                
                # Update identifiers: use serial as primary, device_id as secondary
                if new_serial:
                    new_identifiers = {(DOMAIN, new_serial), (DOMAIN, self._device_id)}
                    current_identifiers = set(device.identifiers)
                    if current_identifiers != new_identifiers:
                        update_kwargs["new_identifiers"] = new_identifiers
                        _LOGGER.info("Updating device identifiers: %s -> %s", current_identifiers, new_identifiers)
                
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
                    self._attr_device_info["identifiers"] = {(DOMAIN, new_serial), (DOMAIN, self._device_id)}
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
                    self._attr_device_info["identifiers"] = {(DOMAIN, new_serial), (DOMAIN, self._device_id)}
                    self._attr_device_info["serial_number"] = new_serial
                if new_firmware:
                    self._attr_device_info["sw_version"] = new_firmware
                if new_manufacturer:
                    self._attr_device_info["manufacturer"] = new_manufacturer
                if new_model:
                    self._attr_device_info["model"] = new_model
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
        
        self._device_info_updated = True

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
                # Also update identifiers
                device_info["identifiers"] = {(DOMAIN, serial), (DOMAIN, self._device_id)}
                _LOGGER.debug("device_info property for %s: serial_number=%s, identifiers=%s, sw_version=%s", 
                             self._attr_unique_id, serial, device_info["identifiers"], device_info.get("sw_version"))
            if device_identity.get("manufacturer"):
                device_info["manufacturer"] = device_identity["manufacturer"]
            if device_identity.get("model"):
                device_info["model"] = device_identity["model"]
        
        return device_info

