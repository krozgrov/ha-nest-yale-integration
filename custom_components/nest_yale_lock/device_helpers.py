from __future__ import annotations

from typing import Optional

from homeassistant.helpers import device_registry as dr

from .const import DOMAIN


def ensure_device_registered(
    hass,
    entry_id: str,
    device_id: str,
    metadata: dict,
) -> Optional[str]:
    """Ensure a device with the Nest Yale identifiers is present and linked to the config entry."""
    dev_reg = dr.async_get(hass)
    identifiers = {(DOMAIN, device_id)}
    serial = metadata.get("serial_number")
    if serial and serial != device_id:
        identifiers.add((DOMAIN, serial))

    device = dev_reg.async_get_device(identifiers)
    if device:
        if entry_id not in device.config_entries:
            dev_reg.async_update_device(device.id, add_config_entry_id=entry_id)
        return device.id

    device = dev_reg.async_get_or_create(
        config_entry_id=entry_id,
        identifiers=identifiers,
        manufacturer=metadata.get("manufacturer", "Nest"),
        model=metadata.get("model", "Nest x Yale Lock"),
        name=metadata.get("name", "Nest Yale Lock"),
        sw_version=metadata.get("firmware_revision"),
    )
    return device.id if device else None
