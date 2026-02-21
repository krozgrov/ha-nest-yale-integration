"""Passcode and guest-user helper utilities.

These helpers intentionally avoid Home Assistant imports so they can be
unit-tested in isolation.
"""

from __future__ import annotations

from typing import Any


def passcode_limits(
    device_data: dict[str, Any] | None,
    default_min_len: int,
    default_max_len: int,
) -> tuple[int, int]:
    """Determine valid passcode length bounds for a device."""
    min_len = default_min_len
    max_len = default_max_len
    if isinstance(device_data, dict):
        traits = device_data.get("traits", {})
        if isinstance(traits, dict):
            caps = traits.get("UserPincodesCapabilitiesTrait", {})
            if isinstance(caps, dict):
                cap_min = caps.get("min_pincode_length")
                cap_max = caps.get("max_pincode_length")
                if isinstance(cap_min, int) and cap_min > 0:
                    min_len = cap_min
                if isinstance(cap_max, int) and cap_max > 0:
                    max_len = cap_max
    if min_len > max_len:
        return default_min_len, default_max_len
    return min_len, max_len


def max_pincodes_supported(
    device_data: dict[str, Any] | None,
    default_max_slots: int = 25,
) -> int:
    """Determine max supported pincode slots for a device."""
    max_slots = default_max_slots
    if isinstance(device_data, dict):
        traits = device_data.get("traits", {})
        if isinstance(traits, dict):
            caps = traits.get("UserPincodesCapabilitiesTrait", {})
            if isinstance(caps, dict):
                raw_max = caps.get("max_pincodes_supported")
                if isinstance(raw_max, int) and raw_max > 0:
                    max_slots = raw_max
    return max_slots


def extract_guest_user_slots(device_data: dict[str, Any] | None) -> dict[int, dict[str, Any]]:
    """Extract guest/user slot metadata from normalized trait data."""
    slots: dict[int, dict[str, Any]] = {}
    if not isinstance(device_data, dict):
        return slots

    traits = device_data.get("traits", {})
    if not isinstance(traits, dict):
        return slots

    pincode_trait = traits.get("UserPincodesSettingsTrait", {})
    if not isinstance(pincode_trait, dict):
        return slots

    user_pincodes = pincode_trait.get("user_pincodes", {})
    if not isinstance(user_pincodes, dict):
        return slots

    for raw_slot, details in user_pincodes.items():
        try:
            slot = int(raw_slot)
        except (TypeError, ValueError):
            continue
        if slot <= 0 or not isinstance(details, dict):
            continue

        slot_info: dict[str, Any] = {"slot": slot}
        user_id = details.get("user_id")
        if isinstance(user_id, str) and user_id.strip():
            slot_info["user_id"] = user_id.strip()

        enabled = details.get("enabled")
        if isinstance(enabled, bool):
            slot_info["enabled"] = enabled

        has_passcode = details.get("has_passcode")
        if isinstance(has_passcode, bool):
            slot_info["has_passcode"] = has_passcode

        slots[slot] = slot_info

    return dict(sorted(slots.items()))


def validate_guest_slot(slot: int | None, device_data: dict[str, Any] | None) -> None:
    """Validate slot range against lock capabilities."""
    if slot is None:
        return
    if not isinstance(slot, int) or slot <= 0:
        raise ValueError("slot must be a positive integer.")
    max_slots = max_pincodes_supported(device_data)
    if slot > max_slots:
        raise ValueError(f"slot must be between 1 and {max_slots} for this lock.")


def resolve_guest_user_id(
    guest_user_id: str | None,
    slot: int | None,
    device_data: dict[str, Any] | None,
) -> str:
    """Resolve user id from explicit id or existing slot mapping."""
    if isinstance(guest_user_id, str):
        normalized = guest_user_id.strip()
        if normalized:
            return normalized

    slots = extract_guest_user_slots(device_data)

    if slot is None:
        mapped_user_ids = sorted(
            {
                slot_info.get("user_id", "").strip()
                for slot_info in slots.values()
                if isinstance(slot_info.get("user_id"), str) and slot_info.get("user_id", "").strip()
            }
        )
        if len(mapped_user_ids) == 1:
            return mapped_user_ids[0]
        if not mapped_user_ids:
            raise ValueError(
                "Provide guest_user_id or slot. "
                "No mapped guest users are available yet."
            )
        raise ValueError(
            "Provide slot or guest_user_id. "
            "Multiple mapped guest users were found for this lock."
        )

    slot_info = slots.get(slot)
    if not slot_info:
        raise ValueError(
            "No user mapping was found for this slot. "
            "Create the guest in the Nest app first, then retry."
        )

    resolved_user_id = slot_info.get("user_id")
    if not isinstance(resolved_user_id, str) or not resolved_user_id.strip():
        raise ValueError(
            "Slot exists but has no user_id mapping. "
            "Create or sync the guest in the Nest app first."
        )
    return resolved_user_id.strip()


def validate_guest_passcode(
    passcode: str,
    device_data: dict[str, Any] | None,
    default_min_len: int,
    default_max_len: int,
) -> None:
    """Validate guest passcode content and length."""
    if not isinstance(passcode, str):
        raise ValueError("Passcode must be a string of digits.")
    value = passcode.strip()
    if not value:
        raise ValueError("Passcode is required.")
    if not value.isdigit():
        raise ValueError("Passcode must contain digits only.")
    min_len, max_len = passcode_limits(device_data, default_min_len, default_max_len)
    if len(value) < min_len or len(value) > max_len:
        raise ValueError(
            f"Passcode length must be between {min_len} and {max_len} digits for this lock."
        )
