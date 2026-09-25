"""Data exposed for Nest Yale lock actions."""


def last_action_attributes(device: dict) -> dict:
    """Return actor and PIN slot owners without exposing passcode digits."""
    traits = device.get("traits") or {}
    if not isinstance(traits, dict):
        traits = {}
    pin_trait = traits.get("UserPincodesSettingsTrait") or {}
    if not isinstance(pin_trait, dict):
        pin_trait = {}
    pins = pin_trait.get("user_pincodes") or {}
    if not isinstance(pins, dict):
        pins = {}
    code_users = {
        str(slot): pin["user_id"]
        for slot, pin in pins.items()
        if isinstance(pin, dict) and pin.get("user_id")
    }
    return {
        "user_id": device.get("last_action_user_id"),
        "code_users": code_users,
    }


def new_lock_action_events(update: dict, previous_data: dict) -> list[dict]:
    """Find completed actions with a new timestamp for an existing lock."""
    events = []
    for device_id, device in update.items():
        if not isinstance(device, dict) or device.get("bolt_moving"):
            continue
        previous = previous_data.get(device_id) or {}
        previous_timestamp = previous.get("last_action_timestamp")
        timestamp = device.get("last_action_timestamp")
        if not previous_timestamp or not timestamp or timestamp == previous_timestamp:
            continue
        method = device.get("last_action")
        if method:
            events.append({
                "device_id": device_id,
                "method": method,
                "user_id": device.get("last_action_user_id"),
                "timestamp": timestamp,
            })
    return events
