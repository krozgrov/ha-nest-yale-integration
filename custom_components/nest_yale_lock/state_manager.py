import logging

_LOGGER = logging.getLogger(__name__)

class NestStateManager:
    def __init__(self, user_id=None, structure_id=None):
        self._user_id = user_id
        self._structure_id = structure_id
        self.current_state = {"devices": {"locks": {}}, "user_id": self._user_id, "structure_id": self._structure_id}

    @property
    def user_id(self):
        return self._user_id

    @property
    def structure_id(self):
        # Always return the latest structure_id, falling back to current_state if needed
        if self._structure_id:
            _LOGGER.debug(f"[DEBUG] state_manager: returning _structure_id={self._structure_id}")
            return self._structure_id
        fallback = self.current_state.get("structure_id")
        _LOGGER.debug(f"[DEBUG] state_manager: returning fallback structure_id={fallback}")
        return fallback

    def update_state(self, locks_data):
        # Always update user_id and structure_id if present, even if no yale data
        if locks_data.get("user_id"):
            old_user_id = self._user_id
            self._user_id = locks_data["user_id"]
            self.current_state["user_id"] = self._user_id
            if old_user_id != self._user_id:
                _LOGGER.info(f"Updated user_id from stream: {self._user_id} (was {old_user_id})")
        if locks_data.get("structureId"):
            old_structure_id = self._structure_id
            self._structure_id = locks_data["structureId"]
            self.current_state["structure_id"] = self._structure_id
            _LOGGER.info(f"[DEBUG] update_state: set structure_id to {self._structure_id} from structureId in locks_data")
            if old_structure_id != self._structure_id:
                _LOGGER.info(f"Updated structure_id from stream: {self._structure_id} (was {old_structure_id})")
        # Only update locks if present
        if "yale" in locks_data and locks_data["yale"]:
            self.current_state["devices"]["locks"].update(locks_data["yale"])
            _LOGGER.debug(f"Updated locks state: {self.current_state['devices']['locks']}")

    def get_device_metadata(self, device_id, auth_data=None):
        lock_data = self.current_state["devices"]["locks"].get(device_id, {})
        metadata = {
            "serial_number": lock_data.get("serial_number", device_id),
            "firmware_revision": lock_data.get("firmware_revision", "unknown"),
            "name": lock_data.get("name", "Front Door Lock"),
            "structure_id": self._structure_id if self._structure_id else "unknown",
        }
        if auth_data and "devices" in auth_data:
            for dev in auth_data.get("devices", []):
                if dev.get("device_id") == device_id:
                    metadata.update({
                        "serial_number": dev.get("serial_number", device_id),
                        "firmware_revision": dev.get("firmware_revision", "unknown"),
                        "name": dev.get("name", "Front Door Lock"),
                    })
                    break
        return metadata