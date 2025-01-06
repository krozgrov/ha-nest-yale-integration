from homeassistant.components.lock import LockEntity
from homeassistant.const import ATTR_BATTERY_LEVEL
from .api_client import APIClient
from .const import ENDPOINTS

class NestYaleLock(LockEntity):
    def __init__(self, client, device):
        """Initialize the Nest x Yale Lock."""
        self._client = client
        self._device = device
        self._is_locked = None
        self._battery_status = None

    @property
    def name(self):
        """Return the name of the lock."""
        return self._device.get("name", "Nest x Yale Lock")

    @property
    def is_locked(self):
        """Return true if the lock is locked."""
        return self._is_locked

    @property
    def extra_state_attributes(self):
        """Return additional state attributes."""
        return {
            ATTR_BATTERY_LEVEL: self._battery_status,
        }

    async def async_lock(self, **kwargs):
        """Lock the door."""
        protobuf_data = {
            "traitLabel": "bolt_lock",
            "command": {
                "type_url": "type.nestlabs.com/weave.trait.security.BoltLockTrait.BoltLockChangeRequest",
                "value": {
                    "state": "BOLT_STATE_EXTENDED",
                    "boltLockActor": {
                        "method": "BOLT_LOCK_ACTOR_METHOD_REMOTE_USER_EXPLICIT",
                        "originator": {"resourceId": self._device.get("user_id")},
                        "agent": None,
                    },
                },
            },
        }
        response = await self._client.lock(protobuf_data)
        if response:
            self._is_locked = True
            self.async_write_ha_state()

    async def async_unlock(self, **kwargs):
        """Unlock the door."""
        protobuf_data = {
            "traitLabel": "bolt_lock",
            "command": {
                "type_url": "type.nestlabs.com/weave.trait.security.BoltLockTrait.BoltLockChangeRequest",
                "value": {
                    "state": "BOLT_STATE_RETRACTED",
                    "boltLockActor": {
                        "method": "BOLT_LOCK_ACTOR_METHOD_REMOTE_USER_EXPLICIT",
                        "originator": {"resourceId": self._device.get("user_id")},
                        "agent": None,
                    },
                },
            },
        }
        response = await self._client.lock(protobuf_data)
        if response:
            self._is_locked = False
            self.async_write_ha_state()

    async def async_update(self):
        """Fetch the latest state from the lock."""
        response = await self._client.get_status(self._device.get("device_id"))
        if response:
            self._is_locked = response.get("bolt_locked", False)
            self._battery_status = (
                100
                if response.get("battery_status") == "BATTERY_REPLACEMENT_INDICATOR_NOT_AT_ALL"
                else 50
                if response.get("battery_status") == "BATTERY_REPLACEMENT_INDICATOR_SOON"
                else 0
            )
            self.async_write_ha_state()