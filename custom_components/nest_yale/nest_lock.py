import logging
import asyncio
from .protobuf_manager import ProtobufManager
from .api_client import APIClient

_LOGGER = logging.getLogger(__name__)

class NestYaleLockAPI:
    """Handles lock/unlock commands for the Nest Yale Lock."""

    def __init__(self, device_id: str, api_client: APIClient, proto_manager: ProtobufManager):
        self.device_id = device_id
        self.api_client = api_client
        self.proto_manager = proto_manager

    async def lock(self):
        """Lock the Yale Lock via Protobuf API."""
        _LOGGER.debug(f"Sending Lock command for device {self.device_id}")

        command_data = {
            "state": "BOLT_STATE_EXTENDED",  # Lock the door
            "boltLockActor": {
                "method": "BOLT_LOCK_ACTOR_METHOD_REMOTE_USER_EXPLICIT",
                "originator": {"resourceId": self.device_id},
                "agent": None
            }
        }

        response = await self._send_command(command_data)
        return response

    async def unlock(self):
        """Unlock the Yale Lock via Protobuf API."""
        _LOGGER.debug(f"Sending Unlock command for device {self.device_id}")

        command_data = {
            "state": "BOLT_STATE_RETRACTED",  # Unlock the door
            "boltLockActor": {
                "method": "BOLT_LOCK_ACTOR_METHOD_REMOTE_USER_EXPLICIT",
                "originator": {"resourceId": self.device_id},
                "agent": None
            }
        }

        response = await self._send_command(command_data)
        return response

    async def _send_command(self, command_data):
        """Send a Protobuf lock/unlock command."""
        try:
            message = self.proto_manager.create_message("weave.trait.security.BoltLockTrait.BoltLockChangeRequest")

            for key, value in command_data.items():
                setattr(message, key, value)

            request_binary = message.SerializeToString()

            response = await self.api_client.send_protobuf_request(
                endpoint="/nestlabs.gateway.v1.ResourceApi/SendCommand",
                message_name="weave.trait.security.BoltLockTrait.BoltLockChangeResponse",
                message_data=request_binary
            )

            _LOGGER.debug(f"Lock API Response: {response}")
            return response
        except Exception as e:
            _LOGGER.error(f"Failed to send Lock/Unlock command: {e}")
            return None