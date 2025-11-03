import logging
import uuid
import asyncio
import aiohttp
import jwt

from google.protobuf import any_pb2

from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .auth import NestAuthenticator
from .protobuf_handler import NestProtobufHandler
from .const import (
    URL_PROTOBUF,
    ENDPOINT_OBSERVE,
    ENDPOINT_SENDCOMMAND,
    PRODUCTION_HOSTNAME,
    USER_AGENT_STRING,
)
from .proto.nestlabs.gateway import v1_pb2, v2_pb2

_LOGGER = logging.getLogger(__name__)


class NestAPIClient:
    def __init__(self, hass, issue_token, api_key, cookies):
        self.hass = hass
        self.authenticator = NestAuthenticator(issue_token, api_key, cookies)
        self._user_id = None
        self._structure_id = None
        self.current_state = {"devices": {"locks": {}}, "user_id": None, "structure_id": None}
        self._observe_payload = self._build_observe_payload()
        self._state_lock = asyncio.Lock()

    async def async_setup(self):
        await self.refresh_state()

    async def refresh_state(self):
        async with self._state_lock:
            session = async_get_clientsession(self.hass)
            try:
                data = await self._fetch_state(session)
                return data
            except Exception as exc:
                _LOGGER.error("Failed to refresh Nest Yale state: %s", exc, exc_info=True)
                raise

    async def send_command(self, command, device_id, structure_id=None):
        async with self._state_lock:
            session = async_get_clientsession(self.hass)
            access_token, user_id, transport_url = await self._authenticate(session)
            if user_id:
                self._user_id = user_id
                self.current_state["user_id"] = user_id

            request_id = str(uuid.uuid4())
            cmd_any = any_pb2.Any()
            cmd_any.type_url = command["command"]["type_url"]
            cmd_any.value = (
                command["command"]["value"]
                if isinstance(command["command"]["value"], bytes)
                else command["command"]["value"].SerializeToString()
            )

            request = v1_pb2.ResourceCommandRequest()
            resource_command = request.resourceCommands.add()
            resource_command.command.CopyFrom(cmd_any)
            if command.get("traitLabel"):
                resource_command.traitLabel = command["traitLabel"]
            request.resourceRequest.resourceId = device_id
            request.resourceRequest.requestId = request_id
            encoded_data = request.SerializeToString()

            headers = self._build_command_headers(access_token, request_id, structure_id)
            api_url = self._resolve_url(transport_url, ENDPOINT_SENDCOMMAND)

            _LOGGER.debug(
                "Sending command to %s (trait=%s), bytes=%d",
                device_id,
                command.get("command", {}).get("type_url"),
                len(encoded_data),
            )

            async with session.post(api_url, headers=headers, data=encoded_data, timeout=aiohttp.ClientTimeout(total=60)) as resp:
                payload = await resp.read()
                if resp.status != 200:
                    body = await resp.text()
                    raise aiohttp.ClientResponseError(
                        request_info=resp.request_info,
                        history=(),
                        status=resp.status,
                        message=body,
                        headers=resp.headers,
                    )
                decoded = v1_pb2.ResourceCommandResponseFromAPI()
                decoded.ParseFromString(payload)
                _LOGGER.debug("Command response ops=%d", len(getattr(decoded, 'resouceCommandResponse', [])))

            await asyncio.sleep(2)
            await self._fetch_state(session, access_token, transport_url)
            return True

    async def reset_connection(self, reason: str):
        _LOGGER.info("Resetting Nest Yale connection due to: %s", reason)
        await self.refresh_state()

    async def _authenticate(self, session):
        auth_data = await self.authenticator.authenticate(session)
        if not auth_data or "access_token" not in auth_data:
            raise RuntimeError("Nest authentication failed")

        access_token = auth_data["access_token"]
        transport_url = auth_data.get("urls", {}).get("transport_url")
        user_id = None
        id_token = auth_data.get("id_token")
        if id_token:
            decoded = jwt.decode(id_token, options={"verify_signature": False})
            user_id = decoded.get("sub")
        return access_token, user_id, transport_url

    async def _fetch_state(self, session, access_token=None, transport_url=None):
        if access_token is None:
            access_token, user_id, transport_url = await self._authenticate(session)
            if user_id:
                self._user_id = user_id
                self.current_state["user_id"] = user_id

        headers = {
            "Authorization": f"Basic {access_token}",
            "Content-Type": "application/x-protobuf",
            "User-Agent": USER_AGENT_STRING,
            "X-Accept-Response-Streaming": "true",
            "X-Accept-Content-Transfer-Encoding": "binary",
            "Accept": "application/x-protobuf",
            "Accept-Encoding": "gzip, deflate, br",
            "referer": "https://home.nest.com/",
            "origin": "https://home.nest.com",
        }
        if self._structure_id:
            headers["X-Nest-Structure-Id"] = self._structure_id
        if self._user_id:
            headers["X-nl-user-id"] = str(self._user_id)

        api_url = self._resolve_url(transport_url, ENDPOINT_OBSERVE)
        handler = NestProtobufHandler()
        payload = self._observe_payload

        async with session.post(api_url, headers=headers, data=payload, timeout=aiohttp.ClientTimeout(total=60)) as resp:
            if resp.status != 200:
                body = await resp.text()
                raise aiohttp.ClientResponseError(
                    request_info=resp.request_info,
                    history=(),
                    status=resp.status,
                    message=body,
                    headers=resp.headers,
                )
            async for chunk in resp.content.iter_chunked(2048):
                locks_data = await handler._process_message(chunk)
                if locks_data.get("auth_failed"):
                    raise RuntimeError("Observe reported authentication failure")
                if locks_data.get("yale"):
                    self._apply_state(locks_data)
                    return locks_data
        return {"yale": {}}

    def _apply_state(self, locks_data):
        yale = locks_data.get("yale", {})
        self.current_state["devices"]["locks"] = yale
        if locks_data.get("user_id"):
            self._user_id = locks_data["user_id"]
            self.current_state["user_id"] = self._user_id
        if locks_data.get("structure_id"):
            self._structure_id = locks_data["structure_id"]
            self.current_state["structure_id"] = self._structure_id

    def get_device_metadata(self, device_id):
        lock_data = self.current_state["devices"]["locks"].get(device_id, {})
        metadata = {
            "serial_number": lock_data.get("serial_number", device_id),
            "firmware_revision": lock_data.get("firmware_revision", "unknown"),
            "name": lock_data.get("name", "Front Door Lock"),
            "structure_id": self._structure_id if self._structure_id else "unknown",
        }
        return metadata

    def _build_observe_payload(self):
        request = v2_pb2.ObserveRequest(version=2, subscribe=True)
        trait_names = [
            "nest.trait.user.UserInfoTrait",
            "nest.trait.structure.StructureInfoTrait",
            "weave.trait.security.BoltLockTrait",
            "weave.trait.security.BoltLockSettingsTrait",
            "weave.trait.security.BoltLockCapabilitiesTrait",
            "weave.trait.security.PincodeInputTrait",
            "weave.trait.security.TamperTrait",
        ]
        for trait in trait_names:
            observe_filter = request.filter.add()
            observe_filter.trait_type = trait
        return request.SerializeToString()

    def _resolve_url(self, transport_url, endpoint):
        base = transport_url or URL_PROTOBUF.format(grpc_hostname=PRODUCTION_HOSTNAME["grpc_hostname"])
        return f"{base}{endpoint}"

    def _build_command_headers(self, access_token, request_id, structure_id):
        headers = {
            "Authorization": f"Basic {access_token}",
            "Content-Type": "application/x-protobuf",
            "User-Agent": USER_AGENT_STRING,
            "X-Accept-Content-Transfer-Encoding": "binary",
            "X-Accept-Response-Streaming": "true",
            "Accept": "application/x-protobuf",
            "Accept-Encoding": "gzip, deflate, br",
            "referer": "https://home.nest.com/",
            "origin": "https://home.nest.com",
            "request-id": request_id,
        }
        eff_structure = structure_id or self._structure_id
        if eff_structure:
            headers["X-Nest-Structure-Id"] = eff_structure
        if self._user_id:
            headers["X-nl-user-id"] = str(self._user_id)
        return headers
