import logging
import uuid
import aiohttp
import asyncio
import jwt
from google.protobuf import any_pb2
from .auth import NestAuthenticator
from .protobuf_handler import NestProtobufHandler
from .const import (
    API_RETRY_DELAY_SECONDS,
    URL_PROTOBUF,
    ENDPOINT_OBSERVE,
    ENDPOINT_SENDCOMMAND,
    PRODUCTION_HOSTNAME,
    USER_AGENT_STRING,
)
from .proto.nestlabs.gateway import v1_pb2
from .proto.nestlabs.gateway import v2_pb2


def _normalize_base(url):
    if not url:
        return None
    return url.rstrip("/")


def _transport_candidates(session_base):
    candidates = []
    normalized_session = _normalize_base(session_base)
    if normalized_session:
        candidates.append(normalized_session)
    default = _normalize_base(URL_PROTOBUF.format(grpc_hostname=PRODUCTION_HOSTNAME["grpc_hostname"]))
    if default and default not in candidates:
        candidates.append(default)
    return candidates

_LOGGER = logging.getLogger(__name__)

class ConnectionShim:
    def __init__(self, session):
        self.connected = True
        self.session = session

    async def stream(self, api_url, headers, data):
        async with self.session.post(api_url, headers=headers, data=data) as response:
            _LOGGER.debug(f"Response headers: {dict(response.headers)}")
            if response.status != 200:
                _LOGGER.error(f"HTTP {response.status}: {await response.text()}")
                self.connected = False
                raise Exception(f"Stream failed with status {response.status}")
            self.connected = True
            try:
                async for chunk in response.content.iter_any():
                    _LOGGER.debug(f"Stream chunk received (length={len(chunk)}): {chunk[:100].hex()}...")
                    yield chunk
            except asyncio.TimeoutError:
                _LOGGER.warning("Stream read timed out; marking connection as closed")
                self.connected = False
                raise

    async def post(self, api_url, headers, data):
        _LOGGER.debug(f"Sending POST to {api_url}, headers={headers}, data={data.hex()}")
        async with self.session.post(api_url, headers=headers, data=data) as response:
            response_data = await response.read()
            _LOGGER.debug(f"Post response status: {response.status}, response: {response_data.hex()}")
            if response.status != 200:
                _LOGGER.error(f"HTTP {response.status}: {await response.text()}")
                self.connected = False
                raise Exception(f"Post failed with status {response.status}")
            self.connected = True
            return response_data

    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()
            self.connected = False
            _LOGGER.debug("ConnectionShim session closed")

class NestAPIClient:
    def __init__(self, hass, issue_token, api_key, cookies):
        self.hass = hass
        self.authenticator = NestAuthenticator(issue_token, api_key, cookies)
        self.protobuf_handler = NestProtobufHandler()
        self.access_token = None
        self.auth_data = {}
        self.transport_url = None
        self._user_id = None  # Discover dynamically
        self._structure_id = None  # Discover dynamically
        self.current_state = {"devices": {"locks": {}}, "user_id": self._user_id, "structure_id": self._structure_id}
        self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=600))
        self.connection = ConnectionShim(self.session)
        self._observe_payload = self._build_observe_payload()
        _LOGGER.debug("NestAPIClient initialized with session")

    @property
    def user_id(self):
        return self._user_id

    @property
    def structure_id(self):
        return self._structure_id

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

    def _get_observe_payload(self):
        return self._observe_payload or self._build_observe_payload()

    def _candidate_bases(self):
        return _transport_candidates(self.transport_url)

    @classmethod
    async def create(cls, hass, issue_token, api_key=None, cookies=None, user_id=None):
        _LOGGER.debug("Entering create")
        instance = cls(hass, issue_token, api_key, cookies)
        await instance.async_setup()
        return instance

    async def async_setup(self):
        _LOGGER.debug("Starting async_setup")
        try:
            await self.authenticate()
            _LOGGER.debug("Setup completed successfully")
        except Exception as e:
            _LOGGER.error(f"Setup failed: {e}", exc_info=True)
            await self.close()
            raise
        finally:
            _LOGGER.debug("Exiting async_setup")

    async def authenticate(self):
        _LOGGER.debug("Authenticating with Nest API")
        try:
            self.auth_data = await self.authenticator.authenticate(self.session)
            _LOGGER.debug(f"Raw auth data received: {self.auth_data}")
            if not self.auth_data or "access_token" not in self.auth_data:
                raise ValueError("Invalid authentication data received")
            self.access_token = self.auth_data["access_token"]
            self.transport_url = self.auth_data.get("urls", {}).get("transport_url")
            id_token = self.auth_data.get("id_token")
            if id_token:
                decoded = jwt.decode(id_token, options={"verify_signature": False})
                self._user_id = decoded.get("sub", None)
                self.current_state["user_id"] = self._user_id
                _LOGGER.info(f"Initial user_id from id_token: {self._user_id}, structure_id: {self._structure_id}")
            else:
                _LOGGER.warning(f"No id_token in auth_data, awaiting stream for user_id and structure_id")
            _LOGGER.info(f"Authenticated with access_token: {self.access_token[:10]}..., user_id: {self._user_id}, structure_id: {self._structure_id}")
            await self.refresh_state()  # Initial refresh to discover IDs
            # Also ensure structure_id is set via REST directly
            self._structure_id = await self.fetch_structure_id()
            self.current_state["structure_id"] = self._structure_id
        except Exception as e:
            _LOGGER.error(f"Authentication failed: {e}", exc_info=True)
            await self.close()
            raise

    async def fetch_structure_id(self):
        """Mimic Homebridge's REST call to get structureId."""
        if not self.access_token:
            _LOGGER.warning("Cannot fetch structure_id without access_token")
            return None
        target_user = self._user_id or 'self'
        url = f"https://home.nest.com/api/0.1/user/{target_user}?auth={self.access_token}"
        headers = {
            "User-Agent": USER_AGENT_STRING,
            "Accept": "application/json",
        }
        async with self.session.get(url, headers=headers) as resp:
            if resp.status != 200:
                _LOGGER.debug("StructureId fetch returned status %s; continuing without explicit structure id", resp.status)
                return None
            user_data = await resp.json()
            # Optionally update user_id if available in user_data
            possible_user_id = user_data.get("userid") or user_data.get("user", {}).get("user_id")
            if possible_user_id:
                old_user_id = self._user_id
                self._user_id = possible_user_id
                self.current_state["user_id"] = self._user_id
                if old_user_id != self._user_id:
                    _LOGGER.info(f"Updated user_id from user_data: {self._user_id} (was {old_user_id})")
            structures = user_data.get("structures", {})
            if not structures:
                _LOGGER.warning("No structures found in user response")
                return None
            return next(iter(structures.keys()))

    async def refresh_state(self):
        if not self.access_token:
            await self.authenticate()

        headers = {
            "Authorization": f"Basic {self.access_token}",
            "Content-Type": "application/x-protobuf",
            "User-Agent": USER_AGENT_STRING,
            "X-Accept-Response-Streaming": "true",
            "X-Accept-Content-Transfer-Encoding": "binary",
            "Accept": "application/x-protobuf",
            "Accept-Encoding": "gzip, deflate, br",
            "referer": "https://home.nest.com/",
            "origin": "https://home.nest.com",
        }

        observe_payload = self._get_observe_payload()
        retries = 0
        max_retries = 3
        last_error = None

        while retries < max_retries:
            for base_url in self._candidate_bases():
                api_url = f"{base_url}{ENDPOINT_OBSERVE}"
                _LOGGER.debug("Starting refresh_state with URL: %s", api_url)
                try:
                    async with self.session.post(api_url, headers=headers, data=observe_payload) as response:
                        if response.status != 200:
                            body = await response.text()
                            _LOGGER.error("HTTP %s from %s: %s", response.status, api_url, body)
                            continue
                        async for chunk in response.content.iter_chunked(1024):
                            locks_data = await self.protobuf_handler._process_message(chunk)
                            if "yale" not in locks_data:
                                continue
                            self.current_state["devices"]["locks"] = locks_data["yale"]
                            if locks_data.get("user_id"):
                                old_user_id = self._user_id
                                self._user_id = locks_data["user_id"]
                                self.current_state["user_id"] = self._user_id
                                if old_user_id != self._user_id:
                                    _LOGGER.info("Updated user_id from stream: %s (was %s)", self._user_id, old_user_id)
                            if locks_data.get("structure_id"):
                                old_structure_id = self._structure_id
                                self._structure_id = locks_data["structure_id"]
                                self.current_state["structure_id"] = self._structure_id
                                if old_structure_id != self._structure_id:
                                    _LOGGER.info("Updated structure_id from stream: %s (was %s)", self._structure_id, old_structure_id)
                            self.transport_url = base_url
                            return locks_data["yale"]
                except Exception as err:
                    last_error = err
                    _LOGGER.error("Refresh state failed via %s: %s", api_url, err, exc_info=True)
                    continue
            retries += 1
            if retries < max_retries:
                await asyncio.sleep(API_RETRY_DELAY_SECONDS)
        if last_error:
            _LOGGER.error("Max retries reached, giving up on refresh_state: %s", last_error)
        return {}

    async def observe(self):
        if not self.access_token or not self.connection.connected:
            await self.authenticate()

        headers = {
            "Authorization": f"Basic {self.access_token}",
            "Content-Type": "application/x-protobuf",
            "User-Agent": USER_AGENT_STRING,
            "X-Accept-Response-Streaming": "true",
            "X-Accept-Content-Transfer-Encoding": "binary",
            "Accept": "application/x-protobuf",
            "Accept-Encoding": "gzip, deflate, br",
            "referer": "https://home.nest.com/",
            "origin": "https://home.nest.com",
        }

        observe_payload = self._get_observe_payload()
        retries = 0
        max_retries = 3
        last_error = None

        while retries < max_retries:
            for base_url in self._candidate_bases():
                api_url = f"{base_url}{ENDPOINT_OBSERVE}"
                _LOGGER.debug("Starting observe stream with URL: %s", api_url)
                try:
                    async for chunk in self.connection.stream(api_url, headers, observe_payload):
                        locks_data = await self.protobuf_handler._process_message(chunk)
                        if "yale" in locks_data:
                            if locks_data.get("user_id"):
                                old_user_id = self._user_id
                                self._user_id = locks_data["user_id"]
                                self.current_state["user_id"] = self._user_id
                                if old_user_id != self._user_id:
                                    _LOGGER.info("Updated user_id from stream: %s (was %s)", self._user_id, old_user_id)
                            if locks_data.get("structure_id"):
                                old_structure_id = self._structure_id
                                self._structure_id = locks_data["structure_id"]
                                self.current_state["structure_id"] = self._structure_id
                                if old_structure_id != self._structure_id:
                                    _LOGGER.info("Updated structure_id from stream: %s (was %s)", self._structure_id, old_structure_id)
                            self.transport_url = base_url
                        yield locks_data.get("yale", {})
                    _LOGGER.debug("Observe stream finished for %s; attempting reconnect", api_url)
                    self.connection.connected = False
                except asyncio.TimeoutError:
                    last_error = None
                    _LOGGER.warning("Observe stream timed out via %s; retrying", api_url)
                    self.connection.connected = False
                    continue
                except Exception as err:
                    last_error = err
                    _LOGGER.error("Error in observe stream via %s: %s", api_url, err, exc_info=True)
                    self.connection.connected = False
                    continue
            retries += 1
            if retries < max_retries:
                await asyncio.sleep(API_RETRY_DELAY_SECONDS)
        if last_error:
            raise last_error
        raise RuntimeError("Observe stream failed without specific error")

    #async def send_command(self, command, device_id):
    async def send_command(self, command, device_id, structure_id=None):
        if not self.access_token:
            await self.authenticate()

        request_id = str(uuid.uuid4())
        headers = {
            "Authorization": f"Basic {self.access_token}",
            "Content-Type": "application/x-protobuf",
            "User-Agent": USER_AGENT_STRING,
            "X-Accept-Content-Transfer-Encoding": "binary",
            "X-Accept-Response-Streaming": "true",
            "request-id": request_id,
        }

        # Always include a structure_id header, defaulting to the fetched one
        effective_structure_id = structure_id or self._structure_id
        if effective_structure_id:
            headers["X-Nest-Structure-Id"] = effective_structure_id
            _LOGGER.debug(f"[nest_yale] Using structure_id: {effective_structure_id}")

        cmd_any = any_pb2.Any()
        cmd_any.type_url = command["command"]["type_url"]
        cmd_any.value = command["command"]["value"] if isinstance(command["command"]["value"], bytes) else command["command"]["value"].SerializeToString()

        request = v1_pb2.ResourceCommandRequest()
        resource_command = request.resourceCommands.add()
        resource_command.command.CopyFrom(cmd_any)
        if command.get("traitLabel"):
            resource_command.traitLabel = command["traitLabel"]
        request.resourceRequest.resourceId = device_id
        request.resourceRequest.requestId = request_id
        encoded_data = request.SerializeToString()

        _LOGGER.debug(
            "Sending command to %s: %s, encoded: %s, structure_id: %s",
            device_id,
            command,
            encoded_data.hex(),
            self._structure_id,
        )

        last_error = None
        for base_url in self._candidate_bases():
            api_url = f"{base_url}{ENDPOINT_SENDCOMMAND}"
            try:
                raw_data = await self.connection.post(api_url, headers, encoded_data)
                self.transport_url = base_url
                await asyncio.sleep(2)
                await self.refresh_state()
                return raw_data
            except Exception as err:
                last_error = err
                _LOGGER.error("Failed to send command to %s via %s: %s", device_id, api_url, err, exc_info=True)
                continue
        if last_error:
            raise last_error
        raise RuntimeError(f"Failed to send command to {device_id} for unknown reasons")

    async def close(self):
        if self.connection and self.connection.connected:
            await self.connection.close()
            _LOGGER.debug("NestAPIClient session closed")

    def get_device_metadata(self, device_id):
        lock_data = self.current_state["devices"]["locks"].get(device_id, {})
        metadata = {
            "serial_number": lock_data.get("serial_number", device_id),
            "firmware_revision": lock_data.get("firmware_revision", "unknown"),
            "name": lock_data.get("name", "Front Door Lock"),
            "structure_id": self._structure_id if self._structure_id else "unknown",
        }
        if "devices" in self.auth_data:
            for dev in self.auth_data.get("devices", []):
                if dev.get("device_id") == device_id:
                    metadata.update({
                        "serial_number": dev.get("serial_number", device_id),
                        "firmware_revision": dev.get("firmware_revision", "unknown"),
                        "name": dev.get("name", "Front Door Lock"),
                    })
                    break
        return metadata
