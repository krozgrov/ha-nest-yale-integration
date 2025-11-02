import logging
import uuid
import aiohttp
import asyncio
import jwt
import time
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
    API_GOOGLE_REAUTH_MINUTES,
)
from .proto.nestlabs.gateway import v1_pb2
from .proto.nestlabs.gateway import v2_pb2
from homeassistant.helpers.aiohttp_client import async_get_clientsession


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
        # Use Home Assistant's shared client session for REST calls
        self.session = async_get_clientsession(hass)
        self._observe_payload = self._build_observe_payload()
        self._reauth_task = None
        # Staleness/health tracking
        self._last_yale_update = time.monotonic()
        self._reset_lock = asyncio.Lock()
        self._ready_event = asyncio.Event()
        self._last_reset = time.monotonic()
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
            self._ready_event.clear()
            self.auth_data = await self.authenticator.authenticate(self.session)
            if _LOGGER.isEnabledFor(logging.DEBUG):
                _LOGGER.debug(
                    "Auth data keys received: %s",
                    list(self.auth_data.keys()) if isinstance(self.auth_data, dict) else type(self.auth_data),
                )
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
            await self.refresh_state(skip_ready=True)  # Initial refresh to discover IDs
            # Also ensure structure_id is set via REST directly (only if available)
            new_sid = await self.fetch_structure_id()
            if new_sid:
                self._structure_id = new_sid
                self.current_state["structure_id"] = self._structure_id
            # Schedule preemptive re-auth
            self._schedule_reauth()
            self._ready_event.set()
        except Exception as e:
            _LOGGER.error(f"Authentication failed: {e}", exc_info=True)
            # Recreate the HTTP session immediately to avoid using a closed session
            try:
                await self._reset_session()
            except Exception:
                pass
            raise

    async def fetch_structure_id(self):
        """Fetch structureId via REST; default to 'self' to avoid 401s."""
        if not self.access_token:
            _LOGGER.warning("Cannot fetch structure_id without access_token")
            return None
        target_user = 'self'
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

    async def refresh_state(self, skip_ready: bool = False):
        if not skip_ready:
            await self.ensure_ready()
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
                            if locks_data.get("auth_failed"):
                                _LOGGER.info("Initial refresh indicated authentication failure; reauthenticating")
                                await self.authenticate()
                                return {}
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
                except RuntimeError as re:
                    last_error = re
                    _LOGGER.error("Refresh state failed via %s: %s", api_url, re, exc_info=True)
                    continue
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


    async def _hard_reset(self, reason: str):
        """Aggressively rebuild HTTP session and reauthenticate, similar to a full reload."""
        if self._reset_lock.locked():
            return
        async with self._reset_lock:
            _LOGGER.warning("Hard reset transport/auth due to: %s", reason)
            self._ready_event.clear()
            self.access_token = None
            self.transport_url = None
            try:
                await self.authenticate()
            except Exception as e:
                _LOGGER.error("Hard reset authenticate failed: %s", e, exc_info=True)
                self._ready_event.clear()
            finally:
                self._last_reset = time.monotonic()
                if self.access_token:
                    self._ready_event.set()

    async def reset_connection(self, reason: str):
        await self._hard_reset(reason)

    async def ensure_ready(self):
        if not self._ready_event.is_set():
            _LOGGER.debug("Waiting for API client readiness")
        await self._ready_event.wait()

    async def send_command(self, command, device_id, structure_id=None):
        await self.ensure_ready()
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

        _LOGGER.debug(
            "Sending command to %s (trait=%s), bytes=%d",
            device_id,
            command.get("command", {}).get("type_url"),
            len(encoded_data),
        )

        try:
            raw = await self._send_command_ephemeral(encoded_data, device_id, structure_id, request_id)
            if raw is not None:
                await asyncio.sleep(2)
                await self.refresh_state()
                return raw
        except Exception as e:
            _LOGGER.error("Ephemeral SendCommand failed for %s: %s", device_id, e, exc_info=True)
            await self._hard_reset("command failure")
            raise

    async def _send_command_ephemeral(self, encoded_data: bytes, device_id: str, structure_id: str | None, request_id: str):
        """Send a command using a fresh session + fresh auth, then close it.

        Mirrors the behavior of standalone test clients to avoid relying on long-lived connections.
        """
        session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=60))
        try:
            # Fresh auth
            auth_data = await self.authenticator.authenticate(session)
            if not auth_data or "access_token" not in auth_data:
                raise RuntimeError("Ephemeral auth failed")
            access_token = auth_data["access_token"]
            base_url = URL_PROTOBUF.format(grpc_hostname=PRODUCTION_HOSTNAME["grpc_hostname"])
            api_url = f"{base_url}{ENDPOINT_SENDCOMMAND}"
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
            if structure_id or self._structure_id:
                headers["X-Nest-Structure-Id"] = structure_id or self._structure_id
            if self._user_id:
                headers["X-nl-user-id"] = str(self._user_id)
            async with session.post(api_url, headers=headers, data=encoded_data) as resp:
                raw = await resp.read()
                if resp.status != 200:
                    body = await resp.text()
                    raise aiohttp.ClientResponseError(
                        request_info=resp.request_info,
                        history=(),
                        status=resp.status,
                        message=body,
                        headers=resp.headers,
                    )
                # Validate protobuf
                decoded = v1_pb2.ResourceCommandResponseFromAPI()
                decoded.ParseFromString(raw)
                _LOGGER.debug("Ephemeral command response ops=%d", len(getattr(decoded, 'resouceCommandResponse', [])))
                return raw
        finally:
            try:
                await session.close()
            except Exception:
                pass

    async def close(self):
        # Cancel preemptive reauth task if running
        if self._reauth_task and not self._reauth_task.done():
            self._reauth_task.cancel()
            self._reauth_task = None

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

    def _schedule_reauth(self):
        # Cancel existing timer
        if self._reauth_task and not self._reauth_task.done():
            self._reauth_task.cancel()

        async def _timer():
            try:
                await asyncio.sleep(API_GOOGLE_REAUTH_MINUTES * 60)
                _LOGGER.info("Preemptive reauthentication timer fired; renewing token")
                await self.authenticate()
            except asyncio.CancelledError:
                pass
            except Exception as e:
                _LOGGER.warning(f"Preemptive reauthentication failed: {e}")
            finally:
                # Reschedule for the next cycle if not closed
                if self.session and not self.session.closed:
                    self._schedule_reauth()

        self._reauth_task = asyncio.create_task(_timer())

        self._connect_failures = 0
