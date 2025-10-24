import logging
import random
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
    API_GOOGLE_REAUTH_MINUTES,
    OBSERVE_IDLE_RESET_SECONDS,
    CONNECT_FAILURE_RESET_THRESHOLD,
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

class ConnectionShim:
    def __init__(self, session):
        self.connected = True
        self.session = session

    async def stream(self, api_url, headers, data, read_timeout=None):
        async with self.session.post(api_url, headers=headers, data=data) as response:
            _LOGGER.debug(f"Response headers: {dict(response.headers)}")
            if response.status != 200:
                # Raise a response error with status for upstream handling
                body = await response.text()
                _LOGGER.error(f"HTTP {response.status}: {body}")
                self.connected = False
                raise aiohttp.ClientResponseError(
                    request_info=response.request_info,
                    history=(),
                    status=response.status,
                    message=body,
                    headers=response.headers,
                )
            self.connected = True
            try:
                while True:
                    chunk = await asyncio.wait_for(response.content.readany(), timeout=read_timeout)
                    if not chunk:
                        break
                    if _LOGGER.isEnabledFor(logging.DEBUG):
                        _LOGGER.debug(
                            "Stream chunk received (length=%d): %s...",
                            len(chunk),
                            chunk[:100].hex(),
                        )
                    yield chunk
            except asyncio.TimeoutError:
                _LOGGER.warning("Stream read timed out; marking connection as closed")
                self.connected = False
                raise

    async def post(self, api_url, headers, data):
        _LOGGER.debug(f"Sending POST to {api_url}, len(data)={len(data)}")
        async with self.session.post(api_url, headers=headers, data=data) as response:
            response_data = await response.read()
            _LOGGER.debug(f"Post response status: {response.status}, len(response)={len(response_data)}")
            if response.status != 200:
                body = await response.text()
                _LOGGER.error(f"HTTP {response.status}: {body}")
                self.connected = False
                raise aiohttp.ClientResponseError(
                    request_info=response.request_info,
                    history=(),
                    status=response.status,
                    message=body,
                    headers=response.headers,
                )
            self.connected = True
            return response_data

    async def close(self):
        # Close owned session if possible
        try:
            if self.session and not self.session.closed:
                await self.session.close()
        except Exception:
            pass
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
        # Use dedicated session so we can recreate it on failures
        self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=600))
        self.connection = ConnectionShim(self.session)
        self._observe_payload = self._build_observe_payload()
        self._connect_failures = 0
        self._reauth_task = None
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
            await self.refresh_state()  # Initial refresh to discover IDs
            # Also ensure structure_id is set via REST directly (only if available)
            new_sid = await self.fetch_structure_id()
            if new_sid:
                self._structure_id = new_sid
                self.current_state["structure_id"] = self._structure_id
            # Schedule preemptive re-auth
            self._schedule_reauth()
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
                    # Handle "Session is closed" immediately by rebuilding the session
                    if "Session is closed" in str(re):
                        _LOGGER.warning("Refresh state encountered closed session; rebuilding HTTP session")
                        await self._reset_session()
                        continue
                    last_error = re
                    _LOGGER.error("Refresh state failed via %s: %s", api_url, re, exc_info=True)
                    self._note_connect_failure(re)
                    continue
                except Exception as err:
                    last_error = err
                    _LOGGER.error("Refresh state failed via %s: %s", api_url, err, exc_info=True)
                    # Note connect failures and maybe reset session
                    self._note_connect_failure(err)
                    continue
            retries += 1
            if retries < max_retries:
                await asyncio.sleep(API_RETRY_DELAY_SECONDS)
        if last_error:
            _LOGGER.error("Max retries reached, giving up on refresh_state: %s", last_error)
        return {}

    async def observe(self):
        """Yield real-time updates, reconnecting on timeouts/errors indefinitely.

        Avoids raising on transient errors to keep the coordinator loop alive.
        """
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
        backoff = API_RETRY_DELAY_SECONDS

        while True:
            for base_url in self._candidate_bases():
                api_url = f"{base_url}{ENDPOINT_OBSERVE}"
                _LOGGER.debug("Starting observe stream with URL: %s", api_url)
                try:
                    async for chunk in self.connection.stream(api_url, headers, observe_payload, read_timeout=OBSERVE_IDLE_RESET_SECONDS):
                        # Reset backoff on any successful data
                        backoff = API_RETRY_DELAY_SECONDS
                        self._connect_failures = 0
                        locks_data = await self.protobuf_handler._process_message(chunk)
                        if locks_data.get("auth_failed"):
                            _LOGGER.info("Observe indicated authentication failure; reauthenticating and restarting stream")
                            try:
                                await self.authenticate()
                            except Exception:
                                _LOGGER.warning("Reauthentication failed after auth_failed; will backoff and retry")
                            self.connection.connected = False
                            break
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
                    _LOGGER.debug("Observe stream finished for %s; reconnecting", api_url)
                    self.connection.connected = False
                except RuntimeError as re:
                    if "Session is closed" in str(re):
                        _LOGGER.warning("Observe encountered closed session; rebuilding HTTP session")
                        await self._reset_session()
                        self.connection.connected = False
                        continue
                    _LOGGER.error("Error in observe stream via %s: %s", api_url, re, exc_info=True)
                    self.connection.connected = False
                except asyncio.TimeoutError:
                    _LOGGER.warning("Observe stream timed out via %s; retrying", api_url)
                    self.connection.connected = False
                except aiohttp.ClientResponseError as cre:
                    if cre.status in (401, 403):
                        _LOGGER.info("Observe received %s; reauthenticating and retrying", cre.status)
                        try:
                            await self.authenticate()
                        except Exception:
                            _LOGGER.warning("Reauthentication failed during observe; will backoff and retry")
                        self.connection.connected = False
                        continue
                    _LOGGER.error("Error in observe stream via %s: %s", api_url, cre, exc_info=True)
                    self.connection.connected = False
                except Exception as err:
                    _LOGGER.error("Error in observe stream via %s: %s", api_url, err, exc_info=True)
                    self.connection.connected = False
                    self._note_connect_failure(err)
            # Exponential backoff with jitter, capped to 60s
            sleep_for = min(backoff, 60) + random.uniform(0, min(backoff, 60) / 2)
            await asyncio.sleep(sleep_for)
            backoff = min(backoff * 2, 60)

    #async def send_command(self, command, device_id):
    async def send_command(self, command, device_id, structure_id=None):
        if not self.access_token:
            await self.authenticate()

        request_id = str(uuid.uuid4())
        base_headers = {
            "Authorization": f"Basic {self.access_token}",
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

        # Match Homebridge more closely: do not send optional X-Nest-Structure-Id / X-nl-user-id for SendCommand

        cmd_any = any_pb2.Any()
        cmd_any.type_url = command["command"]["type_url"]
        cmd_any.value = command["command"]["value"] if isinstance(command["command"]["value"], bytes) else command["command"]["value"].SerializeToString()

        request = v1_pb2.ResourceCommandRequest()
        resource_command = request.resourceCommands.add()
        resource_command.command.CopyFrom(cmd_any)
        if command.get("traitLabel"):
            resource_command.traitLabel = command["traitLabel"]
        # Use the bare device_id (matches 2025.10.18.1 working behavior)
        request.resourceRequest.resourceId = device_id
        request.resourceRequest.requestId = request_id
        encoded_data = request.SerializeToString()

        _LOGGER.debug(
            "Sending command to %s (trait=%s), bytes=%d, structure_id=%s",
            device_id,
            command.get("command", {}).get("type_url"),
            len(encoded_data),
            self._structure_id,
        )

        last_error = None
        for base_url in self._candidate_bases():
            api_url = f"{base_url}{ENDPOINT_SENDCOMMAND}"
            reauthed = False
            for attempt in range(3):
                try:
                    # First try minimal headers (matches Homebridge)
                    headers = dict(base_headers)
                    raw_data = await self.connection.post(api_url, headers, encoded_data)
                    self.transport_url = base_url
                    # Attempt to decode response for diagnostics; fall back to enriched headers if it isn't protobuf
                    try:
                        decoded = v1_pb2.ResourceCommandResponseFromAPI()
                        decoded.ParseFromString(raw_data)
                        _LOGGER.debug("Decoded command response (resource=%s ops=%d)",
                                       getattr(decoded, 'resouceCommandResponse', None),
                                       len(getattr(decoded, 'resouceCommandResponse', [])))
                    except Exception as dec_err:
                        _LOGGER.warning("Command response not protobuf; retrying with enriched headers: %s", dec_err)
                        # Retry once with enriched headers (structure/user) to match server expectations
                        enriched = dict(base_headers)
                        effective_structure_id = structure_id or self._structure_id
                        if effective_structure_id:
                            enriched["X-Nest-Structure-Id"] = effective_structure_id
                        if self._user_id:
                            enriched["X-nl-user-id"] = str(self._user_id)
                        try:
                            raw_data = await self.connection.post(api_url, enriched, encoded_data)
                            decoded = v1_pb2.ResourceCommandResponseFromAPI()
                            decoded.ParseFromString(raw_data)
                            _LOGGER.debug("Decoded command response after enrich (resource=%s ops=%d)",
                                           getattr(decoded, 'resouceCommandResponse', None),
                                           len(getattr(decoded, 'resouceCommandResponse', [])))
                        except Exception as dec_err2:
                            _LOGGER.warning("Enriched command still not protobuf; reauth and retry base: %s", dec_err2)
                            await self.authenticate()
                            continue
                    await asyncio.sleep(2)
                    await self.refresh_state()
                    return raw_data
                except aiohttp.ClientResponseError as cre:
                    if cre.status in (401, 403) and not reauthed:
                        _LOGGER.info("Command got %s; reauthenticating and retrying", cre.status)
                        await self.authenticate()
                        reauthed = True
                        # On retry after reauth, try enriched headers if we have structure/user context
                        try:
                            enriched = dict(base_headers)
                            eff_sid = structure_id or self._structure_id
                            if eff_sid:
                                enriched["X-Nest-Structure-Id"] = eff_sid
                            if self._user_id:
                                enriched["X-nl-user-id"] = str(self._user_id)
                            raw_data = await self.connection.post(api_url, enriched, encoded_data)
                            decoded = v1_pb2.ResourceCommandResponseFromAPI()
                            decoded.ParseFromString(raw_data)
                            await asyncio.sleep(2)
                            await self.refresh_state()
                            return raw_data
                        except Exception:
                            pass
                        continue
                    last_error = cre
                    _LOGGER.error("Failed to send command to %s via %s: %s", device_id, api_url, cre, exc_info=True)
                    break
                except Exception as err:
                    last_error = err
                    _LOGGER.warning("Command error to %s via %s (attempt %d): %s", device_id, api_url, attempt + 1, err)
                    self._note_connect_failure(err)
                    # Try aggressive recovery: rebuild session and reauth
                    try:
                        await self._reset_session()
                        await self.authenticate()
                        continue
                    except Exception:
                        break
        if last_error:
            raise last_error
        raise RuntimeError(f"Failed to send command to {device_id} for unknown reasons")

    async def close(self):
        if self.connection and self.connection.connected:
            await self.connection.close()
            _LOGGER.debug("NestAPIClient connection closed")
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

    def _note_connect_failure(self, err: Exception):
        # Increment on typical connection failures
        if isinstance(err, (aiohttp.ClientConnectorError, asyncio.TimeoutError)) or 'Cannot connect to host' in str(err):
            self._connect_failures += 1
            if self._connect_failures >= CONNECT_FAILURE_RESET_THRESHOLD:
                _LOGGER.warning("Consecutive connect failures reached threshold; recreating HTTP session")
                asyncio.create_task(self._reset_session())
        else:
            # Not a connect failure; reset counter
            self._connect_failures = 0

    async def _reset_session(self):
        try:
            await self.connection.close()
        except Exception:
            pass
        # Recreate dedicated session to clear stale connections
        self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=600))
        self.connection = ConnectionShim(self.session)
        self._connect_failures = 0
