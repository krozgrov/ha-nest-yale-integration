import logging
import random
import uuid
import aiohttp
import asyncio
import jwt
from contextlib import nullcontext
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
    GRPC_CODE_INTERNAL,
    API_TIMEOUT_SECONDS,
)
from .proto.nestlabs.gateway import v1_pb2
from .proto.nestlabs.gateway import v2_pb2
from .proto.nest import rpc_pb2
from homeassistant.helpers.aiohttp_client import async_get_clientsession


def _normalize_base(url):
    if not url:
        return None
    return url.rstrip("/")


def _transport_candidates(session_base):
    """Return the correct gRPC endpoint URL.
    
    Note: The transport_url from auth is the REST API (home.nest.com), not the gRPC endpoint.
    We always use the correct gRPC endpoint (grpc-web.production.nest.com) directly.
    """
    # Always use the correct gRPC endpoint - no need for fallback
    default = _normalize_base(URL_PROTOBUF.format(grpc_hostname=PRODUCTION_HOSTNAME["grpc_hostname"]))
    return [default] if default else []

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

    async def post(self, api_url, headers, data, read_timeout=None):
        _LOGGER.debug(f"Sending POST to {api_url}, len(data)={len(data)}")
        timeout_ctx = asyncio.timeout(read_timeout) if read_timeout else nullcontext()
        try:
            async with timeout_ctx:
                async with self.session.post(api_url, headers=headers, data=data) as response:
                    response_data = await response.read()
                    _LOGGER.debug(f"Post response status: {response.status}, len(response)={len(response_data)}")
                    if response.status != 200:
                        body = response_data.decode(errors="ignore")
                        _LOGGER.error(f"HTTP {response.status}: {body}")
                        self.connected = False
                        raise aiohttp.ClientResponseError(
                            request_info=response.request_info,
                            history=(),
                            status=response.status,
                            message=body,
                            headers=response.headers,
                        )
        except asyncio.TimeoutError:
            _LOGGER.warning("POST to %s timed out after %s seconds", api_url, read_timeout)
            self.connected = False
            raise

        self.connected = True
        return response_data

    async def close(self):
        # Do not close HA-managed session; just mark as disconnected
        self.connected = False
        _LOGGER.debug("ConnectionShim closed (session managed by HA)")

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
        self._last_observe_data_ts = None
        # Use Home Assistant managed session
        self.session = async_get_clientsession(hass)
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
            # HomeKit-relevant traits
            "weave.trait.description.DeviceIdentityTrait",  # Serial, firmware, model
            "weave.trait.power.BatteryPowerSourceTrait",    # Battery level, status
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
                # Check if the error was due to cookie expiration
                error_msg = "Invalid authentication data received"
                if hasattr(self.authenticator, '_last_error') and self.authenticator._last_error:
                    if "Cookie expired" in str(self.authenticator._last_error):
                        error_msg = str(self.authenticator._last_error)
                    elif "USER_LOGGED_OUT" in str(self.authenticator._last_error):
                        error_msg = (
                            "Cookie expired: Your Google session has expired. "
                            "Please re-obtain your cookies from the browser. "
                            "See the integration documentation for instructions."
                        )
                raise ValueError(error_msg)
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
            # Schedule preemptive re-auth
            self._schedule_reauth()
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
                    # Use the exact b2 approach that worked: session.post with iter_chunked
                    # Add timeout wrapper to prevent hanging
                    async with asyncio.timeout(30):  # allow more time for first device payload
                        self.protobuf_handler.reset_stream_state()
                        async with self.session.post(api_url, headers=headers, data=observe_payload) as response:
                            if response.status != 200:
                                body = await response.text()
                                _LOGGER.error("HTTP %s from %s: %s", response.status, api_url, body)
                                continue
                            async for chunk in response.content.iter_chunked(1024):
                                # Prefer framed ingest; also run legacy direct parse to catch partials
                                parsed_messages = await self.protobuf_handler._ingest_chunk(chunk)
                                if not parsed_messages:
                                    legacy_data = await self.protobuf_handler._process_message(chunk)
                                    if legacy_data:
                                        parsed_messages = [legacy_data]
                                for locks_data in parsed_messages:
                                    if locks_data.get("parse_failed"):
                                        _LOGGER.debug("refresh_state received partial frame; waiting for more data")
                                        continue
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
                                    self._last_observe_data_ts = asyncio.get_event_loop().time()
                                    self.transport_url = base_url
                                    return locks_data["yale"]
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

    def _build_observe_headers(self):
        """Build headers for observe stream with current access token."""
        return {
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

    async def observe(self):
        """Yield real-time updates, reconnecting on timeouts/errors indefinitely.

        Avoids raising on transient errors to keep the coordinator loop alive.
        """
        if not self.access_token or not self.connection.connected:
            await self.authenticate()

        observe_payload = self._get_observe_payload()
        backoff = API_RETRY_DELAY_SECONDS
        last_data_time = asyncio.get_event_loop().time()

        _LOGGER.info("Observe stream starting (will auto-reconnect on timeout/error)")
        while True:
            # Ensure we have a valid token before each connection attempt
            if not self.access_token:
                _LOGGER.warning("No access token before observe connection, authenticating")
                await self.authenticate()
            
            # Rebuild headers with current token for each connection attempt
            headers = self._build_observe_headers()
            
            # Use single correct gRPC endpoint (no need to try multiple URLs)
            candidate_bases = self._candidate_bases()
            if not candidate_bases:
                _LOGGER.error("No valid gRPC endpoint available")
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 60)
                continue
            
            # We only have one URL now, but keep loop structure for consistency
            for base_url in candidate_bases:
                api_url = f"{base_url}{ENDPOINT_OBSERVE}"
                _LOGGER.debug("Starting observe stream with URL: %s", api_url)
                try:
                    self.protobuf_handler.reset_stream_state()
                    _LOGGER.info("Observe stream connected to %s", api_url)
                    async for chunk in self.connection.stream(api_url, headers, observe_payload, read_timeout=OBSERVE_IDLE_RESET_SECONDS):
                        # Legacy path: parse chunk directly first (2025.11.9 behavior)
                        legacy_data = await self.protobuf_handler._process_message(chunk)
                        parsed_messages = [legacy_data] if legacy_data else []
                        # Also try framed ingest in case chunking differs
                        framed_messages = await self.protobuf_handler._ingest_chunk(chunk)
                        if framed_messages:
                            parsed_messages.extend(framed_messages)
                        if not parsed_messages:
                            continue

                        # Reset backoff on any successful data
                        backoff = API_RETRY_DELAY_SECONDS
                        self._connect_failures = 0
                        current_time = asyncio.get_event_loop().time()
                        auth_failure = False

                        for locks_data in parsed_messages:
                            if locks_data.get("parse_failed"):
                                _LOGGER.debug("Observe received partial frame; skipping and waiting for next chunk")
                                continue
                            # Check for authentication failure
                            if locks_data.get("auth_failed"):
                                _LOGGER.warning("Observe stream reported authentication failure, triggering re-auth")
                                self.connection.connected = False
                                self.access_token = None
                                await self.authenticate()
                                # Rebuild headers with new token before reconnecting
                                headers = self._build_observe_headers()
                                _LOGGER.info("Re-authenticated, reconnecting observe stream with new token")
                                auth_failure = True
                                break

                            if "yale" in locks_data:
                                last_data_time = current_time
                                _LOGGER.debug("Observe stream received yale data")
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
                            self._last_observe_data_ts = current_time
                        # Yield full locks_data including all_traits so coordinator can extract trait data
                        yield locks_data

                        if auth_failure:
                            # Reconnect with the new token
                            break
                    _LOGGER.warning("Observe stream finished for %s; reconnecting", api_url)
                    self.connection.connected = False
                    self.protobuf_handler.reset_stream_state()
                    # Remember the working URL (though we only have one now)
                    self.transport_url = base_url
                    break  # Exit candidate loop
                except asyncio.TimeoutError:
                    elapsed = asyncio.get_event_loop().time() - last_data_time
                    _LOGGER.warning(
                        "Observe stream timed out via %s after %.1f seconds idle; reconnecting",
                        api_url,
                        elapsed
                    )
                    self.connection.connected = False
                    self.protobuf_handler.reset_stream_state()
                    # Remember the URL (though we only have one now)
                    self.transport_url = base_url
                    break  # Exit candidate loop to reconnect
                except aiohttp.ClientResponseError as cre:
                    if cre.status in (401, 403):
                        _LOGGER.info("Observe received %s; reauthenticating and retrying", cre.status)
                        try:
                            await self.authenticate()
                            # Rebuild headers with new token
                            headers = self._build_observe_headers()
                        except Exception:
                            _LOGGER.warning("Reauthentication failed during observe; will backoff and retry")
                        self.connection.connected = False
                        self.protobuf_handler.reset_stream_state()
                        break  # Exit candidate loop to reconnect with new token
                    _LOGGER.error("Error in observe stream via %s: %s", api_url, cre, exc_info=True)
                    self.connection.connected = False
                    self.protobuf_handler.reset_stream_state()
                    # Try next candidate URL
                    continue
                except Exception as err:
                    _LOGGER.error("Error in observe stream via %s: %s", api_url, err, exc_info=True)
                    self.connection.connected = False
                    self.protobuf_handler.reset_stream_state()
                    self._note_connect_failure(err)
                    # Try next candidate URL
                    continue
            # Exponential backoff with jitter, capped to 60s
            sleep_for = min(backoff, 60) + random.uniform(0, min(backoff, 60) / 2)
            await asyncio.sleep(sleep_for)
            backoff = min(backoff * 2, 60)

    async def send_command(self, command, device_id, structure_id=None):
        # Ensure we have a valid token before sending command
        if not self.access_token:
            _LOGGER.warning("No access token before send_command, authenticating")
            await self.authenticate()

        # If observe stream has been idle too long, proactively refresh state/session
        if self._last_observe_data_ts:
            idle = asyncio.get_event_loop().time() - self._last_observe_data_ts
            if idle > OBSERVE_IDLE_RESET_SECONDS:
                _LOGGER.info("Observe stream idle for %.1f seconds; refreshing state before sending command", idle)
                try:
                    await self.refresh_state()
                except Exception as err:
                    _LOGGER.debug("Pre-command refresh_state failed (continuing anyway): %s", err)

        request_id = str(uuid.uuid4())
        headers = {
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

        # Include structure id when available (matches working test client behavior)
        effective_structure_id = structure_id or self._structure_id
        if effective_structure_id:
            headers["X-Nest-Structure-Id"] = effective_structure_id
            _LOGGER.debug("Using structure_id: %s", effective_structure_id)
        if self._user_id:
            headers["X-nl-user-id"] = str(self._user_id)

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
        forced_refresh = False  # Track whether forced refresh was already attempted

        def _refresh_command_headers():
            headers["Authorization"] = f"Basic {self.access_token}"
            active_structure_id = structure_id or self._structure_id
            if active_structure_id:
                headers["X-Nest-Structure-Id"] = active_structure_id
            else:
                headers.pop("X-Nest-Structure-Id", None)
            if self._user_id:
                headers["X-nl-user-id"] = str(self._user_id)
            else:
                headers.pop("X-nl-user-id", None)

        _refresh_command_headers()

        for base_url in self._candidate_bases():
            api_url = f"{base_url}{ENDPOINT_SENDCOMMAND}"
            reauthed = False
            recovered = False
            for _ in range(3):
                try:
                    raw_data = await self.connection.post(api_url, headers, encoded_data, read_timeout=API_TIMEOUT_SECONDS)
                    self.transport_url = base_url
                    status_code, status_msg = self._parse_command_status(raw_data)
                    if status_code not in (None, 0):
                        _LOGGER.warning(
                            "Command response reported failure for %s: code=%s, msg=%s",
                            device_id,
                            status_code,
                            status_msg,
                        )
                        if status_code == GRPC_CODE_INTERNAL and not recovered:
                            _LOGGER.warning("Internal error indicates stale connection; resetting session and retrying command")
                            await self._recover_after_internal_error()
                            _refresh_command_headers()
                            # Proactively refresh state to regain IDs before retry
                            try:
                                await self.refresh_state()
                            except Exception as err:
                                _LOGGER.debug("refresh_state after INTERNAL error failed: %s", err)
                            recovered = True
                            continue
                        last_error = RuntimeError(f"Command failed (code {status_code}): {status_msg or 'Unknown error'}")
                        break

                    _LOGGER.info(
                        "Command succeeded for %s at %s, payload_len=%d",
                        device_id,
                        api_url,
                        len(raw_data) if raw_data else 0,
                    )
                    return raw_data
                except aiohttp.ClientResponseError as cre:
                    if cre.status in (401, 403) and not reauthed:
                        _LOGGER.info("Command got %s; reauthenticating and retrying", cre.status)
                        await self.authenticate()
                        # Rebuild headers with new token
                        _refresh_command_headers()
                        reauthed = True
                        continue
                    last_error = cre
                    _LOGGER.error("Failed to send command to %s via %s: %s", device_id, api_url, cre, exc_info=True)
                    break
                except Exception as err:
                    last_error = err
                    _LOGGER.error("Failed to send command to %s via %s: %s", device_id, api_url, err, exc_info=True)
                    self._note_connect_failure(err)
                    break
            if last_error and not forced_refresh:
                forced_refresh = True
                _LOGGER.warning("Command ultimately failed after retries; forcing full state refresh to recover")
                try:
                    data = await self.refresh_state()
                    if data and "yale" in data:
                        self.current_state["devices"]["locks"] = data["yale"]
                except Exception as err:
                    _LOGGER.debug("Forced refresh also failed: %s", err)
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
        
        # Try to get metadata from trait data first (most accurate)
        all_traits = self.current_state.get("all_traits", {})
        device_identity_key = f"{device_id}:weave.trait.description.DeviceIdentityTrait"
        if device_identity_key in all_traits:
            trait_info = all_traits[device_identity_key]
            if trait_info.get("decoded") and trait_info.get("data"):
                trait_data = trait_info["data"]
                if trait_data.get("serial_number"):
                    metadata["serial_number"] = trait_data["serial_number"]
                if trait_data.get("firmware_version"):
                    metadata["firmware_revision"] = trait_data["firmware_version"]
        
        # Fallback to auth_data if trait data not available
        if "devices" in self.auth_data:
            for dev in self.auth_data.get("devices", []):
                if dev.get("device_id") == device_id:
                    if metadata["serial_number"] == device_id:  # Only update if not set from traits
                        metadata["serial_number"] = dev.get("serial_number", device_id)
                    if metadata["firmware_revision"] == "unknown":  # Only update if not set from traits
                        metadata["firmware_revision"] = dev.get("firmware_revision", "unknown")
                    metadata["name"] = dev.get("name", "Front Door Lock")
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
        # Recreate lightweight wrapper using HA-managed session
        self.session = async_get_clientsession(self.hass)
        self.connection = ConnectionShim(self.session)
        self._connect_failures = 0
        self.protobuf_handler.reset_stream_state()

    def _parse_command_status(self, response_data):
        """Extract status code/message from a command response payload."""
        if not response_data:
            return 0, None
        try:
            stream_body = rpc_pb2.StreamBody()
            stream_body.ParseFromString(response_data)
            return stream_body.status.code, stream_body.status.message
        except Exception as err:
            _LOGGER.debug("Could not parse command response: %s", err)
            return 0, None

    async def _recover_after_internal_error(self):
        """Reset session and reauthenticate after an INTERNAL gRPC error."""
        self.connection.connected = False
        self.protobuf_handler.reset_stream_state()
        try:
            await self._reset_session()
        except Exception as err:
            _LOGGER.debug("Session reset after INTERNAL error failed: %s", err, exc_info=True)
        # Force token renewal
        self.access_token = None
        await self.authenticate()
