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
    ENDPOINT_UPDATE,
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
from .proto.nest import rpc_pb2
from .proto.weave.trait import security_pb2 as weave_security_pb2
from .proto.nest.trait import security_pb2 as nest_security_pb2
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
        self._structure_id = None  # Legacy structure id (preferred for headers)
        self._structure_id_v2 = None  # UUID-style structure id from v2 observe
        self.current_state = {
            "devices": {"locks": {}},
            "user_id": self._user_id,
            "structure_id": self._structure_id,
            "structure_id_v2": self._structure_id_v2,
        }
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

    @property
    def structure_id_v2(self):
        return self._structure_id_v2

    @staticmethod
    def _is_legacy_structure_id(value: str | None) -> bool:
        if not isinstance(value, str) or not value:
            return False
        if "-" in value:
            return False
        return all(ch in "0123456789abcdefABCDEF" for ch in value)

    def _effective_structure_id(self, requested: str | None = None) -> str | None:
        if requested and self._is_legacy_structure_id(requested):
            return requested
        if self._structure_id:
            return self._structure_id
        return None

    @staticmethod
    def _encode_varint(value: int) -> bytes:
        encoded = bytearray()
        if value < 0:
            value &= (1 << 64) - 1
        while True:
            to_write = value & 0x7F
            value >>= 7
            if value:
                encoded.append(to_write | 0x80)
            else:
                encoded.append(to_write)
                break
        return bytes(encoded)

    @classmethod
    def _encode_tag(cls, field_number: int, wire_type: int) -> bytes:
        return cls._encode_varint((field_number << 3) | wire_type)

    @classmethod
    def _encode_length_delimited(cls, field_number: int, payload: bytes) -> bytes:
        return cls._encode_tag(field_number, 2) + cls._encode_varint(len(payload)) + payload

    @classmethod
    def _encode_string(cls, field_number: int, value: str) -> bytes:
        return cls._encode_length_delimited(field_number, value.encode("utf-8"))

    def _build_observe_payload(self):
        # v2 ObserveRequest (legacy format) with ACCEPTED/CONFIRMED state types.
        # We only set stateTypes and traitTypeParams to keep the payload minimal.
        payload = bytearray()
        for state_type in (2, 1):  # ACCEPTED, CONFIRMED
            payload += self._encode_tag(1, 0)
            payload += self._encode_varint(state_type)
        trait_names = [
            "nest.trait.user.UserInfoTrait",
            "nest.trait.structure.StructureInfoTrait",
            "weave.trait.security.BoltLockTrait",
            "weave.trait.security.BoltLockSettingsTrait",
            "nest.trait.security.EnhancedBoltLockSettingsTrait",
            "weave.trait.security.BoltLockCapabilitiesTrait",
            "weave.trait.security.PincodeInputTrait",
            "weave.trait.security.TamperTrait",
            # HomeKit-relevant traits
            "weave.trait.description.DeviceIdentityTrait",  # Serial, firmware, model
            "weave.trait.power.BatteryPowerSourceTrait",    # Battery level, status
        ]
        for trait in trait_names:
            trait_param = self._encode_string(1, trait)
            payload += self._encode_length_delimited(3, trait_param)
        return bytes(payload)

    def _get_observe_payload(self):
        return self._observe_payload or self._build_observe_payload()

    def _candidate_bases(self):
        return _transport_candidates(self.transport_url)

    def _merge_trait_state(self, existing, incoming):
        if existing is None:
            return incoming
        if incoming is None:
            return existing
        if existing.__class__ is not incoming.__class__:
            return incoming
        merged = existing.__class__()
        merged.CopyFrom(existing)
        for field, value in incoming.ListFields():
            if field.label == field.LABEL_REPEATED:
                target = getattr(merged, field.name)
                target.clear()
                if field.type == field.TYPE_MESSAGE:
                    for item in value:
                        target.add().CopyFrom(item)
                else:
                    target.extend(list(value))
            elif field.type == field.TYPE_MESSAGE:
                getattr(merged, field.name).CopyFrom(value)
            else:
                setattr(merged, field.name, value)
        return merged

    def _merge_trait_states(self, trait_states: dict | None) -> None:
        if not trait_states:
            return
        current_traits = self.current_state.setdefault("traits", {})
        for resource_id, traits in trait_states.items():
            resource_traits = current_traits.setdefault(resource_id, {})
            for trait_name, trait_msg in traits.items():
                existing = resource_traits.get(trait_name)
                resource_traits[trait_name] = self._merge_trait_state(existing, trait_msg)

    def _merge_trait_labels(self, trait_labels: dict | None) -> None:
        if not trait_labels:
            return
        current_labels = self.current_state.setdefault("trait_labels", {})
        for resource_id, traits in trait_labels.items():
            resource_labels = current_labels.setdefault(resource_id, {})
            for trait_name, label in traits.items():
                if label:
                    resource_labels[trait_name] = label

    def _apply_cached_settings_to_update(self, locks_data: dict) -> None:
        yale = locks_data.get("yale") if isinstance(locks_data, dict) else None
        if not yale:
            return
        trait_cache = self.current_state.get("traits", {})
        for device_id, device in yale.items():
            settings = trait_cache.get(device_id, {}).get("weave.trait.security.BoltLockSettingsTrait")
            if not settings:
                continue
            try:
                fields = {field.name for field, _ in settings.ListFields()}
            except Exception:
                fields = set()
        if settings.HasField("autoRelockDuration"):
            device["auto_relock_duration"] = int(settings.autoRelockDuration.seconds)
        if "autoRelockOn" in fields:
            device["auto_relock_on"] = bool(settings.autoRelockOn)
        elif settings.HasField("autoRelockDuration") and settings.autoRelockDuration.seconds == 0:
            device["auto_relock_on"] = False

        enhanced = trait_cache.get(device_id, {}).get("nest.trait.security.EnhancedBoltLockSettingsTrait")
        if enhanced:
            try:
                enhanced_fields = {field.name for field, _ in enhanced.ListFields()}
            except Exception:
                enhanced_fields = set()
            if enhanced.HasField("autoRelockDuration"):
                device["auto_relock_duration"] = int(enhanced.autoRelockDuration.seconds)
            if "autoRelockOn" in enhanced_fields:
                device["auto_relock_on"] = bool(enhanced.autoRelockOn)

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
            # IMPORTANT: Do NOT block authentication on refresh_state().
            #
            # refresh_state() is a streaming call that can take up to API_TIMEOUT_SECONDS
            # (and may retry). During config flow validation / initial setup, this makes
            # adding the integration feel "stuck" even though credentials are valid.
            #
            # Device discovery is primarily handled by the Observe stream started by the
            # coordinator; fallback polling still uses refresh_state() when needed.
            #
            # We keep a best-effort structure_id fetch (REST) but cap it so setup stays snappy.
            try:
                self._structure_id = await asyncio.wait_for(self.fetch_structure_id(), timeout=5)
            except asyncio.TimeoutError:
                _LOGGER.debug("StructureId fetch timed out after 5s; will continue without explicit structure_id")
            except Exception as e:
                _LOGGER.debug("StructureId fetch failed (continuing): %s", e)
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
        targets = ["self", "me"]
        if self._user_id and self._user_id not in targets:
            targets.append(self._user_id)
        headers = {
            "User-Agent": USER_AGENT_STRING,
            "Accept": "application/json",
        }
        for target_user in targets:
            url = f"https://home.nest.com/api/0.1/user/{target_user}?auth={self.access_token}"
            async with self.session.get(url, headers=headers) as resp:
                if resp.status != 200:
                    _LOGGER.debug(
                        "StructureId fetch returned status %s for %s; trying next target",
                        resp.status,
                        target_user,
                    )
                    continue
                user_data = await resp.json()
                # Optionally update user_id if available in user_data
                possible_user_id = user_data.get("userid") or user_data.get("user", {}).get("user_id")
                if possible_user_id:
                    old_user_id = self._user_id
                    self._user_id = possible_user_id
                    self.current_state["user_id"] = self._user_id
                    if old_user_id != self._user_id:
                        _LOGGER.info("Updated user_id from user_data: %s (was %s)", self._user_id, old_user_id)
                structures = user_data.get("structures", {})
                if not structures:
                    _LOGGER.warning("No structures found in user response for %s", target_user)
                    continue
                return next(iter(structures.keys()))
        return None

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
                    self.protobuf_handler.reset_stream_state()
                    async for chunk in self.connection.stream(
                        api_url,
                        headers,
                        observe_payload,
                        read_timeout=API_TIMEOUT_SECONDS,
                    ):
                        parsed_messages = await self.protobuf_handler._ingest_chunk(chunk)
                        if not parsed_messages:
                            continue
                        for locks_data in parsed_messages:
                            if locks_data.get("parse_failed"):
                                _LOGGER.debug("refresh_state received partial frame; waiting for more data")
                                self.protobuf_handler.prepend_chunk(chunk)
                                continue
                            if locks_data.get("yale"):
                                self.current_state["devices"]["locks"] = locks_data["yale"]
                                if locks_data.get("user_id"):
                                    old_user_id = self._user_id
                                    self._user_id = locks_data["user_id"]
                                    self.current_state["user_id"] = self._user_id
                                    if old_user_id != self._user_id:
                                        _LOGGER.info("Updated user_id from stream: %s (was %s)", self._user_id, old_user_id)
                            if locks_data.get("structure_id"):
                                new_structure_id = locks_data["structure_id"]
                                if self._is_legacy_structure_id(new_structure_id):
                                    old_structure_id = self._structure_id
                                    self._structure_id = new_structure_id
                                    self.current_state["structure_id"] = self._structure_id
                                    if old_structure_id != self._structure_id:
                                        _LOGGER.info(
                                            "Updated structure_id from stream: %s (was %s)",
                                            self._structure_id,
                                            old_structure_id,
                                        )
                            if locks_data.get("structure_id_v2"):
                                new_structure_id_v2 = locks_data["structure_id_v2"]
                                if new_structure_id_v2 and new_structure_id_v2 != self._structure_id_v2:
                                    self._structure_id_v2 = new_structure_id_v2
                                    self.current_state["structure_id_v2"] = self._structure_id_v2
                                    _LOGGER.info(
                                        "Stored v2 structure_id from stream: %s",
                                        self._structure_id_v2,
                                    )
                                self._merge_trait_states(locks_data.get("trait_states"))
                                self._merge_trait_labels(locks_data.get("trait_labels"))
                                self._apply_cached_settings_to_update(locks_data)
                                self._last_observe_data_ts = asyncio.get_event_loop().time()
                                self.transport_url = base_url
                                return locks_data["yale"]
                except asyncio.TimeoutError:
                    _LOGGER.debug("refresh_state timeout after %s seconds", API_TIMEOUT_SECONDS)
                    last_error = TimeoutError(f"refresh_state timed out after {API_TIMEOUT_SECONDS} seconds")
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
                        parsed_messages = await self.protobuf_handler._ingest_chunk(chunk)
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
                                self.protobuf_handler.prepend_chunk(chunk)
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
                                new_structure_id = locks_data["structure_id"]
                                if self._is_legacy_structure_id(new_structure_id):
                                    old_structure_id = self._structure_id
                                    self._structure_id = new_structure_id
                                    self.current_state["structure_id"] = self._structure_id
                                    if old_structure_id != self._structure_id:
                                        _LOGGER.info(
                                            "Updated structure_id from stream: %s (was %s)",
                                            self._structure_id,
                                            old_structure_id,
                                        )
                            if locks_data.get("structure_id_v2"):
                                new_structure_id_v2 = locks_data["structure_id_v2"]
                                if new_structure_id_v2 and new_structure_id_v2 != self._structure_id_v2:
                                    self._structure_id_v2 = new_structure_id_v2
                                    self.current_state["structure_id_v2"] = self._structure_id_v2
                                    _LOGGER.info(
                                        "Stored v2 structure_id from stream: %s",
                                        self._structure_id_v2,
                                    )
                            self._merge_trait_states(locks_data.get("trait_states"))
                            self._merge_trait_labels(locks_data.get("trait_labels"))
                            self._apply_cached_settings_to_update(locks_data)
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
            "Referer": "https://home.nest.com/",
            "Origin": "https://home.nest.com",
        }

        cmd_any = any_pb2.Any()
        cmd_any.type_url = command["command"]["type_url"]
        cmd_any.value = command["command"]["value"] if isinstance(command["command"]["value"], bytes) else command["command"]["value"].SerializeToString()

        resource_command = v1_pb2.ResourceCommand()
        resource_command.command.CopyFrom(cmd_any)
        if command.get("traitLabel"):
            resource_command.traitLabel = command["traitLabel"]
        request = v1_pb2.SendCommandRequest(
            resourceRequest=v1_pb2.ResourceRequest(
                resourceId=device_id,
                requestId=request_id,
            ),
            resourceCommands=[resource_command],
        )
        encoded_data = request.SerializeToString()

        _LOGGER.debug(
            "Sending command to %s (trait=%s), bytes=%d",
            device_id,
            command.get("command", {}).get("type_url"),
            len(encoded_data),
        )

        last_error = None
        forced_refresh = False  # Track whether forced refresh was already attempted

        def _refresh_command_headers():
            headers["Authorization"] = f"Basic {self.access_token}"

        _refresh_command_headers()

        for base_url in self._candidate_bases():
            api_url = f"{base_url}{ENDPOINT_SENDCOMMAND}"
            reauthed = False
            recovered = False
            for _ in range(3):
                try:
                    raw_data = await self.connection.post(api_url, headers, encoded_data, read_timeout=API_TIMEOUT_SECONDS)
                    self.transport_url = base_url
                    # Prefer gateway v1 response parsing when possible (more accurate than StreamBody fallback)
                    status_code, status_msg = self._parse_v1_operation_status(raw_data)
                    if status_code is None:
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
                    try:
                        self._last_command_info = {
                            "ts": asyncio.get_event_loop().time(),
                            "device_id": device_id,
                            "type_url": command.get("command", {}).get("type_url"),
                            "status_code": 0,
                            "status_message": None,
                        }
                    except Exception:
                        pass
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
            try:
                self._last_command_info = {
                    "ts": asyncio.get_event_loop().time(),
                    "device_id": device_id,
                    "type_url": command.get("command", {}).get("type_url"),
                    "status_code": getattr(last_error, "status", None) or -1,
                    "status_message": str(last_error),
                }
            except Exception:
                pass
            raise last_error
        raise RuntimeError(f"Failed to send command to {device_id} for unknown reasons")

    async def update_bolt_lock_settings(
        self,
        device_id: str,
        *,
        auto_relock_on: bool | None = None,
        auto_relock_duration: int | None = None,
        structure_id: str | None = None,
    ):
        """Update BoltLockSettingsTrait via TraitBatchApi/BatchUpdateState."""
        if auto_relock_on is None and auto_relock_duration is None:
            return None
        if auto_relock_on is None and auto_relock_duration is not None:
            auto_relock_on = True

        # Ensure token/ids are present
        if not self.access_token:
            await self.authenticate()

        request_id = str(uuid.uuid4())
        headers = {
            "Authorization": f"Basic {self.access_token}",
            "Content-Type": "application/x-protobuf",
            "User-Agent": USER_AGENT_STRING,
            "X-Accept-Content-Transfer-Encoding": "binary",
            "X-Accept-Response-Streaming": "true",
            "Accept": "application/x-protobuf",
            "Accept-Encoding": "gzip, deflate, br",
            "Referer": "https://home.nest.com/",
            "Origin": "https://home.nest.com",
            "request-id": request_id,
        }

        effective_structure_id = structure_id or self._structure_id or self._structure_id_v2
        if effective_structure_id:
            headers["X-Nest-Structure-Id"] = effective_structure_id
        if self._user_id:
            headers["X-nl-user-id"] = str(self._user_id)

        # Build the trait state (full trait update, nest_legacy-style).
        # Prefer the last observed settings trait to avoid resetting fields.
        current_traits = self.current_state.get("traits", {}).get(device_id, {})
        settings_trait = current_traits.get("weave.trait.security.BoltLockSettingsTrait")
        if settings_trait:
            state_proto = weave_security_pb2.BoltLockSettingsTrait()
            state_proto.CopyFrom(settings_trait)
        else:
            cached = {}
            try:
                cached = (
                    self.current_state.get("devices", {})
                    .get("locks", {})
                    .get(device_id, {})
                )
            except Exception:
                cached = {}

            if auto_relock_on is None:
                auto_relock_on = cached.get("auto_relock_on")
            if auto_relock_duration is None:
                auto_relock_duration = cached.get("auto_relock_duration")
            if auto_relock_on is None and auto_relock_duration is None:
                _LOGGER.debug(
                    "No auto-relock values available for %s; skipping update",
                    device_id,
                )
                return None
            state_proto = weave_security_pb2.BoltLockSettingsTrait()

        if auto_relock_duration is None and auto_relock_on:
            auto_relock_duration = 60
        if auto_relock_on is not None:
            state_proto.autoRelockOn = bool(auto_relock_on)
        if auto_relock_duration is not None:
            state_proto.autoRelockDuration.seconds = int(auto_relock_duration)

        any_state = any_pb2.Any()
        # Match Nest style type_url prefix for compatibility
        any_state.Pack(state_proto, type_url_prefix="type.nestlabs.com")

        update_requests = []
        update_req = v1_pb2.TraitUpdateStateRequest(
            traitRequest=v1_pb2.TraitRequest(
                resourceId=device_id,
                traitLabel="bolt_lock_settings",
                requestId=request_id,
            ),
            state=any_state,
        )
        update_requests.append(update_req)

        trait_labels = self.current_state.get("trait_labels", {}).get(device_id, {})
        enhanced_label = trait_labels.get("nest.trait.security.EnhancedBoltLockSettingsTrait")
        enhanced_trait = current_traits.get("nest.trait.security.EnhancedBoltLockSettingsTrait")
        if enhanced_label and enhanced_trait:
            enhanced_state = nest_security_pb2.EnhancedBoltLockSettingsTrait()
            enhanced_state.CopyFrom(enhanced_trait)
            if auto_relock_on is not None:
                enhanced_state.autoRelockOn = bool(auto_relock_on)
            if auto_relock_duration is not None:
                enhanced_state.autoRelockDuration.seconds = int(auto_relock_duration)
            enhanced_any = any_pb2.Any()
            enhanced_any.Pack(enhanced_state, type_url_prefix="type.nestlabs.com")
            enhanced_req = v1_pb2.TraitUpdateStateRequest(
                traitRequest=v1_pb2.TraitRequest(
                    resourceId=device_id,
                    traitLabel=enhanced_label,
                    requestId=str(uuid.uuid4()),
                ),
                state=enhanced_any,
            )
            update_requests.append(enhanced_req)
        elif enhanced_trait and not enhanced_label:
            _LOGGER.debug(
                "Enhanced bolt lock settings trait label missing for %s; skipping enhanced update",
                device_id,
            )

        batch_req = v1_pb2.BatchUpdateStateRequest(
            batchUpdateStateRequest=update_requests,
        )
        encoded = batch_req.SerializeToString()

        for base_url in self._candidate_bases():
            api_url = f"{base_url}{ENDPOINT_UPDATE}"
            raw = await self.connection.post(api_url, headers, encoded, read_timeout=API_TIMEOUT_SECONDS)
            status_code, status_msg = self._parse_v1_operation_status(raw)
            if status_code is None:
                status_code, status_msg = self._parse_command_status(raw)
            if status_code not in (None, 0):
                try:
                    self._last_command_info = {
                        "ts": asyncio.get_event_loop().time(),
                        "device_id": device_id,
                        "type_url": "weave.trait.security.BoltLockSettingsTrait",
                        "status_code": int(status_code) if status_code is not None else None,
                        "status_message": status_msg,
                    }
                except Exception:
                    pass
                raise RuntimeError(
                    f"Update bolt_lock_settings failed (code {status_code}): {status_msg or 'Unknown error'}"
                )
            try:
                self._last_command_info = {
                    "ts": asyncio.get_event_loop().time(),
                    "device_id": device_id,
                    "type_url": "weave.trait.security.BoltLockSettingsTrait",
                    "status_code": 0,
                    "status_message": None,
                }
            except Exception:
                pass
            try:
                current_traits = self.current_state.setdefault("traits", {})
                current_traits.setdefault(device_id, {})[
                    "weave.trait.security.BoltLockSettingsTrait"
                ] = state_proto
            except Exception:
                pass
            return raw
        raise RuntimeError("No valid gRPC endpoint available for BatchUpdateState")

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

    def _parse_v1_operation_status(self, response_data: bytes):
        """Parse v1 gateway responses for operation status (preferred over StreamBody when present).

        The protobuf API may return:
        - SendCommandResponse for SendCommand
        - BatchUpdateStateResponse for BatchUpdateState

        Returns:
            (code, message) if we can confidently determine status, otherwise (None, None)
        """
        if not response_data:
            return None, None

        # 1) SendCommandResponse
        try:
            resp = v1_pb2.SendCommandResponse()
            resp.ParseFromString(response_data)
            if resp.ListFields():
                status = getattr(resp, "status", None)
                if status and getattr(status, "code", 0) not in (0, None):
                    return int(status.code), getattr(status, "message", None)
                return 0, None
        except Exception:
            pass

        # 2) BatchUpdateStateResponse
        try:
            resp = v1_pb2.BatchUpdateStateResponse()
            resp.ParseFromString(response_data)
            if resp.ListFields():
                status = getattr(resp, "status", None)
                if status and getattr(status, "code", 0) not in (0, None):
                    return int(status.code), getattr(status, "message", None)
                return 0, None
        except Exception:
            pass

        return None, None

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
        # Refresh structure_id after reauth so commands have IDs
        try:
            self._structure_id = await self.fetch_structure_id()
            self.current_state["structure_id"] = self._structure_id
        except Exception as err:
            _LOGGER.debug("Structure id refresh after reauth failed: %s", err)
