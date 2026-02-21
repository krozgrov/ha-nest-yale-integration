import logging
import os
import random
import secrets
import time
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
    GRPC_CODE_INVALID_ARGUMENT,
    GRPC_CODE_INTERNAL,
    API_TIMEOUT_SECONDS,
)
from .proto.nestlabs.gateway import v1_pb2
from .proto.nest import rpc_pb2
from .proto.weave.trait import security_pb2 as weave_security_pb2
from .proto.nest.trait import security_pb2 as nest_security_pb2
from .passcode_crypto import (
    ROOT_KEY_CLIENT,
    ROOT_KEY_FABRIC,
    ROOT_KEY_SERVICE,
    PasscodeCryptoError,
    decrypt_passcode_config2,
    decode_hex_bytes,
    derive_passcode_config2_keys,
    encrypt_passcode_config2,
    get_app_group_local_number,
    get_epoch_key_number,
    get_root_key_id,
    is_app_rotating_key,
    parse_encrypted_passcode_metadata,
    update_epoch_key_id,
    uses_current_epoch_key,
)
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.exceptions import ConfigEntryAuthFailed


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

_APP_LAUNCH_URL_FORMAT = "https://{host}/api/0.1/user/{user_id}/app_launch"
_APP_LAUNCH_BUCKET_TYPES = [
    "buckets",
    "delayed_topaz",
    "demand_response",
    "device",
    "device_alert_dialog",
    "geofence_info",
    "kryptonite",
    "link",
    "message",
    "message_center",
    "metadata",
    "occupancy",
    "quartz",
    "rcs_settings",
    "safety",
    "safety_summary",
    "schedule",
    "shared",
    "structure",
    "structure_history",
    "structure_metadata",
    "topaz",
    "topaz_resource",
    "track",
    "trip",
    "tuneups",
    "user",
    "user_alert_dialog",
    "user_settings",
    "where",
    "widget_track",
]
_APP_LAUNCH_TIMEOUT_SECONDS = 15
_APP_LAUNCH_REFRESH_SECONDS = 6 * 60 * 60
_ENV_FABRIC_SECRET_HEX = "NEST_YALE_FABRIC_SECRET_HEX"
_ENV_CLIENT_ROOT_KEY_HEX = "NEST_YALE_CLIENT_ROOT_KEY_HEX"
_ENV_SERVICE_ROOT_KEY_HEX = "NEST_YALE_SERVICE_ROOT_KEY_HEX"

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
    def __init__(self, hass, issue_token, api_key, cookies, auth_failure_raises=False):
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
        self._auth_failure_raises = bool(auth_failure_raises)
        self._legacy_name_overrides = {}
        self._legacy_name_last_fetch = None
        self._legacy_name_task = None
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
            "nest.trait.located.LocatedAnnotationsTrait",
            "nest.trait.located.CustomLocatedAnnotationsTrait",
            "nest.trait.located.DeviceLocatedSettingsTrait",
            "weave.trait.security.BoltLockTrait",
            "weave.trait.description.LabelSettingsTrait",
            "weave.trait.security.BoltLockSettingsTrait",
            "nest.trait.security.EnhancedBoltLockSettingsTrait",
            "weave.trait.security.BoltLockCapabilitiesTrait",
            "weave.trait.security.UserPincodesSettingsTrait",
            "weave.trait.security.UserPincodesCapabilitiesTrait",
            "weave.trait.auth.ApplicationKeysTrait",
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

    @staticmethod
    def _is_map_field(field) -> bool:
        if field.label != field.LABEL_REPEATED or field.type != field.TYPE_MESSAGE:
            return False
        message_type = getattr(field, "message_type", None)
        if message_type is None:
            return False
        try:
            return bool(message_type.GetOptions().map_entry)
        except Exception:
            return False

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
                if self._is_map_field(field):
                    value_field = field.message_type.fields_by_name.get("value")
                    value_is_message = bool(
                        value_field and value_field.type == value_field.TYPE_MESSAGE
                    )
                    for map_key, map_value in value.items():
                        if value_is_message:
                            target[map_key].CopyFrom(map_value)
                        else:
                            target[map_key] = map_value
                elif field.type == field.TYPE_MESSAGE:
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
            if settings.HasField("autoRelockDuration"):
                device["auto_relock_duration"] = int(settings.autoRelockDuration.seconds)
            if hasattr(settings, "autoRelockOn"):
                device["auto_relock_on"] = bool(settings.autoRelockOn)
            nest_settings = trait_cache.get(device_id, {}).get("nest.trait.security.BoltLockSettingsTrait")
            if nest_settings and hasattr(nest_security_pb2, "BoltLockSettingsTrait"):
                if nest_settings.HasField("autoRelockDuration"):
                    device["auto_relock_duration"] = int(nest_settings.autoRelockDuration.seconds)
                if hasattr(nest_settings, "autoRelockOn"):
                    device["auto_relock_on"] = bool(nest_settings.autoRelockOn)

            enhanced = trait_cache.get(device_id, {}).get("nest.trait.security.EnhancedBoltLockSettingsTrait")
            if enhanced:
                if enhanced.HasField("autoRelockDuration"):
                    device["auto_relock_duration"] = int(enhanced.autoRelockDuration.seconds)
                if hasattr(enhanced, "autoRelockOn"):
                    device["auto_relock_on"] = bool(enhanced.autoRelockOn)

    @classmethod
    async def create(
        cls,
        hass,
        issue_token,
        api_key=None,
        cookies=None,
        user_id=None,
        auth_failure_raises=False,
    ):
        _LOGGER.debug("Entering create")
        instance = cls(
            hass,
            issue_token,
            api_key,
            cookies,
            auth_failure_raises=auth_failure_raises,
        )
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
                auth_failure = False
                last_error = getattr(self.authenticator, "_last_error", None)
                if last_error:
                    last_error_msg = str(last_error)
                    if "Cookie expired" in last_error_msg or "USER_LOGGED_OUT" in last_error_msg:
                        error_msg = last_error_msg
                        auth_failure = True
                    elif isinstance(last_error, ValueError):
                        error_msg = last_error_msg
                        auth_failure = True
                if auth_failure and self._auth_failure_raises:
                    raise ConfigEntryAuthFailed(error_msg)
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
                # Some accounts do not return id_token; attempt to decode the Nest JWT
                # before falling back to observe/user-data discovery.
                self._user_id = None
                try:
                    decoded_jwt = jwt.decode(self.access_token, options={"verify_signature": False})
                    if isinstance(decoded_jwt, dict):
                        for key in ("sub", "user_id", "userid"):
                            candidate = decoded_jwt.get(key)
                            if isinstance(candidate, str) and candidate.strip():
                                self._user_id = candidate.strip()
                                break
                except Exception:
                    self._user_id = None
                self.current_state["user_id"] = self._user_id
                _LOGGER.warning(
                    "No id_token in auth_data; derived user_id=%s from access token (may be None)",
                    self._user_id,
                )
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
            self._schedule_legacy_name_refresh("auth")
            # Schedule preemptive re-auth
            self._schedule_reauth()
        except Exception as e:
            _LOGGER.error(f"Authentication failed: {e}", exc_info=True)
            if isinstance(e, ConfigEntryAuthFailed):
                await self.close()
                raise
            error_msg = str(e)
            auth_failure = False
            if isinstance(e, ValueError) and (
                "Cookie expired" in error_msg or "USER_LOGGED_OUT" in error_msg
            ):
                auth_failure = True
            await self.close()
            if auth_failure and self._auth_failure_raises:
                raise ConfigEntryAuthFailed(error_msg) from e
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
                            had_yale_update = False
                            if locks_data.get("yale"):
                                had_yale_update = True
                                self._apply_legacy_name_overrides(locks_data)
                                self.current_state["devices"]["locks"] = locks_data["yale"]
                                if locks_data.get("user_id"):
                                    old_user_id = self._user_id
                                    self._user_id = locks_data["user_id"]
                                    self.current_state["user_id"] = self._user_id
                                    if old_user_id != self._user_id:
                                        _LOGGER.info("Updated user_id from stream: %s (was %s)", self._user_id, old_user_id)
                                        self._schedule_legacy_name_refresh("refresh_state")
                            if locks_data.get("all_traits"):
                                current_traits = self.current_state.get("all_traits", {}) or {}
                                merged_traits = {**current_traits, **locks_data["all_traits"]}
                                self.current_state["all_traits"] = merged_traits
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
                                if had_yale_update:
                                    self._schedule_legacy_name_refresh("refresh_state")
                                return locks_data["yale"]
                except asyncio.TimeoutError:
                    _LOGGER.debug("refresh_state timeout after %s seconds", API_TIMEOUT_SECONDS)
                    last_error = TimeoutError(f"refresh_state timed out after {API_TIMEOUT_SECONDS} seconds")
                except ConfigEntryAuthFailed:
                    raise
                except aiohttp.ClientResponseError as err:
                    last_error = err
                    if err.status in (401, 403):
                        _LOGGER.info(
                            "refresh_state got %s; reauthenticating and retrying",
                            err.status,
                        )
                        try:
                            await self.authenticate()
                        except ConfigEntryAuthFailed:
                            raise
                        except Exception as auth_err:
                            _LOGGER.warning(
                                "Reauthentication failed during refresh_state: %s",
                                auth_err,
                            )
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
                            had_yale_update = False
                            # Check for authentication failure
                            if locks_data.get("auth_failed"):
                                _LOGGER.warning("Observe stream reported authentication failure, triggering re-auth")
                                self.connection.connected = False
                                self.access_token = None
                                try:
                                    await self.authenticate()
                                except ConfigEntryAuthFailed:
                                    raise
                                # Rebuild headers with new token before reconnecting
                                headers = self._build_observe_headers()
                                _LOGGER.info("Re-authenticated, reconnecting observe stream with new token")
                                auth_failure = True
                                break

                            if "yale" in locks_data:
                                had_yale_update = True
                                last_data_time = current_time
                                _LOGGER.debug("Observe stream received yale data")
                                if locks_data.get("user_id"):
                                    old_user_id = self._user_id
                                    self._user_id = locks_data["user_id"]
                                    self.current_state["user_id"] = self._user_id
                                    if old_user_id != self._user_id:
                                        _LOGGER.info("Updated user_id from stream: %s (was %s)", self._user_id, old_user_id)
                                        self._schedule_legacy_name_refresh("observe")
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
                            if locks_data.get("all_traits"):
                                current_traits = self.current_state.get("all_traits", {}) or {}
                                self.current_state["all_traits"] = {
                                    **current_traits,
                                    **locks_data["all_traits"],
                                }
                            self._merge_trait_states(locks_data.get("trait_states"))
                            self._merge_trait_labels(locks_data.get("trait_labels"))
                            self._apply_cached_settings_to_update(locks_data)
                            if had_yale_update:
                                self._schedule_legacy_name_refresh("observe")
                            self.transport_url = base_url
                            self._last_observe_data_ts = current_time
                            # Yield full locks_data including all_traits so coordinator can extract trait data
                            if locks_data.get("yale"):
                                self._apply_legacy_name_overrides(locks_data)
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
                        except ConfigEntryAuthFailed:
                            raise
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
                        error_msg = self._format_command_error_message(
                            status_code,
                            status_msg,
                            command.get("command", {}).get("type_url"),
                        )
                        last_error = RuntimeError(f"Command failed (code {status_code}): {error_msg}")
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
                        try:
                            await self.authenticate()
                        except ConfigEntryAuthFailed:
                            raise
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
        # Ensure token/ids are present
        if not self.access_token:
            await self.authenticate()

        request_id = str(uuid.uuid4())
        headers = self._build_observe_headers()

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
        existing = (
            self.current_state.get("traits", {})
            .get(device_id, {})
            .get("weave.trait.security.BoltLockSettingsTrait")
        )
        if existing:
            try:
                state_proto.CopyFrom(existing)
            except Exception:
                pass
        if auto_relock_duration is None and auto_relock_on:
            auto_relock_duration = 60
        if auto_relock_on is not None:
            state_proto.autoRelockOn = bool(auto_relock_on)
        if auto_relock_duration is not None:
            state_proto.autoRelockDuration.seconds = int(auto_relock_duration)

        any_state = any_pb2.Any()
        # Match Nest style type_url prefix for compatibility
        any_state.Pack(state_proto, type_url_prefix="type.nestlabs.com")

        async def _post_update(update_request, trait_name):
            batch_req = v1_pb2.BatchUpdateStateRequest(
                batchUpdateStateRequest=[update_request],
            )
            encoded = batch_req.SerializeToString()
            for base_url in self._candidate_bases():
                api_url = f"{base_url}{ENDPOINT_UPDATE}"
                reauthed = False
                while True:
                    try:
                        raw = await self.connection.post(
                            api_url, headers, encoded, read_timeout=API_TIMEOUT_SECONDS
                        )
                        break
                    except aiohttp.ClientResponseError as err:
                        if err.status in (401, 403) and not reauthed:
                            _LOGGER.info(
                                "BatchUpdateState got %s; reauthenticating and retrying",
                                err.status,
                            )
                            try:
                                await self.authenticate()
                            except ConfigEntryAuthFailed:
                                raise
                            headers.update(self._build_observe_headers())
                            reauthed = True
                            continue
                        raise
                self._log_batch_update_details(raw)
                status_code, status_msg = self._parse_v1_operation_status(raw)
                if status_code is None:
                    status_code, status_msg = self._parse_command_status(raw)
                if status_code == GRPC_CODE_INTERNAL:
                    _LOGGER.warning(
                        "Update %s returned INTERNAL; treating as transient (code %s): %s",
                        trait_name,
                        status_code,
                        status_msg,
                    )
                    try:
                        await self.refresh_state()
                    except Exception as err:
                        _LOGGER.debug("Refresh after INTERNAL error failed: %s", err)
                    return raw, False
                if status_code not in (None, 0):
                    raise RuntimeError(
                        f"Update {trait_name} failed (code {status_code}): {status_msg or 'Unknown error'}"
                    )
                return raw, True
            raise RuntimeError("No valid gRPC endpoint available for BatchUpdateState")

        current_traits = self.current_state.get("traits", {}).get(device_id, {})
        trait_labels = self.current_state.get("trait_labels", {}).get(device_id, {})
        enhanced_label = trait_labels.get("nest.trait.security.EnhancedBoltLockSettingsTrait")
        enhanced_existing = current_traits.get("nest.trait.security.EnhancedBoltLockSettingsTrait")
        enhanced_state = None
        if enhanced_label and enhanced_existing:
            enhanced_state = nest_security_pb2.EnhancedBoltLockSettingsTrait()
            try:
                enhanced_state.CopyFrom(enhanced_existing)
            except Exception:
                pass
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
            try:
                await _post_update(enhanced_req, "enhanced_bolt_lock_settings")
                try:
                    self.current_state.setdefault("traits", {}).setdefault(device_id, {})[
                        "nest.trait.security.EnhancedBoltLockSettingsTrait"
                    ] = enhanced_state
                except Exception:
                    pass
            except Exception as err:
                _LOGGER.warning("Enhanced auto-lock update failed: %s", err)

        update_req = v1_pb2.TraitUpdateStateRequest(
            traitRequest=v1_pb2.TraitRequest(
                resourceId=device_id,
                traitLabel="bolt_lock_settings",
                requestId=request_id,
            ),
            state=any_state,
        )

        raw, success = await _post_update(update_req, "bolt_lock_settings")
        if success:
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

    def _user_pincodes_trait_label(self, device_id: str) -> str | None:
        labels = self.current_state.get("trait_labels", {}).get(device_id, {})
        label = labels.get("weave.trait.security.UserPincodesSettingsTrait")
        if isinstance(label, str) and label.strip():
            return label
        return None

    def _structure_resource_id(self) -> str | None:
        """Return the canonical STRUCTURE_* resource id when available."""
        trait_labels = self.current_state.get("trait_labels", {})
        if not isinstance(trait_labels, dict):
            trait_labels = {}

        structure_id = self._structure_id or self.current_state.get("structure_id")
        if isinstance(structure_id, str) and structure_id:
            candidate = f"STRUCTURE_{structure_id}"
            if candidate in trait_labels:
                return candidate
            return candidate

        for resource_id in trait_labels:
            if isinstance(resource_id, str) and resource_id.startswith("STRUCTURE_"):
                return resource_id
        return None

    def _structure_user_pincodes_trait_label(self) -> str | None:
        """Resolve structure-level user_pincodes trait label, if present."""
        structure_resource_id = self._structure_resource_id()
        if not structure_resource_id:
            return None
        labels = self.current_state.get("trait_labels", {}).get(structure_resource_id, {})
        if not isinstance(labels, dict):
            return None
        label = labels.get("weave.trait.security.UserPincodesSettingsTrait")
        if isinstance(label, str) and label.strip():
            return label
        return None

    @staticmethod
    def _is_grpc_status_error(err: Exception, code: int) -> bool:
        message = str(err)
        return f"(code {code})" in message or f"code={code}" in message

    @classmethod
    def _is_passcode_target_rejection(cls, err: Exception) -> bool:
        return cls._is_grpc_status_error(err, GRPC_CODE_INTERNAL) or cls._is_grpc_status_error(
            err, GRPC_CODE_INVALID_ARGUMENT
        )

    @staticmethod
    def _decode_env_key(name: str, expected_len: int) -> bytes | None:
        try:
            return decode_hex_bytes(os.getenv(name), expected_len=expected_len)
        except PasscodeCryptoError as err:
            raise RuntimeError(f"Invalid {name}: {err}") from err

    @staticmethod
    def _decode_app_keys_candidates(
        app_keys_data: dict,
        *,
        field_name: str,
        expected_len: int,
    ) -> list[bytes]:
        entries = app_keys_data.get(field_name, []) if isinstance(app_keys_data, dict) else []
        if not isinstance(entries, list):
            return []

        candidates: list[bytes] = []
        seen: set[bytes] = set()
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            key_hex = entry.get("key_hex")
            try:
                key_bytes = decode_hex_bytes(key_hex, expected_len=expected_len)
            except PasscodeCryptoError:
                continue
            if not key_bytes or key_bytes in seen:
                continue
            seen.add(key_bytes)
            candidates.append(key_bytes)
        return candidates

    def _get_application_keys_data(self, device_id: str) -> dict | None:
        all_traits = self.current_state.get("all_traits", {})
        if not isinstance(all_traits, dict):
            return None
        for trait_info in all_traits.values():
            if not isinstance(trait_info, dict):
                continue
            if trait_info.get("object_id") != device_id:
                continue
            type_url = trait_info.get("type_url")
            if not isinstance(type_url, str):
                continue
            if not type_url.endswith("/weave.trait.auth.ApplicationKeysTrait"):
                continue
            data = trait_info.get("data")
            if isinstance(data, dict):
                return data
        return None

    def _collect_encrypted_pincode_metadata(self, device_id: str) -> list[dict]:
        trait_cache = self.current_state.get("traits", {})
        resource_traits = trait_cache.get(device_id, {}) if isinstance(trait_cache, dict) else {}
        trait = (
            resource_traits.get("weave.trait.security.UserPincodesSettingsTrait")
            if isinstance(resource_traits, dict)
            else None
        )
        if not trait:
            return []

        metadata: list[dict] = []
        try:
            for slot, user_pincode in trait.userPincodes.items():
                pincode_bytes = bytes(getattr(user_pincode, "pincode", b""))
                parsed = parse_encrypted_passcode_metadata(pincode_bytes)
                if not parsed:
                    continue
                user_id = None
                if user_pincode.HasField("userId"):
                    user_id = getattr(user_pincode.userId, "resourceId", None)
                metadata.append(
                    {
                        "slot": int(slot),
                        "user_id": user_id,
                        "config": parsed.config,
                        "key_id": parsed.key_id,
                        "nonce": parsed.nonce,
                        "pincode_bytes": pincode_bytes,
                    }
                )
        except Exception:
            return []
        return metadata

    @staticmethod
    def _passcode_material_candidates(
        root_key_id: int,
        *,
        fabric_secret: bytes | None,
        client_root_key: bytes | None,
        service_root_key: bytes | None,
    ) -> list[dict[str, bytes | str | None]]:
        candidates: list[dict[str, bytes | str | None]] = []
        if root_key_id == ROOT_KEY_CLIENT:
            # Prefer canonical derivation from fabric secret when available.
            if fabric_secret:
                candidates.append(
                    {
                        "name": "fabric_secret",
                        "fabric_secret": fabric_secret,
                        "client_root_key": None,
                        "service_root_key": service_root_key,
                    }
                )
            if client_root_key:
                candidates.append(
                    {
                        "name": "client_root_key",
                        "fabric_secret": None,
                        "client_root_key": client_root_key,
                        "service_root_key": service_root_key,
                    }
                )
            return candidates
        if root_key_id == ROOT_KEY_FABRIC:
            if fabric_secret:
                candidates.append(
                    {
                        "name": "fabric_secret",
                        "fabric_secret": fabric_secret,
                        "client_root_key": client_root_key,
                        "service_root_key": service_root_key,
                    }
                )
            return candidates
        if root_key_id == ROOT_KEY_SERVICE:
            if service_root_key:
                candidates.append(
                    {
                        "name": "service_root_key",
                        "fabric_secret": fabric_secret,
                        "client_root_key": client_root_key,
                        "service_root_key": service_root_key,
                    }
                )
            return candidates
        return candidates

    @staticmethod
    def _merge_passcode_material_candidates(
        first: list[dict[str, bytes | str | None]],
        second: list[dict[str, bytes | str | None]],
    ) -> list[dict[str, bytes | str | None]]:
        def _normalize_bytes(value):
            if isinstance(value, bytes):
                return value
            if isinstance(value, bytearray):
                return bytes(value)
            return None

        merged: list[dict[str, bytes | str | None]] = []
        seen: set[tuple[bytes | None, bytes | None, bytes | None]] = set()
        for candidate in [*first, *second]:
            signature = (
                _normalize_bytes(candidate.get("fabric_secret")),
                _normalize_bytes(candidate.get("client_root_key")),
                _normalize_bytes(candidate.get("service_root_key")),
            )
            if signature in seen:
                continue
            seen.add(signature)
            merged.append(candidate)
        return merged

    def _auto_passcode_material_candidates(
        self,
        *,
        app_keys_data: dict,
        root_key_id: int,
        service_root_key: bytes | None,
    ) -> list[dict[str, bytes | str | None]]:
        """Build root-key candidates discovered from ApplicationKeysTrait payloads."""
        candidate_keys_32 = self._decode_app_keys_candidates(
            app_keys_data, field_name="candidate_keys_32", expected_len=32
        )
        candidate_keys_36 = self._decode_app_keys_candidates(
            app_keys_data, field_name="candidate_keys_36", expected_len=36
        )
        if not candidate_keys_32 and not candidate_keys_36:
            return []

        auto_candidates: list[dict[str, bytes | str | None]] = []
        if root_key_id == ROOT_KEY_CLIENT:
            for fabric_secret in candidate_keys_36:
                auto_candidates.extend(
                    self._passcode_material_candidates(
                        root_key_id,
                        fabric_secret=fabric_secret,
                        client_root_key=None,
                        service_root_key=service_root_key,
                    )
                )
            for client_root_key in candidate_keys_32:
                auto_candidates.extend(
                    self._passcode_material_candidates(
                        root_key_id,
                        fabric_secret=None,
                        client_root_key=client_root_key,
                        service_root_key=service_root_key,
                    )
                )
        elif root_key_id == ROOT_KEY_FABRIC:
            for fabric_secret in candidate_keys_36:
                auto_candidates.extend(
                    self._passcode_material_candidates(
                        root_key_id,
                        fabric_secret=fabric_secret,
                        client_root_key=None,
                        service_root_key=service_root_key,
                    )
                )
        elif root_key_id == ROOT_KEY_SERVICE:
            for service_key in candidate_keys_32:
                auto_candidates.extend(
                    self._passcode_material_candidates(
                        root_key_id,
                        fabric_secret=None,
                        client_root_key=None,
                        service_root_key=service_key,
                    )
                )

        if auto_candidates:
            _LOGGER.debug(
                "Discovered %d auto passcode key candidates from ApplicationKeysTrait (32-byte=%d, 36-byte=%d)",
                len(auto_candidates),
                len(candidate_keys_32),
                len(candidate_keys_36),
            )
        return auto_candidates

    def _derive_passcode_keys(
        self,
        *,
        app_keys_data: dict,
        key_id: int,
        nonce: int,
        candidate: dict[str, bytes | str | None],
    ) -> tuple[int, bytes, bytes, bytes]:
        master_key = self._select_master_key(app_keys_data, key_id)
        epoch_key, resolved_key_id = self._select_epoch_key(app_keys_data, key_id)
        enc_key, auth_key, fingerprint_key = derive_passcode_config2_keys(
            key_id=resolved_key_id,
            nonce=nonce,
            master_key=master_key,
            epoch_key=epoch_key,
            fabric_secret=candidate.get("fabric_secret"),
            client_root_key=candidate.get("client_root_key"),
            service_root_key=candidate.get("service_root_key"),
        )
        return resolved_key_id, enc_key, auth_key, fingerprint_key

    def _material_matches_existing_encrypted_pincodes(
        self,
        device_id: str,
        app_keys_data: dict,
        candidate: dict[str, bytes | str | None],
        expected_root_key_id: int | None = None,
    ) -> bool:
        samples = [
            entry
            for entry in self._collect_encrypted_pincode_metadata(device_id)
            if int(entry.get("config", 0) or 0) == 2
            and isinstance(entry.get("pincode_bytes"), (bytes, bytearray))
        ]
        if expected_root_key_id is not None:
            samples = [
                entry
                for entry in samples
                if get_root_key_id(int(entry.get("key_id", 0) or 0)) == expected_root_key_id
            ]
        if not samples:
            return True

        for sample in samples:
            key_id = int(sample.get("key_id", 0) or 0)
            nonce = int(sample.get("nonce", 0) or 0)
            payload = sample.get("pincode_bytes")
            if not isinstance(payload, (bytes, bytearray)):
                continue
            try:
                _, enc_key, auth_key, fingerprint_key = self._derive_passcode_keys(
                    app_keys_data=app_keys_data,
                    key_id=key_id,
                    nonce=nonce,
                    candidate=candidate,
                )
                decrypt_passcode_config2(
                    encrypted_passcode=bytes(payload),
                    key_id=key_id,
                    enc_key=enc_key,
                    auth_key=auth_key,
                    fingerprint_key=fingerprint_key,
                )
                return True
            except (PasscodeCryptoError, RuntimeError, ValueError):
                continue

        return False

    def _select_passcode_key_id(self, device_id: str, guest_user_id: str) -> int:
        candidates = [
            entry
            for entry in self._collect_encrypted_pincode_metadata(device_id)
            if int(entry.get("config", 0) or 0) == 2
        ]
        if not candidates:
            raise RuntimeError(
                "No encrypted pincode entries were found on this lock; cannot determine passcode key id"
            )

        for entry in candidates:
            if entry.get("user_id") == guest_user_id:
                return int(entry["key_id"])
        return int(candidates[0]["key_id"])

    @staticmethod
    def _select_master_key(app_keys_data: dict, key_id: int) -> bytes:
        master_keys = app_keys_data.get("master_keys", []) if isinstance(app_keys_data, dict) else []
        group_short_id = get_app_group_local_number(key_id)
        for entry in master_keys:
            if not isinstance(entry, dict):
                continue
            if int(entry.get("application_group_short_id", -1)) != group_short_id:
                continue
            key_hex = entry.get("key_hex")
            key_bytes = decode_hex_bytes(key_hex, expected_len=32)
            if key_bytes:
                return key_bytes
        raise RuntimeError(
            f"Application group short id {group_short_id} not found in ApplicationKeysTrait"
        )

    @staticmethod
    def _select_epoch_key(app_keys_data: dict, key_id: int) -> tuple[bytes | None, int]:
        if not is_app_rotating_key(key_id):
            return None, key_id

        epoch_keys = app_keys_data.get("epoch_keys", []) if isinstance(app_keys_data, dict) else []
        if not isinstance(epoch_keys, list) or not epoch_keys:
            raise RuntimeError("No epoch keys available for rotating passcode key id")

        target_epoch = get_epoch_key_number(key_id)
        if uses_current_epoch_key(key_id):
            now = int(time.time())
            active_entry = None
            active_start = None
            dict_entries = [entry for entry in epoch_keys if isinstance(entry, dict)]
            if not dict_entries:
                raise RuntimeError("No usable epoch key entries found")
            for entry in epoch_keys:
                if not isinstance(entry, dict):
                    continue
                start_time = entry.get("start_time")
                if not isinstance(start_time, int):
                    continue
                if start_time > now:
                    continue
                if active_start is None or start_time > active_start:
                    active_start = start_time
                    active_entry = entry
            if active_entry is None:
                active_entry = min(dict_entries, key=lambda item: int(item.get("start_time", 0) or 0))
            key_hex = active_entry.get("key_hex")
            key_bytes = decode_hex_bytes(key_hex, expected_len=32)
            if key_bytes:
                resolved_key_id = update_epoch_key_id(
                    key_id,
                    int(active_entry.get("key_id", 0) or 0),
                )
                return key_bytes, resolved_key_id
            raise RuntimeError("Active epoch key is missing valid key bytes")

        for entry in epoch_keys:
            if not isinstance(entry, dict):
                continue
            if int(entry.get("key_id", -1)) != target_epoch:
                continue
            key_hex = entry.get("key_hex")
            key_bytes = decode_hex_bytes(key_hex, expected_len=32)
            if key_bytes:
                return key_bytes, key_id
        raise RuntimeError(f"Epoch key id {target_epoch} not found in ApplicationKeysTrait")

    def _generate_passcode_nonce(self, device_id: str, key_id: int) -> int:
        used_nonces = {
            int(entry.get("nonce", 0))
            for entry in self._collect_encrypted_pincode_metadata(device_id)
            if int(entry.get("key_id", -1)) == int(key_id)
        }
        for _ in range(64):
            nonce = secrets.randbits(32)
            if nonce not in used_nonces:
                return nonce
        raise RuntimeError("Could not generate a unique passcode nonce")

    def _encrypt_guest_passcode(self, device_id: str, guest_user_id: str, passcode_text: str) -> bytes:
        app_keys_data = self._get_application_keys_data(device_id)
        if not app_keys_data:
            raise RuntimeError(
                "ApplicationKeysTrait data is not available for this lock. "
                "Cannot derive encryption keys for passcode updates."
            )

        selected_key_id = self._select_passcode_key_id(device_id, guest_user_id)
        try:
            master_key = self._select_master_key(app_keys_data, selected_key_id)
            epoch_key, resolved_key_id = self._select_epoch_key(app_keys_data, selected_key_id)
        except PasscodeCryptoError as err:
            raise RuntimeError(f"Invalid ApplicationKeysTrait payload: {err}") from err
        nonce = self._generate_passcode_nonce(device_id, resolved_key_id)

        fabric_secret = self._decode_env_key(_ENV_FABRIC_SECRET_HEX, 36)
        client_root_key = self._decode_env_key(_ENV_CLIENT_ROOT_KEY_HEX, 32)
        service_root_key = self._decode_env_key(_ENV_SERVICE_ROOT_KEY_HEX, 32)

        root_key_id = get_root_key_id(resolved_key_id)
        _LOGGER.debug(
            (
                "Preparing encrypted passcode for %s using selected_key_id=0x%08x "
                "resolved_key_id=0x%08x root_key_id=0x%08x nonce=%d"
            ),
            device_id,
            selected_key_id,
            resolved_key_id,
            root_key_id,
            nonce,
        )
        material_candidates = self._passcode_material_candidates(
            root_key_id,
            fabric_secret=fabric_secret,
            client_root_key=client_root_key,
            service_root_key=service_root_key,
        )
        material_candidates = self._merge_passcode_material_candidates(
            material_candidates,
            self._auto_passcode_material_candidates(
                app_keys_data=app_keys_data,
                root_key_id=root_key_id,
                service_root_key=service_root_key,
            ),
        )
        if not material_candidates:
            if root_key_id == ROOT_KEY_CLIENT:
                raise RuntimeError(
                    "Missing client root key material. Set "
                    f"{_ENV_CLIENT_ROOT_KEY_HEX} (32-byte hex) or {_ENV_FABRIC_SECRET_HEX} (36-byte hex). "
                    "No usable key material was discovered in ApplicationKeysTrait."
                )
            if root_key_id == ROOT_KEY_FABRIC:
                raise RuntimeError(
                    f"Missing fabric secret. Set {_ENV_FABRIC_SECRET_HEX} (36-byte hex). "
                    "No usable key material was discovered in ApplicationKeysTrait."
                )
            if root_key_id == ROOT_KEY_SERVICE:
                raise RuntimeError(
                    f"Missing service root key. Set {_ENV_SERVICE_ROOT_KEY_HEX} (32-byte hex). "
                    "No usable key material was discovered in ApplicationKeysTrait."
                )
            raise RuntimeError(f"Unsupported passcode root key id: 0x{root_key_id:08x}")

        had_validation_samples = bool(
            [
                entry
                for entry in self._collect_encrypted_pincode_metadata(device_id)
                if int(entry.get("config", 0) or 0) == 2
                and isinstance(entry.get("pincode_bytes"), (bytes, bytearray))
            ]
        )

        last_crypto_error: PasscodeCryptoError | None = None
        for candidate in material_candidates:
            if had_validation_samples and not self._material_matches_existing_encrypted_pincodes(
                device_id,
                app_keys_data,
                candidate,
                expected_root_key_id=root_key_id,
            ):
                _LOGGER.debug(
                    "Passcode root material candidate %s rejected for %s (validation mismatch)",
                    candidate.get("name"),
                    device_id,
                )
                continue
            try:
                enc_key, auth_key, fingerprint_key = derive_passcode_config2_keys(
                    key_id=resolved_key_id,
                    nonce=nonce,
                    master_key=master_key,
                    epoch_key=epoch_key,
                    fabric_secret=candidate.get("fabric_secret"),
                    client_root_key=candidate.get("client_root_key"),
                    service_root_key=candidate.get("service_root_key"),
                )
            except PasscodeCryptoError as err:
                last_crypto_error = err
                continue

            _LOGGER.debug(
                "Using passcode root material source %s for %s",
                candidate.get("name"),
                device_id,
            )
            return encrypt_passcode_config2(
                passcode=passcode_text,
                key_id=resolved_key_id,
                nonce=nonce,
                enc_key=enc_key,
                auth_key=auth_key,
                fingerprint_key=fingerprint_key,
            )

        if had_validation_samples:
            raise RuntimeError(
                "Configured passcode key material does not match this lock's existing encrypted pincodes. "
                "Set valid key material and retry."
            )
        if last_crypto_error is not None:
            raise RuntimeError(f"Failed to encrypt passcode: {last_crypto_error}") from last_crypto_error
        raise RuntimeError("Failed to derive passcode encryption keys")

    async def set_guest_passcode(
        self,
        device_id: str,
        guest_user_id: str,
        passcode: str,
        *,
        enabled: bool = True,
    ):
        """Set or update a guest passcode for a given guest user resource id."""
        if not isinstance(guest_user_id, str) or not guest_user_id.strip():
            raise ValueError("guest_user_id is required")
        if not isinstance(passcode, str):
            raise ValueError("passcode must be a string")
        passcode_text = passcode.strip()
        if not passcode_text.isdigit():
            raise ValueError("passcode must contain digits only")

        encrypted_passcode = self._encrypt_guest_passcode(
            device_id,
            guest_user_id.strip(),
            passcode_text,
        )
        request = weave_security_pb2.UserPincodesSettingsTrait.SetUserPincodeRequest()
        request.userPincode.userId.resourceId = guest_user_id.strip()
        request.userPincode.pincode = encrypted_passcode
        request.userPincode.pincodeCredentialEnabled.value = bool(enabled)

        request_bytes = request.SerializeToString()
        command_type_urls = [
            "type.nestlabs.com/weave.trait.security.UserPincodesSettingsTrait.SetUserPincodeRequest",
            "type.googleapis.com/weave.trait.security.UserPincodesSettingsTrait.SetUserPincodeRequest",
        ]

        target_attempts: list[tuple[str, str | None, str]] = []
        target_attempts.append((device_id, self._user_pincodes_trait_label(device_id), "device"))

        structure_resource_id = self._structure_resource_id()
        if structure_resource_id and structure_resource_id != device_id:
            target_attempts.append(
                (
                    structure_resource_id,
                    self._structure_user_pincodes_trait_label(),
                    "structure",
                )
            )

        attempts: list[tuple[str, str | None, str, str]] = []
        seen_attempts: set[tuple[str, str | None, str]] = set()
        for target_resource_id, trait_label, scope in target_attempts:
            trait_label_options = [trait_label, None] if trait_label else [None]
            for label_option in trait_label_options:
                for type_url in command_type_urls:
                    dedupe_key = (target_resource_id, label_option, type_url)
                    if dedupe_key in seen_attempts:
                        continue
                    seen_attempts.add(dedupe_key)
                    attempts.append((target_resource_id, label_option, scope, type_url))

        if _LOGGER.isEnabledFor(logging.DEBUG):
            attempt_targets = [
                f"{target}:{scope}:{'label' if label else 'no-label'}:{type_url}"
                for target, label, scope, type_url in attempts
            ]
            _LOGGER.debug(
                "Sending guest passcode update for %s via attempts=%s",
                device_id,
                attempt_targets,
            )

        last_error: Exception | None = None
        for target_resource_id, trait_label, scope, type_url in attempts:
            cmd_any = {
                "command": {
                    "type_url": type_url,
                    "value": request_bytes,
                },
            }
            if trait_label:
                cmd_any["traitLabel"] = trait_label

            try:
                return await self.send_command(
                    cmd_any,
                    target_resource_id,
                    structure_id=self._structure_id,
                )
            except (RuntimeError, ValueError) as err:
                last_error = err
                if self._is_passcode_target_rejection(err):
                    _LOGGER.warning(
                        (
                            "Guest passcode update failed via %s target %s "
                            "(trait_label=%s, type_url=%s); trying next variant if available: %s"
                        ),
                        scope,
                        target_resource_id,
                        trait_label,
                        type_url,
                        err,
                    )
                    continue
                raise

        if last_error:
            raise RuntimeError(
                "Passcode update rejected by Nest after trying all command target/type variants. "
                "This lock/account likely requires encrypted pincode payloads that are not available from this session. "
                "Update the passcode in the Nest app."
            ) from last_error
        raise RuntimeError("Passcode update failed before command dispatch")

    async def delete_guest_passcode(self, device_id: str, guest_user_id: str):
        """Delete a guest passcode for a given guest user resource id."""
        if not isinstance(guest_user_id, str) or not guest_user_id.strip():
            raise ValueError("guest_user_id is required")

        request = weave_security_pb2.UserPincodesSettingsTrait.DeleteUserPincodeRequest()
        request.userId.resourceId = guest_user_id.strip()

        cmd_any = {
            "command": {
                "type_url": "type.nestlabs.com/weave.trait.security.UserPincodesSettingsTrait.DeleteUserPincodeRequest",
                "value": request.SerializeToString(),
            },
        }
        trait_label = self._user_pincodes_trait_label(device_id)
        if trait_label:
            cmd_any["traitLabel"] = trait_label
        _LOGGER.info("Sending guest passcode delete for device %s", device_id)
        return await self.send_command(cmd_any, device_id, structure_id=self._structure_id)

    async def close(self):
        if self.connection and self.connection.connected:
            await self.connection.close()
            _LOGGER.debug("NestAPIClient connection closed")
        # Cancel preemptive reauth task if running
        if self._reauth_task and not self._reauth_task.done():
            self._reauth_task.cancel()
            self._reauth_task = None
        if self._legacy_name_task and not self._legacy_name_task.done():
            self._legacy_name_task.cancel()
            self._legacy_name_task = None

    def _schedule_legacy_name_refresh(self, reason: str) -> None:
        if not self.access_token:
            return
        if self._legacy_name_task and not self._legacy_name_task.done():
            return
        now = asyncio.get_event_loop().time()
        if self._legacy_name_last_fetch and (now - self._legacy_name_last_fetch) < _APP_LAUNCH_REFRESH_SECONDS:
            return
        _LOGGER.debug("Scheduling legacy name refresh (%s)", reason)
        self._legacy_name_task = asyncio.create_task(self._refresh_legacy_device_names(reason))

    def _legacy_app_launch_host(self) -> str:
        candidates = [
            self.transport_url,
            self.auth_data.get("urls", {}).get("transport_url") if isinstance(self.auth_data, dict) else None,
            "https://home.nest.com",
        ]
        for candidate in candidates:
            if not isinstance(candidate, str):
                continue
            host = candidate.replace("https://", "").replace("http://", "").strip("/")
            if host:
                return host.split("/")[0]
        return "home.nest.com"

    def _legacy_user_candidates(self) -> list[str]:
        candidates: list[str] = []

        def _add(value) -> None:
            if not isinstance(value, str):
                return
            normalized = value.strip()
            if not normalized:
                return
            if normalized.lower() == "unknown":
                return
            if normalized not in candidates:
                candidates.append(normalized)

        _add(self._user_id)
        if isinstance(self.auth_data, dict):
            _add(self.auth_data.get("userid"))
            _add(self.auth_data.get("user_id"))
            user_obj = self.auth_data.get("user")
            if isinstance(user_obj, dict):
                _add(user_obj.get("user_id"))

        # If id_token was unavailable, try decoding the Nest JWT as a fallback source.
        if self.access_token:
            try:
                decoded = jwt.decode(self.access_token, options={"verify_signature": False})
                if isinstance(decoded, dict):
                    for key in ("sub", "user_id", "userid"):
                        _add(decoded.get(key))
            except Exception:
                pass

        # Harvest observed USER_* ids from the pincode trait cache as a last resort.
        trait_cache = self.current_state.get("traits", {}) or {}
        for resource_traits in trait_cache.values():
            if not isinstance(resource_traits, dict):
                continue
            pincode_trait = resource_traits.get("weave.trait.security.UserPincodesSettingsTrait")
            if not pincode_trait:
                continue
            try:
                for user_pincode in pincode_trait.userPincodes.values():
                    if not user_pincode.HasField("userId"):
                        continue
                    _add(getattr(user_pincode.userId, "resourceId", None))
            except Exception:
                continue

        return candidates

    async def _refresh_legacy_device_names(self, reason: str) -> None:
        try:
            if not self.access_token:
                return
            user_candidates = self._legacy_user_candidates()
            if not user_candidates:
                _LOGGER.debug("Skipping app_launch name refresh (%s): no user id candidates", reason)
                return
            host = self._legacy_app_launch_host()
            payload = {
                "known_bucket_types": _APP_LAUNCH_BUCKET_TYPES,
                "known_bucket_versions": [],
            }
            timeout = aiohttp.ClientTimeout(total=_APP_LAUNCH_TIMEOUT_SECONDS)
            attempted = False
            for raw_user_id in user_candidates:
                candidate_ids: list[str] = []
                normalized_user_id = raw_user_id.strip()
                if normalized_user_id.upper().startswith("USER_"):
                    stripped = normalized_user_id.split("_", 1)[1].strip()
                    if stripped:
                        candidate_ids.append(stripped)
                if normalized_user_id:
                    candidate_ids.append(normalized_user_id)
                for request_user_id in candidate_ids:
                    attempted = True
                    url = _APP_LAUNCH_URL_FORMAT.format(host=host, user_id=request_user_id)
                    headers = {
                        "Authorization": f"Basic {self.access_token}",
                        "X-nl-user-id": str(request_user_id),
                        "X-nl-protocol-version": "1",
                        "User-Agent": USER_AGENT_STRING,
                    }
                    _LOGGER.debug(
                        "Requesting app_launch for legacy names (%s) with user_id=%s",
                        reason,
                        request_user_id,
                    )
                    async with self.session.post(
                        url,
                        json=payload,
                        headers=headers,
                        timeout=timeout,
                    ) as resp:
                        if resp.status != 200:
                            _LOGGER.debug(
                                "app_launch returned status %s for user_id=%s (%s)",
                                resp.status,
                                request_user_id,
                                reason,
                            )
                            continue
                        data = await resp.json()
                    overrides = self._extract_legacy_device_names(data)
                    if overrides:
                        self._legacy_name_overrides.update(overrides)
                        self._apply_legacy_name_overrides_to_current()
                        _LOGGER.info(
                            "Applied legacy app_launch names for %d devices using user_id=%s",
                            len(overrides),
                            request_user_id,
                        )
                        if attempted:
                            self._legacy_name_last_fetch = asyncio.get_event_loop().time()
                        return
            if attempted:
                self._legacy_name_last_fetch = asyncio.get_event_loop().time()
        except asyncio.CancelledError:
            raise
        except Exception as err:
            _LOGGER.debug("Legacy app_launch name refresh failed (%s): %s", reason, err)
        finally:
            self._legacy_name_task = None

    def _apply_legacy_name_overrides(self, locks_data: dict) -> None:
        if not self._legacy_name_overrides:
            return
        yale = locks_data.get("yale")
        if not isinstance(yale, dict):
            return
        for device_id, payload in yale.items():
            if not isinstance(payload, dict):
                continue
            # Trust trait-derived label_name when present; app_launch is fallback.
            if self._normalize_device_name(payload.get("label_name")):
                continue
            override = self._normalize_device_name(self._legacy_name_overrides.get(device_id))
            if not override:
                continue
            door_label = self._normalize_device_name(payload.get("door_label"))
            if door_label:
                payload["label_name"] = override
                override = self._compose_lock_name(door_label, override)
            current_name = self._normalize_device_name(payload.get("name"))
            if (
                override
                and (
                    not current_name
                    or current_name.casefold() != override.casefold()
                )
            ):
                payload["name"] = override

    def _apply_legacy_name_overrides_to_current(self) -> None:
        yale = self.current_state.get("devices", {}).get("locks", {})
        if not isinstance(yale, dict):
            return
        for device_id, payload in yale.items():
            if not isinstance(payload, dict):
                continue
            if self._normalize_device_name(payload.get("label_name")):
                continue
            override = self._normalize_device_name(self._legacy_name_overrides.get(device_id))
            if not override:
                continue
            door_label = self._normalize_device_name(payload.get("door_label"))
            if door_label:
                payload["label_name"] = override
                override = self._compose_lock_name(door_label, override)
            current_name = self._normalize_device_name(payload.get("name"))
            if (
                override
                and (
                    not current_name
                    or current_name.casefold() != override.casefold()
                )
            ):
                payload["name"] = override

    def _extract_legacy_device_names(self, payload: dict) -> dict[str, str]:
        if not isinstance(payload, dict):
            return {}
        results: dict[str, str] = {}
        serial_map = self._serial_map_from_traits()
        self._scan_legacy_value(payload, None, None, None, serial_map, results)
        return results

    def _scan_legacy_value(
        self,
        value,
        key_hint: str | None,
        device_id_hint: str | None,
        serial_hint: str | None,
        serial_map: dict[str, str],
        results: dict[str, str],
    ) -> None:
        if isinstance(value, dict):
            explicit_device_id = self._extract_device_id(value, key_hint)
            explicit_serial = self._extract_serial(value, key_hint)
            device_id = explicit_device_id or device_id_hint
            serial = explicit_serial or serial_hint
            has_explicit_device_ref = bool(
                explicit_device_id
                or explicit_serial
                or (
                    isinstance(key_hint, str)
                    and key_hint.startswith("DEVICE_")
                )
            )
            name = self._extract_name(value, allow_fallback=has_explicit_device_ref)
            if name and has_explicit_device_ref:
                if isinstance(device_id, str) and device_id.startswith("DEVICE_"):
                    results[device_id] = name
                elif serial and serial in serial_map:
                    results[serial_map[serial]] = name
            for child_key, child_value in value.items():
                next_hint = child_key if isinstance(child_key, str) else None
                self._scan_legacy_value(
                    child_value,
                    next_hint,
                    device_id,
                    serial,
                    serial_map,
                    results,
                )
            return
        if isinstance(value, list):
            for entry in value:
                self._scan_legacy_value(
                    entry,
                    key_hint,
                    device_id_hint,
                    serial_hint,
                    serial_map,
                    results,
                )

    def _extract_device_id(self, node: dict, key_hint: str | None) -> str | None:
        for key in ("device_id", "deviceId", "deviceID", "device"):
            val = node.get(key)
            candidate = self._extract_value_string(val)
            if isinstance(candidate, str) and "DEVICE_" in candidate:
                return candidate.split()[0]
        if isinstance(key_hint, str):
            if key_hint.startswith("DEVICE_"):
                return key_hint
            if "DEVICE_" in key_hint:
                idx = key_hint.find("DEVICE_")
                return key_hint[idx:].split(".")[0]
        return None

    def _extract_serial(self, node: dict, key_hint: str | None) -> str | None:
        for key in ("serial_number", "serialNumber", "serial", "sn"):
            val = node.get(key)
            candidate = self._extract_value_string(val)
            if isinstance(candidate, str):
                return candidate
        if isinstance(key_hint, str):
            hint = key_hint.strip()
            if hint.lower().startswith("device.") and "." in hint:
                return hint.split(".", 1)[1]
        return None

    def _extract_name(self, node: dict, *, allow_fallback: bool = False) -> str | None:
        primary_keys = ("name", "device_name", "deviceName")
        fallback_keys = ("label", "description") if allow_fallback else ()
        for key in (*primary_keys, *fallback_keys):
            val = node.get(key)
            name = self._normalize_device_name(val)
            if name:
                return name
            if isinstance(val, dict):
                nested = self._normalize_device_name(val.get("value"))
                if nested:
                    return nested
                for nested_key in (*primary_keys, *fallback_keys):
                    nested = self._normalize_device_name(val.get(nested_key))
                    if nested:
                        return nested
                nested = self._extract_name(val, allow_fallback=allow_fallback)
                if nested:
                    return nested
        return None

    @staticmethod
    def _extract_value_string(value) -> str | None:
        if isinstance(value, str):
            return value
        if isinstance(value, dict):
            for key in ("value", "device_id", "deviceId", "resource_id", "resourceId", "id"):
                nested = value.get(key)
                if isinstance(nested, str):
                    return nested
        return None

    def _serial_map_from_traits(self) -> dict[str, str]:
        serial_map: dict[str, str] = {}
        all_traits = self.current_state.get("all_traits", {}) or {}
        for key, info in all_traits.items():
            if not isinstance(info, dict):
                continue
            if "DeviceIdentityTrait" not in str(key):
                continue
            data = info.get("data")
            if not isinstance(data, dict):
                continue
            serial = data.get("serial_number")
            if not isinstance(serial, str) or not serial:
                continue
            device_id = info.get("object_id")
            if isinstance(device_id, str) and device_id.startswith("DEVICE_"):
                serial_map[serial] = device_id
        return serial_map

    @staticmethod
    def _normalize_device_name(name):
        if not isinstance(name, str):
            return None
        value = name.strip()
        if not value:
            return None
        if value.lower() == "undefined":
            return None
        return value

    def _compose_lock_name(self, door_label: str | None, label_name: str | None) -> str | None:
        door = self._normalize_device_name(door_label)
        if door:
            return door
        label = self._normalize_device_name(label_name)
        if label:
            return label
        return "Lock"

    def get_device_metadata(self, device_id):
        lock_data = self.current_state["devices"]["locks"].get(device_id, {})
        name = self._normalize_device_name(lock_data.get("name"))
        metadata = {
            "serial_number": lock_data.get("serial_number", device_id),
            "firmware_revision": lock_data.get("firmware_revision", "unknown"),
            "name": name,
            "structure_id": self._structure_id if self._structure_id else "unknown",
        }
        
        # Try to get metadata from trait data first (most accurate).
        # Some payloads prefix type_url with "type.googleapis.com/".
        all_traits = self.current_state.get("all_traits", {}) or {}
        device_identity_key = f"{device_id}:weave.trait.description.DeviceIdentityTrait"
        trait_info = all_traits.get(device_identity_key)
        if not trait_info:
            device_identity_key = f"{device_id}:type.googleapis.com/weave.trait.description.DeviceIdentityTrait"
            trait_info = all_traits.get(device_identity_key)
        if not trait_info:
            for candidate in all_traits.values():
                if not isinstance(candidate, dict):
                    continue
                if candidate.get("object_id") != device_id:
                    continue
                type_url = candidate.get("type_url") or ""
                if type_url.endswith("weave.trait.description.DeviceIdentityTrait"):
                    trait_info = candidate
                    break
        if trait_info and trait_info.get("decoded") and trait_info.get("data"):
            trait_data = trait_info["data"]
            if trait_data.get("serial_number"):
                metadata["serial_number"] = trait_data["serial_number"]
            if trait_data.get("firmware_version"):
                metadata["firmware_revision"] = trait_data["firmware_version"]

        label_trait_info = None
        label_trait_key = f"{device_id}:weave.trait.description.LabelSettingsTrait"
        label_trait_info = all_traits.get(label_trait_key)
        if not label_trait_info:
            label_trait_key = f"{device_id}:type.googleapis.com/weave.trait.description.LabelSettingsTrait"
            label_trait_info = all_traits.get(label_trait_key)
        if not label_trait_info:
            for candidate in all_traits.values():
                if not isinstance(candidate, dict):
                    continue
                if candidate.get("object_id") != device_id:
                    continue
                type_url = candidate.get("type_url") or ""
                if type_url.endswith("weave.trait.description.LabelSettingsTrait"):
                    label_trait_info = candidate
                    break
        if label_trait_info and label_trait_info.get("data"):
            label = self._normalize_device_name(label_trait_info["data"].get("label"))
            if label:
                metadata["name"] = label
        
        # Fallback to auth_data if trait data not available
        if "devices" in self.auth_data:
            for dev in self.auth_data.get("devices", []):
                if dev.get("device_id") == device_id:
                    if metadata["serial_number"] == device_id:  # Only update if not set from traits
                        metadata["serial_number"] = dev.get("serial_number", device_id)
                    if metadata["firmware_revision"] == "unknown":  # Only update if not set from traits
                        metadata["firmware_revision"] = dev.get("firmware_revision", "unknown")
                    candidate_name = self._normalize_device_name(dev.get("name"))
                    if candidate_name and not metadata.get("name"):
                        metadata["name"] = candidate_name
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

        # 1) BatchUpdateStateResponse
        try:
            resp = v1_pb2.BatchUpdateStateResponse()
            resp.ParseFromString(response_data)
            if resp.ListFields():
                saw_trait_status = False
                for op_group in resp.batchUpdateStateResponse:
                    for operation in op_group.traitOperations:
                        saw_trait_status = True
                        status = getattr(operation, "status", None)
                        if status and getattr(status, "code", 0) not in (0, None):
                            return int(status.code), self._status_message_with_details(status)
                if saw_trait_status:
                    return 0, None
                status = getattr(resp, "status", None)
                if status and getattr(status, "code", 0) not in (0, None):
                    return int(status.code), self._status_message_with_details(status)
                return 0, None
        except Exception:
            pass

        # 2) SendCommandResponse
        try:
            resp = v1_pb2.SendCommandResponse()
            resp.ParseFromString(response_data)
            if resp.ListFields():
                saw_trait_status = False
                for op_group in getattr(resp, "sendCommandResponse", []):
                    for operation in getattr(op_group, "traitOperations", []):
                        saw_trait_status = True
                        status = getattr(operation, "status", None)
                        if status and getattr(status, "code", 0) not in (0, None):
                            return int(status.code), self._status_message_with_details(status)
                status = getattr(resp, "status", None)
                if status and getattr(status, "code", 0) not in (0, None):
                    return int(status.code), self._status_message_with_details(status)
                if saw_trait_status:
                    return 0, None
                return 0, None
        except Exception:
            pass

        return None, None

    @staticmethod
    def _status_message_with_details(status) -> str | None:
        if not status:
            return None
        base_message = getattr(status, "message", None)
        details_text: list[str] = []
        for detail in getattr(status, "details", []):
            type_url = getattr(detail, "type_url", "") or ""
            raw_value = getattr(detail, "value", b"")
            if not raw_value:
                continue
            try:
                if type_url.endswith("/nestlabs.gateway.v1.WeaveStatusReport"):
                    report = v1_pb2.WeaveStatusReport()
                    report.ParseFromString(raw_value)
                    details_text.append(
                        f"WeaveStatusReport(profile_id={report.profileId}, status_code={report.statusCode})"
                    )
                    continue
                if type_url.endswith(
                    "/weave.trait.security.UserPincodesSettingsTrait.SetUserPincodeResponse"
                ):
                    response = (
                        weave_security_pb2.UserPincodesSettingsTrait.SetUserPincodeResponse()
                    )
                    response.ParseFromString(raw_value)
                    status_code = int(getattr(response, "status", 0) or 0)
                    try:
                        status_name = (
                            weave_security_pb2.UserPincodesSettingsTrait.PincodeErrorCodes.Name(
                                status_code
                            )
                        )
                    except Exception:
                        status_name = str(status_code)
                    details_text.append(f"SetUserPincodeResponse(status={status_name})")
                    continue
            except Exception:
                continue

        if details_text:
            suffix = "; ".join(details_text)
            if base_message:
                return f"{base_message} ({suffix})"
            return suffix
        return base_message

    @staticmethod
    def _format_command_error_message(
        status_code: int | None,
        status_msg: str | None,
        command_type_url: str | None,
    ) -> str:
        msg = (status_msg or "").strip()
        if msg:
            return msg
        if command_type_url and command_type_url.endswith("SetUserPincodeRequest"):
            if status_code in (GRPC_CODE_INTERNAL, GRPC_CODE_INVALID_ARGUMENT):
                return "Passcode update rejected by Nest for this target."
        return "Unknown error"

    def _log_batch_update_details(self, response_data: bytes) -> None:
        if not response_data:
            return
        try:
            resp = v1_pb2.BatchUpdateStateResponse()
            resp.ParseFromString(response_data)
        except Exception:
            return
        if not resp.ListFields():
            return
        for op_group in resp.batchUpdateStateResponse:
            for operation in op_group.traitOperations:
                trait_req = getattr(operation, "traitRequest", None)
                status = getattr(operation, "status", None)
                if not trait_req or not status:
                    continue
                _LOGGER.debug(
                    "BatchUpdateState trait=%s resource=%s status=%s msg=%s",
                    getattr(trait_req, "traitLabel", None),
                    getattr(trait_req, "resourceId", None),
                    getattr(status, "code", None),
                    getattr(status, "message", None),
                )

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
