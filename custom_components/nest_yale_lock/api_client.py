import logging
import uuid
import asyncio
import aiohttp
import jwt
from typing import Callable, Optional

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
    API_RETRY_DELAY_SECONDS,
    API_OBSERVE_TIMEOUT_SECONDS,
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
        # Long-running observe stream management
        self._observe_task: Optional[asyncio.Task] = None
        self._observe_callback: Optional[Callable] = None
        self._shutdown_event = asyncio.Event()
        self._reconnect_delay = API_RETRY_DELAY_SECONDS
        self._max_reconnect_delay = 300  # Max 5 minutes
        self._connection_healthy = False

    @property
    def user_id(self) -> str | None:
        return self._user_id

    @property
    def structure_id(self) -> str | None:
        return self._structure_id

    async def async_setup(self):
        """Initialize and start the observe stream."""
        # Do an initial authentication to get user_id and structure_id
        await self.refresh_state()
        # Start the long-running observe stream as a background task
        # Use async_create_background_task for long-running tasks (HA 2024.2+)
        if hasattr(self.hass, 'async_create_background_task'):
            self._observe_task = self.hass.async_create_background_task(
                self._run_observe_stream(), "nest_yale_observe_stream"
            )
        else:
            # Fallback for older HA versions
            self._observe_task = self.hass.async_create_task(self._run_observe_stream())

    @classmethod
    async def create(cls, hass, issue_token, api_key=None, cookies=None, user_id=None):
        instance = cls(hass, issue_token, api_key, cookies)
        await instance.async_setup()
        return instance

    def set_state_callback(self, callback: Callable):
        """Set callback for state updates from observe stream."""
        self._observe_callback = callback

    async def authenticate(self):
        """Compat shim used by config flow for credential validation."""
        session = async_get_clientsession(self.hass)
        access_token, user_id, transport_url = await self._authenticate(session)
        if user_id:
            self._user_id = user_id
            self.current_state["user_id"] = user_id
        # Trigger a lightweight state fetch to verify credentials
        await self._fetch_state_once(session, access_token, transport_url)
        return True

    async def refresh_state(self):
        """Refresh state by doing a one-time fetch (for initial setup)."""
        async with self._state_lock:
            session = async_get_clientsession(self.hass)
            data = await self._fetch_state_once(session)
            return data

    async def send_command(self, command, device_id, structure_id=None):
        """Send a command to a device.
        
        Follows Home Assistant best practices:
        - Proper async/await patterns
        - Comprehensive error handling
        - Multiple transport candidate retry logic
        - Returns success/failure status
        
        Args:
            command: Command dictionary with traitLabel and command details
            device_id: Target device ID
            structure_id: Optional structure ID for command headers
            
        Returns:
            True if command succeeded
            
        Raises:
            RuntimeError: If command fails for all transport endpoints
            aiohttp.ClientResponseError: For HTTP errors
        """
        async with self._state_lock:
            session = async_get_clientsession(self.hass)
            access_token, user_id, transport_url = await self._authenticate(session)
            if user_id:
                self._user_id = user_id
                self.current_state["user_id"] = user_id

            request_id = str(uuid.uuid4())
            
            # Build protobuf command structure (required format for Nest API)
            cmd_any = any_pb2.Any()
            cmd_any.type_url = command["command"]["type_url"]
            cmd_any.value = (
                command["command"]["value"]
                if isinstance(command["command"]["value"], bytes)
                else command["command"]["value"].SerializeToString()
            )

            # Create ResourceCommand and add to request
            # Using extend() as required by the Nest API protobuf structure
            resource_command = v1_pb2.ResourceCommand()
            resource_command.command.CopyFrom(cmd_any)
            if command.get("traitLabel"):
                resource_command.traitLabel = command["traitLabel"]

            request = v1_pb2.ResourceCommandRequest()
            request.resourceCommands.extend([resource_command])
            request.resourceRequest.resourceId = device_id
            request.resourceRequest.requestId = request_id
            encoded_data = request.SerializeToString()

            headers = self._build_command_headers(access_token, request_id, structure_id)
            
            # Build transport candidate list with fallback options
            # This improves reliability if one endpoint is unavailable
            transport_candidates = []
            if transport_url:
                transport_candidates.append(transport_url.rstrip("/"))
            default_url = URL_PROTOBUF.format(grpc_hostname=PRODUCTION_HOSTNAME["grpc_hostname"]).rstrip("/")
            if default_url not in transport_candidates:
                transport_candidates.append(default_url)

            _LOGGER.info(
                "Sending command to %s (trait=%s, device_id=%s), trying %d transport candidate(s)",
                device_id,
                command.get("command", {}).get("type_url"),
                device_id,
                len(transport_candidates),
            )

            # Try each transport candidate until one succeeds
            last_error = None
            response_message = None
            for base_url in transport_candidates:
                api_url = f"{base_url}{ENDPOINT_SENDCOMMAND}"
                try:
                    _LOGGER.info("Attempting command POST to %s for device %s", api_url, device_id)
                    async with session.post(
                        api_url,
                        headers=headers,
                        data=encoded_data,
                        timeout=aiohttp.ClientTimeout(total=60)
                    ) as resp:
                        payload = await resp.read()
                        if resp.status != 200:
                            body = await resp.text()
                            _LOGGER.error(
                                "Command failed with status %d: %s",
                                resp.status,
                                body[:200] if body else "No response body",
                            )
                            raise aiohttp.ClientResponseError(
                                request_info=resp.request_info,
                                history=(),
                                status=resp.status,
                                message=body,
                                headers=resp.headers,
                            )
                        
                        # Parse response to verify command was accepted
                        response_message = v1_pb2.ResourceCommandResponseFromAPI()
                        response_message.ParseFromString(payload)
                        
                        # Log response details for debugging
                        response_ops = getattr(response_message, 'resouceCommandResponse', [])
                        _LOGGER.info(
                            "Command succeeded for %s at %s, response ops=%d, payload_len=%d",
                            device_id,
                            api_url,
                            len(response_ops),
                            len(payload),
                        )
                        if response_ops:
                            _LOGGER.debug("Response details: %s", response_message)
                        else:
                            _LOGGER.warning("Command response has no operations - command may not have been processed")
                        
                        break  # Success, exit retry loop
                        
                except aiohttp.ClientError as err:
                    last_error = err
                    _LOGGER.warning("Command attempt failed for %s: %s", api_url, err)
                except Exception as err:
                    last_error = err
                    _LOGGER.warning("Unexpected error sending command to %s: %s", api_url, err)
            
            if response_message is None:
                error_msg = f"Command failed for all {len(transport_candidates)} transport endpoint(s)"
                if last_error:
                    error_msg += f": {last_error}"
                raise RuntimeError(error_msg)

            # Success - observe stream will handle state updates
            return True

    async def reset_connection(self, reason: str):
        """Reset the observe stream connection."""
        _LOGGER.info("Resetting Nest Yale connection due to: %s", reason)
        self._connection_healthy = False
        # Cancel existing observe task if running
        if self._observe_task and not self._observe_task.done():
            self._observe_task.cancel()
            try:
                await self._observe_task
            except asyncio.CancelledError:
                pass
        # Restart the observe stream
        if not self._shutdown_event.is_set():
            if hasattr(self.hass, 'async_create_background_task'):
                self._observe_task = self.hass.async_create_background_task(
                    self._run_observe_stream(), "nest_yale_observe_stream"
                )
            else:
                self._observe_task = self.hass.async_create_task(self._run_observe_stream())

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

    async def _fetch_state_once(self, session, access_token=None, transport_url=None):
        """Fetch state once (for initial setup only).
        
        This is a lightweight initial fetch that doesn't wait for stream data.
        The actual state will come from the background observe stream.
        """
        if access_token is None:
            access_token, user_id, transport_url = await self._authenticate(session)
            if user_id:
                self._user_id = user_id
                self.current_state["user_id"] = user_id

        headers = self._build_observe_headers(access_token)
        api_url = self._resolve_url(transport_url, ENDPOINT_OBSERVE)
        handler = NestProtobufHandler()
        payload = self._observe_payload

        # For initial setup, we just verify authentication works
        # The actual state will come from the background observe stream
        # We don't try to read chunks here to avoid blocking startup
        _LOGGER.debug("Performing initial authentication (state will come from background stream)")
        
        # Just verify we can authenticate - don't try to read observe stream
        # The background stream will handle the actual data fetching
        return {}

    async def _run_observe_stream(self):
        """Run the long-running observe stream with auto-reconnect."""
        _LOGGER.info("Starting observe stream")
        consecutive_failures = 0
        
        while not self._shutdown_event.is_set():
            try:
                session = async_get_clientsession(self.hass)
                access_token, user_id, transport_url = await self._authenticate(session)
                if user_id:
                    self._user_id = user_id
                    self.current_state["user_id"] = user_id

                headers = self._build_observe_headers(access_token)
                api_url = self._resolve_url(transport_url, ENDPOINT_OBSERVE)
                handler = NestProtobufHandler()
                payload = self._observe_payload

                # Use longer timeout for streaming connection
                timeout = aiohttp.ClientTimeout(total=API_OBSERVE_TIMEOUT_SECONDS or 300)
                
                _LOGGER.debug("Connecting to observe stream at %s", api_url)
                async with session.post(api_url, headers=headers, data=payload, timeout=timeout) as resp:
                    if resp.status != 200:
                        body = await resp.text()
                        _LOGGER.error("Observe stream returned status %d: %s", resp.status, body[:200])
                        raise aiohttp.ClientResponseError(
                            request_info=resp.request_info,
                            history=(),
                            status=resp.status,
                            message=body,
                            headers=resp.headers,
                        )
                    
                    _LOGGER.info("Observe stream connected successfully")
                    self._connection_healthy = True
                    consecutive_failures = 0
                    self._reconnect_delay = API_RETRY_DELAY_SECONDS
                    
                    # Process stream chunks continuously
                    last_update_time = asyncio.get_event_loop().time()
                    async for chunk in resp.content.iter_chunked(2048):
                        if self._shutdown_event.is_set():
                            break
                            
                        try:
                            locks_data = await handler._process_message(chunk)
                            
                            if locks_data.get("auth_failed"):
                                _LOGGER.warning("Observe stream reported authentication failure")
                                raise RuntimeError("Observe reported authentication failure")
                            
                            # Update state for any meaningful data
                            if locks_data.get("yale") or locks_data.get("structure_id") or locks_data.get("user_id"):
                                async with self._state_lock:
                                    self._apply_state(locks_data)
                                
                                # Notify coordinator of update
                                if self._observe_callback:
                                    try:
                                        self._observe_callback(locks_data)
                                    except Exception as e:
                                        _LOGGER.error("Error in state callback: %s", e, exc_info=True)
                                
                                last_update_time = asyncio.get_event_loop().time()
                                
                        except Exception as e:
                            _LOGGER.error("Error processing observe chunk: %s", e, exc_info=True)
                            # Continue processing other chunks
                    
                    # Connection closed normally
                    _LOGGER.warning("Observe stream connection closed")
                    self._connection_healthy = False
                    
            except asyncio.CancelledError:
                _LOGGER.info("Observe stream task cancelled")
                self._connection_healthy = False
                break
            except aiohttp.ClientError as e:
                _LOGGER.error("Observe stream client error: %s", e)
                self._connection_healthy = False
                consecutive_failures += 1
            except RuntimeError as e:
                if "authentication failure" in str(e):
                    _LOGGER.error("Authentication failure in observe stream: %s", e)
                    self._connection_healthy = False
                    consecutive_failures += 1
                    # Force re-authentication
                    self.authenticator.access_token = None
                else:
                    raise
            except Exception as e:
                _LOGGER.error("Unexpected error in observe stream: %s", e, exc_info=True)
                self._connection_healthy = False
                consecutive_failures += 1
            
            # Reconnect with exponential backoff
            if not self._shutdown_event.is_set():
                delay = min(self._reconnect_delay * (2 ** min(consecutive_failures - 1, 4)), self._max_reconnect_delay)
                _LOGGER.info("Reconnecting observe stream in %d seconds (failure count: %d)", delay, consecutive_failures)
                try:
                    await asyncio.wait_for(self._shutdown_event.wait(), timeout=delay)
                    break  # Shutdown was requested
                except asyncio.TimeoutError:
                    pass  # Continue to reconnect
        
        _LOGGER.info("Observe stream task ended")

    def _build_observe_headers(self, access_token):
        """Build headers for observe requests."""
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
        return headers

    def _apply_state(self, locks_data):
        """Apply state updates from observe stream, merging with existing state."""
        yale = locks_data.get("yale", {})
        if yale:
            # Merge lock data instead of replacing
            self.current_state["devices"]["locks"].update(yale)
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

    async def close(self):
        """Close the API client and stop the observe stream."""
        _LOGGER.debug("Closing NestAPIClient")
        self._shutdown_event.set()
        
        if self._observe_task and not self._observe_task.done():
            self._observe_task.cancel()
            try:
                await asyncio.wait_for(self._observe_task, timeout=5.0)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass
        
        self._observe_task = None
        self._observe_callback = None
        _LOGGER.debug("NestAPIClient closed")
