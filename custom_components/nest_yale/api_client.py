#!/usr/bin/env python3
import os
import logging
import uuid
import aiohttp
import asyncio
import jwt
from aiohttp import ClientSession
from google.protobuf import any_pb2
from .auth import NestAuthenticator
from .protobuf_handler import NestProtobufHandler
from .protobuf_manager import read_protobuf_file
from .const import (
    API_RETRY_DELAY_SECONDS,
    URL_PROTOBUF,
    ENDPOINT_OBSERVE,
    ENDPOINT_SENDCOMMAND,
    PRODUCTION_HOSTNAME,
    USER_AGENT_STRING,
)
from .proto import root_pb2

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
                raise Exception(f"Stream failed with status {response.status}")
            async for chunk in response.content.iter_chunked(1024):
                _LOGGER.debug(f"Stream chunk received (length={len(chunk)}): {chunk[:100].hex()}...")
                yield chunk

    async def post(self, api_url, headers, data):
        _LOGGER.debug(f"Sending POST to {api_url}, headers={headers}, data={data.hex()}")
        async with self.session.post(api_url, headers=headers, data=data) as response:
            response_data = await response.read()
            _LOGGER.debug(f"Post response status: {response.status}, response: {response_data.hex()}")
            if response.status != 200:
                _LOGGER.error(f"HTTP {response.status}: {await response.text()}")
                raise Exception(f"Post failed with status {response.status}")
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
        _LOGGER.debug("NestAPIClient initialized with session")

    @property
    def user_id(self):
        return self._user_id

    @property
    def structure_id(self):
        return self._structure_id

    @classmethod
    async def create(cls, hass, issue_token, api_key, cookies, user_id=None):
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
        except Exception as e:
            _LOGGER.error(f"Authentication failed: {e}", exc_info=True)
            await self.close()
            raise

    async def refresh_state(self):
        if not self.access_token:
            await self.authenticate()

        headers = {
            "Authorization": f"Basic {self.access_token}",
            "Content-Type": "application/x-protobuf",
            "User-Agent": USER_AGENT_STRING,
            "X-Accept-Response-Streaming": "true",
            "Accept": "application/x-protobuf",
            "x-nl-webapp-version": "NlAppSDKVersion/8.15.0 NlSchemaVersion/2.1.20-87-gce5742894",
            "referer": "https://home.nest.com/",
            "origin": "https://home.nest.com",
        }

        api_url = f"{URL_PROTOBUF.format(grpc_hostname=PRODUCTION_HOSTNAME['grpc_hostname'])}{ENDPOINT_OBSERVE}"
        observe_data = await read_protobuf_file(os.path.join(os.path.dirname(__file__), "proto", "ObserveTraits.bin"))

        _LOGGER.debug("Starting refresh_state with URL: %s", api_url)
        retries = 0
        max_retries = 3
        while retries < max_retries:
            try:
                async with self.session.post(api_url, headers=headers, data=observe_data) as response:
                    if response.status != 200:
                        _LOGGER.error(f"HTTP {response.status}: {await response.text()}")
                        return {}
                    async for chunk in response.content.iter_chunked(1024):
                        locks_data = await self.protobuf_handler._process_message(chunk)
                        if "yale" in locks_data:
                            self.current_state["devices"]["locks"] = locks_data["yale"]
                            if locks_data.get("user_id"):
                                old_user_id = self._user_id
                                self._user_id = locks_data["user_id"]
                                self.current_state["user_id"] = self._user_id
                                if old_user_id != self._user_id:
                                    _LOGGER.info(f"Updated user_id from stream: {self._user_id} (was {old_user_id})")
                            if locks_data.get("structure_id"):
                                old_structure_id = self._structure_id
                                self._structure_id = locks_data["structure_id"]
                                self.current_state["structure_id"] = self._structure_id
                                if old_structure_id != self._structure_id:
                                    _LOGGER.info(f"Updated structure_id from stream: {self._structure_id} (was {old_structure_id})")
                            return locks_data["yale"]
                return {}
            except Exception as e:
                retries += 1
                _LOGGER.error(f"Refresh state failed (attempt {retries}/{max_retries}): {e}", exc_info=True)
                if retries < max_retries:
                    await asyncio.sleep(API_RETRY_DELAY_SECONDS)
                else:
                    _LOGGER.error("Max retries reached, giving up on refresh_state")
                    return {}

    async def observe(self):
        if not self.access_token or not self.connection.connected:
            await self.authenticate()

        headers = {
            "Authorization": f"Basic {self.access_token}",
            "Content-Type": "application/x-protobuf",
            "User-Agent": USER_AGENT_STRING,
            "X-Accept-Response-Streaming": "true",
            "Accept": "application/x-protobuf",
            "x-nl-webapp-version": "NlAppSDKVersion/8.15.0 NlSchemaVersion/2.1.20-87-gce5742894",
            "referer": "https://home.nest.com/",
            "origin": "https://home.nest.com",
        }

        api_url = f"{URL_PROTOBUF.format(grpc_hostname=PRODUCTION_HOSTNAME['grpc_hostname'])}{ENDPOINT_OBSERVE}"
        observe_data = await read_protobuf_file(os.path.join(os.path.dirname(__file__), "proto", "ObserveTraits.bin"))

        _LOGGER.debug("Starting observe stream with URL: %s", api_url)
        retries = 0
        max_retries = 3
        while retries < max_retries:
            try:
                async for chunk in self.connection.stream(api_url, headers, observe_data):
                    locks_data = await self.protobuf_handler._process_message(chunk)
                    if "yale" in locks_data:
                        if locks_data.get("user_id"):
                            old_user_id = self._user_id
                            self._user_id = locks_data["user_id"]
                            self.current_state["user_id"] = self._user_id
                            if old_user_id != self._user_id:
                                _LOGGER.info(f"Updated user_id from stream: {self._user_id} (was {old_user_id})")
                        if locks_data.get("structure_id"):
                            old_structure_id = self._structure_id
                            self._structure_id = locks_data["structure_id"]
                            self.current_state["structure_id"] = self._structure_id
                            if old_structure_id != self._structure_id:
                                _LOGGER.info(f"Updated structure_id from stream: {self._structure_id} (was {old_structure_id})")
                    yield locks_data.get("yale", {})
                break
            except Exception as e:
                retries += 1
                _LOGGER.error(f"Error in observe stream (attempt {retries}/{max_retries}): {e}", exc_info=True)
                self.connection.connected = False
                if retries < max_retries:
                    await asyncio.sleep(API_RETRY_DELAY_SECONDS)
                else:
                    raise

    async def send_command(self, command, device_id):
        if not self.access_token:
            await self.authenticate()

        headers = {
            "Authorization": f"Basic {self.access_token}",
            "Content-Type": "application/x-protobuf",
            "User-Agent": USER_AGENT_STRING,
            "X-Accept-Content-Transfer-Encoding": "binary",
            "X-Accept-Response-Streaming": "true",
            "x-nl-webapp-version": "NlAppSDKVersion/8.15.0 NlSchemaVersion/2.1.20-87-gce5742894",
            "referer": "https://home.nest.com/",
            "origin": "https://home.nest.com",
            "X-Nest-Structure-Id": self._structure_id if self._structure_id else "unknown",
            "request-id": str(uuid.uuid4()),
        }

        api_url = f"{URL_PROTOBUF.format(grpc_hostname=PRODUCTION_HOSTNAME['grpc_hostname'])}{ENDPOINT_SENDCOMMAND}"

        cmd_any = any_pb2.Any()
        cmd_any.type_url = command["command"]["type_url"]
        cmd_any.value = command["command"]["value"] if isinstance(command["command"]["value"], bytes) else command["command"]["value"].SerializeToString()

        request = root_pb2.ResourceCommandRequest()
        request.resourceCommands.add().command.CopyFrom(cmd_any)
        request.resourceRequest.resourceId = device_id
        request.resourceRequest.requestId = str(uuid.uuid4())
        encoded_data = request.SerializeToString()

        _LOGGER.debug(f"Sending command to {device_id}: {command}, encoded: {encoded_data.hex()}, structure_id: {self._structure_id}")
        try:
            raw_data = await self.connection.post(api_url, headers, encoded_data)
            await asyncio.sleep(2)
            await self.refresh_state()
            return raw_data
        except Exception as e:
            _LOGGER.error(f"Failed to send command to {device_id}: {e}", exc_info=True)
            raise

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