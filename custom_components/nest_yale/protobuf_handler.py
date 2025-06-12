#!/usr/bin/env python3
import os
import logging
import uuid
import asyncio
import aiofiles
from google.protobuf.message import DecodeError
from google.protobuf.any_pb2 import Any
from .proto import root_pb2, weave_security_pb2
from .protobuf_manager import read_protobuf_file
from .const import (
    USER_AGENT_STRING,
    URL_PROTOBUF,
    ENDPOINT_OBSERVE,
    PRODUCTION_HOSTNAME,
)

_LOGGER = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s")

MAX_BUFFER_SIZE = 4194304  # 4MB
LOG_PAYLOAD_TO_FILE = True
RETRY_DELAY_SECONDS = 10
STREAM_TIMEOUT_SECONDS = 600  # 10min
PING_INTERVAL_SECONDS = 60
CATALOG_THRESHOLD = 20000  # 20KB

class NestProtobufHandler:
    def __init__(self):
        self.buffer = bytearray()
        self.pending_length = None
        self.stream_body = root_pb2.StreamBody()

    def _decode_varint(self, buffer, pos):
        value = 0
        shift = 0
        start = pos
        max_bytes = 10
        while pos < len(buffer) and shift < 64:
            byte = buffer[pos]
            value |= (byte & 0x7F) << shift
            pos += 1
            shift += 7
            if not (byte & 0x80):
                _LOGGER.debug(f"Decoded varint: {value} from position {start} using {pos - start} bytes")
                return value, pos
            if pos - start >= max_bytes:
                _LOGGER.error(f"Varint too long at pos {start}")
                return None, pos
        _LOGGER.error(f"Incomplete varint at pos {start}")
        return None, pos

    async def _process_message(self, message):
        _LOGGER.debug(f"Raw chunk (length={len(message)}): {message.hex()}")

        if not message:
            _LOGGER.error("Empty protobuf message received.")
            return {"yale": {}, "user_id": None, "structure_id": None}

        locks_data = {"yale": {}, "user_id": None, "structure_id": None}

        try:
            self.stream_body.Clear()
            self.stream_body.ParseFromString(message)
            _LOGGER.debug(f"Parsed StreamBody: {self.stream_body}")

            for msg in self.stream_body.message:
                for get_op in msg.get:
                    obj_id = get_op.object.id if get_op.object.id else None
                    obj_key = get_op.object.key if get_op.object.key else "unknown"

                    type_url = getattr(get_op.data.property, "type_url", None)
                    if not type_url and 7 in get_op:
                        type_url = "weave.trait.security.BoltLockTrait"

                    _LOGGER.debug(f"Extracting `{type_url}` for `{obj_id}` with key `{obj_key}`")

                    if "BoltLockTrait" in type_url and obj_id:
                        bolt_lock = weave_security_pb2.BoltLockTrait()
                        try:
                            unpacked = get_op.data.property.Unpack(bolt_lock)
                            if not unpacked:
                                _LOGGER.warning(f"Unpacking failed for {obj_id}, skipping")
                                continue

                            locks_data["yale"][obj_id] = {
                                "device_id": obj_id,
                                "bolt_locked": bolt_lock.lockedState == weave_security_pb2.BoltLockTrait.BOLT_LOCKED_STATE_LOCKED,
                                "bolt_moving": bolt_lock.actuatorState not in [weave_security_pb2.BoltLockTrait.BOLT_ACTUATOR_STATE_OK],
                                "actuator_state": bolt_lock.actuatorState
                            }
                            if bolt_lock.boltLockActor.originator.resourceId:
                                locks_data["user_id"] = bolt_lock.boltLockActor.originator.resourceId
                            _LOGGER.debug(f"Parsed BoltLockTrait for {obj_id}: {locks_data['yale'][obj_id]}, user_id={locks_data['user_id']}")

                        except DecodeError as e:
                            _LOGGER.error(f"Failed to decode BoltLockTrait for {obj_id}: {e}")
                            continue
                        except Exception as e:
                            _LOGGER.error(f"Unexpected error unpacking BoltLockTrait for {obj_id}: {e}")
                            continue

                    elif "structure_info" in type_url and obj_id:
                        try:
                            # Log raw structure_info for debugging
                            _LOGGER.debug(f"Raw structure_info data for {obj_id}: {get_op.data.property}")
                            # Extract legacyId or use obj_id as fallback
                            structure_id = None
                            if hasattr(get_op.data.property, "value"):
                                value = get_op.data.property.value
                                if isinstance(value, dict) and "legacyId" in value:
                                    structure_id = value["legacyId"].split('.')[1]
                                elif hasattr(value, "legacyId"):
                                    structure_id = value.legacyId.split('.')[1]
                            if not structure_id:
                                structure_id = obj_id.replace("STRUCTURE_", "")
                            locks_data["structure_id"] = structure_id
                            _LOGGER.debug(f"Parsed structure_info for {obj_id}: structure_id={structure_id}")
                        except Exception as e:
                            _LOGGER.error(f"Failed to parse structure_info for {obj_id}: {e}")

            _LOGGER.debug(f"Final lock data: {locks_data}")
            return locks_data

        except DecodeError as e:
            _LOGGER.error(f"DecodeError in StreamBody: {e}")
            return locks_data
        except Exception as e:
            _LOGGER.error(f"Unexpected error processing message: {e}", exc_info=True)
            return locks_data

    async def stream(self, api_url, headers, observe_data, connection):
        attempt = 0
        while True:
            attempt += 1
            _LOGGER.info(f"Starting stream attempt {attempt} with headers: {headers}")
            self.buffer = bytearray()
            self.pending_length = None
            try:
                async for data in connection.stream(api_url, headers, observe_data):
                    if not isinstance(data, bytes):
                        _LOGGER.error(f"Received non-bytes data: {data}")
                        continue

                    if self.pending_length is None:
                        self.pending_length, offset = self._decode_varint(data, 0)
                        if self.pending_length is None or offset >= len(data):
                            _LOGGER.warning(f"Invalid varint in chunk: {data.hex()[:200]}... skipping")
                            continue
                        self.buffer.extend(data[offset:])
                    else:
                        self.buffer.extend(data)

                    _LOGGER.debug(f"Buffer size: {len(self.buffer)} bytes, pending_length: {self.pending_length}")

                    while self.pending_length and len(self.buffer) >= self.pending_length:
                        message = self.buffer[:self.pending_length]
                        self.buffer = self.buffer[self.pending_length:]
                        locks_data = await self._process_message(message)
                        self.pending_length = None if len(self.buffer) < 5 else self._decode_varint(self.buffer, 0)[0]

                        if locks_data.get("yale"):
                            yield locks_data
                            continue

                    if len(self.buffer) >= CATALOG_THRESHOLD and self.pending_length:
                        message = self.buffer[:self.pending_length]
                        self.buffer = self.buffer[self.pending_length:]
                        locks_data = await self._process_message(message)
                        self.pending_length = None if len(self.buffer) < 5 else self._decode_varint(self.buffer, 0)[0]

                        if locks_data.get("yale"):
                            yield locks_data
                            continue

                await asyncio.sleep(PING_INTERVAL_SECONDS / 1000)

            except asyncio.TimeoutError:
                _LOGGER.warning("Stream timeout, retrying...")
                yield {"yale": {}, "user_id": None, "structure_id": None}
            except Exception as e:
                _LOGGER.error(f"Stream error: {e}", exc_info=True)

            _LOGGER.info(f"Retrying stream in {RETRY_DELAY_SECONDS} seconds")
            await asyncio.sleep(RETRY_DELAY_SECONDS)
            yield None

    async def refresh_state(self, connection, access_token):
        headers = {
            "Authorization": f"Basic {access_token}",
            "Content-Type": "application/x-protobuf",
            "User-Agent": USER_AGENT_STRING,
            "X-Accept-Response-Streaming": "true",
            "Accept": "application/x-protobuf",
        }

        api_url = f"{URL_PROTOBUF.format(grpc_hostname=PRODUCTION_HOSTNAME['grpc_hostname'])}{ENDPOINT_OBSERVE}"
        observe_data = await read_protobuf_file(os.path.join(os.path.dirname(__file__), "proto", "ObserveTraits.bin"))

        try:
            async with connection.session.post(api_url, headers=headers, data=observe_data) as response:
                if response.status != 200:
                    _LOGGER.error(f"HTTP {response.status}: {await response.text()}")
                    return {}
                async for chunk in response.content.iter_chunked(1024):
                    locks_data = await self._process_message(chunk)
                    if locks_data.get("yale"):
                        return locks_data
        except Exception as e:
            _LOGGER.error(f"Refresh state error: {e}", exc_info=True)
        return {"yale": {}, "user_id": None, "structure_id": None}