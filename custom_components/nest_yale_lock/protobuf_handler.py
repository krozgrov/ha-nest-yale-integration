import logging
import asyncio
import os
from google.protobuf.message import DecodeError
from google.protobuf.any_pb2 import Any
from base64 import b64decode
import binascii

from .proto.weave.trait import security_pb2 as weave_security_pb2
from .proto.nest.trait import structure_pb2 as nest_structure_pb2
from .proto.nest import rpc_pb2 as rpc_pb2
from .protobuf_manager import read_protobuf_file
from .const import (
    USER_AGENT_STRING,
    URL_PROTOBUF,
    ENDPOINT_OBSERVE,
    PRODUCTION_HOSTNAME,
)

_LOGGER = logging.getLogger(__name__)

MAX_BUFFER_SIZE = 4194304  # 4MB
LOG_PAYLOAD_TO_FILE = True
RETRY_DELAY_SECONDS = 10
STREAM_TIMEOUT_SECONDS = 600  # 10min
PING_INTERVAL_SECONDS = 60
CATALOG_THRESHOLD = 20000  # 20KB


def _normalize_any_type(any_message: Any) -> Any:
    """Map legacy Nest type URLs onto googleapis prefix so Unpack succeeds."""
    if not isinstance(any_message, Any):
        return any_message
    type_url = any_message.type_url or ""
    if type_url.startswith("type.nestlabs.com/"):
        normalized = Any()
        normalized.value = any_message.value
        normalized.type_url = type_url.replace("type.nestlabs.com/", "type.googleapis.com/", 1)
        return normalized
    return any_message


class NestProtobufHandler:
    def __init__(self):
        self.buffer = bytearray()
        self.pending_length = None
        self.stream_body = rpc_pb2.StreamBody()

    def _decode_varint(self, buffer, pos):
        value = 0
        shift = 0
        start = pos
        max_bytes = 10
        while pos < len(buffer):
            byte = buffer[pos]
            value |= (byte & 0x7F) << shift
            pos += 1
            if not (byte & 0x80):
                _LOGGER.debug("Decoded varint: %s from position %s using %s bytes", value, start, pos - start)
                return value, pos
            shift += 7
            if shift >= 64 or pos - start >= max_bytes:
                _LOGGER.error("Varint too long at pos %s", start)
                return None, pos
        # Not enough bytes yet to decode the varint; wait for more data.
        _LOGGER.debug("Incomplete varint at pos %s; awaiting additional data", start)
        return None, start

    async def _ingest_chunk(self, payload):
        results = []

        if not payload:
            return results

        stripped = payload.strip()
        if stripped and all(b < 128 for b in stripped):
            try:
                decoded = b64decode(stripped, validate=True)
                if decoded:
                    payload = decoded
            except binascii.Error:
                pass

        self.buffer.extend(payload)

        while True:
            if self.pending_length is None:
                if len(self.buffer) >= 5 and self.buffer[0] in (0x00, 0x80):
                    frame_type = self.buffer[0]
                    frame_len = int.from_bytes(self.buffer[1:5], "big")
                    if len(self.buffer) < 5 + frame_len:
                        break
                    del self.buffer[:5]
                    if frame_type == 0x80:
                        del self.buffer[:frame_len]
                        continue
                    if frame_len == 0:
                        continue
                    self.pending_length = frame_len
                else:
                    length, offset = self._decode_varint(self.buffer, 0)
                    if length is None or offset > len(self.buffer):
                        break
                    del self.buffer[:offset]
                    if length == 0:
                        continue
                    self.pending_length = length

            if self.pending_length is None or len(self.buffer) < self.pending_length:
                break

            message = self.buffer[:self.pending_length]
            del self.buffer[:self.pending_length]
            self.pending_length = None
            locks_data = await self._process_message(message)
            if locks_data.get("yale"):
                results.append(locks_data)

        if (
            self.pending_length
            and len(self.buffer) >= self.pending_length
            and len(self.buffer) >= CATALOG_THRESHOLD
        ):
            message = self.buffer[:self.pending_length]
            del self.buffer[:self.pending_length]
            self.pending_length = None
            locks_data = await self._process_message(message)
            if locks_data.get("yale"):
                results.append(locks_data)

        return results

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

                    property_any = getattr(get_op.data, "property", None)
                    property_any = _normalize_any_type(property_any) if property_any else None
                    type_url = getattr(property_any, "type_url", None) if property_any else None
                    if not type_url and 7 in get_op:
                        type_url = "weave.trait.security.BoltLockTrait"

                    _LOGGER.debug("Extracting `%s` for `%s` with key `%s`", type_url, obj_id, obj_key)

                    if "BoltLockTrait" in (type_url or "") and obj_id:
                        bolt_lock = weave_security_pb2.BoltLockTrait()
                        try:
                            if not property_any:
                                _LOGGER.warning("No property payload for %s, skipping BoltLockTrait decode", obj_id)
                                continue
                            unpacked = property_any.Unpack(bolt_lock)
                            if not unpacked:
                                _LOGGER.warning("Unpacking BoltLockTrait failed for %s, skipping", obj_id)
                                continue

                            locks_data["yale"][obj_id] = {
                                "device_id": obj_id,
                                "bolt_locked": bolt_lock.lockedState == weave_security_pb2.BoltLockTrait.BOLT_LOCKED_STATE_LOCKED,
                                "bolt_moving": bolt_lock.actuatorState
                                not in [weave_security_pb2.BoltLockTrait.BOLT_ACTUATOR_STATE_OK],
                                "actuator_state": bolt_lock.actuatorState,
                            }
                            if bolt_lock.boltLockActor.originator.resourceId:
                                locks_data["user_id"] = bolt_lock.boltLockActor.originator.resourceId
                            _LOGGER.debug("Parsed BoltLockTrait for %s: %s, user_id=%s", obj_id, locks_data["yale"][obj_id], locks_data["user_id"])

                        except DecodeError as err:
                            _LOGGER.error("Failed to decode BoltLockTrait for %s: %s", obj_id, err)
                            continue
                        except Exception as err:
                            _LOGGER.error("Unexpected error unpacking BoltLockTrait for %s: %s", obj_id, err, exc_info=True)
                            continue

                    elif "StructureInfoTrait" in (type_url or "") and obj_id:
                        try:
                            if not property_any:
                                _LOGGER.warning("No StructureInfo payload for %s", obj_id)
                                continue
                            structure = nest_structure_pb2.StructureInfoTrait()
                            unpacked = property_any.Unpack(structure)
                            if not unpacked:
                                _LOGGER.warning("Unpacking StructureInfoTrait failed for %s, skipping", obj_id)
                                continue
                            if structure.legacy_id:
                                locks_data["structure_id"] = structure.legacy_id.split(".")[1]
                            elif obj_id.startswith("STRUCTURE_"):
                                locks_data["structure_id"] = obj_id.replace("STRUCTURE_", "")
                            _LOGGER.debug("Parsed StructureInfoTrait for %s: structure_id=%s", obj_id, locks_data["structure_id"])
                        except Exception as err:
                            _LOGGER.error("Failed to parse StructureInfoTrait for %s: %s", obj_id, err, exc_info=True)

                    elif "UserInfoTrait" in (type_url or ""):
                        try:
                            locks_data["user_id"] = obj_id
                        except Exception as err:
                            _LOGGER.error("Failed to parse UserInfoTrait: %s", err, exc_info=True)

            _LOGGER.debug(f"Final lock data: {locks_data}")
            return locks_data

        except DecodeError as e:
            _LOGGER.error(f"DecodeError in StreamBody: {e}")
            if message:
                _LOGGER.debug("Failed StreamBody payload (hex, first 200 bytes): %s", message[:200].hex())
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

                    for locks_data in await self._ingest_chunk(data):
                        yield locks_data

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
            temp_handler = NestProtobufHandler()
            async with connection.session.post(api_url, headers=headers, data=observe_data) as response:
                if response.status != 200:
                    _LOGGER.error(f"HTTP {response.status}: {await response.text()}")
                    return {}
                async for chunk in response.content.iter_any():
                    for locks_data in await temp_handler._ingest_chunk(chunk):
                        if locks_data.get("yale"):
                            return locks_data
        except Exception as e:
            _LOGGER.error(f"Refresh state error: {e}", exc_info=True)
        return {"yale": {}, "user_id": None, "structure_id": None}
