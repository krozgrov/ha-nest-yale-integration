import httpx
import logging
import asyncio
from .const import (
    API_TIMEOUT_SECONDS,
    API_OBSERVE_TIMEOUT_SECONDS,
    API_HTTP2_PING_INTERVAL_SECONDS,
    USER_AGENT_STRING,
)

_LOGGER = logging.getLogger(__name__)

class NestConnection:
    def __init__(self):
        self.client = None
        self.connected = False
        self._ping_task = None

    async def setup(self):
        """Set up the HTTP client asynchronously."""
        self.client = httpx.AsyncClient(
            http2=True,
            timeout=API_TIMEOUT_SECONDS,
            verify=False,
            headers={"User-Agent": USER_AGENT_STRING}
        )
        self.connected = True
        _LOGGER.debug("HTTP client set up successfully")

    async def post(self, url, headers, content):
        if not self.client:
            raise RuntimeError("Client not initialized; call setup first")
        _LOGGER.debug(f"Sending POST to {url} with headers: {headers}")
        resp = await self.client.post(url, headers=headers, content=content)
        resp.raise_for_status()
        raw_data = await resp.aread()
        _LOGGER.debug(f"Raw response from {url}: Length {len(raw_data)} bytes")  # Simplified
        return raw_data

    async def stream(self, url, headers, content, timeout=API_OBSERVE_TIMEOUT_SECONDS):
        """Stream data from a POST request with per-chunk timeout."""
        if not self.client:
            raise RuntimeError("Client not initialized; call setup first")
        _LOGGER.debug(f"Starting stream at {url} with headers: {headers}")
        async with self.client.stream("POST", url, headers=headers, content=content, timeout=timeout) as resp:
            resp.raise_for_status()
            async with asyncio.timeout(5):  # 5-second per-chunk timeout
                async for chunk in resp.aiter_bytes():
                    # Removed: _LOGGER.debug(f"Raw stream chunk: {chunk.hex()[:100]} - Length: {len(chunk)} bytes")
                    yield chunk
                    await asyncio.sleep(0)  # Yield control briefly
                    async with asyncio.timeout(5):
                        pass  # Re-arm timeout

    async def start_ping(self):
        """Start periodic pings to maintain connection."""
        async def ping():
            while self.connected:
                await asyncio.sleep(API_HTTP2_PING_INTERVAL_SECONDS)
                _LOGGER.debug("Sending HTTP/2 ping to maintain connection")
        self._ping_task = asyncio.create_task(ping())
        return self._ping_task

    async def close(self):
        """Close the client session."""
        if self.client:
            if self._ping_task:
                self._ping_task.cancel()
            await self.client.aclose()
            self.client = None
            self.connected = False
            _LOGGER.debug("HTTP client closed")