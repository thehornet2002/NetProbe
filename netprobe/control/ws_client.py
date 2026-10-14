import asyncio
import logging
from typing import Dict, Any, Callable, Optional
import websockets
from netprobe.control.protocol import ControlMessage, MessageType

logger = logging.getLogger("netprobe.ws_client")


class ControlWSClient:
    """Out-of-band WebSocket client running on Windows connecting to Server."""

    def __init__(self, server_ip: str, port: int = 8765):
        self.uri = f"ws://{server_ip}:{port}"
        self.ws = None
        self.on_message_callback: Optional[Callable[[Dict[str, Any]], None]] = None

    async def connect(self, retry_count: int = 5, retry_delay: float = 2.0):
        for attempt in range(1, retry_count + 1):
            try:
                logger.info(f"Connecting to Control Server at {self.uri} (Attempt {attempt}/{retry_count})...")
                self.ws = await websockets.connect(self.uri, ping_interval=None)
                logger.info("Connected to Control Server.")
                return True
            except Exception as e:
                logger.warning(f"Connection failed: {e}")
                if attempt < retry_count:
                    await asyncio.sleep(retry_delay)
        return False

    async def listen(self):
        try:
            async for raw_msg in self.ws:
                msg = ControlMessage.parse(raw_msg)
                logger.debug(f"WS Client received: {msg.get('type')}")
                if self.on_message_callback:
                    await self.on_message_callback(msg)
        except websockets.exceptions.ConnectionClosed:
            logger.info("WebSocket connection to server closed.")

    async def send(self, msg_type: str, payload: Optional[Dict[str, Any]] = None):
        if self.ws:
            msg = ControlMessage.create(msg_type, payload)
            await self.ws.send(msg)

    async def close(self):
        if self.ws:
            await self.ws.close()
            logger.info("Control connection closed.")
