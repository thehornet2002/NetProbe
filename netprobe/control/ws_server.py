import asyncio
import logging
from typing import Dict, Any, Callable, Optional
import websockets
from netprobe.control.protocol import ControlMessage, MessageType

logger = logging.getLogger("netprobe.ws_server")


class ControlWSServer:
    """Out-of-band WebSocket server running on Linux to coordinate scenarios."""

    def __init__(self, host: str = "0.0.0.0", port: int = 8765):
        self.host = host
        self.port = port
        self.server = None
        self.client_ws = None
        self.connected_event = asyncio.Event()
        self.on_message_callback: Optional[Callable[[Dict[str, Any]], None]] = None

    async def start(self):
        self.server = await websockets.serve(self._handler, self.host, self.port, ping_interval=None)
        logger.info(f"WebSocket Control Server listening on ws://{self.host}:{self.port}")

    async def _handler(self, websocket):
        self.client_ws = websocket
        self.connected_event.set()
        logger.info(f"Control channel established with peer: {websocket.remote_address}")
        try:
            async for raw_msg in websocket:
                msg = ControlMessage.parse(raw_msg)
                logger.debug(f"WS Received: {msg.get('type')}")
                if self.on_message_callback:
                    await self.on_message_callback(msg)
        except websockets.exceptions.ConnectionClosed:
            logger.info("Control connection closed by peer.")
        finally:
            self.client_ws = None
            self.connected_event.clear()

    async def send(self, msg_type: str, payload: Optional[Dict[str, Any]] = None):
        if self.client_ws:
            msg = ControlMessage.create(msg_type, payload)
            await self.client_ws.send(msg)

    async def wait_for_client(self, timeout: float = 30.0):
        logger.info("Waiting for client connection on control channel...")
        await asyncio.wait_for(self.connected_event.wait(), timeout=timeout)

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            logger.info("WebSocket Control Server stopped.")
