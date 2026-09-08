import asyncio
import logging
import json
import aiohttp
from typing import Optional, Callable, List, Dict, Any
from urllib.parse import quote

from .const import EVENT_SESSIONS

_LOGGER = logging.getLogger(__name__)

class JellyfinWebSocketClient:
    """Jellyfin WebSocket Client."""

    def __init__(self, session: aiohttp.ClientSession, server_url: str, api_key: str, device_id: str):
        """Initialize the WebSocket client."""
        self._session = session
        self._server_url = server_url
        self._api_key = api_key
        self._device_id = device_id
        self._ws: Optional[aiohttp.ClientWebSocketResponse] = None
        self._connected = False
        self._on_session_update: Optional[Callable[[List[Dict[str, Any]]], Any]] = None
        self._on_connect: Optional[Callable[[], Any]] = None
        self._on_disconnect: Optional[Callable[[], Any]] = None
        self._stop_event = asyncio.Event()
        self._loop_task: Optional[asyncio.Task] = None

    def set_on_session_update(self, callback: Callable[[List[Dict[str, Any]]], Any]):
        """Set the callback for session updates."""
        self._on_session_update = callback

    def set_on_connect(self, callback: Callable[[], Any]):
        """Set the callback for connection."""
        self._on_connect = callback

    def set_on_disconnect(self, callback: Callable[[], Any]):
        """Set the callback for disconnection."""
        self._on_disconnect = callback

    async def start(self):
        """Start the WebSocket client loop."""
        self._stop_event.clear()
        self._loop_task = asyncio.create_task(self._run())

    async def stop(self):
        """Stop the WebSocket client."""
        self._stop_event.set()
        if self._ws:
            await self._ws.close()
        if self._loop_task:
            await self._loop_task

    @property
    def connected(self) -> bool:
        """Return True if connected."""
        return self._connected

    async def _run(self):
        """Run the WebSocket loop."""
        # Construct WebSocket URL
        # server_url might be http://... or https://...
        # We need to switch protocol to ws or wss
        url = self._server_url
        if url.startswith("https://"):
            url = url.replace("https://", "wss://", 1)
        elif url.startswith("http://"):
            url = url.replace("http://", "ws://", 1)
            
        encoded_id = quote(self._device_id)
        encoded_key = quote(self._api_key)
        url = f"{url}/socket?api_key={encoded_key}&deviceId={encoded_id}"

        # Jellyfin 12 dropped query-string api_key auth on the API and /socket
        # routes (image/stream routes still accept it), so the token is also sent
        # in the Authorization header. Older servers ignore the header and use the
        # query parameter, so sending both keeps 10.x working.
        headers = {
            "Authorization": f'MediaBrowser Client="Home Assistant", '
            f'Device="HACS Integration", '
            f'DeviceId="{self._device_id}", '
            f'Version="1.0.0", '
            f'Token="{self._api_key}"'
        }

        retry_delay = 2  # Start with 2 seconds
        
        while not self._stop_event.is_set():
            try:
                _LOGGER.debug("Connecting to Jellyfin WebSocket: %s", url)
                async with self._session.ws_connect(url, headers=headers) as ws:
                    self._ws = ws
                    self._connected = True
                    _LOGGER.info("Connected to Jellyfin WebSocket")
                    if self._on_connect:
                        if asyncio.iscoroutinefunction(self._on_connect):
                            await self._on_connect()
                        else:
                            self._on_connect()
                    
                    # Send a message to get initial state if needed, or wait for automatic init
                    # Jellyfin usually sends SessionsStart immediately after connection for authenticated devices
                    
                    await ws.send_str('{"MessageType": "SessionsStart", "Data": "0,500"}')
                    
                    async for msg in ws:
                        if self._stop_event.is_set():
                            break
                        
                        if msg.type == aiohttp.WSMsgType.TEXT:
                            await self._handle_message(msg.data)
                        elif msg.type == aiohttp.WSMsgType.ERROR:
                            _LOGGER.error("WebSocket connection error: %s", ws.exception())
                            break
            except Exception as ex:  # pylint: disable=broad-except
                 if not self._stop_event.is_set():
                    _LOGGER.error("WebSocket connection failed, retrying in %ds: %s", retry_delay, ex)
            finally:
                if self._connected:
                    # Successful connection happened, reset backoff
                    retry_delay = 2
                    
                was_connected = self._connected
                self._connected = False
                self._ws = None
                if was_connected and self._on_disconnect:
                    if asyncio.iscoroutinefunction(self._on_disconnect):
                        await self._on_disconnect()
                    else:
                        self._on_disconnect()
            
            if not self._stop_event.is_set():
                await asyncio.sleep(retry_delay)
                # Exponential backoff with jitter could be better, but simple doubling is fine
                retry_delay = min(retry_delay * 2, 30)

    async def _handle_message(self, data: str):
        """Handle incoming WebSocket message."""
        try:
            message = json.loads(data)
            msg_type = message.get("MessageType")
            
            if msg_type == "SessionsStart" or msg_type == EVENT_SESSIONS:
                # SessionsStart gives us the initial list of sessions
                # Sessions gives us updates
                sessions = message.get("Data", [])
                _LOGGER.debug("Received session update (%s): %d sessions", msg_type, len(sessions))
                if self._on_session_update:
                    if asyncio.iscoroutinefunction(self._on_session_update):
                        await self._on_session_update(sessions)
                    else:
                        self._on_session_update(sessions)
            elif msg_type == "KeepAlive":
                 _LOGGER.debug("Received KeepAlive")
            elif msg_type == "ForceKeepAlive":
                 pass
            else:
                 _LOGGER.debug("Received unknown message type: %s", msg_type)
        except Exception as ex:  # pylint: disable=broad-except
            _LOGGER.error("Error handling WebSocket message: %s", ex)
