"""JellyHA integration for Home Assistant."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant

from homeassistant.loader import async_get_integration
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.components.http import StaticPathConfig
import os

from .const import (
    DOMAIN,
    CONF_SERVER_URL,
    CONF_API_KEY,
    CONF_DEVICE_NAME,
    DEFAULT_DEVICE_NAME,
)
from .ws_client import JellyfinWebSocketClient
from .coordinator import JellyHALibraryCoordinator, JellyHASessionCoordinator
from .services import async_register_services
from .storage import JellyfinLibraryData
from .websocket import async_register_websocket
from .views import JellyHAImageView

_LOGGER = logging.getLogger(__name__)

from dataclasses import dataclass

@dataclass
class JellyHAData:
    """JellyHA data stored in the config entry."""
    library: JellyHALibraryCoordinator
    session: JellyHASessionCoordinator
    ws_client: JellyfinWebSocketClient

PLATFORMS: list[Platform] = [Platform.SENSOR, Platform.MEDIA_PLAYER]

# Type alias for the config entry
JellyHAConfigEntry = ConfigEntry[JellyHAData]






async def async_setup_entry(hass: HomeAssistant, entry: JellyHAConfigEntry) -> bool:
    """Set up JellyHA from a config entry."""
    integration = await async_get_integration(hass, DOMAIN)
    _LOGGER.info("Setting up JellyHA integration version %s", integration.version)
    storage = JellyfinLibraryData(hass, entry.entry_id)
    await storage.async_load()

    lib_coordinator = JellyHALibraryCoordinator(hass, entry, storage)
    await lib_coordinator.async_config_entry_first_refresh()

    # Initialize WebSocket Client
    session = async_get_clientsession(hass)
    server_url = entry.data.get(CONF_SERVER_URL)
    api_key = entry.data.get(CONF_API_KEY)
    device_name = entry.data.get(CONF_DEVICE_NAME, DEFAULT_DEVICE_NAME)
    
    # Use entry_id as part of device_id to ensure uniqueness if needed, or just device_name
    ws_client = JellyfinWebSocketClient(session, server_url, api_key, device_name)

    # Initialize session coordinator (api is initialized in library coordinator)
    session_coordinator = JellyHASessionCoordinator(
        hass, entry, lib_coordinator._api, ws_client
    )
    # Start session coordinator refresh (non-blocking)
    await session_coordinator.async_config_entry_first_refresh()
    
    entry.runtime_data = JellyHAData(
        library=lib_coordinator,
        session=session_coordinator,
        ws_client=ws_client,
    )
    
    # Start WebSocket client
    await ws_client.start()

    
    # Register services and websocket
    await async_register_services(hass)
    async_register_websocket(hass)

    # Register static path for assets (phrases, etc)
    # Security: Only expose the dedicated 'static' subdirectory, not the entire integration
    static_path = os.path.join(os.path.dirname(__file__), "static")
    await hass.http.async_register_static_paths([
        StaticPathConfig("/jellyha_static", static_path, False)
    ])
    
    # Register image proxy view
    hass.http.register_view(JellyHAImageView(hass))
    


    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # Listen for media events to trigger library refresh
    async def _handle_media_event(event):
        """Handle media events to trigger library refresh."""
        event_data = event.data
        event_type = event_data.get("type")
        
        # Only refresh on stop (or maybe pause if we want to be aggressive, but stop is key for Next Up)
        if event_type == "media_stop":
            _LOGGER.debug("Media stop event received, requesting library refresh for Next Up update")
            # We want to refresh the library to update "Next Up" list
            # A short delay might be needed for Jellyfin to update its internal state?
            # Let's try immediate first, coordinator handles debouncing usually if built-in, 
            # but here we force refresh.
            await lib_coordinator.async_request_refresh()

    entry.async_on_unload(
        hass.bus.async_listen(f"{DOMAIN}_event", _handle_media_event)
    )
    
    return True


async def async_unload_entry(hass: HomeAssistant, entry: JellyHAConfigEntry) -> bool:
    """Unload a config entry."""
    if unload_ok := await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        data = entry.runtime_data
        ws_client = data.ws_client
        if ws_client:
            await ws_client.stop()
        
        # Close API client session
        lib_coordinator = data.library
        if lib_coordinator and lib_coordinator._api:
            await lib_coordinator._api.logout()
            await lib_coordinator._api.close()
    
    return unload_ok


async def async_reload_entry(hass: HomeAssistant, entry: JellyHAConfigEntry) -> None:
    """Reload config entry."""
    await async_unload_entry(hass, entry)
    await async_setup_entry(hass, entry)
