"""JellyHA integration for Home Assistant."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant

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


async def async_migrate_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Migrate old entry."""
    _LOGGER.debug("Migrating configuration from version %s", entry.version)

    if entry.version == 1:
        # Placeholder for future interactions
        # new_data = {**entry.data}
        # hass.config_entries.async_update_entry(entry, data=new_data, version=2)
        pass

    _LOGGER.info("Migration to version %s successful", entry.version)
    return True



async def async_setup_entry(hass: HomeAssistant, entry: JellyHAConfigEntry) -> bool:
    """Set up JellyHA from a config entry."""
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
            await lib_coordinator._api.close()
    
    return unload_ok


async def async_reload_entry(hass: HomeAssistant, entry: JellyHAConfigEntry) -> None:
    """Reload config entry."""
    await async_unload_entry(hass, entry)
    await async_setup_entry(hass, entry)
