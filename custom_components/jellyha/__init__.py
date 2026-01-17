"""JellyHA integration for Home Assistant."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant

from .const import DOMAIN
from .coordinator import JellyHALibraryCoordinator, JellyHASessionCoordinator
from .services import async_register_services
from .storage import JellyfinLibraryData
from .websocket import async_register_websocket

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.SENSOR, Platform.MEDIA_PLAYER]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up JellyHA from a config entry."""
    storage = JellyfinLibraryData(hass, entry.entry_id)
    await storage.async_load()

    lib_coordinator = JellyHALibraryCoordinator(hass, entry, storage)
    await lib_coordinator.async_config_entry_first_refresh()

    # Initialize session coordinator (api is initialized in library coordinator)
    session_coordinator = JellyHASessionCoordinator(
        hass, entry, lib_coordinator._api
    )
    # Start session coordinator refresh (non-blocking)
    await session_coordinator.async_config_entry_first_refresh()
    
    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = {
        "library": lib_coordinator,
        "session": session_coordinator,
    }
    
    # Register services and websocket
    await async_register_services(hass)
    async_register_websocket(hass)
    
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    if unload_ok := await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        hass.data[DOMAIN].pop(entry.entry_id)
    
    return unload_ok


async def async_reload_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Reload config entry."""
    await async_unload_entry(hass, entry)
    await async_setup_entry(hass, entry)
