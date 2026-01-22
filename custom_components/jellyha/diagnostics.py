"""Diagnostics support for JellyHA."""
from __future__ import annotations

from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from . import JellyHAConfigEntry
from .const import CONF_API_KEY, CONF_SERVER_URL, DOMAIN

TO_REDACT = {CONF_API_KEY, CONF_SERVER_URL}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: JellyHAConfigEntry
) -> dict[str, Any]:
    """Return diagnostics for a config entry."""
    
    # Extract coordinators
    library_coordinator = entry.runtime_data.library
    session_coordinator = entry.runtime_data.session
    ws_client = entry.runtime_data.ws_client

    diagnostics_data = {
        "entry": async_redact_data(entry.as_dict(), TO_REDACT),
        "library_coordinator": {
            "last_refresh": library_coordinator.last_refresh_time,
            "last_data_change": library_coordinator.last_data_change_time,
            "server_version": library_coordinator._server_version,
            "server_name": library_coordinator._server_name,
            "data_summary": {
                "count": library_coordinator.data.get("count") if library_coordinator.data else 0,
                # Don't dump all items to avoid massive log files
                "items_sample": (
                    library_coordinator.data.get("items")[:5] 
                    if library_coordinator.data and library_coordinator.data.get("items") 
                    else []
                )
            }
        },
        "session_coordinator": {
            "users_loaded": len(session_coordinator.users),
            "active_sessions": len(session_coordinator.data) if session_coordinator.data else 0,
        },
        "websocket": {
            "connected": ws_client.connected,
        }
    }

    return diagnostics_data
