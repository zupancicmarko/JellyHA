"""Diagnostics support for JellyHA."""
from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import DOMAIN

TO_REDACT = {
    "api_key",
    "password",
    "access_token",
    "user_id",
}

async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: ConfigEntry
) -> dict[str, Any]:
    """Return diagnostics for a config entry."""
    
    diagnostics_data: dict[str, Any] = {
        "entry": async_redact_data(entry.as_dict(), TO_REDACT),
        "data": {},
        "server": {}
    }

    if hasattr(entry, "runtime_data") and entry.runtime_data:
        library = entry.runtime_data.library
        ws_client = entry.runtime_data.ws_client
        session = entry.runtime_data.session
        
        if library and library.data:
            diagnostics_data["server"]["version"] = library.data.get("server_info", {}).get("Version", "Unknown")
            diagnostics_data["server"]["os"] = library.data.get("server_info", {}).get("OperatingSystem", "Unknown")
            
            # Libraries list
            views = library.data.get("views", [])
            diagnostics_data["data"]["libraries"] = [
                {"Name": v.get("Name"), "CollectionType": v.get("CollectionType")} 
                for v in views
            ]
            
            # Counts
            items = library.data.get("items", [])
            diagnostics_data["data"]["item_counts"] = {
                "total": len(items),
                "movies": len([i for i in items if i.get("type") == "Movie"]),
                "episodes": len([i for i in items if i.get("type") == "Episode"]),
                "series": len([i for i in items if i.get("type") == "Series"]),
            }

        if ws_client:
            diagnostics_data["websocket"] = {
                "connected": ws_client.connected,
                "listening_device_id": ws_client._device_id
            }

        if session and session.users:
            diagnostics_data["sessions"] = {
                "active_user_count": len(session.users),
            }

    return diagnostics_data
