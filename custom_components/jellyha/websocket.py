"""WebSocket API for JellyHA."""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant.components import websocket_api
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import config_validation as cv

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

from homeassistant.exceptions import HomeAssistantError

@callback
def async_register_websocket(hass: HomeAssistant) -> None:
    """Register JellyHA WebSocket handlers."""
    try:
        websocket_api.async_register_command(hass, websocket_get_items)
        websocket_api.async_register_command(hass, websocket_get_next_up)
        websocket_api.async_register_command(hass, websocket_get_user_next_up)
        websocket_api.async_register_command(hass, websocket_get_episodes)
    except HomeAssistantError:
        # Command already registered, which is fine (e.g. multiple entries)
        pass


@websocket_api.websocket_command({
    vol.Required("type"): "jellyha/get_items",
    vol.Required("entity_id"): cv.entity_id,
})
@websocket_api.async_response
async def websocket_get_items(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Handle get items command."""
    entity_id = msg["entity_id"]
    
    # Verify entity exists and is a JellyHA sensor
    state = hass.states.get(entity_id)
    if not state:
        connection.send_error(
            msg["id"], websocket_api.ERR_NOT_FOUND, f"Entity {entity_id} not found"
        )
        return

    # Helper: we need to find the config entry ID from the entity
    # We can try to get it from entity registry or attribute if we put it there.
    # The plan says we put entry_id in attributes.
    entry_id = state.attributes.get("entry_id")
    
    if not entry_id:
        # Fallback: try to find coordinator by looking at domain data
        # This is risky if multiple entries.
        # Let's rely on attribute. If missing, error.
        connection.send_error(
            msg["id"], 
            websocket_api.ERR_INVALID_FORMAT, 
            f"Entity {entity_id} does not have entry_id attribute"
        )
        return

    # Retrieve entry and runtime_data
    entry = hass.config_entries.async_get_entry(entry_id)
    if not entry or not hasattr(entry, "runtime_data"):
        connection.send_error(
             msg["id"], websocket_api.ERR_NOT_FOUND, "Integration not loaded"
        )
        return

    coordinator = entry.runtime_data.library

    if not coordinator:
        connection.send_error(
             msg["id"], websocket_api.ERR_NOT_FOUND, "Library coordinator not found"
        )
        return

    # Get items from storage
    # Get items from storage
    if not hasattr(coordinator, "storage") or not coordinator.storage:
         connection.send_error(
             msg["id"], websocket_api.ERR_HOME_ASSISTANT_ERROR, "Storage not initialized"
         )
         return
         
    items = coordinator.storage.get_all_items()
    
    # Fallback: if storage is empty but coordinator has data
    if not items and coordinator.data and "items" in coordinator.data:
        items = coordinator.data["items"]
    
    connection.send_result(msg["id"], {"items": items})

@websocket_api.websocket_command({
    vol.Required("type"): "jellyha/get_next_up",
    vol.Required("entity_id"): cv.entity_id,
    vol.Required("series_id"): str,
})
@websocket_api.async_response
async def websocket_get_next_up(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Handle get next up episode command."""
    entity_id = msg["entity_id"]
    series_id = msg["series_id"]
    
    state = hass.states.get(entity_id)
    if not state:
        connection.send_error(msg["id"], websocket_api.ERR_NOT_FOUND, f"Entity {entity_id} not found")
        return

    entry_id = state.attributes.get("entry_id")
    if not entry_id:
        connection.send_error(msg["id"], websocket_api.ERR_INVALID_FORMAT, "Missing entry_id")
        return

    entry = hass.config_entries.async_get_entry(entry_id)
    if not entry or not hasattr(entry, "runtime_data"):
        connection.send_error(msg["id"], websocket_api.ERR_NOT_FOUND, "Integration not loaded")
        return

    coordinator = entry.runtime_data.library
        
    if not coordinator:
        connection.send_error(msg["id"], websocket_api.ERR_NOT_FOUND, "Library coordinator not found")
        return

    if not coordinator._api:
         await coordinator._async_setup()

    try:
        # Use .get() for safety, though it should be there if config flow worked
        user_id = coordinator.entry.data.get("user_id")
        if not user_id:
             connection.send_error(msg["id"], websocket_api.ERR_INVALID_FORMAT, "User ID missing from config")
             return

        _LOGGER.debug(f"Fetching Next Up for user {user_id}, series {series_id}")
        next_up = await coordinator._api.get_next_up_episode(user_id, series_id)
        
        if next_up:
            # Transform using coordinator's helper
            item = coordinator._transform_item(next_up)
            # Find the season index/number from the raw item usually (ParentIndexNumber) or simple SeasonName
            # Jellyfin 'ParentIndexNumber' is Season Number, 'IndexNumber' is Episode Number
            item["season"] = next_up.get("ParentIndexNumber")
            item["episode"] = next_up.get("IndexNumber")
            item["season_name"] = next_up.get("SeasonName")
            
            # Map media streams if present (logic copied from services.py)
            if "MediaSources" in next_up and next_up["MediaSources"]:
                 item["media_streams"] = next_up["MediaSources"][0].get("MediaStreams", [])
                 
            connection.send_result(msg["id"], {"item": item})
        else:
            connection.send_result(msg["id"], {"item": None})
            
    except Exception as err:
        _LOGGER.exception("Error fetching Next Up episode: %s", err)
        connection.send_error(msg["id"], websocket_api.ERR_UNKNOWN_ERROR, f"Error: {str(err)}")

@websocket_api.websocket_command({
    vol.Required("type"): "jellyha/get_user_next_up",
    vol.Required("entity_id"): cv.entity_id,
})
@websocket_api.async_response
async def websocket_get_user_next_up(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Handle get global next up items command."""
    entity_id = msg["entity_id"]
    
    state = hass.states.get(entity_id)
    if not state:
        connection.send_error(msg["id"], websocket_api.ERR_NOT_FOUND, f"Entity {entity_id} not found")
        return

    entry_id = state.attributes.get("entry_id")
    if not entry_id:
        connection.send_error(msg["id"], websocket_api.ERR_INVALID_FORMAT, "Missing entry_id")
        return

    entry = hass.config_entries.async_get_entry(entry_id)
    if not entry or not hasattr(entry, "runtime_data"):
        connection.send_error(msg["id"], websocket_api.ERR_NOT_FOUND, "Integration not loaded")
        return

    coordinator = entry.runtime_data.library
    if not coordinator:
        connection.send_error(msg["id"], websocket_api.ERR_NOT_FOUND, "Library coordinator not found")
        return

    # Serve from coordinator cache if available
    if coordinator.data and "next_up_items" in coordinator.data:
        connection.send_result(msg["id"], {"items": coordinator.data["next_up_items"]})
        return

    # Fallback to direct fetch if cache miss (e.g. first run)
    try:
        if not coordinator._api:
            await coordinator._async_setup()
            
        user_id = coordinator.entry.data["user_id"]
        raw_next_up = await coordinator._api.get_next_up_items(user_id=user_id, limit=20)
        items = []
        if raw_next_up:
            items = [coordinator._transform_item(item) for item in raw_next_up]
            for i, raw in zip(items, raw_next_up):
                i["season"] = raw.get("ParentIndexNumber")
                i["episode"] = raw.get("IndexNumber")
                i["season_name"] = raw.get("SeasonName")
                i["series_name"] = raw.get("SeriesName")
                
        connection.send_result(msg["id"], {"items": items})
    except Exception as err:
        connection.send_error(msg["id"], websocket_api.ERR_UNKNOWN_ERROR, str(err))

@websocket_api.websocket_command({
    vol.Required("type"): "jellyha/get_episodes",
    vol.Required("entity_id"): cv.entity_id,
    vol.Required("series_id"): str,
    vol.Required("season"): int,
})
@websocket_api.async_response
async def websocket_get_episodes(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Handle get episodes command."""
    entity_id = msg["entity_id"]
    series_id = msg["series_id"]
    season = msg["season"]
    
    state = hass.states.get(entity_id)
    if not state:
        connection.send_error(msg["id"], websocket_api.ERR_NOT_FOUND, f"Entity {entity_id} not found")
        return

    entry_id = state.attributes.get("entry_id")
    if not entry_id:
        connection.send_error(msg["id"], websocket_api.ERR_INVALID_FORMAT, "Missing entry_id")
        return

    entry = hass.config_entries.async_get_entry(entry_id)
    if not entry or not hasattr(entry, "runtime_data"):
        connection.send_error(msg["id"], websocket_api.ERR_NOT_FOUND, "Integration not loaded")
        return

    coordinator = entry.runtime_data.library
    if not coordinator:
        connection.send_error(msg["id"], websocket_api.ERR_NOT_FOUND, "Library coordinator not found")
        return

    try:
        if not coordinator._api:
            await coordinator._async_setup()
            
        user_id = coordinator.entry.data["user_id"]
        
        # Use our new API method
        raw_episodes = await coordinator._api.get_episodes_by_season(
            user_id=user_id, series_id=series_id, season=season
        )
        
        items = []
        if raw_episodes:
            items = [coordinator._transform_item(item) for item in raw_episodes]
            # Enrich items with logic similar to NextUp to ensure consistency
            for i, raw in zip(items, raw_episodes):
                i["season"] = raw.get("ParentIndexNumber")
                i["episode"] = raw.get("IndexNumber")
                
                # Ensure media streams are present for playback info
                if "MediaSources" in raw and raw["MediaSources"]:
                    i["media_streams"] = raw["MediaSources"][0].get("MediaStreams", [])
                elif "MediaStreams" in raw:
                     i["media_streams"] = raw["MediaStreams"]

        connection.send_result(msg["id"], {"items": items})
    except Exception as err:
        _LOGGER.exception("Error fetching episodes: %s", err)
        connection.send_error(msg["id"], websocket_api.ERR_UNKNOWN_ERROR, str(err))