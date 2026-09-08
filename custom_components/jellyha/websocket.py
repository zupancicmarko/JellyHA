"""WebSocket API for JellyHA."""
from __future__ import annotations

import logging
import asyncio
from typing import Any

import voluptuous as vol

from homeassistant.components import websocket_api
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers import entity_registry as er
from homeassistant.exceptions import HomeAssistantError

from .const import DOMAIN, ITEM_TYPE_EPISODE

_LOGGER = logging.getLogger(__name__)


def _get_coordinator_from_msg(
    hass: HomeAssistant, msg: dict[str, Any]
) -> tuple[Any, str | None]:
    """Get the JellyHA library coordinator from msg or entities.

    Returns (coordinator, error_message). If coordinator is found, error_message is None.
    """
    config_entry_id = msg.get("config_entry_id")
    entity_id = msg.get("entity_id") or msg.get("server_entity_id")

    # 1. Direct config entry ID
    if config_entry_id:
        entry = hass.config_entries.async_get_entry(config_entry_id)
        if entry and entry.domain == DOMAIN and hasattr(entry, "runtime_data") and entry.runtime_data:
            coord = getattr(entry.runtime_data, "library", None)
            if coord:
                return coord, None

    # 2. Entity lookup
    if entity_id:
        # Check entity registry first
        registry = er.async_get(hass)
        ent = registry.async_get(entity_id)
        if ent and ent.config_entry_id:
            c_entry = hass.config_entries.async_get_entry(ent.config_entry_id)
            if c_entry and c_entry.domain == DOMAIN and hasattr(c_entry, "runtime_data") and c_entry.runtime_data:
                coord = getattr(c_entry.runtime_data, "library", None)
                if coord:
                    return coord, None

        # Check state attributes for entry_id or config_entry_id
        state = hass.states.get(entity_id)
        if state:
            c_id = state.attributes.get("entry_id") or state.attributes.get("config_entry_id")
            if c_id:
                c_entry = hass.config_entries.async_get_entry(c_id)
                if c_entry and c_entry.domain == DOMAIN and hasattr(c_entry, "runtime_data") and c_entry.runtime_data:
                    coord = getattr(c_entry.runtime_data, "library", None)
                    if coord:
                        return coord, None

    # 3. Fallback: first active JellyHA domain entry
    jellyha_entries = hass.config_entries.async_entries(DOMAIN)
    for entry in jellyha_entries:
        if hasattr(entry, "runtime_data") and entry.runtime_data:
            coord = getattr(entry.runtime_data, "library", None)
            if coord:
                return coord, None

    return None, "No active JellyHA integration found"


@callback
def async_register_websocket(hass: HomeAssistant) -> None:
    """Register JellyHA WebSocket handlers."""
    try:
        websocket_api.async_register_command(hass, websocket_get_items)
        websocket_api.async_register_command(hass, websocket_get_next_up)
        websocket_api.async_register_command(hass, websocket_get_user_next_up)
        websocket_api.async_register_command(hass, websocket_get_episodes)
        websocket_api.async_register_command(hass, websocket_search_media)
        websocket_api.async_register_command(hass, websocket_get_latest_items)
    except HomeAssistantError:
        # Command already registered, which is fine (e.g. multiple entries)
        pass


@websocket_api.websocket_command({
    vol.Required("type"): "jellyha/get_items",
    vol.Optional("entity_id"): cv.entity_id,
    vol.Optional("server_entity_id"): cv.entity_id,
    vol.Optional("config_entry_id"): cv.string,
})
@websocket_api.async_response
async def websocket_get_items(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Handle get items command."""
    coordinator, err = _get_coordinator_from_msg(hass, msg)
    if not coordinator:
        connection.send_error(msg["id"], websocket_api.ERR_NOT_FOUND, err or "Integration not loaded")
        return

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
    vol.Required("series_id"): str,
    vol.Optional("entity_id"): cv.entity_id,
    vol.Optional("server_entity_id"): cv.entity_id,
    vol.Optional("config_entry_id"): cv.string,
})
@websocket_api.async_response
async def websocket_get_next_up(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Handle get next up episode command."""
    series_id = msg["series_id"]
    coordinator, err = _get_coordinator_from_msg(hass, msg)
    if not coordinator:
        connection.send_error(msg["id"], websocket_api.ERR_NOT_FOUND, err or "Integration not loaded")
        return

    if not coordinator._api:
        await coordinator._async_setup()

    try:
        user_id = coordinator.entry.data.get("user_id")
        if not user_id:
            connection.send_error(msg["id"], websocket_api.ERR_INVALID_FORMAT, "User ID missing from config")
            return

        _LOGGER.debug(f"Fetching Next Up for user {user_id}, series {series_id}")
        next_up = await coordinator._api.get_next_up_episode(user_id, series_id)

        if next_up:
            # Transform using coordinator's helper
            item = await coordinator._async_transform_item(next_up)
            item["season"] = next_up.get("ParentIndexNumber")
            item["episode"] = next_up.get("IndexNumber")
            item["season_name"] = next_up.get("SeasonName")

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
    vol.Optional("entity_id"): cv.entity_id,
    vol.Optional("server_entity_id"): cv.entity_id,
    vol.Optional("config_entry_id"): cv.string,
})
@websocket_api.async_response
async def websocket_get_user_next_up(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Handle get global next up items command."""
    coordinator, err = _get_coordinator_from_msg(hass, msg)
    if not coordinator:
        connection.send_error(msg["id"], websocket_api.ERR_NOT_FOUND, err or "Integration not loaded")
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
            items = await asyncio.gather(*(coordinator._async_transform_item(item) for item in raw_next_up))
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
    vol.Required("series_id"): str,
    vol.Optional("season"): vol.Any(int, None),
    vol.Optional("entity_id"): cv.entity_id,
    vol.Optional("server_entity_id"): cv.entity_id,
    vol.Optional("config_entry_id"): cv.string,
})
@websocket_api.async_response
async def websocket_get_episodes(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Handle get episodes command."""
    series_id = msg["series_id"]
    season = msg.get("season")
    _LOGGER.debug(f"Fetching episodes for series {series_id}, season={season}")

    coordinator, err = _get_coordinator_from_msg(hass, msg)
    if not coordinator:
        connection.send_error(msg["id"], websocket_api.ERR_NOT_FOUND, err or "Integration not loaded")
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
            items = await asyncio.gather(*(coordinator._async_transform_item(item) for item in raw_episodes))
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


@websocket_api.websocket_command({
    vol.Required("type"): "jellyha/search_media",
    vol.Required("query"): str,
    vol.Optional("entity_id"): cv.entity_id,
    vol.Optional("server_entity_id"): cv.entity_id,
    vol.Optional("config_entry_id"): cv.string,
    vol.Optional("media_type"): vol.In([
        "Movie", "Series", "Episode",
        "Audio", "MusicAlbum", "MusicArtist", "MusicVideo", "Video",
    ]),
    vol.Optional("limit", default=20): int,
})
@websocket_api.async_response
async def websocket_search_media(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Search Jellyfin server directly (bypasses local cache)."""
    query = msg["query"]
    media_type = msg.get("media_type")
    limit = msg.get("limit", 20)

    coordinator, err = _get_coordinator_from_msg(hass, msg)
    if not coordinator:
        connection.send_error(msg["id"], websocket_api.ERR_NOT_FOUND, err or "Integration not loaded")
        return

    if not coordinator._api:
        await coordinator._async_setup()

    try:
        user_id = coordinator.entry.data.get("user_id")
        if not user_id:
            connection.send_error(msg["id"], websocket_api.ERR_INVALID_FORMAT, "User ID missing from config")
            return

        # MusicArtist requires the dedicated AlbumArtists endpoint
        if media_type == "MusicArtist":
            params = {
                "SortBy": "SortName",
                "SortOrder": "Ascending",
                "Recursive": "true",
                "Fields": "PrimaryImageAspectRatio",
                "Limit": str(limit),
            }
            if query:
                params["searchTerm"] = query
            result = await coordinator._api._request("GET", "/Artists/AlbumArtists", params=params)
            raw_items = result.get("Items", [])
        else:
            # Build item_types list from media_type parameter
            item_types = [media_type] if media_type else None

            # Query the Jellyfin server directly via the API
            raw_items = await coordinator._api.get_library_items(
                user_id=user_id,
                limit=limit,
                search_term=query,
                item_types=item_types,
            )

        # Transform items using coordinator's helper
        items_tuple = await asyncio.gather(*(coordinator._async_transform_item(raw) for raw in raw_items))
        items = list(items_tuple)

        # For Audio items, enrich with artist info
        for i, raw in zip(items, raw_items):
            if raw.get("Type") == "Audio":
                album_artist = raw.get("AlbumArtist")
                artists = raw.get("Artists", [])
                i["artist_name"] = album_artist or (artists[0] if artists else None)
                i["album"] = raw.get("Album")
            elif raw.get("Type") == "MusicAlbum":
                i["artist_name"] = raw.get("AlbumArtist")

        connection.send_result(msg["id"], {"items": items})

    except Exception as err:
        _LOGGER.exception("Error searching media: %s", err)
        connection.send_error(msg["id"], websocket_api.ERR_UNKNOWN_ERROR, f"Error: {str(err)}")


@websocket_api.websocket_command({
    vol.Required("type"): "jellyha/get_latest_items",
    vol.Optional("entity_id"): cv.entity_id,
    vol.Optional("server_entity_id"): cv.entity_id,
    vol.Optional("config_entry_id"): cv.string,
    vol.Optional("item_types"): [str],
    vol.Optional("limit", default=100): int,
})
@websocket_api.async_response
async def websocket_get_latest_items(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Handle get latest items command."""
    item_types = msg.get("item_types") or [ITEM_TYPE_EPISODE]
    limit = msg.get("limit", 100)

    coordinator, err = _get_coordinator_from_msg(hass, msg)
    if not coordinator:
        connection.send_error(msg["id"], websocket_api.ERR_NOT_FOUND, err or "Integration not loaded")
        return

    try:
        if not coordinator._api:
            await coordinator._async_setup()

        user_id = coordinator.entry.data.get("user_id")
        if not user_id:
            connection.send_error(msg["id"], websocket_api.ERR_INVALID_FORMAT, "User ID missing from config")
            return

        libraries = coordinator.entry.data.get("libraries", [])
        raw_items = await coordinator._api.get_library_items(
            user_id=user_id,
            limit=limit,
            item_types=item_types,
            library_ids=libraries if libraries else None,
        )

        items = []
        if raw_items:
            items = await asyncio.gather(*(coordinator._async_transform_item(item) for item in raw_items))

        connection.send_result(msg["id"], {"items": list(items)})
    except Exception as err:
        _LOGGER.exception("Error fetching latest items: %s", err)
        connection.send_error(msg["id"], websocket_api.ERR_UNKNOWN_ERROR, f"Error: {str(err)}")