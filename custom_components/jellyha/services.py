"""Services for JellyHA integration - Tuned 2026 Quality Strategy."""
from __future__ import annotations

import logging
import asyncio
import voluptuous as vol

from homeassistant.core import HomeAssistant, ServiceCall, SupportsResponse, ServiceResponse
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers import entity_registry as er
from homeassistant.components.media_player import (
    DOMAIN as MEDIA_PLAYER_DOMAIN,
    SERVICE_PLAY_MEDIA,
    ATTR_MEDIA_CONTENT_ID,
    ATTR_MEDIA_CONTENT_TYPE,
)

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

# Service Constants
SERVICE_PLAY_ON_CHROMECAST = "play_on_chromecast"
SERVICE_REFRESH_LIBRARY = "refresh_library"
SERVICE_DELETE_ITEM = "delete_item"
SERVICE_SESSION_CONTROL = "session_control"
SERVICE_SESSION_SEEK = "session_seek"
SERVICE_SESSION_GENERAL_COMMAND = "session_general_command"
SERVICE_UPDATE_FAVORITE = "update_favorite"
SERVICE_MARK_WATCHED = "mark_watched"
SERVICE_SEARCH = "search"
SERVICE_GET_RECOMMENDATIONS = "get_recommendations"
SERVICE_GET_ITEM = "get_item"

def _get_coordinator(hass: HomeAssistant, config_entry_id: str | None = None, entity_id: str | None = None):
    """Get the JellyHA coordinator from config_entry_id or entity_id."""
    if entity_id:
        registry = er.async_get(hass)
        entry = registry.async_get(entity_id)
        if entry and entry.config_entry_id:
            config_entry_id = entry.config_entry_id

    if config_entry_id:
        entry = hass.config_entries.async_get_entry(config_entry_id)
        if entry and hasattr(entry, "runtime_data") and entry.runtime_data:
             return entry.runtime_data.library
        raise ValueError(f"Config entry {config_entry_id} not found or not loaded")

    # Default to first available entry
    jellyha_entries = hass.config_entries.async_entries(DOMAIN)
    for entry in jellyha_entries:
        if hasattr(entry, "runtime_data") and entry.runtime_data:
             return entry.runtime_data.library
             
    raise ValueError("No JellyHA integration loaded")

# Schemas
PLAY_ON_CHROMECAST_SCHEMA = vol.Schema(
    {
        vol.Required("entity_id"): cv.entity_id,
        vol.Required("item_id"): cv.string,
        vol.Optional("server_entity_id"): cv.entity_id,
        vol.Optional("config_entry_id"): cv.string,
    }
)

DELETE_ITEM_SCHEMA = vol.Schema(
    {
        vol.Required("item_id"): cv.string,
        vol.Optional("entity_id"): cv.entity_id,
        vol.Optional("config_entry_id"): cv.string,
    }
)

SESSION_CONTROL_SCHEMA = vol.Schema(
    {
        vol.Required("session_id"): cv.string,
        vol.Required("command"): vol.In(["Pause", "Unpause", "PlayPause", "TogglePause", "Stop", "NextTrack", "PreviousTrack", "Shuffle", "SetRepeatMode"]),
        vol.Optional("entity_id"): cv.entity_id,
        vol.Optional("config_entry_id"): cv.string,
    }
)

SESSION_SEEK_SCHEMA = vol.Schema(
    {
        vol.Required("session_id"): cv.string,
        vol.Required("position_ticks"): cv.positive_int,
        vol.Optional("entity_id"): cv.entity_id,
        vol.Optional("config_entry_id"): cv.string,
    }
)

SESSION_GENERAL_COMMAND_SCHEMA = vol.Schema(
    {
        vol.Required("session_id"): cv.string,
        vol.Required("command"): cv.string,
        vol.Optional("arguments"): dict,
        vol.Optional("entity_id"): cv.entity_id,
        vol.Optional("config_entry_id"): cv.string,
    }
)

SEARCH_SCHEMA = vol.Schema(
    {
        vol.Optional("query"): cv.string,
        vol.Optional("media_type"): vol.In([
            "Movie", "Series", "Episode",
            "Audio", "MusicAlbum", "MusicArtist", "MusicVideo", "Video",
            "Playlist", "BoxSet",
        ]),
        vol.Optional("limit", default=5): cv.positive_int,
        vol.Optional("is_played"): cv.boolean,
        vol.Optional("is_favorite"): cv.boolean,
        vol.Optional("genre"): cv.string,
        vol.Optional("year"): cv.positive_int,
        vol.Optional("min_rating"): vol.Coerce(float),
        vol.Optional("season"): cv.positive_int,
        vol.Optional("episode"): cv.positive_int,
        vol.Optional("entity_id"): cv.entity_id,
        vol.Optional("config_entry_id"): cv.string,
    }
)

UPDATE_FAVORITE_SCHEMA = vol.Schema({
    vol.Required("item_id"): cv.string,
    vol.Required("is_favorite"): cv.boolean,
    vol.Optional("entity_id"): cv.entity_id,
    vol.Optional("config_entry_id"): cv.string,
})

MARK_WATCHED_SCHEMA = vol.Schema({
    vol.Required("item_id"): cv.string,
    vol.Required("is_played"): cv.boolean,
    vol.Optional("entity_id"): cv.entity_id,
    vol.Optional("config_entry_id"): cv.string,
})

GET_RECOMMENDATIONS_SCHEMA = vol.Schema({
    vol.Required("item_id"): cv.string,
    vol.Optional("limit", default=5): cv.positive_int,
    vol.Optional("entity_id"): cv.entity_id,
    vol.Optional("config_entry_id"): cv.string,
})

GET_ITEM_SCHEMA = vol.Schema({
    vol.Required("item_id"): cv.string,
    vol.Optional("entity_id"): cv.entity_id,
    vol.Optional("config_entry_id"): cv.string,
})

async def async_register_services(hass: HomeAssistant) -> None:
    """Register services for JellyHA."""

    async def async_refresh_library(call: ServiceCall) -> None:
        """Force refresh library data."""
        entity_id = call.data.get("entity_id")
        config_entry_id = call.data.get("config_entry_id")
        
        if config_entry_id or entity_id:
             try:
                 coordinator = _get_coordinator(hass, config_entry_id, entity_id)
                 await coordinator.async_refresh()
                 return
             except ValueError as e:
                 _LOGGER.error("Refresh failed: %s", e)
                 return

        # Refresh ALL if no ID specified
        jellyha_entries = hass.config_entries.async_entries(DOMAIN)
        for entry in jellyha_entries:
            if hasattr(entry, "runtime_data") and entry.runtime_data:
                await entry.runtime_data.library.async_refresh()

    async def async_play_on_device(call: ServiceCall) -> None:
        """Play a Jellyfin item using Tuned 2026 Strategy."""
        target_entity_id = call.data["entity_id"]
        item_id = call.data["item_id"]
        server_entity_id = call.data.get("server_entity_id")
        config_entry_id = call.data.get("config_entry_id")

        try:
            coordinator = _get_coordinator(hass, config_entry_id, server_entity_id)
        except ValueError as e:
            _LOGGER.error("Playback target failed: %s", e)
            return

        api = coordinator._api
        user_id = coordinator.config_entry.data.get("user_id")

        # Fetch item
        item = await api.get_item(user_id, item_id)
        if not item:
             _LOGGER.error("Item %s not found", item_id)
             return

        # Resolve Series/Season to Next Episode
        item_type = item.get("Type")
        if item_type in ["Series", "Season"]:
            series_id = item_id if item_type == "Series" else item.get("SeriesId")
            if series_id:
                next_episode = await api.get_next_up_episode(user_id, series_id)
                if next_episode:
                    item = next_episode
                    item_id = item.get("Id")
                else:
                    return

        # Strategy logic
        from .media_strategy import MediaStrategy
        model_name, _ = await hass.async_add_executor_job(
            MediaStrategy.discover_chromecast_model, hass, target_entity_id
        )

        media_info = MediaStrategy.analyze_media(item)
        playback_info = MediaStrategy.get_playback_info(
            api._server_url, api._api_key, item_id, media_info, model_name, item_type=item.get("Type")
        )

        # Cast
        metadata = {"title": item.get("Name", "Jellyfin Media"), "images": [{"url": api.get_image_url(item_id, "Primary")}]}
        if item.get("Type") == "Episode":
            metadata.update({"metadataType": 1, "seriesTitle": item.get("SeriesName"), "season": item.get("ParentIndexNumber"), "episode": item.get("IndexNumber")})

        await hass.services.async_call(
            MEDIA_PLAYER_DOMAIN, SERVICE_PLAY_MEDIA,
            {
                "entity_id": target_entity_id,
                ATTR_MEDIA_CONTENT_ID: playback_info["media_url"],
                ATTR_MEDIA_CONTENT_TYPE: playback_info["content_type"],
                "extra": {"title": metadata["title"], "thumb": metadata["images"][0]["url"], "autoplay": True, "metadata": metadata},
            },
            blocking=True,
        )

    async def async_search(call: ServiceCall) -> ServiceResponse:
        """Search for media and return results."""
        try:
            coordinator = _get_coordinator(hass, call.data.get("config_entry_id"), call.data.get("entity_id"))
        except ValueError as e:
            raise ValueError(str(e)) from e
            
        user_id = coordinator.entry.data.get("user_id")
        media_type = call.data.get("media_type")
        limit = call.data.get("limit", 5)
        query = call.data.get("query")

        if media_type == "MusicArtist":
            params = {"SortBy": "SortName", "SortOrder": "Ascending", "Recursive": "true", "Fields": "PrimaryImageAspectRatio", "Limit": str(limit)}
            if query: params["searchTerm"] = query
            result = await coordinator._api._request("GET", "/Artists/AlbumArtists", params=params)
            items = result.get("Items", [])
        else:
            items = await coordinator._api.get_library_items(
                user_id=user_id, limit=limit, search_term=query, item_types=[media_type] if media_type else None,
                is_played=call.data.get("is_played"), is_favorite=call.data.get("is_favorite"),
                genre=call.data.get("genre"), year=call.data.get("year"), min_rating=call.data.get("min_rating"),
                season=call.data.get("season"), episode=call.data.get("episode")
            )

        results = list(await asyncio.gather(*(coordinator._async_transform_item(item) for item in items)))
        return {"items": results}

    async def async_delete_item(call: ServiceCall) -> None:
        """Delete an item from Jellyfin library."""
        try:
            coordinator = _get_coordinator(hass, call.data.get("config_entry_id"), call.data.get("entity_id"))
            await coordinator._api._request("DELETE", f"/Items/{call.data['item_id']}")
            await coordinator.async_refresh()
        except Exception as e:
            _LOGGER.error("Delete failed: %s", e)

    async def async_update_favorite(call: ServiceCall) -> None:
        """Update favorite status for an item."""
        try:
            coordinator = _get_coordinator(hass, call.data.get("config_entry_id"), call.data.get("entity_id"))
            user_id = coordinator.entry.data.get("user_id")
            await coordinator._api.update_favorite(user_id, call.data["item_id"], call.data["is_favorite"])
            await coordinator.async_refresh()
        except Exception as e:
            _LOGGER.error("Favorite update failed: %s", e)

    async def async_mark_watched(call: ServiceCall) -> None:
        """Update watched status for an item."""
        try:
            coordinator = _get_coordinator(hass, call.data.get("config_entry_id"), call.data.get("entity_id"))
            user_id = coordinator.entry.data.get("user_id")
            await coordinator._api.update_played_status(user_id, call.data["item_id"], call.data["is_played"])
            await coordinator.async_refresh()
        except Exception as e:
            _LOGGER.error("Mark watched failed: %s", e)

    async def async_session_control(call: ServiceCall) -> None:
        """Send control command to session."""
        try:
            coordinator = _get_coordinator(hass, call.data.get("config_entry_id"), call.data.get("entity_id"))
            await coordinator._api.session_control(call.data["session_id"], call.data["command"])
        except Exception as e:
            _LOGGER.error("Session control failed: %s", e)

    async def async_session_seek(call: ServiceCall) -> None:
        """Send seek command to session."""
        try:
            coordinator = _get_coordinator(hass, call.data.get("config_entry_id"), call.data.get("entity_id"))
            await coordinator._api.session_seek(call.data["session_id"], call.data["position_ticks"])
        except Exception as e:
            _LOGGER.error("Session seek failed: %s", e)

    async def async_session_general_command(call: ServiceCall) -> None:
        """Send a general command to session."""
        try:
            coordinator = _get_coordinator(hass, call.data.get("config_entry_id"), call.data.get("entity_id"))
            await coordinator._api.session_general_command(call.data["session_id"], call.data["command"], call.data.get("arguments"))
        except Exception as e:
            _LOGGER.error("Session general command failed: %s", e)

    async def async_get_recommendations(call: ServiceCall) -> ServiceResponse:
        """Get recommendations for an item."""
        try:
            coordinator = _get_coordinator(hass, call.data.get("config_entry_id"), call.data.get("entity_id"))
            user_id = coordinator.entry.data.get("user_id")
            items = await coordinator._api.get_similar_items(user_id=user_id, item_id=call.data["item_id"], limit=call.data["limit"])
            results = list(await asyncio.gather(*(coordinator._async_transform_item(item) for item in items)))
            return {"items": results}
        except Exception as e:
            raise ValueError(f"Recommendations failed: {e}") from e

    async def async_get_item(call: ServiceCall) -> ServiceResponse:
        """Get full details for an item."""
        try:
            coordinator = _get_coordinator(hass, call.data.get("config_entry_id"), call.data.get("entity_id"))
            user_id = coordinator.entry.data.get("user_id")
            item = await coordinator._api.get_item(user_id=user_id, item_id=call.data["item_id"])
            
            # Enrich with streams
            if "MediaSources" in item and item["MediaSources"]:
                 item["media_streams"] = item["MediaSources"][0].get("MediaStreams", [])
            elif "MediaStreams" in item:
                 item["media_streams"] = item["MediaStreams"]
                 
            user_data = item.get("UserData", {})
            item["is_favorite"] = user_data.get("IsFavorite", False)
            item["is_played"] = user_data.get("Played", False)

            return {"item": item}
        except Exception as e:
            raise ValueError(f"Get Item failed: {e}") from e

    # Register all services properly
    service_map = [
        (SERVICE_REFRESH_LIBRARY, async_refresh_library, None),
        (SERVICE_PLAY_ON_CHROMECAST, async_play_on_device, PLAY_ON_CHROMECAST_SCHEMA),
        (SERVICE_DELETE_ITEM, async_delete_item, DELETE_ITEM_SCHEMA),
        (SERVICE_SESSION_CONTROL, async_session_control, SESSION_CONTROL_SCHEMA),
        (SERVICE_SESSION_SEEK, async_session_seek, SESSION_SEEK_SCHEMA),
        (SERVICE_SESSION_GENERAL_COMMAND, async_session_general_command, SESSION_GENERAL_COMMAND_SCHEMA),
        (SERVICE_UPDATE_FAVORITE, async_update_favorite, UPDATE_FAVORITE_SCHEMA),
        (SERVICE_MARK_WATCHED, async_mark_watched, MARK_WATCHED_SCHEMA),
        (SERVICE_SEARCH, async_search, SEARCH_SCHEMA, True),
        (SERVICE_GET_RECOMMENDATIONS, async_get_recommendations, GET_RECOMMENDATIONS_SCHEMA, True),
        (SERVICE_GET_ITEM, async_get_item, GET_ITEM_SCHEMA, True),
    ]

    for name, func, schema, *resp in service_map:
        if not hass.services.has_service(DOMAIN, name):
            hass.services.async_register(
                DOMAIN, name, func, schema=schema,
                supports_response=SupportsResponse.ONLY if resp and resp[0] else SupportsResponse.NONE
            )