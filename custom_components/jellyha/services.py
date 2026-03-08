"""Services for JellyHA integration - Tuned 2026 Quality Strategy.

Strategy (Universal):
1. Connect & Detect Device Model.
2. Analyze Media (Video Height & Audio Channels).
3. Decision Matrix:
   - If Legacy (Gen 1): DIRECT PLAY only if 720p & Stereo. Else TRANSCODE (720p/Stereo).
   - If Modern: DIRECT PLAY if 1080p. Else TRANSCODE (1080p/5.1).
"""
from __future__ import annotations

import logging
import asyncio
import voluptuous as vol

from homeassistant.core import HomeAssistant, ServiceCall, SupportsResponse, ServiceResponse
from homeassistant.helpers import config_validation as cv
from homeassistant.components.media_player import (
    DOMAIN as MEDIA_PLAYER_DOMAIN,
    SERVICE_PLAY_MEDIA,
    ATTR_MEDIA_CONTENT_ID,
    ATTR_MEDIA_CONTENT_TYPE,
)

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

SERVICE_PLAY_ON_CHROMECAST = "play_on_chromecast"
SERVICE_REFRESH_LIBRARY = "refresh_library"
SERVICE_DELETE_ITEM = "delete_item"
SERVICE_SESSION_CONTROL = "session_control"
SERVICE_SESSION_SEEK = "session_seek"
SERVICE_PLAY_ON_CHROMECAST = "play_on_chromecast"
SERVICE_REFRESH_LIBRARY = "refresh_library"
SERVICE_DELETE_ITEM = "delete_item"
SERVICE_SESSION_CONTROL = "session_control"
SERVICE_SESSION_SEEK = "session_seek"
SERVICE_SEARCH = "search"

def _get_coordinator(hass: HomeAssistant, config_entry_id: str | None = None):
    """Get the JellyHA coordinator."""
    if config_entry_id:
        entry = hass.config_entries.async_get_entry(config_entry_id)
        if entry and hasattr(entry, "runtime_data") and entry.runtime_data:
             return entry.runtime_data.library
        raise ValueError(f"Config entry {config_entry_id} not found or not loaded")

    # Default to first available
    jellyha_entries = hass.config_entries.async_entries(DOMAIN)
    for entry in jellyha_entries:
        if hasattr(entry, "runtime_data") and entry.runtime_data:
             return entry.runtime_data.library
             
    raise ValueError("No JellyHA integration loaded")

PLAY_ON_CHROMECAST_SCHEMA = vol.Schema(
    {
        vol.Required("entity_id"): cv.entity_id,
        vol.Required("item_id"): cv.string,
        vol.Optional("config_entry_id"): cv.string,
    }
)

DELETE_ITEM_SCHEMA = vol.Schema(
    {
        vol.Required("item_id"): cv.string,
        vol.Optional("config_entry_id"): cv.string,
    }
)

SESSION_CONTROL_SCHEMA = vol.Schema(
    {
        vol.Required("session_id"): cv.string,
        vol.Required("command"): vol.In(["Pause", "Unpause", "PlayPause", "TogglePause", "Stop", "NextTrack", "PreviousTrack", "Shuffle", "SetRepeatMode"]),
        vol.Optional("config_entry_id"): cv.string,
    }
)

SESSION_SEEK_SCHEMA = vol.Schema(
    {
        vol.Required("session_id"): cv.string,
        vol.Required("position_ticks"): cv.positive_int,
        vol.Optional("config_entry_id"): cv.string,
    }
)

SESSION_GENERAL_COMMAND_SCHEMA = vol.Schema(
    {
        vol.Required("session_id"): cv.string,
        vol.Required("command"): cv.string,
        vol.Optional("arguments"): dict,
        vol.Optional("config_entry_id"): cv.string,
    }
)

SEARCH_SCHEMA = vol.Schema(
    {
        vol.Optional("query"): cv.string,
        vol.Optional("media_type"): vol.In([
            "Movie", "Series", "Episode",
            "Audio", "MusicAlbum", "MusicArtist", "MusicVideo", "Video",
        ]),
        vol.Optional("limit", default=5): cv.positive_int,
        vol.Optional("is_played"): cv.boolean,
        vol.Optional("is_favorite"): cv.boolean,
        vol.Optional("genre"): cv.string,
        vol.Optional("year"): cv.positive_int,
        vol.Optional("min_rating"): vol.Coerce(float),
        vol.Optional("season"): cv.positive_int,
        vol.Optional("episode"): cv.positive_int,
        vol.Optional("config_entry_id"): cv.string,
    }
)

async def async_register_services(hass: HomeAssistant) -> None:
    """Register services for JellyHA."""
    
    # ... (other services)

    # Note: I am not updating lines prior to async_search here as they are unchanged logic from previous context
    # Only updating async_search and below from the original view context if I were viewing it all. 
    # But I will just output the replacement for async_search if possible.
    # Actually, I am replacing the whole block or function.

# (Redundant comments removed for cleaner replacement)

    async def async_search(call: ServiceCall) -> ServiceResponse:
        """Search for media and return results."""
        query = call.data.get("query")
        media_type = call.data.get("media_type")
        limit = call.data.get("limit", 5)
        
        # New filters
        is_played = call.data.get("is_played")
        is_favorite = call.data.get("is_favorite")
        genre = call.data.get("genre")
        year = call.data.get("year")
        min_rating = call.data.get("min_rating")
        season = call.data.get("season")
        episode = call.data.get("episode")
        config_entry_id = call.data.get("config_entry_id")

        try:
            coordinator = _get_coordinator(hass, config_entry_id)
        except ValueError as e:
            raise ValueError(str(e)) from e
        
        if not coordinator or not coordinator._api:
            raise ValueError("No JellyHA integration loaded")
            
        user_id = coordinator.entry.data.get("user_id")
        if not user_id:
             raise ValueError("No user ID found in config entry")

        item_types = [media_type] if media_type else None
        
        try:
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
                items = result.get("Items", [])
            else:
                items = await coordinator._api.get_library_items(
                    user_id=user_id,
                    limit=limit,
                    search_term=query,
                    item_types=item_types,
                    is_played=is_played,
                    is_favorite=is_favorite,
                    genre=genre,
                    year=year,
                    min_rating=min_rating,
                    season=season,
                    episode=episode,
                )
        except Exception as err:
            _LOGGER.error("Search failed: %s", err)
            raise ValueError(f"Search failed: {err}") from err

        # Transform items securely via coordinator (generates signed paths)
        results = list(await asyncio.gather(*(coordinator._async_transform_item(item) for item in items)))

        # Augment with extra music metadata not in the default schema
        for i, raw in zip(results, items):
            item_type = raw.get("Type")
            if item_type == "Audio":
                album_artist = raw.get("AlbumArtist")
                artists = raw.get("Artists", [])
                i["artist_name"] = album_artist or (artists[0] if artists else None)
                i["album"] = raw.get("Album")
            elif item_type in ("MusicAlbum", "MusicVideo"):
                i["artist_name"] = raw.get("AlbumArtist") or (raw.get("Artists", [])[0] if raw.get("Artists") else None)

        return {"items": results}

    if not hass.services.has_service(DOMAIN, SERVICE_SEARCH):
        hass.services.async_register(
            DOMAIN,
            SERVICE_SEARCH,
            async_search,
            schema=SEARCH_SCHEMA,
            supports_response=SupportsResponse.ONLY,
        )

    async def async_play_on_device(call: ServiceCall) -> None:
        """Play a Jellyfin item using Tuned 2026 Strategy."""
        target_entity_id = call.data["entity_id"]
        item_id = call.data["item_id"]
        config_entry_id = call.data.get("config_entry_id")

        try:
            coordinator = _get_coordinator(hass, config_entry_id)
        except ValueError:
            _LOGGER.error("No JellyHA integration found for playback")
            return

        if not coordinator or not coordinator._api:
            _LOGGER.error("No JellyHA API client found")
            return

        api = coordinator._api
        server_url = api._server_url
        api_key = api._api_key
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
                    # Switch target to the episode
                    item = next_episode
                    item_id = item.get("Id")
                    _LOGGER.info("Resolved %s to Next Up: %s", item_type, item.get("Name"))
                else:
                    _LOGGER.warning("No unplayed episodes found for %s", item.get("Name"))
                    return

        title = item.get("Name", "Jellyfin Media")
        image_url = api.get_image_url(item_id, "Primary", max_height=800)
        
        # ------------------------------------------------------------------
        # 1. CONNECT & DETECT MODEL via Strategy (Async wrapper)
        # ------------------------------------------------------------------
        from .media_strategy import MediaStrategy
        
        # Run discovery in executor to avoid blocking
        model_name, is_legacy_device = await hass.async_add_executor_job(
            MediaStrategy.discover_chromecast_model, hass, target_entity_id
        )

        _LOGGER.info("Detected Device: %s (Legacy Mode: %s)", model_name, is_legacy_device)

        # ------------------------------------------------------------------
        # 2. ANALYSIS
        # ------------------------------------------------------------------
        media_info = MediaStrategy.analyze_media(item)
        
        # ------------------------------------------------------------------
        # 3. USE STRATEGY
        # ------------------------------------------------------------------
        playback_info = MediaStrategy.get_playback_info(
            server_url, api_key, item_id, media_info, model_name
        )
        
        media_url = playback_info["media_url"]
        content_type = playback_info["content_type"]

        # Prepare Metadata
        metadata = {
            "title": title,
            "images": [{"url": image_url}]
        }

        if item.get("Type") == "Episode":
            metadata["metadataType"] = 1  # TV Show
            if series_name := item.get("SeriesName"):
                metadata["seriesTitle"] = series_name
            if season_num := item.get("ParentIndexNumber"):
                metadata["season"] = season_num
            if episode_num := item.get("IndexNumber"):
                metadata["episode"] = episode_num
        else:
            metadata["metadataType"] = 0  # Movie/Generic

        # Cast
        try:
             await hass.services.async_call(
                MEDIA_PLAYER_DOMAIN,
                SERVICE_PLAY_MEDIA,
                {
                    "entity_id": target_entity_id,
                    ATTR_MEDIA_CONTENT_ID: media_url,
                    ATTR_MEDIA_CONTENT_TYPE: content_type,
                    "extra": {
                        "title": title,
                        "thumb": image_url,
                        "autoplay": True,
                        "metadata": metadata
                    },
                },
                blocking=True,
            )
             _LOGGER.info("✓ Cast Command Sent")
        except Exception as e:
             _LOGGER.error("Failed to call play_media: %s", e)

    if not hass.services.has_service(DOMAIN, SERVICE_PLAY_ON_CHROMECAST):
        hass.services.async_register(
            DOMAIN,
            SERVICE_PLAY_ON_CHROMECAST,
            async_play_on_device,
            schema=PLAY_ON_CHROMECAST_SCHEMA,
        )

        # Iterate over config entries
        jellyha_entries = hass.config_entries.async_entries(DOMAIN)
        for entry in jellyha_entries:
            if hasattr(entry, "runtime_data") and entry.runtime_data:
                coordinator = entry.runtime_data.library
                await coordinator.async_refresh()
                _LOGGER.info("Library refresh triggered via service for %s", entry.entry_id)

    async def async_refresh_library(call: ServiceCall) -> None:
        """Force refresh library data."""
        config_entry_id = call.data.get("config_entry_id")
        
        if config_entry_id:
             try:
                 coordinator = _get_coordinator(hass, config_entry_id)
                 await coordinator.async_refresh()
                 _LOGGER.info("Library refresh triggered for %s", config_entry_id)
                 return
             except ValueError:
                 _LOGGER.error("Config entry %s not found for refresh", config_entry_id)
                 return

        # Default: Refresh ALL if no ID specified (or refactor to refresh first found)
        # To maintain previous behavior (refresh all), we iterate.
        jellyha_entries = hass.config_entries.async_entries(DOMAIN)
        for entry in jellyha_entries:
            if hasattr(entry, "runtime_data") and entry.runtime_data:
                coordinator = entry.runtime_data.library
                await coordinator.async_refresh()
                _LOGGER.info("Library refresh triggered via service for %s", entry.entry_id)

    if not hass.services.has_service(DOMAIN, SERVICE_REFRESH_LIBRARY):
        hass.services.async_register(
            DOMAIN,
            SERVICE_REFRESH_LIBRARY,
            async_refresh_library,
        )

    async def async_delete_item(call: ServiceCall) -> None:
        """Delete an item from Jellyfin library."""
        item_id = call.data["item_id"]
        config_entry_id = call.data.get("config_entry_id")

        try:
            coordinator = _get_coordinator(hass, config_entry_id)
        except ValueError:
            _LOGGER.error("No JellyHA integration found")
            return

        if not coordinator or not coordinator._api:
            _LOGGER.error("No JellyHA API client found")
            return

        api = coordinator._api
        try:
            # Jellyfin API: DELETE /Items/{itemId}
            await api._request("DELETE", f"/Items/{item_id}")
            _LOGGER.info("Deleted item %s from Jellyfin", item_id)
            # Refresh to update local data
            await coordinator.async_refresh()
        except Exception as e:
            _LOGGER.error("Failed to delete item %s: %s", item_id, e)

    if not hass.services.has_service(DOMAIN, SERVICE_DELETE_ITEM):
        hass.services.async_register(
            DOMAIN,
            SERVICE_DELETE_ITEM,
            async_delete_item,
            schema=DELETE_ITEM_SCHEMA,
        )

    async def async_update_favorite(call: ServiceCall) -> None:
        """Update favorite status for an item."""
        item_id = call.data["item_id"]
        is_favorite = call.data["is_favorite"]
        config_entry_id = call.data.get("config_entry_id")
        
        try:
            coordinator = _get_coordinator(hass, config_entry_id)
        except ValueError:
             _LOGGER.error("No JellyHA integration found")
             return
        
        if not coordinator or not coordinator._api:
            _LOGGER.error("No JellyHA API client found")
            return
            
        user_id = coordinator.entry.data.get("user_id")
        if not user_id:
            _LOGGER.error("No user ID found in config entry")
            return

        success = await coordinator._api.update_favorite(user_id, item_id, is_favorite)
        if success:
            _LOGGER.info("Updated favorite status for %s to %s", item_id, is_favorite)
            # Force refresh to update UI immediately
            await coordinator.async_refresh()

    if not hass.services.has_service(DOMAIN, "update_favorite"):
        hass.services.async_register(
            DOMAIN,
            "update_favorite",
            async_update_favorite,
            schema=vol.Schema({
                vol.Required("item_id"): cv.string,
                vol.Required("is_favorite"): cv.boolean,
                vol.Optional("config_entry_id"): cv.string,
            }),
        )

    async def async_session_control(call: ServiceCall) -> None:
        """Send control command to session."""
        session_id = call.data["session_id"]
        command = call.data["command"]
        config_entry_id = call.data.get("config_entry_id")
        
        try:
            coordinator = _get_coordinator(hass, config_entry_id)
        except ValueError:
             _LOGGER.error("No JellyHA integration found")
             return
        
        if not coordinator or not coordinator._api:
            _LOGGER.error("No JellyHA API client found")
            return
            
        await coordinator._api.session_control(session_id, command)

    async def async_session_seek(call: ServiceCall) -> None:
        """Send seek command to session."""
        session_id = call.data["session_id"]
        ticks = call.data["position_ticks"]
        config_entry_id = call.data.get("config_entry_id")
        
        try:
            coordinator = _get_coordinator(hass, config_entry_id)
        except ValueError:
             _LOGGER.error("No JellyHA integration found")
             return
        
        if not coordinator or not coordinator._api:
            _LOGGER.error("No JellyHA API client found")
            return
            
        await coordinator._api.session_seek(session_id, ticks)

    if not hass.services.has_service(DOMAIN, SERVICE_SESSION_CONTROL):
        hass.services.async_register(
            DOMAIN,
            SERVICE_SESSION_CONTROL,
            async_session_control,
            schema=SESSION_CONTROL_SCHEMA,
        )

    if not hass.services.has_service(DOMAIN, SERVICE_SESSION_SEEK):
        hass.services.async_register(
            DOMAIN,
            SERVICE_SESSION_SEEK,
            async_session_seek,
            schema=SESSION_SEEK_SCHEMA,
        )

    async def async_session_general_command(call: ServiceCall) -> None:
        """Send a general command (with optional arguments) to session."""
        session_id = call.data["session_id"]
        command = call.data["command"]
        arguments = call.data.get("arguments")
        config_entry_id = call.data.get("config_entry_id")
        
        try:
            coordinator = _get_coordinator(hass, config_entry_id)
        except ValueError:
             _LOGGER.error("No JellyHA integration found")
             return
        
        if not coordinator or not coordinator._api:
            _LOGGER.error("No JellyHA API client found")
            return
            
        await coordinator._api.session_general_command(session_id, command, arguments)

    if not hass.services.has_service(DOMAIN, "session_general_command"):
        hass.services.async_register(
            DOMAIN,
            "session_general_command",
            async_session_general_command,
            schema=SESSION_GENERAL_COMMAND_SCHEMA,
        )

    async def async_mark_watched(call: ServiceCall) -> None:
        """Update watched status for an item."""
        item_id = call.data["item_id"]
        is_played = call.data["is_played"]
        config_entry_id = call.data.get("config_entry_id")
        
        try:
            coordinator = _get_coordinator(hass, config_entry_id)
        except ValueError:
             _LOGGER.error("No JellyHA integration found")
             return
        
        if not coordinator or not coordinator._api:
            _LOGGER.error("No JellyHA API client found")
            return
            
        user_id = coordinator.entry.data.get("user_id")
        if not user_id:
            _LOGGER.error("No user ID found in config entry")
            return

        success = await coordinator._api.update_played_status(user_id, item_id, is_played)
        if success:
            _LOGGER.info("Updated played status for %s to %s", item_id, is_played)
            # Force refresh
            await coordinator.async_refresh()

    if not hass.services.has_service(DOMAIN, "mark_watched"):
        hass.services.async_register(
            DOMAIN,
            "mark_watched",
            async_mark_watched,
            schema=vol.Schema({
                vol.Required("item_id"): cv.string,
                vol.Required("is_played"): cv.boolean,
                vol.Optional("config_entry_id"): cv.string,
            }),
        )

    async def async_search(call: ServiceCall) -> ServiceResponse:
        """Search for media and return results."""
        query = call.data["query"]
        media_type = call.data.get("media_type")
        limit = call.data.get("limit", 5)

        # Find first loaded config entry for JellyHA
        # In multi-server scenarios, this might need an entity_id target to pick specific server
        # For now, default to first available like other services, but we should improve this later
        jellyha_entries = hass.config_entries.async_entries(DOMAIN)
        coordinator = None
        for entry in jellyha_entries:
            if hasattr(entry, "runtime_data") and entry.runtime_data:
                coordinator = entry.runtime_data.library
                break
        
        if not coordinator or not coordinator._api:
            raise ValueError("No JellyHA API client found")
            
        user_id = coordinator.entry.data.get("user_id")
        if not user_id:
             raise ValueError("No user ID found in config entry")

        item_types = [media_type] if media_type else None
        
        try:
            items = await coordinator._api.get_library_items(
                user_id=user_id,
                limit=limit,
                search_term=query,
                item_types=item_types
            )
        except Exception as err:
            _LOGGER.error("Search failed: %s", err)
            raise ValueError(f"Search failed: {err}") from err

        results = []
        for item in items:
            results.append({
                "id": item.get("Id"),
                "name": item.get("Name"),
                "type": item.get("Type"),
                "year": item.get("ProductionYear"),
                "rating": item.get("CommunityRating"),
            })

        return {"items": results}

    if not hass.services.has_service(DOMAIN, SERVICE_SEARCH):
        hass.services.async_register(
            DOMAIN,
            SERVICE_SEARCH,
            async_search,
            schema=SEARCH_SCHEMA,
            supports_response=SupportsResponse.ONLY,
        )

    GET_RECOMMENDATIONS_SCHEMA = vol.Schema(
        {
            vol.Required("item_id"): cv.string,
            vol.Optional("limit", default=5): cv.positive_int,
            vol.Optional("config_entry_id"): cv.string,
        }
    )

    async def async_get_recommendations(call: ServiceCall) -> ServiceResponse:
        """Get recommendations for an item."""
        item_id = call.data["item_id"]
        limit = call.data.get("limit", 5)
        config_entry_id = call.data.get("config_entry_id")

        try:
            coordinator = _get_coordinator(hass, config_entry_id)
        except ValueError as e:
            raise ValueError(str(e)) from e
            
        if not coordinator._api:
             raise ValueError("API not initialized")
        
        if not coordinator or not coordinator._api:
            raise ValueError("No JellyHA integration loaded")
            
        user_id = coordinator.entry.data.get("user_id")
        if not user_id:
             raise ValueError("No user ID found in config entry")

        try:
            items = await coordinator._api.get_similar_items(
                user_id=user_id,
                item_id=item_id,
                limit=limit
            )
        except Exception as err:
            _LOGGER.error("Recommendations failed: %s", err)
            raise ValueError(f"Recommendations failed: {err}") from err

        results = []
        for item in items:
            results.append({
                "id": item.get("Id"),
                "name": item.get("Name"),
                "type": item.get("Type"),
                "year": item.get("ProductionYear"),
                "rating": item.get("CommunityRating"),
                "image_url": coordinator._api.get_image_url(item.get("Id"), "Primary"),
            })

        return {"items": results}

    if not hass.services.has_service(DOMAIN, "get_recommendations"):
        hass.services.async_register(
            DOMAIN,
            "get_recommendations",
            async_get_recommendations,
            schema=GET_RECOMMENDATIONS_SCHEMA,
            supports_response=SupportsResponse.ONLY,
        )

    GET_ITEM_SCHEMA = vol.Schema(
        {
            vol.Required("item_id"): cv.string,
            vol.Optional("config_entry_id"): cv.string,
        }
    )

    async def async_get_item(call: ServiceCall) -> ServiceResponse:
        """Get full details for an item."""
        item_id = call.data["item_id"]
        config_entry_id = call.data.get("config_entry_id")

        try:
            coordinator = _get_coordinator(hass, config_entry_id)
        except ValueError as e:
            raise ValueError(str(e)) from e

        if not coordinator._api:
             raise ValueError("API not initialized")
        
        if not coordinator or not coordinator._api:
            raise ValueError("No JellyHA integration loaded")
            
        user_id = coordinator.entry.data.get("user_id")
        if not user_id:
             raise ValueError("No user ID found in config entry")

        try:
            item = await coordinator._api.get_item(
                user_id=user_id,
                item_id=item_id,
            )
        except Exception as err:
            _LOGGER.error("Get Item failed: %s", err)
            raise ValueError(f"Get Item failed: {err}") from err

        # Return full item dictionary directly
             
        # Return full item dictionary with mapped keys for frontend
        if "MediaSources" in item and item["MediaSources"]:
             # Usually the first source is the main file
             item["media_streams"] = item["MediaSources"][0].get("MediaStreams", [])
        elif "MediaStreams" in item:
             item["media_streams"] = item["MediaStreams"]
             
        # Extract UserData fields for top-level access in frontend
        user_data = item.get("UserData", {})
        item["is_favorite"] = user_data.get("IsFavorite", False)
        item["is_played"] = user_data.get("Played", False)

        # Map other potential missing fields if necessary, but start with streams
        return {"item": item}

    if not hass.services.has_service(DOMAIN, "get_item"):
        hass.services.async_register(
            DOMAIN,
            "get_item",
            async_get_item,
            schema=GET_ITEM_SCHEMA,
            supports_response=SupportsResponse.ONLY,
        )