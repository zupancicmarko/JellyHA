"""Services for JellyHA integration - Tuned 2026 Quality Strategy."""
from __future__ import annotations

import logging
import asyncio
from typing import Any
import random
import voluptuous as vol

from homeassistant.core import HomeAssistant, ServiceCall, SupportsResponse, ServiceResponse
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers import entity_registry as er
from homeassistant.components.media_player import (
    DOMAIN as MEDIA_PLAYER_DOMAIN,
    SERVICE_PLAY_MEDIA,
    SERVICE_MEDIA_STOP,
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
SERVICE_SESSION_PLAY = "session_play"
SERVICE_SESSION_SEEK = "session_seek"
SERVICE_SESSION_GENERAL_COMMAND = "session_general_command"
SERVICE_UPDATE_FAVORITE = "update_favorite"
SERVICE_MARK_WATCHED = "mark_watched"
SERVICE_SEARCH = "search"
SERVICE_GET_RECOMMENDATIONS = "get_recommendations"
SERVICE_GET_ITEM = "get_item"
SERVICE_GET_LIVE_TV_CHANNELS = "get_live_tv_channels"
SERVICE_PLAY_LIVE_TV_CHANNEL = "play_live_tv_channel"
SERVICE_MUSIC_SEARCH = "music_search"
SERVICE_PLAY_MUSIC = "play_music"
SERVICE_PLAY_PLAYLIST = "play_playlist"
SERVICE_GET_PLAYLISTS = "get_playlists"
SERVICE_GET_COLLECTIONS = "get_collections"

def _get_coordinator(
    hass: HomeAssistant,
    config_entry_id: str | None = None,
    entity_id: str | None = None,
    prefer_music: bool = False,
):
    """Get the JellyHA coordinator from config_entry_id or entity_id."""
    if config_entry_id:
        entry = hass.config_entries.async_get_entry(config_entry_id)
        if entry and entry.domain == DOMAIN and hasattr(entry, "runtime_data") and entry.runtime_data:
            return entry.runtime_data.library

    if entity_id:
        # Check entity registry first
        registry = er.async_get(hass)
        ent = registry.async_get(entity_id)
        if ent and ent.config_entry_id:
            c_entry = hass.config_entries.async_get_entry(ent.config_entry_id)
            if c_entry and c_entry.domain == DOMAIN and hasattr(c_entry, "runtime_data") and c_entry.runtime_data:
                return c_entry.runtime_data.library

        # Fallback: check state attributes for entry_id
        state = hass.states.get(entity_id)
        if state and "entry_id" in state.attributes:
            c_entry = hass.config_entries.async_get_entry(state.attributes["entry_id"])
            if c_entry and c_entry.domain == DOMAIN and hasattr(c_entry, "runtime_data") and c_entry.runtime_data:
                return c_entry.runtime_data.library

    jellyha_entries = [
        e for e in hass.config_entries.async_entries(DOMAIN)
        if hasattr(e, "runtime_data") and e.runtime_data
    ]
    if not jellyha_entries:
        raise ValueError("No JellyHA integration loaded")

    # Multi-instance smart selection for music operations
    if prefer_music and len(jellyha_entries) > 1:
        # 1. Prefer instance with 'music' in label or device_name
        for entry in jellyha_entries:
            label = str(entry.data.get("instance_label", "")).lower()
            name = str(entry.data.get("device_name", "")).lower()
            if "music" in label or "music" in name:
                return entry.runtime_data.library

        # 2. Prefer instance with song count > 0
        for entry in jellyha_entries:
            lib = entry.runtime_data.library
            counts = getattr(lib, "item_counts", {})
            if counts.get("songs", 0) > 0 or counts.get("albums", 0) > 0:
                return lib

        # 3. Prefer instance with all libraries (no restricted library list)
        for entry in jellyha_entries:
            if not entry.data.get("libraries"):
                return entry.runtime_data.library

    # Default to first available entry
    return jellyha_entries[0].runtime_data.library


def _clean_transformed_item(item: dict[str, Any]) -> dict[str, Any]:
    """Strip irrelevant null attributes depending on media type to return clean service responses."""
    if not isinstance(item, dict):
        return item

    item_type = item.get("type")
    cleaned = dict(item)

    video_series_keys = {
        "series_name", "series_id", "season", "episode", "season_name",
        "series_poster_url", "total_episodes", "unplayed_count",
        "dynamic_range", "video_range", "video_range_type", "video_codec",
        "video_bit_depth", "dv_profile", "width", "height", "resolution",
        "aspect_ratio", "trailer_url", "media_streams",
    }
    music_keys = {
        "artist_name", "album_artist", "album", "album_id",
        "track_number", "disc_number", "stream_url", "audio_container",
        "audio_quality_label",
    }
    tv_series_keys = {
        "series_name", "series_id", "season", "episode", "season_name",
        "series_poster_url", "total_episodes", "unplayed_count",
    }

    if item_type in ("Audio", "MusicAlbum", "MusicArtist"):
        for k in video_series_keys:
            cleaned.pop(k, None)
    elif item_type == "Movie":
        for k in music_keys:
            cleaned.pop(k, None)
        for k in tv_series_keys:
            cleaned.pop(k, None)
    elif item_type == "Series":
        for k in music_keys:
            cleaned.pop(k, None)
        for k in (
            "season", "episode", "season_name", "series_name", "series_id",
            "series_poster_url", "dynamic_range", "video_range", "video_range_type",
            "video_codec", "video_bit_depth", "dv_profile", "width", "height",
            "resolution", "aspect_ratio", "trailer_url", "media_streams",
            "audio_codec", "audio_channels", "audio_bit_rate", "audio_sample_rate",
            "audio_bit_depth", "audio_channel_layout", "is_lossless", "is_hi_res",
        ):
            cleaned.pop(k, None)
    elif item_type == "Episode":
        for k in music_keys:
            cleaned.pop(k, None)

    return cleaned


# Schemas
PLAY_ON_CHROMECAST_SCHEMA = vol.Schema(
    {
        vol.Required("entity_id"): cv.entity_id,
        vol.Required("item_id"): cv.string,
        vol.Optional("use_series_image", default=True): cv.boolean,
        vol.Optional("server_entity_id"): cv.entity_id,
        vol.Optional("config_entry_id"): cv.string,
        vol.Optional("subtitle_mode", default="auto"): vol.In(["auto", "none", "forced_only", "custom"]),
        vol.Optional("subtitle_language"): vol.Any(cv.string, None),
        vol.Optional("subtitle_index"): vol.Any(vol.Coerce(int), None),
    }
)

DELETE_ITEM_SCHEMA = vol.Schema(
    {
        vol.Required("item_id"): cv.string,
        vol.Optional("entity_id"): cv.entity_id,
        vol.Optional("server_entity_id"): cv.entity_id,
        vol.Optional("config_entry_id"): cv.string,
    }
)

SESSION_CONTROL_SCHEMA = vol.Schema(
    {
        vol.Required("session_id"): cv.string,
        vol.Required("command"): vol.In(["Pause", "Unpause", "PlayPause", "TogglePause", "Stop", "NextTrack", "PreviousTrack", "Shuffle", "SetRepeatMode"]),
        vol.Optional("entity_id"): cv.entity_id,
        vol.Optional("server_entity_id"): cv.entity_id,
        vol.Optional("config_entry_id"): cv.string,
    }
)

SESSION_SEEK_SCHEMA = vol.Schema(
    {
        vol.Required("session_id"): cv.string,
        vol.Optional("position_ticks"): cv.positive_int,
        vol.Optional("position_seconds"): vol.Coerce(float),
        vol.Optional("entity_id"): cv.entity_id,
        vol.Optional("server_entity_id"): cv.entity_id,
        vol.Optional("config_entry_id"): cv.string,
    }
)

SESSION_GENERAL_COMMAND_SCHEMA = vol.Schema(
    {
        vol.Required("session_id"): cv.string,
        vol.Required("command"): cv.string,
        vol.Optional("arguments"): dict,
        vol.Optional("entity_id"): cv.entity_id,
        vol.Optional("server_entity_id"): cv.entity_id,
        vol.Optional("config_entry_id"): cv.string,
    }
)

SESSION_PLAY_SCHEMA = vol.Schema(
    {
        vol.Required("item_id"): cv.string,
        vol.Optional("device_name"): cv.string,
        vol.Optional("device_id"): cv.string,
        vol.Optional("client"): cv.string,
        vol.Optional("session_id"): cv.string,
        vol.Optional("entity_id"): cv.entity_id,
        vol.Optional("play_command", default="PlayNow"): vol.In(
            ["PlayNow", "PlayNext", "PlayLast"]
        ),
        vol.Optional("start_position_ticks"): cv.positive_int,
        vol.Optional("server_entity_id"): cv.entity_id,
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
        vol.Optional("sort_by"): cv.string,
        vol.Optional("sort_order"): vol.In(["Ascending", "Descending", "ascending", "descending"]),
        vol.Optional("parent_id"): cv.string,
        vol.Optional("series_id"): cv.string,
        vol.Optional("official_rating"): cv.string,
        vol.Optional("studio"): cv.string,
        vol.Optional("person"): cv.string,
        vol.Optional("offset"): vol.All(vol.Coerce(int), vol.Range(min=0)),
        vol.Optional("entity_id"): cv.entity_id,
        vol.Optional("server_entity_id"): cv.entity_id,
        vol.Optional("config_entry_id"): cv.string,
    }
)

UPDATE_FAVORITE_SCHEMA = vol.Schema({
    vol.Required("item_id"): cv.string,
    vol.Required("is_favorite"): cv.boolean,
    vol.Optional("entity_id"): cv.entity_id,
    vol.Optional("server_entity_id"): cv.entity_id,
    vol.Optional("config_entry_id"): cv.string,
})

MARK_WATCHED_SCHEMA = vol.Schema({
    vol.Required("item_id"): cv.string,
    vol.Required("is_played"): cv.boolean,
    vol.Optional("entity_id"): cv.entity_id,
    vol.Optional("server_entity_id"): cv.entity_id,
    vol.Optional("config_entry_id"): cv.string,
})

GET_RECOMMENDATIONS_SCHEMA = vol.Schema({
    vol.Required("item_id"): cv.string,
    vol.Optional("limit", default=5): cv.positive_int,
    vol.Optional("entity_id"): cv.entity_id,
    vol.Optional("server_entity_id"): cv.entity_id,
    vol.Optional("config_entry_id"): cv.string,
})

GET_ITEM_SCHEMA = vol.Schema({
    vol.Required("item_id"): cv.string,
    vol.Optional("entity_id"): cv.entity_id,
    vol.Optional("server_entity_id"): cv.entity_id,
    vol.Optional("config_entry_id"): cv.string,
})

LIVE_TV_CHANNELS_SCHEMA = vol.Schema({
    vol.Optional("query"): cv.string,
    vol.Optional("limit"): cv.positive_int,
    vol.Optional("entity_id"): cv.entity_id,
    vol.Optional("server_entity_id"): cv.entity_id,
    vol.Optional("config_entry_id"): cv.string,
})

PLAY_LIVE_TV_CHANNEL_SCHEMA = vol.Schema({
    vol.Optional("channel_name"): cv.string,
    vol.Optional("channel_number"): cv.string,
    vol.Optional("entity_id"): cv.entity_id,
    vol.Optional("session_id"): cv.string,
    vol.Optional("device_name"): cv.string,
    vol.Optional("device_id"): cv.string,
    vol.Optional("client"): cv.string,
    vol.Optional("server_entity_id"): cv.entity_id,
    vol.Optional("config_entry_id"): cv.string,
})

MUSIC_SEARCH_SCHEMA = vol.Schema(
    {
        vol.Optional("query"): cv.string,
        vol.Optional("search_type", default="all"): vol.In(
            ["all", "track", "song", "album", "artist"]
        ),
        vol.Optional("artist"): cv.string,
        vol.Optional("album"): cv.string,
        vol.Optional("genre"): cv.string,
        vol.Optional("year"): cv.positive_int,
        vol.Optional("codec"): cv.string,
        vol.Optional("is_hi_res"): cv.boolean,
        vol.Optional("is_lossless"): cv.boolean,
        vol.Optional("is_favorite"): cv.boolean,
        vol.Optional("limit", default=20): cv.positive_int,
        vol.Optional("offset", default=0): vol.All(vol.Coerce(int), vol.Range(min=0)),
        vol.Optional("sort_by"): cv.string,
        vol.Optional("sort_order"): vol.In(["Ascending", "Descending", "ascending", "descending"]),
        vol.Optional("config_entry_id"): cv.string,
        vol.Optional("server_entity_id"): cv.entity_id,
        vol.Optional("entity_id"): cv.entity_id,
    }
)

PLAY_MUSIC_SCHEMA = vol.Schema(
    {
        vol.Required("entity_id"): cv.entity_id,
        vol.Optional("query"): cv.string,
        vol.Optional("artist"): cv.string,
        vol.Optional("album"): cv.string,
        vol.Optional("search_type", default="track"): vol.In(
            ["track", "song", "album", "all"]
        ),
        vol.Optional("genre"): cv.string,
        vol.Optional("year"): cv.positive_int,
        vol.Optional("codec"): cv.string,
        vol.Optional("is_hi_res"): cv.boolean,
        vol.Optional("is_lossless"): cv.boolean,
        vol.Optional("item_id"): cv.string,
        vol.Optional("config_entry_id"): cv.string,
        vol.Optional("server_entity_id"): cv.entity_id,
    }
)

PLAY_PLAYLIST_SCHEMA = vol.Schema(
    {
        vol.Required("entity_id"): cv.entity_id,
        vol.Optional("playlist"): cv.string,
        vol.Optional("playlist_name"): cv.string,
        vol.Optional("playlist_id"): cv.string,
        vol.Optional("shuffle", default=False): cv.boolean,
        vol.Optional("config_entry_id"): cv.string,
        vol.Optional("server_entity_id"): cv.entity_id,
    }
)

GET_PLAYLISTS_SCHEMA = vol.Schema(
    {
        vol.Optional("query"): cv.string,
        vol.Optional("limit", default=50): cv.positive_int,
        vol.Optional("config_entry_id"): cv.string,
        vol.Optional("server_entity_id"): cv.entity_id,
        vol.Optional("entity_id"): cv.entity_id,
    }
)

GET_COLLECTIONS_SCHEMA = vol.Schema(
    {
        vol.Optional("query"): cv.string,
        vol.Optional("limit", default=50): cv.positive_int,
        vol.Optional("include_items", default=True): cv.boolean,
        vol.Optional("config_entry_id"): cv.string,
        vol.Optional("server_entity_id"): cv.entity_id,
        vol.Optional("entity_id"): cv.entity_id,
    }
)

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
        user_id = coordinator.entry.data.get("user_id")

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
                if not next_episode:
                    # Fallback: if next_up returns None (e.g. unstarted series), find the first unplayed episode
                    first_unplayed = await api.get_library_items(
                        user_id=user_id,
                        item_types=["Episode"],
                        parent_id=series_id,
                        is_played=False,
                        sort_by="IndexNumber",
                        sort_order="Ascending",
                        limit=1,
                    )
                    if first_unplayed:
                        next_episode = first_unplayed[0]
                    else:
                        # If all are played or no unplayed found, fall back to first episode
                        all_eps = await api.get_library_items(
                            user_id=user_id,
                            item_types=["Episode"],
                            parent_id=series_id,
                            sort_by="IndexNumber",
                            sort_order="Ascending",
                            limit=1,
                        )
                        if all_eps:
                            next_episode = all_eps[0]

                if next_episode:
                    item = next_episode
                    item_id = item.get("Id")
                else:
                    _LOGGER.warning("No playable episode found for series %s", series_id)
                    return

        # Strategy logic
        from .media_strategy import MediaStrategy
        zc = None
        try:
            from homeassistant.components import zeroconf
            zc = await zeroconf.async_get_instance(hass)
        except Exception:
            pass

        model_name, _ = await hass.async_add_executor_job(
            MediaStrategy.discover_chromecast_model, hass, target_entity_id, zc
        )

        # Subtitle selection
        subtitle_mode = call.data.get("subtitle_mode", "auto")
        subtitle_language = call.data.get("subtitle_language")
        subtitle_index = call.data.get("subtitle_index")

        user_config = None
        if subtitle_mode == "auto":
            try:
                user_obj = await api.get_user(user_id)
                if user_obj:
                    user_config = user_obj.get("Configuration", {})
            except Exception as e:
                _LOGGER.debug("Could not fetch user configuration for subtitle resolution: %s", e)

        selected_sub = MediaStrategy.resolve_subtitle_stream(
            item=item,
            subtitle_mode=subtitle_mode,
            subtitle_language=subtitle_language,
            user_config=user_config,
            subtitle_index=subtitle_index,
        )

        media_source_id = None
        if "MediaSources" in item and item["MediaSources"]:
            media_source_id = item["MediaSources"][0].get("Id")

        media_info = MediaStrategy.analyze_media(item)
        playback_info = MediaStrategy.get_playback_info(
            api._server_url,
            api._api_key,
            item_id,
            media_info,
            model_name,
            item_type=item.get("Type"),
            selected_sub=selected_sub,
            media_source_id=media_source_id,
        )

        # Cast
        use_series_img = call.data.get("use_series_image", True)
        is_episode = item.get("Type") == "Episode"
        series_id = item.get("SeriesId")

        # Choose primary image: series poster for episodes if enabled, otherwise item image
        if is_episode and series_id and use_series_img:
            primary_img_url = api.get_image_url(series_id, "Primary")
        else:
            primary_img_url = api.get_image_url(item_id, "Primary")

        metadata = {"title": item.get("Name", "Jellyfin Media"), "images": [{"url": primary_img_url}]}
        if is_episode:
            metadata.update({
                "metadataType": 1,
                "seriesTitle": item.get("SeriesName"),
                "season": item.get("ParentIndexNumber"),
                "episode": item.get("IndexNumber"),
            })
            # Also include episode still as secondary image in metadata
            episode_img_url = api.get_image_url(item_id, "Primary")
            if episode_img_url != primary_img_url:
                metadata["images"].append({"url": episode_img_url})

        extra_payload = {
            "title": metadata["title"],
            "thumb": primary_img_url,
            "autoplay": True,
            "metadata": metadata,
        }
        if playback_info.get("vtt_url"):
            extra_payload.update({
                "subtitles": playback_info["vtt_url"],
                "subtitles_lang": playback_info.get("subtitles_lang", "en"),
                "subtitles_mime": "text/vtt",
                "subtitle_id": 1,
            })

        # Stop any ongoing playback on the target device so Chromecast cleanly re-initializes
        target_state = hass.states.get(target_entity_id)
        if target_state and target_state.state in ["playing", "paused", "buffering"]:
            try:
                await hass.services.async_call(
                    MEDIA_PLAYER_DOMAIN,
                    SERVICE_MEDIA_STOP,
                    {"entity_id": target_entity_id},
                    blocking=True,
                )
                await asyncio.sleep(0.3)
            except Exception as e:
                _LOGGER.debug("Could not stop previous media on %s: %s", target_entity_id, e)

        await hass.services.async_call(
            MEDIA_PLAYER_DOMAIN, SERVICE_PLAY_MEDIA,
            {
                "entity_id": target_entity_id,
                ATTR_MEDIA_CONTENT_ID: playback_info["media_url"],
                ATTR_MEDIA_CONTENT_TYPE: playback_info["content_type"],
                "extra": extra_payload,
            },
            blocking=True,
        )

    async def async_search(call: ServiceCall) -> ServiceResponse:
        """Search for media and return results."""
        try:
            entity_id = call.data.get("entity_id") or call.data.get("server_entity_id")
            coordinator = _get_coordinator(hass, call.data.get("config_entry_id"), entity_id)
        except ValueError as e:
            raise ValueError(str(e)) from e
            
        user_id = coordinator.entry.data.get("user_id")
        media_type = call.data.get("media_type")
        limit = call.data.get("limit", 5)
        query = call.data.get("query")
        sort_by = call.data.get("sort_by")
        sort_order = call.data.get("sort_order")
        parent_id = call.data.get("parent_id") or call.data.get("series_id")
        official_rating = call.data.get("official_rating")
        studio = call.data.get("studio")
        person = call.data.get("person")
        offset = call.data.get("offset")

        if media_type == "MusicArtist":
            params = {
                "SortBy": sort_by or "SortName",
                "SortOrder": sort_order or "Ascending",
                "Recursive": "true",
                "Fields": "PrimaryImageAspectRatio",
                "Limit": str(limit),
            }
            if offset and offset > 0:
                params["StartIndex"] = str(offset)
            if query:
                params["searchTerm"] = query
            result = await coordinator._api._request("GET", "/Artists/AlbumArtists", params=params)
            items = result.get("Items", [])
        else:
            items = await coordinator._api.get_library_items(
                user_id=user_id,
                limit=limit,
                search_term=query,
                item_types=[media_type] if media_type else None,
                is_played=call.data.get("is_played"),
                is_favorite=call.data.get("is_favorite"),
                genre=call.data.get("genre"),
                year=call.data.get("year"),
                min_rating=call.data.get("min_rating"),
                season=call.data.get("season"),
                episode=call.data.get("episode"),
                sort_by=sort_by,
                sort_order=sort_order,
                parent_id=parent_id,
                official_rating=official_rating,
                studio=studio,
                person=person,
                offset=offset,
            )

        results = list(await asyncio.gather(*(coordinator._async_transform_item(item) for item in items)))
        return {"items": [_clean_transformed_item(item) for item in results]}

    async def async_music_search(call: ServiceCall) -> ServiceResponse:
        """Search music library and return items with rich audio metadata."""
        entity_id = call.data.get("entity_id") or call.data.get("server_entity_id")
        config_entry_id = call.data.get("config_entry_id")
        coordinator = _get_coordinator(hass, config_entry_id, entity_id, prefer_music=True)

        user_id = coordinator.entry.data.get("user_id")
        query = call.data.get("query")
        search_type = call.data.get("search_type", "all")
        artist = call.data.get("artist")
        album = call.data.get("album")
        genre = call.data.get("genre")
        year = call.data.get("year")
        codec_filter = (call.data.get("codec") or "").strip().lower()
        is_hi_res = call.data.get("is_hi_res")
        is_lossless = call.data.get("is_lossless")
        is_favorite = call.data.get("is_favorite")
        limit = call.data.get("limit", 20)
        offset = call.data.get("offset", 0)
        sort_by = call.data.get("sort_by")
        sort_order = call.data.get("sort_order")

        # When filtering by codec/hi-res/lossless in-memory, fetch a larger batch
        needs_post_filter = bool(codec_filter or is_hi_res is not None or is_lossless is not None)
        fetch_limit = min(max(limit * 5, 50), 200) if needs_post_filter else limit

        configured_libs = coordinator.entry.data.get("libraries", [])

        raw_items = await coordinator._api.search_music(
            user_id=user_id,
            query=query,
            search_type=search_type,
            artist=artist,
            album=album,
            genre=genre,
            year=year,
            is_favorite=is_favorite,
            limit=fetch_limit,
            offset=offset,
            sort_by=sort_by,
            sort_order=sort_order,
            library_ids=configured_libs if configured_libs else None,
        )

        transformed = list(
            await asyncio.gather(*(coordinator._async_transform_item(item) for item in raw_items))
        )

        # Apply post-filters if specified
        results = []
        for item in transformed:
            if codec_filter and (item.get("audio_codec") or "").lower() != codec_filter:
                continue
            if is_hi_res is not None and item.get("is_hi_res") != is_hi_res:
                continue
            if is_lossless is not None and item.get("is_lossless") != is_lossless:
                continue
            results.append(_clean_transformed_item(item))
            if len(results) >= limit:
                break

        return {"items": results}

    async def async_play_music(call: ServiceCall) -> None:
        """Search and play a music track or album on a Home Assistant media player."""
        target_player = call.data["entity_id"]
        direct_item_id = call.data.get("item_id")
        config_entry_id = call.data.get("config_entry_id")
        server_entity_id = call.data.get("server_entity_id")
        coordinator = _get_coordinator(hass, config_entry_id, server_entity_id, prefer_music=True)
        api = coordinator._api
        user_id = coordinator.entry.data.get("user_id")

        item = None
        if direct_item_id:
            raw = await api.get_item(user_id, direct_item_id)
            if raw:
                item = await coordinator._async_transform_item(raw)
        else:
            # Search using music_search logic
            search_res = await async_music_search(
                ServiceCall(
                    DOMAIN,
                    SERVICE_MUSIC_SEARCH,
                    {
                        "query": call.data.get("query"),
                        "artist": call.data.get("artist"),
                        "album": call.data.get("album"),
                        "search_type": call.data.get("search_type", "track"),
                        "genre": call.data.get("genre"),
                        "year": call.data.get("year"),
                        "codec": call.data.get("codec"),
                        "is_hi_res": call.data.get("is_hi_res"),
                        "is_lossless": call.data.get("is_lossless"),
                        "limit": 1,
                        "config_entry_id": coordinator.entry.entry_id,
                    },
                )
            )
            items = search_res.get("items", []) if isinstance(search_res, dict) else []
            if items:
                item = items[0]

        if not item:
            _LOGGER.warning(
                "No music track found matching query=%s, artist=%s, album=%s",
                call.data.get("query"),
                call.data.get("artist"),
                call.data.get("album"),
            )
            raise ValueError(
                f"No music found in Jellyfin for query='{call.data.get('query')}' artist='{call.data.get('artist')}'"
            )

        # Resolve media URL and MIME type
        item_id = item["id"]
        item_type = item.get("type", "Audio")
        container = (item.get("audio_container") or item.get("container") or "mp3").lower()

        # If an album was selected, resolve to its first track
        if item_type == "MusicAlbum":
            try:
                tracks_result = await api._request(
                    "GET",
                    "/Items",
                    params={
                        "UserId": user_id,
                        "ParentId": item_id,
                        "IncludeItemTypes": "Audio",
                        "SortBy": "IndexNumber",
                        "SortOrder": "Ascending",
                        "Limit": 1,
                        "Recursive": "true",
                    },
                )
                first_tracks = tracks_result.get("Items", [])
                if first_tracks:
                    item = await coordinator._async_transform_item(first_tracks[0])
                    item_id = item["id"]
                    container = (item.get("audio_container") or item.get("container") or "mp3").lower()
                else:
                    raise ValueError(f"Album '{item.get('name')}' has no playable tracks")
            except Exception as err:
                _LOGGER.debug("Could not resolve first track for album %s: %s", item_id, err)
                if isinstance(err, ValueError):
                    raise

        # Determine exact MIME type
        if container == "flac":
            mime_type = "audio/flac"
        elif container in ("m4a", "aac"):
            mime_type = "audio/mp4"
        elif container in ("ogg", "oga", "opus"):
            mime_type = "audio/ogg"
        elif container == "wav":
            mime_type = "audio/wav"
        else:
            mime_type = "audio/mpeg"

        # Stream URL
        media_url = item.get("stream_url")
        if not media_url:
            media_url = f"{api._server_url}/Audio/{item_id}/stream?static=true&api_key={api._api_key}&ApiKey={api._api_key}"

        # Cover art: provide direct absolute server URL so external speakers (Chromecast, Sonos) can load it
        thumb_url = api.get_image_url(item_id, "Primary")
        album_id = item.get("album_id")
        if not thumb_url and album_id:
            thumb_url = api.get_image_url(album_id, "Primary")

        title = item.get("name")
        artist = item.get("artist_name") or item.get("album_artist")
        album = item.get("album")

        metadata = {
            "metadataType": 3,
            "title": title,
            "artist": artist,
            "albumTitle": album,
        }
        if thumb_url:
            metadata["images"] = [{"url": thumb_url}]

        extra_payload = {
            "title": title,
            "artist": artist,
            "album_name": album,
            "thumb": thumb_url,
            "autoplay": True,
            "metadata": metadata,
        }

        # Check if target_player is a Jellyfin session or Jellyfin media player entity
        target_session_id = None
        session_coord = getattr(coordinator.entry.runtime_data, "session", None)
        if session_coord and session_coord.data:
            target_state = hass.states.get(target_player)
            if target_state:
                target_session_id = target_state.attributes.get("session_id")
                if not target_session_id and "device_name" in target_state.attributes:
                    d_name = target_state.attributes["device_name"]
                    for s in session_coord.data:
                        if s.get("DeviceName") == d_name:
                            target_session_id = s.get("Id")
                            break

        if target_session_id:
            _LOGGER.info(
                "Playing '%s' (%s) directly on Jellyfin session %s",
                item.get("name"),
                item_id,
                target_session_id,
            )
            await api.session_play(target_session_id, item_id)
            return

        # Stop previous playback if currently active to reset buffers
        target_state = hass.states.get(target_player)
        if target_state and target_state.state in ("playing", "paused", "buffering"):
            try:
                await hass.services.async_call(
                    MEDIA_PLAYER_DOMAIN,
                    SERVICE_MEDIA_STOP,
                    {"entity_id": target_player},
                    blocking=True,
                )
                await asyncio.sleep(0.2)
            except Exception as err:
                _LOGGER.debug("Could not stop prior playback on %s: %s", target_player, err)

        _LOGGER.info(
            "Playing '%s' by '%s' on %s (MIME: %s)",
            item.get("name"),
            item.get("artist_name"),
            target_player,
            mime_type,
        )

        await hass.services.async_call(
            MEDIA_PLAYER_DOMAIN,
            SERVICE_PLAY_MEDIA,
            {
                "entity_id": target_player,
                ATTR_MEDIA_CONTENT_ID: media_url,
                ATTR_MEDIA_CONTENT_TYPE: mime_type,
                "extra": extra_payload,
            },
            blocking=True,
        )

    async def async_play_playlist(call: ServiceCall) -> None:
        """Play a playlist on a target player with optional shuffle."""
        target_player = call.data["entity_id"]
        playlist_query = (
            call.data.get("playlist")
            or call.data.get("playlist_name")
            or call.data.get("playlist_id")
        )
        if not playlist_query:
            raise ValueError("Either 'playlist', 'playlist_name', or 'playlist_id' must be provided")

        shuffle = call.data.get("shuffle", False)
        server_entity_id = call.data.get("server_entity_id")
        config_entry_id = call.data.get("config_entry_id")

        try:
            coordinator = _get_coordinator(
                hass,
                config_entry_id,
                server_entity_id,
                prefer_music=True,
            )
        except ValueError as e:
            raise ValueError(str(e)) from e

        api = getattr(coordinator, "api", None) or getattr(coordinator, "_api", None)
        user_id = coordinator.entry.data.get("user_id")

        if not api or not user_id:
            raise ValueError("Jellyfin API or user_id not available")

        # 1. Resolve playlist item
        playlist_item = None
        # Check if query is a direct 32-char hex ID
        if len(playlist_query) == 32 and all(c in "0123456789abcdefABCDEF" for c in playlist_query):
            try:
                raw_item = await api.get_item(user_id, playlist_query)
                if raw_item and raw_item.get("Type") == "Playlist":
                    playlist_item = raw_item
            except Exception:
                playlist_item = None

        if not playlist_item:
            # Query all user playlists
            raw_playlists = await api.get_library_items(
                user_id=user_id,
                limit=100,
                item_types=["Playlist"],
            )
            # Find match: exact case-insensitive first, then substring
            q_lower = playlist_query.lower().strip()
            for p in raw_playlists:
                if p.get("Name", "").lower().strip() == q_lower:
                    playlist_item = p
                    break
            if not playlist_item:
                for p in raw_playlists:
                    if q_lower in p.get("Name", "").lower():
                        playlist_item = p
                        break

        if not playlist_item:
            raise ValueError(f"Playlist '{playlist_query}' not found on Jellyfin server")

        playlist_id = playlist_item["Id"]
        playlist_name = playlist_item.get("Name", "Playlist")

        # 2. Check if target_player is a Jellyfin session or Jellyfin media player entity
        target_session_id = None
        session_coord = getattr(coordinator.entry.runtime_data, "session", None)
        if session_coord and session_coord.data:
            target_state = hass.states.get(target_player)
            if target_state:
                target_session_id = target_state.attributes.get("session_id")
                if not target_session_id and "device_name" in target_state.attributes:
                    d_name = target_state.attributes["device_name"]
                    for s in session_coord.data:
                        if s.get("DeviceName") == d_name:
                            target_session_id = s.get("Id")
                            break

        if target_session_id:
            # Native Jellyfin session queue
            _LOGGER.info(
                "Playing playlist '%s' (%s) directly on Jellyfin session %s",
                playlist_name,
                playlist_id,
                target_session_id,
            )
            await api.session_play(target_session_id, playlist_id)
            if shuffle:
                await asyncio.sleep(0.3)
                await api.session_general_command(
                    target_session_id, "SetShuffleQueue", {"ShuffleMode": "Shuffle"}
                )
            return

        # 3. For standard Home Assistant media players (Chromecast, Sonos, etc.)
        params = {
            "UserId": user_id,
            "ParentId": playlist_id,
            "Recursive": "true",
            "Fields": "Genres,RunTimeTicks,AlbumArtist,Artists,Album,MediaStreams,MediaSources,Path",
            "SortBy": "IndexNumber",
            "SortOrder": "Ascending",
        }
        res = await api._request("GET", "/Items", params=params)
        tracks = res.get("Items", []) if isinstance(res, dict) else []
        if not tracks:
            raise ValueError(f"Playlist '{playlist_name}' has no playable tracks")

        if shuffle:
            random.shuffle(tracks)

        # Get first track
        first_track = tracks[0]
        first_id = first_track["Id"]
        first_transformed = await coordinator._async_transform_item(first_track)

        container = (
            first_transformed.get("audio_container")
            or first_transformed.get("container")
            or "mp3"
        ).lower()
        if container == "flac":
            mime_type = "audio/flac"
        elif container in ("m4a", "aac"):
            mime_type = "audio/mp4"
        elif container in ("ogg", "oga", "opus"):
            mime_type = "audio/ogg"
        elif container == "wav":
            mime_type = "audio/wav"
        else:
            mime_type = "audio/mpeg"

        media_url = first_transformed.get("stream_url")
        if not media_url:
            media_url = f"{api._server_url}/Audio/{first_id}/stream?static=true&api_key={api._api_key}&ApiKey={api._api_key}"

        thumb_url = api.get_image_url(first_id, "Primary") or api.get_image_url(playlist_id, "Primary")
        title = first_transformed.get("name")
        artist = (
            first_transformed.get("artist_name")
            or first_transformed.get("album_artist")
            or playlist_name
        )
        album = first_transformed.get("album") or playlist_name

        metadata = {
            "metadataType": 3,
            "title": title,
            "artist": artist,
            "albumTitle": album,
        }
        if thumb_url:
            metadata["images"] = [{"url": thumb_url}]

        extra_payload = {
            "title": title,
            "artist": artist,
            "album_name": album,
            "thumb": thumb_url,
            "autoplay": True,
            "metadata": metadata,
            "playlist_id": playlist_id,
            "playlist_name": playlist_name,
            "total_tracks": len(tracks),
        }

        # Stop prior playback if active
        target_state = hass.states.get(target_player)
        if target_state and target_state.state in ("playing", "paused", "buffering"):
            try:
                await hass.services.async_call(
                    MEDIA_PLAYER_DOMAIN,
                    SERVICE_MEDIA_STOP,
                    {"entity_id": target_player},
                    blocking=True,
                )
                await asyncio.sleep(0.2)
            except Exception as err:
                _LOGGER.debug("Could not stop prior playback on %s: %s", target_player, err)

        _LOGGER.info(
            "Playing playlist '%s' track '%s' on %s (MIME: %s)",
            playlist_name,
            title,
            target_player,
            mime_type,
        )
        await hass.services.async_call(
            MEDIA_PLAYER_DOMAIN,
            SERVICE_PLAY_MEDIA,
            {
                "entity_id": target_player,
                ATTR_MEDIA_CONTENT_ID: media_url,
                ATTR_MEDIA_CONTENT_TYPE: mime_type,
                "extra": extra_payload,
            },
            blocking=True,
        )

    async def async_get_playlists(call: ServiceCall) -> ServiceResponse:
        """Get all user playlists from Jellyfin."""
        try:
            entity_id = call.data.get("entity_id") or call.data.get("server_entity_id")
            coordinator = _get_coordinator(
                hass, call.data.get("config_entry_id"), entity_id, prefer_music=True
            )
        except ValueError as e:
            raise ValueError(str(e)) from e

        api = getattr(coordinator, "api", None) or getattr(coordinator, "_api", None)
        user_id = coordinator.entry.data.get("user_id")

        if not api or not user_id:
            raise ValueError("Jellyfin API or user_id not available")

        limit = call.data.get("limit", 50)
        query = call.data.get("query")

        raw_playlists = await api.get_library_items(
            user_id=user_id,
            limit=limit,
            search_term=query,
            item_types=["Playlist"],
        )

        playlists = []
        for p in raw_playlists:
            pid = p.get("Id", "")
            run_time_ticks = p.get("RunTimeTicks", 0)
            runtime_mins = round(run_time_ticks / (10_000_000 * 60)) if run_time_ticks else None
            playlists.append(
                {
                    "id": pid,
                    "name": p.get("Name", "Unknown Playlist"),
                    "item_count": p.get("ChildCount") or p.get("RecursiveItemCount") or 0,
                    "runtime_minutes": runtime_mins,
                    "image_url": api.get_image_url(pid, "Primary") if pid else None,
                    "is_favorite": p.get("UserData", {}).get("IsFavorite", False),
                }
            )

        return {"playlists": playlists, "count": len(playlists)}

    async def async_get_collections(call: ServiceCall) -> ServiceResponse:
        """Get BoxSets / Collections from Jellyfin."""
        try:
            entity_id = call.data.get("entity_id") or call.data.get("server_entity_id")
            coordinator = _get_coordinator(
                hass, call.data.get("config_entry_id"), entity_id
            )
        except ValueError as e:
            raise ValueError(str(e)) from e

        api = getattr(coordinator, "api", None) or getattr(coordinator, "_api", None)
        user_id = coordinator.entry.data.get("user_id")

        if not api or not user_id:
            raise ValueError("Jellyfin API or user_id not available")

        limit = call.data.get("limit", 50)
        query = call.data.get("query")
        include_items = call.data.get("include_items", True)

        raw_collections = await api.get_library_items(
            user_id=user_id,
            limit=limit,
            search_term=query,
            item_types=["BoxSet"],
        )

        collections = []
        for c in raw_collections:
            cid = c.get("Id", "")
            col_data = {
                "id": cid,
                "name": c.get("Name", "Unknown Collection"),
                "item_count": c.get("ChildCount") or c.get("RecursiveItemCount") or 0,
                "overview": c.get("Overview"),
                "image_url": api.get_image_url(cid, "Primary") if cid else None,
                "backdrop_url": api.get_image_url(cid, "Backdrop") if cid else None,
            }

            if include_items and cid:
                try:
                    params = {
                        "UserId": user_id,
                        "ParentId": cid,
                        "Recursive": "true",
                        "Fields": "Genres,RunTimeTicks,CommunityRating,ProductionYear,Overview,Path",
                        "SortBy": "SortName",
                        "SortOrder": "Ascending",
                    }
                    res = await api._request("GET", "/Items", params=params)
                    items_raw = res.get("Items", []) if isinstance(res, dict) else []
                    col_data["items"] = [
                        {
                            "id": i.get("Id"),
                            "name": i.get("Name"),
                            "type": i.get("Type"),
                            "year": i.get("ProductionYear"),
                            "rating": i.get("CommunityRating"),
                            "runtime_minutes": (
                                round(i.get("RunTimeTicks", 0) / (10_000_000 * 60))
                                if i.get("RunTimeTicks")
                                else None
                            ),
                            "path": i.get("Path"),
                        }
                        for i in items_raw
                    ]
                except Exception as err:
                    _LOGGER.debug("Could not fetch items for collection %s: %s", cid, err)
                    col_data["items"] = []

            collections.append(col_data)

        return {"collections": collections, "count": len(collections)}

    async def async_delete_item(call: ServiceCall) -> None:
        """Delete an item from Jellyfin library."""
        try:
            entity_id = call.data.get("entity_id") or call.data.get("server_entity_id")
            coordinator = _get_coordinator(hass, call.data.get("config_entry_id"), entity_id)
            await coordinator._api._request("DELETE", f"/Items/{call.data['item_id']}")
            await coordinator.async_refresh()
        except Exception as e:
            _LOGGER.error("Delete failed: %s", e)

    async def async_update_favorite(call: ServiceCall) -> None:
        """Update favorite status for an item."""
        try:
            entity_id = call.data.get("entity_id") or call.data.get("server_entity_id")
            coordinator = _get_coordinator(hass, call.data.get("config_entry_id"), entity_id)
            state = hass.states.get(entity_id) if entity_id else None
            user_id = (state.attributes.get("user_id") if state else None) or coordinator.entry.data.get("user_id")
            await coordinator._api.update_favorite(user_id, call.data["item_id"], call.data["is_favorite"])
            await coordinator.async_refresh()
        except Exception as e:
            _LOGGER.error("Favorite update failed: %s", e)

    async def async_mark_watched(call: ServiceCall) -> None:
        """Update watched status for an item."""
        try:
            entity_id = call.data.get("entity_id") or call.data.get("server_entity_id")
            coordinator = _get_coordinator(hass, call.data.get("config_entry_id"), entity_id)
            state = hass.states.get(entity_id) if entity_id else None
            user_id = (state.attributes.get("user_id") if state else None) or coordinator.entry.data.get("user_id")
            await coordinator._api.update_played_status(user_id, call.data["item_id"], call.data["is_played"])
            await coordinator.async_refresh()
        except Exception as e:
            _LOGGER.error("Mark watched failed: %s", e)

    async def async_session_control(call: ServiceCall) -> None:
        """Send control command to session."""
        try:
            entity_id = call.data.get("entity_id") or call.data.get("server_entity_id")
            coordinator = _get_coordinator(hass, call.data.get("config_entry_id"), entity_id)
            await coordinator._api.session_control(call.data["session_id"], call.data["command"])
        except Exception as e:
            _LOGGER.error("Session control failed: %s", e)

    async def async_session_seek(call: ServiceCall) -> None:
        """Send seek command to session."""
        try:
            entity_id = call.data.get("entity_id") or call.data.get("server_entity_id")
            coordinator = _get_coordinator(hass, call.data.get("config_entry_id"), entity_id)
            position_ticks = call.data.get("position_ticks")
            if position_ticks is None and "position_seconds" in call.data:
                position_ticks = int(call.data["position_seconds"] * 10_000_000)
            if position_ticks is None:
                raise ValueError("Either 'position_ticks' or 'position_seconds' must be provided.")
            await coordinator._api.session_seek(call.data["session_id"], position_ticks)
        except Exception as e:
            _LOGGER.error("Session seek failed: %s", e)

    async def async_session_general_command(call: ServiceCall) -> None:
        """Send a general command to session."""
        try:
            entity_id = call.data.get("entity_id") or call.data.get("server_entity_id")
            coordinator = _get_coordinator(hass, call.data.get("config_entry_id"), entity_id)
            await coordinator._api.session_general_command(call.data["session_id"], call.data["command"], call.data.get("arguments"))
        except Exception as e:
            _LOGGER.error("Session general command failed: %s", e)

    async def async_session_play(call: ServiceCall) -> None:
        """Instruct a Jellyfin session/device to play an item."""
        try:
            entity_id = call.data.get("entity_id") or call.data.get("server_entity_id")
            coordinator = _get_coordinator(hass, call.data.get("config_entry_id"), entity_id)
            api = coordinator._api
            session_coordinator = coordinator.entry.runtime_data.session
            sessions = session_coordinator.data or []

            dev_id = call.data.get("device_id")
            dev_name = call.data.get("device_name")
            client = call.data.get("client")
            target_session_id = call.data.get("session_id")

            # Check if entity_id provided maps to a device player entity
            if not target_session_id and entity_id and entity_id.startswith("media_player."):
                ent_state = hass.states.get(entity_id)
                if ent_state:
                    ent_attrs = ent_state.attributes
                    dev_id = dev_id or ent_attrs.get("device_id")
                    dev_name = dev_name or ent_attrs.get("device_name")
                    target_session_id = target_session_id or ent_attrs.get("session_id")

            if not target_session_id:
                for s in sessions:
                    if dev_id and s.get("DeviceId") == dev_id:
                        target_session_id = s.get("Id")
                        break
                    s_names = {
                        str(s.get("DeviceName") or "").strip().lower(),
                        str(s.get("CustomName") or "").strip().lower(),
                        str(s.get("DeviceCustomName") or "").strip().lower(),
                    }
                    if dev_name and dev_name.strip().lower() in s_names:
                        target_session_id = s.get("Id")
                        break
                    if client and s.get("Client", "").strip().lower() == client.strip().lower():
                        target_session_id = s.get("Id")
                        break

            if not target_session_id:
                # Live fallback directly from Jellyfin API in case WS hasn't refreshed
                live_sessions = await api._request("GET", "/Sessions")
                for s in live_sessions:
                    if dev_id and s.get("DeviceId") == dev_id:
                        target_session_id = s.get("Id")
                        break
                    s_names = {
                        str(s.get("DeviceName") or "").strip().lower(),
                        str(s.get("CustomName") or "").strip().lower(),
                        str(s.get("DeviceCustomName") or "").strip().lower(),
                    }
                    if dev_name and dev_name.strip().lower() in s_names:
                        target_session_id = s.get("Id")
                        break
                    if client and s.get("Client", "").strip().lower() == client.strip().lower():
                        target_session_id = s.get("Id")
                        break

            if not target_session_id:
                _LOGGER.warning(
                    "No active session found for device_name=%s, device_id=%s, client=%s",
                    dev_name,
                    dev_id,
                    client,
                )
                return

            item_id = call.data["item_id"]
            # Auto-resolve series to Next Up episode
            user_id = coordinator.entry.data.get("user_id")
            if user_id:
                try:
                    item = await api.get_item(user_id, item_id)
                    if item and item.get("Type") in ("Series", "Season"):
                        series_id = item_id if item.get("Type") == "Series" else item.get("SeriesId")
                        if series_id:
                            next_ep = await api.get_next_up_episode(user_id, series_id)
                            if next_ep:
                                item_id = next_ep.get("Id", item_id)
                except Exception as e:
                    _LOGGER.debug("Could not resolve series next-up for %s: %s", item_id, e)

            await api.session_play(
                target_session_id,
                item_id,
                play_command=call.data.get("play_command", "PlayNow"),
                start_position_ticks=call.data.get("start_position_ticks"),
            )
        except Exception as e:
            _LOGGER.error("Session play failed: %s", e)

    async def async_get_recommendations(call: ServiceCall) -> ServiceResponse:
        """Get recommendations for an item."""
        try:
            entity_id = call.data.get("entity_id") or call.data.get("server_entity_id")
            coordinator = _get_coordinator(hass, call.data.get("config_entry_id"), entity_id)
            user_id = coordinator.entry.data.get("user_id")
            items = await coordinator._api.get_similar_items(user_id=user_id, item_id=call.data["item_id"], limit=call.data["limit"])
            results = list(await asyncio.gather(*(coordinator._async_transform_item(item) for item in items)))
            return {"items": [_clean_transformed_item(r) for r in results]}
        except Exception as e:
            raise ValueError(f"Recommendations failed: {e}") from e

    async def async_get_item(call: ServiceCall) -> ServiceResponse:
        """Get full details for an item."""
        try:
            entity_id = call.data.get("entity_id") or call.data.get("server_entity_id")
            coordinator = _get_coordinator(hass, call.data.get("config_entry_id"), entity_id)
            user_id = coordinator.entry.data.get("user_id")
            raw_item = await coordinator._api.get_item(user_id=user_id, item_id=call.data["item_id"])
            if not raw_item:
                return {"item": None}

            transformed_item = await coordinator._async_transform_item(raw_item)
            return {"item": _clean_transformed_item(transformed_item) if transformed_item else None}
        except Exception as e:
            raise ValueError(f"Get Item failed: {e}") from e

    async def async_get_live_tv_channels(call: ServiceCall) -> ServiceResponse:
        """Retrieve Live TV channels with optional filtering and search."""
        target_entity_id = (
            call.data.get("server_entity_id") or call.data.get("entity_id")
        )
        coordinator = _get_coordinator(
            hass, call.data.get("config_entry_id"), target_entity_id
        )
        query = call.data.get("query")
        limit = call.data.get("limit")

        try:
            # Use coordinator in-memory cache if available, otherwise fetch from API
            channels = (
                coordinator.data.get("live_tv_channels")
                if coordinator.data and coordinator.data.get("live_tv_channels")
                else None
            )
            if channels is None:
                channels = await coordinator._api.get_live_tv_channels()

            # Filter if query was provided
            if query and str(query).strip():
                query_str = str(query).strip().lower()
                norm_query = coordinator._api.normalize_live_tv_channel_name(query_str)
                filtered = []
                for ch in channels:
                    name = str(ch.get("Name") or "")
                    norm_name = coordinator._api.normalize_live_tv_channel_name(name)
                    num = str(ch.get("ChannelNumber") or "").strip()
                    if query_str == num or norm_query in norm_name or query_str in name.lower():
                        filtered.append(ch)
                channels = filtered

            if limit and limit > 0:
                channels = channels[:limit]

            return {
                "total": len(channels),
                "channels": [
                    {
                        "id": channel.get("Id"),
                        "number": str(channel["ChannelNumber"])
                        if channel.get("ChannelNumber") is not None else None,
                        "name": channel.get("Name", ""),
                        "normalized_name": coordinator._api.normalize_live_tv_channel_name(
                            channel.get("Name", "")
                        ),
                    }
                    for channel in channels
                ]
            }
        except Exception as err:
            raise ValueError(f"Live TV channel lookup failed: {err}") from err

    async def async_play_live_tv_channel(call: ServiceCall) -> None:
        """Resolve a Live TV channel by number or normalized name and play it."""
        requested_channel = call.data.get("channel_number")
        if requested_channel is None:
            requested_channel = call.data.get("channel_name")
        if requested_channel is None or not str(requested_channel).strip():
            raise ValueError(
                "Provide either channel_number or channel_name"
            )

        target_entity_id = call.data.get("entity_id")
        server_entity_id = call.data.get("server_entity_id")
        coordinator = _get_coordinator(
            hass,
            call.data.get("config_entry_id"),
            server_entity_id or target_entity_id,
        )
        api = coordinator._api
        session_id = call.data.get("session_id")
        device_id = call.data.get("device_id")
        device_name = call.data.get("device_name")
        client = call.data.get("client")

        if not session_id and target_entity_id:
            state = hass.states.get(target_entity_id)
            if state:
                session_id = state.attributes.get("session_id")
                device_id = device_id or state.attributes.get("device_id")
                device_name = device_name or state.attributes.get("device_name")

        def find_session_id(sessions: list[dict]) -> str | None:
            for session in sessions:
                if device_id and session.get("DeviceId") == device_id:
                    return session.get("Id")
                s_names = {
                    str(session.get("DeviceName") or "").strip().lower(),
                    str(session.get("CustomName") or "").strip().lower(),
                    str(session.get("DeviceCustomName") or "").strip().lower(),
                }
                if device_name and device_name.strip().lower() in s_names:
                    return session.get("Id")
                if client and session.get("Client", "").strip().lower() == client.strip().lower():
                    return session.get("Id")
            return None

        if not session_id:
            sessions = coordinator.entry.runtime_data.session.data or []
            session_id = find_session_id(sessions)

        if not session_id:
            # The WebSocket cache can be briefly stale when a device appears.
            live_sessions = await api.get_sessions()
            session_id = find_session_id(live_sessions)

        if not session_id:
            raise ValueError(
                "No active Jellyfin session matched the supplied session_id, media "
                "player entity_id, device_name, device_id, or client"
            )

        try:
            await api.play_live_tv_channel(session_id, requested_channel)
        except Exception as err:
            raise ValueError(f"Live TV playback failed: {err}") from err

    # Register all services properly
    service_map = [
        (SERVICE_REFRESH_LIBRARY, async_refresh_library, None),
        (SERVICE_PLAY_ON_CHROMECAST, async_play_on_device, PLAY_ON_CHROMECAST_SCHEMA),
        (SERVICE_DELETE_ITEM, async_delete_item, DELETE_ITEM_SCHEMA),
        (SERVICE_SESSION_CONTROL, async_session_control, SESSION_CONTROL_SCHEMA),
        (SERVICE_SESSION_PLAY, async_session_play, SESSION_PLAY_SCHEMA),
        (SERVICE_SESSION_SEEK, async_session_seek, SESSION_SEEK_SCHEMA),
        (SERVICE_SESSION_GENERAL_COMMAND, async_session_general_command, SESSION_GENERAL_COMMAND_SCHEMA),
        (SERVICE_UPDATE_FAVORITE, async_update_favorite, UPDATE_FAVORITE_SCHEMA),
        (SERVICE_MARK_WATCHED, async_mark_watched, MARK_WATCHED_SCHEMA),
        (SERVICE_SEARCH, async_search, SEARCH_SCHEMA, True),
        (SERVICE_GET_RECOMMENDATIONS, async_get_recommendations, GET_RECOMMENDATIONS_SCHEMA, True),
        (SERVICE_GET_ITEM, async_get_item, GET_ITEM_SCHEMA, True),
        (SERVICE_GET_LIVE_TV_CHANNELS, async_get_live_tv_channels, LIVE_TV_CHANNELS_SCHEMA, True),
        (SERVICE_PLAY_LIVE_TV_CHANNEL, async_play_live_tv_channel, PLAY_LIVE_TV_CHANNEL_SCHEMA),
        (SERVICE_MUSIC_SEARCH, async_music_search, MUSIC_SEARCH_SCHEMA, True),
        (SERVICE_PLAY_MUSIC, async_play_music, PLAY_MUSIC_SCHEMA),
        (SERVICE_PLAY_PLAYLIST, async_play_playlist, PLAY_PLAYLIST_SCHEMA),
        (SERVICE_GET_PLAYLISTS, async_get_playlists, GET_PLAYLISTS_SCHEMA, True),
        (SERVICE_GET_COLLECTIONS, async_get_collections, GET_COLLECTIONS_SCHEMA, True),
    ]

    for name, func, schema, *resp in service_map:
        if not hass.services.has_service(DOMAIN, name):
            hass.services.async_register(
                DOMAIN, name, func, schema=schema,
                supports_response=SupportsResponse.ONLY if resp and resp[0] else SupportsResponse.NONE
            )
