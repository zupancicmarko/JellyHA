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
SERVICE_SESSION_PLAY = "session_play"
SERVICE_SESSION_SEEK = "session_seek"
SERVICE_SESSION_GENERAL_COMMAND = "session_general_command"
SERVICE_UPDATE_FAVORITE = "update_favorite"
SERVICE_MARK_WATCHED = "mark_watched"
SERVICE_SEARCH = "search"
SERVICE_GET_RECOMMENDATIONS = "get_recommendations"
SERVICE_GET_ITEM = "get_item"

def _get_coordinator(hass: HomeAssistant, config_entry_id: str | None = None, entity_id: str | None = None):
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
        vol.Optional("use_series_image", default=True): cv.boolean,
        vol.Optional("server_entity_id"): cv.entity_id,
        vol.Optional("config_entry_id"): cv.string,
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

        media_info = MediaStrategy.analyze_media(item)
        playback_info = MediaStrategy.get_playback_info(
            api._server_url, api._api_key, item_id, media_info, model_name, item_type=item.get("Type")
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

        await hass.services.async_call(
            MEDIA_PLAYER_DOMAIN, SERVICE_PLAY_MEDIA,
            {
                "entity_id": target_entity_id,
                ATTR_MEDIA_CONTENT_ID: playback_info["media_url"],
                ATTR_MEDIA_CONTENT_TYPE: playback_info["content_type"],
                "extra": {"title": metadata["title"], "thumb": primary_img_url, "autoplay": True, "metadata": metadata},
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
        return {"items": results}

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
            user_id = coordinator.entry.data.get("user_id")
            await coordinator._api.update_favorite(user_id, call.data["item_id"], call.data["is_favorite"])
            await coordinator.async_refresh()
        except Exception as e:
            _LOGGER.error("Favorite update failed: %s", e)

    async def async_mark_watched(call: ServiceCall) -> None:
        """Update watched status for an item."""
        try:
            entity_id = call.data.get("entity_id") or call.data.get("server_entity_id")
            coordinator = _get_coordinator(hass, call.data.get("config_entry_id"), entity_id)
            user_id = coordinator.entry.data.get("user_id")
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
                    if dev_id and (s.get("DeviceId") == dev_id or (s.get("DeviceId") or "").startswith(dev_id)):
                        target_session_id = s.get("Id")
                        break
                    if dev_name and s.get("DeviceName", "").strip().lower() == dev_name.strip().lower():
                        target_session_id = s.get("Id")
                        break
                    if client and s.get("Client", "").strip().lower() == client.strip().lower():
                        target_session_id = s.get("Id")
                        break

            if not target_session_id:
                # Live fallback directly from Jellyfin API in case WS hasn't refreshed
                live_sessions = await api._request("GET", "/Sessions")
                for s in live_sessions:
                    if dev_id and (s.get("DeviceId") == dev_id or (s.get("DeviceId") or "").startswith(dev_id)):
                        target_session_id = s.get("Id")
                        break
                    if dev_name and s.get("DeviceName", "").strip().lower() == dev_name.strip().lower():
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
            return {"items": results}
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
            return {"item": transformed_item}
        except Exception as e:
            raise ValueError(f"Get Item failed: {e}") from e

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
    ]

    for name, func, schema, *resp in service_map:
        if not hass.services.has_service(DOMAIN, name):
            hass.services.async_register(
                DOMAIN, name, func, schema=schema,
                supports_response=SupportsResponse.ONLY if resp and resp[0] else SupportsResponse.NONE
            )