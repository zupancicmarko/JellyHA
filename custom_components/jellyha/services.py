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

from homeassistant.core import HomeAssistant, ServiceCall
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

PLAY_ON_CHROMECAST_SCHEMA = vol.Schema(
    {
        vol.Required("entity_id"): cv.entity_id,
        vol.Required("item_id"): cv.string,
    }
)

DELETE_ITEM_SCHEMA = vol.Schema(
    {
        vol.Required("item_id"): cv.string,
    }
)

async def async_register_services(hass: HomeAssistant) -> None:
    """Register services for JellyHA."""

    async def async_play_on_device(call: ServiceCall) -> None:
        """Play a Jellyfin item using Tuned 2026 Strategy."""
        target_entity_id = call.data["entity_id"]
        item_id = call.data["item_id"]

        # Find coordinator
        coordinator = None
        if DOMAIN in hass.data:
            for entry_id in hass.data[DOMAIN]:
                coordinator = hass.data[DOMAIN][entry_id]["library"]
                break

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
        # 1. CONNECT & DETECT MODEL
        # ------------------------------------------------------------------
        model_name = "Unknown"
        is_legacy_device = False
        
        try:
            entity_state = hass.states.get(target_entity_id)
            if entity_state:
                friendly_name = entity_state.attributes.get("friendly_name")
                if friendly_name:
                    import pychromecast
                    chromecasts, browser = await hass.async_add_executor_job(
                        pychromecast.get_listed_chromecasts, [friendly_name]
                    )
                    if chromecasts:
                        cast_device = chromecasts[0]
                        model_name = cast_device.model_name
                        # Gen 1, 2, 3 are "Chromecast". Ultra/TV are different.
                        if model_name == "Chromecast":
                            is_legacy_device = True
                    if browser:
                        await hass.async_add_executor_job(browser.stop_discovery)
        except Exception as e:
            _LOGGER.warning("Could not detect Chromecast model: %s", e)

        _LOGGER.info("Detected Device: %s (Legacy Mode: %s)", model_name, is_legacy_device)

        # ------------------------------------------------------------------
        # 2. ANALYSIS
        # ------------------------------------------------------------------
        media_streams = item.get("MediaStreams", [])
        video_codec = "unknown"
        video_height = 0
        bit_depth = 8
        audio_codec = "unknown"
        audio_channels = 2
        
        for stream in media_streams:
            if stream.get("Type") == "Video":
                video_codec = stream.get("Codec", "unknown").lower()
                video_height = int(stream.get("Height", 0))
                bit_depth = int(stream.get("BitDepth", 8))
            elif stream.get("Type") == "Audio" and stream.get("Index") == 1:
                # Assuming first audio track is main
                audio_codec = stream.get("Codec", "unknown").lower()
                audio_channels = int(stream.get("Channels", 2))
        
        if audio_codec == "unknown":
             for stream in media_streams:
                if stream.get("Type") == "Audio":
                    audio_codec = stream.get("Codec", "unknown").lower()
                    audio_channels = int(stream.get("Channels", 2))
                    break

        # Check Format Basics
        is_format_standard = (
            video_codec in ["h264", "avc"] and 
            bit_depth == 8 and
            audio_codec in ["aac", "mp3", "ac3"]
        )

        # ------------------------------------------------------------------
        # 3. DECISION MATRIX (Corrected for Gen 1 Limits)
        # ------------------------------------------------------------------
        
        should_direct_play = False

        if is_legacy_device:
            # LEGACY: Strict limits (Max 720p, Max Stereo)
            # 720p H.264 Stereo -> DIRECT PLAY
            # 1080p H.264 Stereo -> TRANSCODE (Downscale)
            # 720p H.264 5.1 -> TRANSCODE (Downmix)
            if is_format_standard and video_height <= 720 and audio_channels <= 2:
                should_direct_play = True
        else:
            # MODERN: Standard limits (Max 1080p)
            if is_format_standard and video_height <= 1080:
                should_direct_play = True

        _LOGGER.info("Media: %s/%s | %sp | %sch | Legacy? %s | DirectPlay? %s", 
                     video_codec, audio_codec, video_height, audio_channels, is_legacy_device, should_direct_play)

        media_url = ""
        content_type = ""
        log_mode = ""

        if should_direct_play:
            # [A] DIRECT PLAY
            log_mode = "DIRECT (H.264)"
            media_url = (
                f"{server_url}/Videos/{item_id}/stream"
                f"?Static=true"
                f"&api_key={api_key}"
                f"&VideoCodec=h264"
                f"&AudioCodec=aac"
            )
            content_type = "video/mp4"
            
        elif is_legacy_device:
            # [B] LEGACY TRANSCODE (Gen 1)
            # FORCE 720p & STEREO (Fixes Nuremberg/District 9)
            log_mode = "TRANSCODE (Legacy Gen 1 - Force 720p/Stereo)"
            
            media_url = (
                f"{server_url}/Videos/{item_id}/master.m3u8"
                f"?api_key={api_key}"
                f"&MediaSourceId={item_id}"
                
                # FORCE 720p
                f"&Width=1280"
                f"&Height=720"
                
                # FORCE 18 Mbps
                f"&VideoBitrate=18000000"
                f"&MaxStreamingBitrate=18000000"
                
                # COMPATIBILITY
                f"&EncoderPreset=veryfast"
                f"&VideoCodec=h264"
                f"&h264-profile=high"
                f"&h264-level=41"
                f"&h264-videobitdepth=8"
                
                # AUDIO (Force Stereo)
                f"&AudioCodec=aac"
                f"&AudioBitrate=256000"
                f"&AudioSampleRate=48000"
                f"&TranscodingMaxAudioChannels=2" 
                
                # HLS
                f"&SegmentContainer=ts"
                f"&MinSegments=2"
                f"&BreakOnNonKeyFrames=False"
                f"&CopyTimestamps=true"
                f"&EnableSubtitlesInManifest=false"
            )
            content_type = "application/x-mpegURL"
            
        else:
            # [C] MODERN TRANSCODE (Tuned 2026 Settings)
            log_mode = "TRANSCODE (Modern HQ)"
            
            media_url = (
                f"{server_url}/Videos/{item_id}/master.m3u8"
                f"?api_key={api_key}"
                f"&MediaSourceId={item_id}"
                
                # FORCE 1080p
                f"&Width=1920"
                f"&Height=1080"
                
                # FORCE 20 Mbps
                f"&VideoBitrate=20000000"
                f"&MaxStreamingBitrate=20000000"
                
                # QUALITY
                f"&EncoderPreset=medium"
                f"&VideoCodec=h264"
                f"&h264-profile=high"
                f"&h264-level=51"
                f"&h264-videobitdepth=8"
                
                # AUDIO (5.1 OK)
                f"&AudioCodec=aac"
                f"&AudioBitrate=320000"
                f"&TranscodingMaxAudioChannels=6"
                
                # HLS
                f"&SegmentContainer=ts"
                f"&MinSegments=2"
                f"&BreakOnNonKeyFrames=False"
                f"&CopyTimestamps=true"
                f"&EnableSubtitlesInManifest=false"
            )
            content_type = "application/x-mpegURL"

        # Log
        safe_url = media_url.replace(api_key, "REDACTED")
        _LOGGER.info("Strategy: %s", log_mode)
        _LOGGER.info("URL: %s", safe_url)

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

    async def async_refresh_library(call: ServiceCall) -> None:
        """Force refresh library data."""
        if DOMAIN in hass.data:
            for entry_id in hass.data[DOMAIN]:
                coordinator = hass.data[DOMAIN][entry_id]["library"]
                await coordinator.async_refresh()
                _LOGGER.info("Library refresh triggered via service")

    async def async_delete_item(call: ServiceCall) -> None:
        """Delete an item from Jellyfin library."""
        item_id = call.data["item_id"]

        coordinator = None
        if DOMAIN in hass.data:
            for entry_id in hass.data[DOMAIN]:
                coordinator = hass.data[DOMAIN][entry_id]["library"]
                break

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

    if not hass.services.has_service(DOMAIN, SERVICE_REFRESH_LIBRARY):
        hass.services.async_register(
            DOMAIN,
            SERVICE_REFRESH_LIBRARY,
            async_refresh_library,
        )

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
        
        # Find coordinator (assuming one instance for simplicity, but robust loop is better)
        coordinator = None
        if DOMAIN in hass.data:
            for entry_id in hass.data[DOMAIN]:
                coordinator = hass.data[DOMAIN][entry_id]["library"]
                break
        
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
            }),
        )

    async def async_mark_watched(call: ServiceCall) -> None:
        """Update watched status for an item."""
        item_id = call.data["item_id"]
        is_played = call.data["is_played"]
        
        # Find coordinator
        coordinator = None
        if DOMAIN in hass.data:
            for entry_id in hass.data[DOMAIN]:
                coordinator = hass.data[DOMAIN][entry_id]["library"]
                break
        
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
            }),
        )