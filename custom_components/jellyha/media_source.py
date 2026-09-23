"""Media source for JellyHA."""
from __future__ import annotations

import inspect
import logging
from typing import Any

from homeassistant.components.media_player import BrowseMedia, MediaClass
try:
    from homeassistant.components.media_player import SearchMedia, SearchMediaQuery
except ImportError:
    SearchMedia = None  # type: ignore[assignment, misc]
    SearchMediaQuery = None  # type: ignore[assignment, misc]
from homeassistant.components.media_source.error import MediaSourceError, Unresolvable
from homeassistant.components.media_source.models import (
    BrowseMediaSource,
    MediaSource,
    MediaSourceItem,
    PlayMedia,
)
from homeassistant.core import HomeAssistant

from .browse_media import async_browse_media, async_browse_media_search
from .const import DOMAIN
from .media_strategy import MediaStrategy

_LOGGER = logging.getLogger(__name__)

_BROWSE_MEDIA_SOURCE_HAS_CAN_SEARCH = (
    "can_search" in inspect.signature(BrowseMediaSource.__init__).parameters
)


async def async_get_media_source(hass: HomeAssistant) -> MediaSource:
    """Set up JellyHA media source."""
    return JellyHAMediaSource(hass)


class JellyHAMediaSource(MediaSource):
    """Provide Jellyfin media libraries as a media source."""

    name: str = "JellyHA"

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize."""
        super().__init__(DOMAIN)
        self.hass = hass

    async def async_resolve_media(self, item: MediaSourceItem) -> PlayMedia:
        """Resolve media to a url."""
        from datetime import timedelta
        from homeassistant.components.http.auth import async_sign_path

        # URI format: media-source://jellyha/{entry_id}/{type}/{item_id}
        identifier = item.identifier
        
        parts = identifier.split("/", 2)
        if len(parts) < 3:
             raise Unresolvable("Invalid identifier format. Expected entry_id/type/item_id")
             
        entry_id = parts[0]
        category = parts[1]
        item_id = parts[2]
        
        entry = self.hass.config_entries.async_get_entry(entry_id)
        if not entry or not hasattr(entry, "runtime_data"):
            raise Unresolvable(f"Config entry {entry_id} not loaded")
            
        coordinator = entry.runtime_data.library
        api = coordinator._api
        if not api:
            raise Unresolvable("API not available")

        user_id = coordinator.entry.data.get("user_id")

        # If an album or playlist is requested, resolve its first playable track
        if category in ("album", "playlist"):
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
                items = tracks_result.get("Items", [])
                if items:
                    item_id = items[0]["Id"]
                else:
                    raise Unresolvable(f"No tracks found in {category} {item_id}")
            except Exception as e:
                _LOGGER.error("Failed to resolve %s %s: %s", category, item_id, e)
                raise Unresolvable(f"Cannot resolve {category}: {e}") from e

        # If collection or boxset is requested, resolve its first playable video
        elif category in ("collection", "boxset"):
            try:
                col_result = await api._request(
                    "GET",
                    "/Items",
                    params={
                        "UserId": user_id,
                        "ParentId": item_id,
                        "IncludeItemTypes": "Movie,Video,Episode",
                        "SortBy": "SortName",
                        "SortOrder": "Ascending",
                        "Limit": 1,
                        "Recursive": "true",
                    },
                )
                items = col_result.get("Items", [])
                if items:
                    item_id = items[0]["Id"]
                else:
                    raise Unresolvable(f"No items found in {category} {item_id}")
            except Exception as e:
                _LOGGER.error("Failed to resolve %s %s: %s", category, item_id, e)
                raise Unresolvable(f"Cannot resolve {category}: {e}") from e

        # If series, season, or show is requested, resolve next up or first unplayed episode
        elif category in ("series", "season", "show"):
            try:
                next_ep = await api.get_next_up_episode(user_id, item_id)
                if not next_ep:
                    first_unplayed = await api.get_library_items(
                        user_id=user_id,
                        item_types=["Episode"],
                        parent_id=item_id,
                        is_played=False,
                        sort_by="IndexNumber",
                        sort_order="Ascending",
                        limit=1,
                    )
                    if first_unplayed:
                        next_ep = first_unplayed[0]
                if next_ep:
                    item_id = next_ep.get("Id", item_id)
            except Exception as e:
                _LOGGER.debug("Failed to resolve next-up for %s %s: %s", category, item_id, e)
            
        # Detect item type and MIME type
        item_type = "Video"
        mime = "video/mp4"
        filename = None
        try:
            item_info = await api.get_item(user_id, item_id)
            item_type = item_info.get("Type", "Video")
            container = item_info.get("Container", "mp3").lower() if item_type == "Audio" else "mp4"
            
            if item_type == "Audio":
                if container == "flac":
                    mime = "audio/flac"
                elif container in ["m4a", "aac"]:
                    mime = "audio/mp4"
                elif container in ["ogg", "oga"]:
                    mime = "audio/ogg"
                elif container == "wav":
                    mime = "audio/wav"
                else:
                    mime = "audio/mpeg"
            
            # Construct friendly filename for stream URL so players display Title & Artist
            filename = self._build_friendly_filename(item_info)
            if filename and item_type == "Audio":
                ext = container if container else ("flac" if mime == "audio/flac" else "mp3")
                filename = f"{filename}.{ext}"
        except Exception:
            pass

        # Use signed proxy URL — no API key exposed to the client
        stream_path = api.get_stream_path(entry_id, item_id, item_type, filename=filename)
        signed_url = async_sign_path(self.hass, stream_path, timedelta(hours=24))
        
        return PlayMedia(signed_url, mime)

    async def async_browse_media(
        self,
        media_content_id: MediaSourceItem | None,
    ) -> BrowseMediaSource:
        """Return media."""
        # Root level: List available JellyHA servers (ConfigEntries)
        if media_content_id is None or not media_content_id.identifier:
            return self._build_root()
            
        identifier = media_content_id.identifier
        
        # Format: entry_id/path/to/content
        parts = identifier.split("/", 1)
        entry_id = parts[0]
        path = parts[1] if len(parts) > 1 else ""
         
        # Check if entry exists and is loaded
        entry = self.hass.config_entries.async_get_entry(entry_id)
        if not entry:
             raise MediaSourceError(f"Server {entry_id} not available")

        # Map to internal jellyha:// format expected by browse_media.py
        # path is like "movies", "item/123", "favorites"
        # browse_media expects: "jellyha://movies", "jellyha://item/123"
        if path:
            internal_content_id = f"jellyha://{path}"
        else:
             # Browsing server root
            internal_content_id = None
            
        try:
            # Delegate to existing browse logic
            browse_result = await async_browse_media(
                self.hass, 
                entry_id, 
                None,  # media_content_type not strictly used for routing
                internal_content_id
            )
            
            # Convert result to BrowseMediaSource and rewrite IDs
            return self._convert_browse_media(browse_result, entry_id)

        except Exception as err:
            # Handle any browsing errors gracefully
            _LOGGER.error("Error browsing media: %s", err)
            raise MediaSourceError(str(err)) from err


    async def async_search_media(
        self,
        item: MediaSourceItem,
        query: Any,
    ) -> Any:
        """Search media inside this media source."""
        search_query = getattr(query, "search_query", str(query) if query else "")
        if not search_query:
            return SearchMedia(result=[]) if SearchMedia else []

        identifier = item.identifier or ""
        parts = identifier.split("/", 1)
        entry_id = parts[0] if parts and parts[0] else None

        if not entry_id:
            for e in self.hass.config_entries.async_entries(DOMAIN):
                if hasattr(e, "runtime_data") and e.runtime_data:
                    entry_id = e.entry_id
                    break

        if not entry_id:
            return SearchMedia(result=[]) if SearchMedia else []

        browse_result = await async_browse_media_search(
            self.hass,
            entry_id,
            search_query,
        )
        converted = self._convert_browse_media(browse_result, entry_id)
        results = converted.children or [converted]

        if SearchMedia is not None:
            return SearchMedia(result=results)
        return results

    def _build_root(self) -> BrowseMediaSource:
        """Build root showing available servers."""
        children = []
        # Iterate over loaded config entries
        jellyha_entries = self.hass.config_entries.async_entries(DOMAIN)
        for entry in jellyha_entries:
            if hasattr(entry, "runtime_data") and entry.runtime_data:
                server_kwargs: dict[str, Any] = {
                    "domain": DOMAIN,
                    "identifier": entry.entry_id,
                    "media_class": MediaClass.DIRECTORY,
                    "media_content_type": "server",
                    "title": entry.title,
                    "can_play": False,
                    "can_expand": True,
                }
                if _BROWSE_MEDIA_SOURCE_HAS_CAN_SEARCH:
                    server_kwargs["can_search"] = True
                children.append(BrowseMediaSource(**server_kwargs))
            
        root_kwargs: dict[str, Any] = {
            "domain": DOMAIN,
            "identifier": "",
            "media_class": MediaClass.DIRECTORY,
            "media_content_type": "root",
            "title": "JellyHA",
            "can_play": False,
            "can_expand": True,
            "children": children,
            "children_media_class": MediaClass.DIRECTORY,
        }
        if _BROWSE_MEDIA_SOURCE_HAS_CAN_SEARCH:
            root_kwargs["can_search"] = True
        return BrowseMediaSource(**root_kwargs)

    def _convert_browse_media(self, bm: BrowseMedia, entry_id: str) -> BrowseMediaSource:
        """Recursive conversion from BrowseMedia to BrowseMediaSource."""
        # Rewrite identifier: internal "jellyha://path" -> public "entry_id/path"
        original_id = bm.media_content_id
        if original_id.startswith("jellyha://"):
             path = original_id.replace("jellyha://", "")
             new_id = f"{entry_id}/{path}"
        else:
             # Fallback or empty
             new_id = f"{entry_id}/{original_id}"
             
        children = None
        if bm.children:
            children = [self._convert_browse_media(c, entry_id) for c in bm.children]
            
        source_kwargs: dict[str, Any] = {
            "domain": DOMAIN,
            "identifier": new_id,
            "media_class": bm.media_class,
            "media_content_type": bm.media_content_type,
            "title": bm.title,
            "can_play": bm.can_play,
            "can_expand": bm.can_expand,
            "thumbnail": bm.thumbnail,
            "children": children,
            "children_media_class": MediaClass.DIRECTORY,
        }
        if _BROWSE_MEDIA_SOURCE_HAS_CAN_SEARCH and bm.can_expand:
            source_kwargs["can_search"] = True
        return BrowseMediaSource(**source_kwargs)

    @staticmethod
    def _build_friendly_filename(item_info: dict[str, Any]) -> str:
        """Build a clean display title from item metadata (e.g. Artist - Title)."""
        import re

        item_type = item_info.get("Type", "")
        name = item_info.get("Name", "").strip()

        if item_type == "Audio":
            artists = item_info.get("Artists", [])
            artist = ", ".join(artists) if artists else (item_info.get("AlbumArtist") or "")
            if not artist and item_info.get("ArtistItems"):
                artist = item_info["ArtistItems"][0].get("Name", "")
            base = MediaStrategy.format_audio_title(artist, name)
        elif item_type == "Episode":
            series = item_info.get("SeriesName", "")
            season_num = item_info.get("ParentIndexNumber")
            ep_num = item_info.get("IndexNumber")
            if series and season_num is not None and ep_num is not None:
                base = f"{series} - S{season_num:02d}E{ep_num:02d} - {name}"
            elif series and name:
                base = f"{series} - {name}"
            else:
                base = name or "video"
        elif item_type == "Movie":
            year = item_info.get("ProductionYear")
            if year and name:
                base = f"{name} ({year})"
            else:
                base = name or "video"
        else:
            base = name or "media"

        safe_base = re.sub(r'[/\\?%*:|"<>#]', "_", base).strip(" ._")
        if not safe_base:
            safe_base = "media"
        return safe_base

