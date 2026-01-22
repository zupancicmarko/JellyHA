"""Media source for JellyHA."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.media_player import BrowseMedia
from homeassistant.components.media_source.error import MediaSourceError, Unresolvable
from homeassistant.components.media_source.models import (
    BrowseMediaSource,
    MediaSource,
    MediaSourceItem,
    PlayMedia,
)
from homeassistant.core import HomeAssistant

from homeassistant.components.media_player.const import MediaClass
from .browse_media import async_browse_media
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


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
        # URI format: media-source://jellyha/{entry_id}/{type}/{item_id}
        identifier = item.identifier
        
        parts = identifier.split("/", 2)
        if len(parts) < 3:
             raise Unresolvable("Invalid identifier format. Expected entry_id/type/item_id")
             
        entry_id = parts[0]
        # media_type = parts[1] # Not strictly needed if we just stream item_id
        item_id = parts[2]
        
        entry = self.hass.config_entries.async_get_entry(entry_id)
        if not entry or not hasattr(entry, "runtime_data"):
            raise Unresolvable(f"Config entry {entry_id} not loaded")
            
        coordinator = entry.runtime_data.library
        api = coordinator._api
        if not api:
            raise Unresolvable("API not available")
            
        # Get content URL for direct playback
        url = api.get_content_url(item_id)
        
        # Mime type guessing (simplified)
        mime = "video/mp4" 
        
        return PlayMedia(url, mime)

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


    def _build_root(self) -> BrowseMediaSource:
        """Build root showing available servers."""
        children = []
        # Iterate over loaded config entries
        jellyha_entries = self.hass.config_entries.async_entries(DOMAIN)
        for entry in jellyha_entries:
            if hasattr(entry, "runtime_data") and entry.runtime_data:
                coordinator = entry.runtime_data.library
                children.append(
                    BrowseMediaSource(
                        domain=DOMAIN,
                        identifier=entry.entry_id,
                        media_class=MediaClass.DIRECTORY,
                        media_content_type="server",
                        title=coordinator._server_name or "Jellyfin",
                        can_play=False,
                        can_expand=True,
                    )
                )
            
        return BrowseMediaSource(
            domain=DOMAIN,
            identifier="",
            media_class=MediaClass.DIRECTORY,
            media_content_type="root",
            title="JellyHA",
            can_play=False,
            can_expand=True,
            children=children,
            children_media_class=MediaClass.DIRECTORY,
        )

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
            
        return BrowseMediaSource(
            domain=DOMAIN,
            identifier=new_id,
            media_class=bm.media_class,
            media_content_type=bm.media_content_type,
            title=bm.title,
            can_play=bm.can_play,
            can_expand=bm.can_expand,
            thumbnail=bm.thumbnail,
            children=children,
            children_media_class=MediaClass.DIRECTORY, # Ensure children have media class if needed
        )
