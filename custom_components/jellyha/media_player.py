"""Media player platform for JellyHA."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.media_player import (
    BrowseMedia,
    MediaPlayerEntity,
    MediaPlayerEntityFeature,
    MediaPlayerState,
)
from homeassistant.components.media_player.const import MediaType
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .browse_media import async_browse_media, async_browse_media_search, parse_item_id
from .const import CONF_DEVICE_NAME, DEFAULT_DEVICE_NAME, DOMAIN
from .coordinator import JellyHALibraryCoordinator
from .device import get_device_info
from . import JellyHAConfigEntry

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: JellyHAConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up JellyHA media player from config entry."""
    coordinator: JellyHALibraryCoordinator = entry.runtime_data.library
    device_name = entry.data.get(CONF_DEVICE_NAME, DEFAULT_DEVICE_NAME)

    async_add_entities([JellyHAMediaPlayer(coordinator, entry, device_name)])


class JellyHAMediaPlayer(CoordinatorEntity[JellyHALibraryCoordinator], MediaPlayerEntity):
    """Media player entity for browsing Jellyfin library."""

    _attr_has_entity_name = True
    _attr_name = "Library Browser"
    _attr_icon = "mdi:multimedia"
    _attr_media_content_type = MediaType.VIDEO
    _attr_supported_features = (
        MediaPlayerEntityFeature.BROWSE_MEDIA
        | MediaPlayerEntityFeature.PLAY_MEDIA
        | MediaPlayerEntityFeature.SEARCH_MEDIA
    )

    def __init__(
        self,
        coordinator: JellyHALibraryCoordinator,
        entry: ConfigEntry,
        device_name: str,
    ) -> None:
        """Initialize the media player."""
        super().__init__(coordinator)
        self._entry = entry
        self._device_name = device_name
        self._attr_unique_id = f"{device_name}_media_browser"
        self.entity_id = f"media_player.{device_name}_browser"
        self._current_item: dict[str, Any] | None = None

    @property
    def device_info(self) -> DeviceInfo:
        """Return device info."""
        return get_device_info(self._entry.entry_id, self._device_name)

    @property
    def state(self) -> MediaPlayerState:
        """Return the state of the media player."""
        return MediaPlayerState.IDLE

    @property
    def media_title(self) -> str | None:
        """Return current media title."""
        if self._current_item:
            return self._current_item.get("name")
        return None

    @property
    def media_image_url(self) -> str | None:
        """Return current media poster."""
        if self._current_item:
            return self._current_item.get("poster_url")
        return None

    async def async_browse_media(
        self,
        media_content_type: str | None = None,
        media_content_id: str | None = None,
    ) -> BrowseMedia:
        """Implement the browse media interface."""
        return await async_browse_media(
            self.hass,
            self._entry.entry_id,
            media_content_type,
            media_content_id,
        )

    async def async_play_media(
        self,
        media_type: str,
        media_id: str,
        **kwargs: Any,
    ) -> None:
        """Play media from Jellyfin."""
        _LOGGER.debug("Play media requested: type=%s, id=%s", media_type, media_id)

        # Parse the item ID
        category, item_id = parse_item_id(media_id)

        if category != "item" or not item_id:
            _LOGGER.warning("Cannot play: invalid media_id format: %s", media_id)
            return

        # Find the item in coordinator data
        items = self.coordinator.data.get("items", []) if self.coordinator.data else []
        item = next((i for i in items if i.get("id") == item_id), None)

        if not item:
            _LOGGER.warning("Item not found: %s", item_id)
            return

        self._current_item = item

        # Call the play_on_chromecast service if a default device is configured
        # For now, just log the play request - user can configure card action
        _LOGGER.info(
            "Play request for '%s' (ID: %s). Use card or call jellyha.play_on_chromecast service.",
            item.get("name"),
            item_id,
        )

    async def async_search_media(
        self,
        media_content_type: str | None = None,
        media_content_id: str | None = None,
    ) -> BrowseMedia:
        """Search media from Jellyfin."""
        return await async_browse_media_search(
            self.hass,
            self._entry.entry_id,
            media_content_id or "",
        )
