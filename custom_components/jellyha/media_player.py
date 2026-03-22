"""Media player platform for JellyHA."""
from __future__ import annotations

import logging
from datetime import datetime
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
from homeassistant.util import dt as dt_util

from .browse_media import async_browse_media, async_browse_media_search, parse_item_id
from .const import CONF_DEVICE_NAME, DEFAULT_DEVICE_NAME, DOMAIN, TICKS_PER_SECOND
from .coordinator import JellyHALibraryCoordinator, JellyHASessionCoordinator
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
    session_coordinator: JellyHASessionCoordinator = entry.runtime_data.session
    device_name = entry.data.get(CONF_DEVICE_NAME, DEFAULT_DEVICE_NAME)

    entities: list[MediaPlayerEntity] = [
        JellyHAMediaPlayer(coordinator, entry, device_name),
    ]

    # Create a media player for each Jellyfin user
    if session_coordinator.users:
        for user_id, username in session_coordinator.users.items():
            entities.append(
                JellyHAUserMediaPlayer(
                    session_coordinator, entry, user_id, username, device_name
                )
            )

    async_add_entities(entities)


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
        self._attr_unique_id = f"{entry.entry_id}_media_browser"
        # self.entity_id = f"media_player.{device_name}_browser"
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
            # Item might be a music track or other item not in the sync cache —
            # fall back to a direct API call
            _LOGGER.debug("Item %s not in cache, fetching from API", item_id)
            try:
                api = self.coordinator._api
                user_id = self._entry.data.get("user_id")
                if api and user_id:
                    raw = await api.get_item(user_id, item_id)
                    item = await self.coordinator._async_transform_item(raw)
            except Exception:
                _LOGGER.warning("Item not found in cache or API: %s", item_id)
                return

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


class JellyHAUserMediaPlayer(
    CoordinatorEntity[JellyHASessionCoordinator], MediaPlayerEntity
):
    """Media player entity tracking a Jellyfin user's active playback session.

    One entity is created per Jellyfin user.  When the user is not playing
    anything the entity reports IDLE.  During playback it exposes the
    standard Home Assistant media_player transport controls (play, pause,
    stop, seek, next/previous track) and volume controls by delegating to
    the Jellyfin remote-session API.
    """

    _attr_has_entity_name = True
    _attr_supported_features = (
        MediaPlayerEntityFeature.PAUSE
        | MediaPlayerEntityFeature.PLAY
        | MediaPlayerEntityFeature.STOP
        | MediaPlayerEntityFeature.SEEK
        | MediaPlayerEntityFeature.NEXT_TRACK
        | MediaPlayerEntityFeature.PREVIOUS_TRACK
        | MediaPlayerEntityFeature.VOLUME_SET
        | MediaPlayerEntityFeature.VOLUME_MUTE
    )

    def __init__(
        self,
        coordinator: JellyHASessionCoordinator,
        entry: ConfigEntry,
        user_id: str,
        username: str,
        device_name: str,
    ) -> None:
        """Initialize the user media player."""
        super().__init__(coordinator)
        self._entry = entry
        self._user_id = user_id
        self._username = username
        self._device_name = device_name
        self._attr_unique_id = f"{entry.entry_id}_media_player_{user_id}"
        self._attr_name = f"{username}"
        self._attr_icon = "mdi:account-play"

    # ------------------------------------------------------------------
    # Device info
    # ------------------------------------------------------------------

    @property
    def device_info(self) -> DeviceInfo:
        """Return device info."""
        return get_device_info(self._entry.entry_id, self._device_name)

    # ------------------------------------------------------------------
    # Session lookup — reuses same priority logic as JellyHAUserSensor
    # ------------------------------------------------------------------

    def _get_active_session(self) -> dict[str, Any] | None:
        """Get the active session for this user with stable priority.

        If the user has multiple active sessions (e.g. phone + TV), prefer
        the one that is currently playing (not paused).  Ties are broken by
        session ID for determinism.
        """
        if not self.coordinator.data:
            return None

        user_sessions = [
            s
            for s in self.coordinator.data
            if s.get("UserId") == self._user_id and "NowPlayingItem" in s
        ]

        if not user_sessions:
            return None

        user_sessions.sort(
            key=lambda s: (
                s.get("PlayState", {}).get("IsPaused", False),
                s.get("Id", ""),
            )
        )
        return user_sessions[0]

    # ------------------------------------------------------------------
    # State
    # ------------------------------------------------------------------

    @property
    def state(self) -> MediaPlayerState:
        """Return the current state of the media player."""
        session = self._get_active_session()
        if not session:
            return MediaPlayerState.IDLE

        if session.get("PlayState", {}).get("IsPaused", False):
            return MediaPlayerState.PAUSED

        return MediaPlayerState.PLAYING

    # ------------------------------------------------------------------
    # Media metadata
    # ------------------------------------------------------------------

    @property
    def media_content_type(self) -> MediaType | str | None:
        """Return the content type of current playing media."""
        session = self._get_active_session()
        if not session:
            return None
        item_type = session.get("NowPlayingItem", {}).get("Type", "")
        if item_type == "Episode":
            return MediaType.TVSHOW
        if item_type == "Movie":
            return MediaType.MOVIE
        if item_type == "Audio":
            return MediaType.MUSIC
        return MediaType.VIDEO

    @property
    def media_title(self) -> str | None:
        """Return the title of current playing media."""
        session = self._get_active_session()
        if not session:
            return None
        item = session.get("NowPlayingItem", {})
        return item.get("Name")

    @property
    def media_series_title(self) -> str | None:
        """Return the series title (TV shows only)."""
        session = self._get_active_session()
        if not session:
            return None
        item = session.get("NowPlayingItem", {})
        return item.get("SeriesName")

    @property
    def media_season(self) -> str | None:
        """Return the season number (TV shows only)."""
        session = self._get_active_session()
        if not session:
            return None
        item = session.get("NowPlayingItem", {})
        season = item.get("ParentIndexNumber")
        return str(season) if season is not None else None

    @property
    def media_episode(self) -> str | None:
        """Return the episode number (TV shows only)."""
        session = self._get_active_session()
        if not session:
            return None
        item = session.get("NowPlayingItem", {})
        episode = item.get("IndexNumber")
        return str(episode) if episode is not None else None

    @property
    def media_image_url(self) -> str | None:
        """Return the image URL of current playing media (signed poster)."""
        session = self._get_active_session()
        if not session:
            return None
        return session.get("jellyha_poster_url")

    @property
    def media_image_remotely_accessible(self) -> bool:
        """Image is served via HA's signed proxy, not directly accessible."""
        return False

    @property
    def media_duration(self) -> int | None:
        """Return the duration of current playing media in seconds."""
        session = self._get_active_session()
        if not session:
            return None
        ticks = session.get("NowPlayingItem", {}).get("RunTimeTicks", 0)
        if ticks and ticks > 0:
            return int(ticks / TICKS_PER_SECOND)
        return None

    @property
    def media_position(self) -> int | None:
        """Return the current position in seconds."""
        session = self._get_active_session()
        if not session:
            return None
        ticks = session.get("PlayState", {}).get("PositionTicks", 0)
        return int(ticks / TICKS_PER_SECOND) if ticks else 0

    @property
    def media_position_updated_at(self) -> datetime | None:
        """Return when position was last updated.

        HA uses this together with media_position to interpolate the
        current position in the UI without polling every second.
        """
        session = self._get_active_session()
        if not session:
            return None
        return dt_util.utcnow()

    # ------------------------------------------------------------------
    # Volume
    # ------------------------------------------------------------------

    @property
    def volume_level(self) -> float | None:
        """Return the volume level (0.0 to 1.0).

        Note: Not all Jellyfin clients report volume via the session API.
        When unavailable this returns None.
        """
        session = self._get_active_session()
        if not session:
            return None
        # Jellyfin stores volume as 0-100 int in TranscodingInfo or
        # may not expose it at all depending on the client.
        # Some clients report it in NowPlayingItem or PlayState.
        # We check common locations:
        transcode_info = session.get("TranscodingInfo", {})
        if transcode_info and "AudioChannels" in transcode_info:
            # TranscodingInfo doesn't actually contain volume — fallback
            pass
        # Volume is not consistently available in Jellyfin session data.
        # Return None to indicate it's unknown.
        return None

    @property
    def is_volume_muted(self) -> bool | None:
        """Return True if volume is muted."""
        session = self._get_active_session()
        if not session:
            return None
        return session.get("PlayState", {}).get("IsMuted", False)

    # ------------------------------------------------------------------
    # Extra state attributes
    # ------------------------------------------------------------------

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return additional state attributes."""
        session = self._get_active_session()
        attrs: dict[str, Any] = {"user_id": self._user_id}

        if not session:
            return attrs

        item = session.get("NowPlayingItem", {})
        play_state = session.get("PlayState", {})

        attrs["session_id"] = session.get("Id")
        attrs["device_name"] = session.get("DeviceName")
        attrs["client"] = session.get("Client")
        attrs["item_id"] = item.get("Id")
        attrs["media_type"] = item.get("Type")

        # Progress percentage
        position_ticks = play_state.get("PositionTicks", 0)
        duration_ticks = item.get("RunTimeTicks", 0)
        if duration_ticks and duration_ticks > 0:
            attrs["progress_percent"] = int((position_ticks / duration_ticks) * 100)
        else:
            attrs["progress_percent"] = 0

        attrs["config_external_url"] = self._entry.options.get(
            "external_url", self._entry.data.get("external_url", "")
        )

        return attrs

    # ------------------------------------------------------------------
    # Transport controls
    # ------------------------------------------------------------------

    async def async_media_play(self) -> None:
        """Send play (unpause) command to session."""
        session = self._get_active_session()
        if not session:
            _LOGGER.debug("No active session for user %s, cannot play", self._username)
            return
        await self.coordinator.api.session_control(session["Id"], "Unpause")

    async def async_media_pause(self) -> None:
        """Send pause command to session."""
        session = self._get_active_session()
        if not session:
            _LOGGER.debug("No active session for user %s, cannot pause", self._username)
            return
        await self.coordinator.api.session_control(session["Id"], "Pause")

    async def async_media_stop(self) -> None:
        """Send stop command to session."""
        session = self._get_active_session()
        if not session:
            _LOGGER.debug("No active session for user %s, cannot stop", self._username)
            return
        await self.coordinator.api.session_control(session["Id"], "Stop")

    async def async_media_seek(self, position: float) -> None:
        """Seek to a position (in seconds)."""
        session = self._get_active_session()
        if not session:
            _LOGGER.debug("No active session for user %s, cannot seek", self._username)
            return
        position_ticks = int(position * TICKS_PER_SECOND)
        await self.coordinator.api.session_seek(session["Id"], position_ticks)

    async def async_media_next_track(self) -> None:
        """Send next track command to session."""
        session = self._get_active_session()
        if not session:
            _LOGGER.debug("No active session for user %s, cannot skip", self._username)
            return
        await self.coordinator.api.session_control(session["Id"], "NextTrack")

    async def async_media_previous_track(self) -> None:
        """Send previous track command to session."""
        session = self._get_active_session()
        if not session:
            _LOGGER.debug("No active session for user %s, cannot go back", self._username)
            return
        await self.coordinator.api.session_control(session["Id"], "PreviousTrack")

    async def async_set_volume_level(self, volume: float) -> None:
        """Set volume level (0.0 to 1.0)."""
        session = self._get_active_session()
        if not session:
            _LOGGER.debug("No active session for user %s, cannot set volume", self._username)
            return
        # Jellyfin expects 0-100 integer
        volume_int = str(int(volume * 100))
        await self.coordinator.api.session_general_command(
            session["Id"], "SetVolume", {"Volume": volume_int}
        )

    async def async_mute_volume(self, mute: bool) -> None:
        """Mute or unmute the volume."""
        session = self._get_active_session()
        if not session:
            _LOGGER.debug("No active session for user %s, cannot mute", self._username)
            return
        command = "Mute" if mute else "Unmute"
        await self.coordinator.api.session_general_command(session["Id"], command)

