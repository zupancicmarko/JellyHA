"""Media player platform for JellyHA."""
from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlparse

from homeassistant.components.media_player import (
    BrowseMedia,
    MediaPlayerEntity,
    MediaPlayerEntityFeature,
    MediaPlayerState,
    MediaType,
    RepeatMode,
)
try:
    from homeassistant.components.media_player import SearchMedia, SearchMediaQuery
except ImportError:
    SearchMedia = None  # type: ignore[assignment, misc]
    SearchMediaQuery = None  # type: ignore[assignment, misc]
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.util import dt as dt_util

from .browse_media import async_browse_media, async_browse_media_search, parse_item_id
from .const import (
    CONF_DEVICE_NAME,
    CONF_DEVICE_NAMES,
    CONF_DEVICE_PLAYERS,
    DEFAULT_DEVICE_NAME,
    DOMAIN,
    TICKS_PER_SECOND,
)
from .coordinator import JellyHALibraryCoordinator, JellyHASessionCoordinator
from .device import get_device_info
from .media_strategy import MediaStrategy

if TYPE_CHECKING:
    from ..jellyha import JellyHAConfigEntry

_LOGGER = logging.getLogger(__name__)

UUID_HEX_RE = re.compile(
    r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def extract_item_id(media_id: str) -> str:
    """Extract a valid Jellyfin item ID from raw IDs, URLs, or query strings."""
    if not media_id:
        return ""
    media_id = media_id.strip()
    if UUID_HEX_RE.match(media_id):
        return media_id.replace("-", "")

    try:
        parsed = urlparse(media_id)
    except Exception:
        parsed = None

    # Check query parameters (?itemId=, ?item_id=, ?id=, ?itemIds=)
    if parsed and parsed.query:
        qs = parse_qs(parsed.query)
        for key in ("item_id", "itemId", "id", "itemIds"):
            if key in qs and qs[key] and UUID_HEX_RE.match(qs[key][0]):
                return qs[key][0].replace("-", "")

    # Check URL fragment (e.g. web client #!/details?id=...)
    if parsed and parsed.fragment and "?" in parsed.fragment:
        fqs = parse_qs(parsed.fragment.split("?")[-1])
        for key in ("id", "itemId", "item_id"):
            if key in fqs and fqs[key] and UUID_HEX_RE.match(fqs[key][0]):
                return fqs[key][0].replace("-", "")

    # Inspect path segments in reverse for a valid GUID/UUID
    path = parsed.path if parsed and parsed.path else media_id.split("?")[0]
    segments = [s for s in path.rstrip("/").split("/") if s]
    for seg in reversed(segments):
        if UUID_HEX_RE.match(seg):
            return seg.replace("-", "")

    # Strip known endpoint suffixes (stream, download, file, master.m3u8, main.m3u8, etc.)
    known_suffixes = {"stream", "download", "file", "master.m3u8", "main.m3u8"}
    while segments and (segments[-1].lower() in known_suffixes or segments[-1].lower().startswith("stream.")):
        segments.pop()

    if segments:
        candidate = segments[-1]
        if "." in candidate and not UUID_HEX_RE.match(candidate):
            candidate = candidate.split(".")[0]
        return candidate

    return media_id



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

    # Create a media player for each configured client device
    device_ids: list[str] = entry.options.get(CONF_DEVICE_PLAYERS, [])
    device_names: dict[str, str] = entry.options.get(CONF_DEVICE_NAMES, {})
    for dev_id in device_ids:
        dev_title = device_names.get(dev_id) or "Device"
        entities.append(
            JellyHADeviceMediaPlayer(
                session_coordinator, entry, dev_id, dev_title, device_name
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
            name = self._current_item.get("name")
            if self._current_item.get("type") == "Audio" and name:
                artist = self._current_item.get("artist") or self._current_item.get("artist_name")
                return MediaStrategy.format_audio_title(artist, name)
            return name
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
        category, parsed_id = parse_item_id(media_id)
        item_id = parsed_id or extract_item_id(media_id)

        if not item_id:
            _LOGGER.warning("Cannot play: invalid media_id format: %s", media_id)
            return

        api = self.coordinator._api
        user_id = self._entry.data.get("user_id")

        # If album or playlist, resolve first playable track
        if (category in ("album", "playlist") or media_type in ("album", "playlist")) and api and user_id:
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
            except Exception as err:
                _LOGGER.debug("Could not resolve tracks for %s %s: %s", category, item_id, err)

        # If collection or boxset, resolve first playable video
        if (category in ("collection", "boxset") or media_type in ("collection", "boxset")) and api and user_id:
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
            except Exception as err:
                _LOGGER.debug("Could not resolve item for %s %s: %s", category, item_id, err)

        # Auto-resolve series/season to Next Up episode
        if api and user_id:
            try:
                item_details = await api.get_item(user_id, item_id)
                if item_details and item_details.get("Type") in ("Series", "Season"):
                    series_id = item_id if item_details.get("Type") == "Series" else item_details.get("SeriesId")
                    if series_id:
                        next_ep = await api.get_next_up_episode(user_id, series_id)
                        if not next_ep:
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
                                next_ep = first_unplayed[0]
                        if next_ep:
                            item_id = next_ep.get("Id", item_id)
            except Exception as err:
                _LOGGER.debug("Could not resolve series next-up for %s: %s", item_id, err)

        # Find the item in coordinator data
        items = self.coordinator.data.get("items", []) if self.coordinator.data else []
        item = next((i for i in items if i.get("id") == item_id), None)

        if not item:
            # Item might be a music track or other item not in the sync cache —
            # fall back to a direct API call
            _LOGGER.debug("Item %s not in cache, fetching from API", item_id)
            try:
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

        # Route playback to active Jellyfin player session(s)
        session_coordinator = getattr(self.coordinator.entry.runtime_data, "session", None)
        active_sessions = session_coordinator.data if session_coordinator and session_coordinator.data else []
        target_sessions = [
            s for s in active_sessions
            if s.get("UserId") == user_id and s.get("Client") not in ("home-assistant", "Seerr")
        ]
        if not target_sessions:
            target_sessions = [
                s for s in active_sessions
                if s.get("Client") not in ("home-assistant", "Seerr")
            ]

        if target_sessions and api:
            for s in target_sessions:
                sid = s.get("Id")
                if sid:
                    _LOGGER.info(
                        "Routing play request for '%s' (ID: %s) to active Jellyfin session %s (%s)",
                        item.get("name"),
                        item_id,
                        sid,
                        s.get("DeviceName"),
                    )
                    await api.session_play(sid, item_id)
        else:
            _LOGGER.info(
                "Play request for '%s' (ID: %s). No active Jellyfin sessions found to remote-control.",
                item.get("name"),
                item_id,
            )

    async def async_search_media(
        self,
        query: Any = None,
        media_content_type: str | None = None,
        media_content_id: str | None = None,
        **kwargs: Any,
    ) -> Any:
        """Search media from Jellyfin."""
        search_term = ""
        if query is not None:
            if hasattr(query, "search_query"):
                search_term = query.search_query
            elif isinstance(query, str):
                search_term = query
        if not search_term:
            search_term = media_content_id or kwargs.get("search_query") or ""

        result = await async_browse_media_search(
            self.hass,
            self._entry.entry_id,
            search_term,
        )
        if SearchMedia is not None and (query is not None and not isinstance(query, str)):
            return SearchMedia(result=result)
        return result


def _session_activity_timestamp(s: dict[str, Any]) -> float:
    """Extract epoch timestamp from session LastPlaybackCheckIn or LastActivityDate."""
    raw = s.get("LastPlaybackCheckIn") or s.get("LastActivityDate")
    if not raw:
        return 0.0
    parsed = dt_util.parse_datetime(raw)
    return parsed.timestamp() if parsed else 0.0


class JellyHABasePlaybackMediaPlayer(
    CoordinatorEntity[JellyHASessionCoordinator], MediaPlayerEntity
):
    """Base media player entity for Jellyfin playback sessions.

    Provides common playback state extraction, media metadata properties,
    chapter/segment awareness, and transport controls.
    """

    _attr_has_entity_name = True
    def _is_session_remote_controllable(self, session: dict[str, Any] | None) -> bool:
        """Check if a session can receive remote control commands."""
        if not session:
            return False
        # Do not route commands to our own integration or backend server sessions
        if session.get("Client") in ("home-assistant", "Seerr"):
            return False
        # If session explicitly declares remote control support, it is controllable
        if session.get("SupportsRemoteControl") is True:
            return True
        caps = session.get("Capabilities") or {}
        if caps.get("SupportsRemoteControl") is True:
            return True
        # For client players (Wholphin, Android TV, Smart TVs, Web, Mobile),
        # Jellyfin accepts /Playing and session commands even when SupportsRemoteControl is False when idle.
        return True

    @property
    def supported_features(self) -> MediaPlayerEntityFeature:
        """Flag media player features that are supported."""
        return (
            MediaPlayerEntityFeature.PAUSE
            | MediaPlayerEntityFeature.PLAY
            | MediaPlayerEntityFeature.STOP
            | MediaPlayerEntityFeature.SEEK
            | MediaPlayerEntityFeature.NEXT_TRACK
            | MediaPlayerEntityFeature.PREVIOUS_TRACK
            | MediaPlayerEntityFeature.VOLUME_SET
            | MediaPlayerEntityFeature.VOLUME_MUTE
            | MediaPlayerEntityFeature.SHUFFLE_SET
            | MediaPlayerEntityFeature.REPEAT_SET
            | MediaPlayerEntityFeature.BROWSE_MEDIA
            | MediaPlayerEntityFeature.PLAY_MEDIA
            | MediaPlayerEntityFeature.SEARCH_MEDIA
        )

    def __init__(
        self,
        coordinator: JellyHASessionCoordinator,
        entry: ConfigEntry,
        device_name: str,
    ) -> None:
        """Initialize the base media player."""
        super().__init__(coordinator)
        self._entry = entry
        self._device_name = device_name

    # ------------------------------------------------------------------
    # Device info
    # ------------------------------------------------------------------

    @property
    def device_info(self) -> DeviceInfo:
        """Return device info."""
        return get_device_info(self._entry.entry_id, self._device_name)

    # ------------------------------------------------------------------
    # Active session lookup (implemented by subclasses)
    # ------------------------------------------------------------------

    def _get_active_session(self) -> dict[str, Any] | None:
        """Get the active session for this media player entity."""
        raise NotImplementedError

    async def async_browse_media(
        self,
        media_content_type: str | None = None,
        media_content_id: str | None = None,
    ) -> BrowseMedia:
        """Browse this integration's Jellyfin library for this player."""
        return await async_browse_media(
            self.hass,
            self._entry.entry_id,
            media_content_type,
            media_content_id,
        )

    async def async_search_media(
        self,
        query: Any = None,
        media_content_type: str | None = None,
        media_content_id: str | None = None,
        **kwargs: Any,
    ) -> Any:
        """Search media from Jellyfin for this player."""
        search_term = ""
        if query is not None:
            if hasattr(query, "search_query"):
                search_term = query.search_query
            elif isinstance(query, str):
                search_term = query
        if not search_term:
            search_term = media_content_id or kwargs.get("search_query") or ""

        result = await async_browse_media_search(
            self.hass,
            self._entry.entry_id,
            search_term,
        )
        if SearchMedia is not None and (query is not None and not isinstance(query, str)):
            return SearchMedia(result=result)
        return result

    # ------------------------------------------------------------------
    # State
    # ------------------------------------------------------------------

    @property
    def state(self) -> MediaPlayerState:
        """Return the current state of the media player."""
        session = self._get_active_session()
        if not session or "NowPlayingItem" not in session:
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
        if not session or "NowPlayingItem" not in session:
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
        if not session or "NowPlayingItem" not in session:
            return None
        item = session.get("NowPlayingItem", {})
        name = item.get("Name")
        if item.get("Type") == "Audio" and name:
            album_artist = item.get("AlbumArtist")
            artists = item.get("Artists", [])
            artist = album_artist or (artists[0] if artists else None)
            return MediaStrategy.format_audio_title(artist, name)
        return name

    @property
    def media_artist(self) -> str | None:
        """Return the artist of current playing media (music track)."""
        session = self._get_active_session()
        if not session or "NowPlayingItem" not in session:
            return None
        item = session.get("NowPlayingItem", {})
        album_artist = item.get("AlbumArtist")
        artists = item.get("Artists", [])
        return album_artist or (artists[0] if artists else None)

    @property
    def media_album_name(self) -> str | None:
        """Return the album name of current playing media (music track)."""
        session = self._get_active_session()
        if not session or "NowPlayingItem" not in session:
            return None
        item = session.get("NowPlayingItem", {})
        return item.get("Album")

    @property
    def media_series_title(self) -> str | None:
        """Return the series title (TV shows only)."""
        session = self._get_active_session()
        if not session or "NowPlayingItem" not in session:
            return None
        item = session.get("NowPlayingItem", {})
        return item.get("SeriesName")

    @property
    def media_season(self) -> str | None:
        """Return the season number (TV shows only)."""
        session = self._get_active_session()
        if not session or "NowPlayingItem" not in session:
            return None
        item = session.get("NowPlayingItem", {})
        season = item.get("ParentIndexNumber")
        return str(season) if season is not None else None

    @property
    def media_episode(self) -> str | None:
        """Return the episode number (TV shows only)."""
        session = self._get_active_session()
        if not session or "NowPlayingItem" not in session:
            return None
        item = session.get("NowPlayingItem", {})
        episode = item.get("IndexNumber")
        return str(episode) if episode is not None else None

    @property
    def media_content_id(self) -> str | None:
        """Return the content ID of current playing media."""
        session = self._get_active_session()
        if not session or "NowPlayingItem" not in session:
            return None
        return session.get("NowPlayingItem", {}).get("Id")

    @property
    def media_image_url(self) -> str | None:
        """Return the image URL of current playing media (signed poster)."""
        session = self._get_active_session()
        if not session or "NowPlayingItem" not in session:
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
        if not session or "NowPlayingItem" not in session:
            return None
        ticks = session.get("NowPlayingItem", {}).get("RunTimeTicks", 0)
        if ticks and ticks > 0:
            return int(ticks / TICKS_PER_SECOND)
        return None

    @property
    def media_position(self) -> int | None:
        """Return the current position in seconds."""
        session = self._get_active_session()
        if not session or "NowPlayingItem" not in session:
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
        if not session or "NowPlayingItem" not in session:
            return None
        return dt_util.utcnow()

    @property
    def shuffle(self) -> bool | None:
        """Return True if shuffle is enabled."""
        session = self._get_active_session()
        if not session or "NowPlayingItem" not in session:
            return None
        play_state = session.get("PlayState", {})
        return (
            play_state.get("ShuffleMethod") == "Shuffle"
            or play_state.get("ShuffleMode") == "Shuffle"
        )

    @property
    def repeat(self) -> RepeatMode | str | None:
        """Return current repeat mode."""
        session = self._get_active_session()
        if not session or "NowPlayingItem" not in session:
            return None
        play_state = session.get("PlayState", {})
        mode = play_state.get("RepeatMode", "RepeatNone")
        if mode == "RepeatAll":
            return RepeatMode.ALL
        if mode == "RepeatOne":
            return RepeatMode.ONE
        return RepeatMode.OFF

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
        return None

    @property
    def is_volume_muted(self) -> bool | None:
        """Return True if volume is muted."""
        session = self._get_active_session()
        if not session:
            return None
        return session.get("PlayState", {}).get("IsMuted", False)

    # ------------------------------------------------------------------
    # Extra state attributes base helper
    # ------------------------------------------------------------------

    def _get_common_extra_attributes(
        self, session: dict[str, Any] | None
    ) -> dict[str, Any]:
        """Extract common playback attributes from active session."""
        attrs: dict[str, Any] = {
            "entry_id": self._entry.entry_id,
            "config_entry_id": self._entry.entry_id,
            "session_id": session.get("Id") if session else None,
            "device_name": session.get("DeviceName") if session else None,
            "client": session.get("Client") if session else None,
            "item_id": None,
            "title": None,
            "progress_percent": 0,
            "position_ticks": 0,
            "duration_ticks": 0,
            "runtime_minutes": 0,
            "image_url": None,
            "backdrop_url": None,
            "media_type": None,
            "is_paused": False,
            "repeat_mode": "RepeatNone",
            "shuffle_mode": "Sorted",
            "is_favorite": False,
            "config_external_url": self._entry.options.get(
                "external_url", self._entry.data.get("external_url", "")
            ),
            "supports_remote_control": self._is_session_remote_controllable(session),
            "dynamic_range": None,
            "video_range": None,
            "video_range_type": None,
            "video_codec": None,
            "video_bit_depth": None,
            "dv_profile": None,
            "color_transfer": None,
            "color_primaries": None,
        }

        if not session or "NowPlayingItem" not in session:
            return attrs

        item = session.get("NowPlayingItem", {})
        play_state = session.get("PlayState", {})
        item_type = item.get("Type")
        item_id = item.get("Id")

        attrs["item_id"] = item_id
        attrs["media_type"] = item_type
        attrs["title"] = self.media_title or item.get("Name")

        # Video stream and dynamic range attributes (SDR, HDR10, Dolby Vision, HLG)
        if item_type in ("Movie", "Episode", "Video", "MusicVideo"):
            video_attrs = MediaStrategy.extract_video_stream_attributes(item)
            attrs.update(video_attrs)

        # Ratings & metadata
        attrs["official_rating"] = item.get("OfficialRating")
        attrs["community_rating"] = item.get("CommunityRating")
        attrs["critic_rating"] = item.get("CriticRating")
        attrs["genres"] = item.get("Genres", [])

        runtime_ticks = item.get("RunTimeTicks", 0)
        if runtime_ticks > 0:
            attrs["runtime_minutes"] = int(runtime_ticks / TICKS_PER_SECOND / 60)
        else:
            attrs["runtime_minutes"] = 0

        # Type-specific attributes
        if item_type == "Episode":
            attrs["series_title"] = item.get("SeriesName")
            attrs["season"] = item.get("ParentIndexNumber")
            attrs["episode"] = item.get("IndexNumber")
            attrs["series_image_url"] = session.get("jellyha_series_poster_url")
        elif item_type == "Audio":
            album_artist = item.get("AlbumArtist")
            artists = item.get("Artists", [])
            attrs["artist_name"] = album_artist or (artists[0] if artists else None)
            attrs["album_name"] = item.get("Album")

        # Universal year resolution (with PremiereDate fallback)
        prod_year = item.get("ProductionYear")
        if not prod_year and item.get("PremiereDate") and len(item.get("PremiereDate", "")) >= 4 and item["PremiereDate"][:4].isdigit():
            prod_year = int(item["PremiereDate"][:4])
        attrs["year"] = prod_year

        # Playback state
        position_ticks = play_state.get("PositionTicks", 0)
        duration_ticks = item.get("RunTimeTicks", 0)
        attrs["is_paused"] = play_state.get("IsPaused", False)
        attrs["position_ticks"] = position_ticks
        attrs["duration_ticks"] = duration_ticks

        if duration_ticks and duration_ticks > 0:
            attrs["progress_percent"] = int((position_ticks / duration_ticks) * 100)
        else:
            attrs["progress_percent"] = 0

        # Modes & Flags
        attrs["repeat_mode"] = play_state.get("RepeatMode", "RepeatNone")
        attrs["shuffle_mode"] = (
            "Shuffle"
            if play_state.get("ShuffleMethod") == "Shuffle"
            or play_state.get("ShuffleMode") == "Shuffle"
            else "Sorted"
        )
        is_fav = item.get("UserData", {}).get("IsFavorite", False)
        if not is_fav and item_type == "Episode":
            series_id = item.get("SeriesId")
            lib_coord = getattr(getattr(self._entry, "runtime_data", None), "library", None)
            if series_id and lib_coord and series_id in getattr(lib_coord, "_favorite_series_ids", set()):
                is_fav = True
        attrs["is_favorite"] = is_fav

        # Poster & Backdrop URLs
        attrs["image_url"] = session.get("jellyha_poster_url")
        attrs["backdrop_url"] = session.get("jellyha_backdrop_url")

        # Chapter/segment awareness
        session_id_val = session.get("Id")
        if session_id_val:
            chapter = self.coordinator._get_current_chapter(
                session_id_val,
                position_ticks,
            )
            if chapter:
                attrs["media_chapter_index"] = chapter["chapter_index"]
                attrs["media_chapter_count"] = chapter["chapter_count"]
                attrs["media_chapter_name"] = chapter["chapter_name"]
                attrs["is_last_chapter"] = chapter["is_last_chapter"]

            segment = self.coordinator._get_current_segment(
                session_id_val,
                position_ticks,
            )
            if segment:
                attrs["media_segment_type"] = segment["type"]
                attrs["segment_end_seconds"] = round(
                    segment["end_ticks"] / TICKS_PER_SECOND, 1
                )

        return attrs

    # ------------------------------------------------------------------
    # Transport controls
    # ------------------------------------------------------------------

    def _get_target_session_ids(self) -> list[str]:
        """Get all target session IDs for this entity to route commands."""
        session = self._get_active_session()
        if not session or not self._is_session_remote_controllable(session):
            return []
        target_ids = [session["Id"]]
        # Broadcast only to sessions with the exact same device ID. WebOS IDs
        # share an encoded user-agent prefix across unrelated clients.
        dev_id = getattr(self, "_device_id", None) or session.get("DeviceId") or ""
        if dev_id and self.coordinator.data:
            for s in self.coordinator.data:
                sid = s.get("Id")
                if not sid or sid in target_ids:
                    continue
                s_dev_id = s.get("DeviceId") or ""
                if s_dev_id == dev_id:
                    if s.get("SupportsRemoteControl") is True:
                        target_ids.append(sid)
        return target_ids

    async def _send_session_control(self, command: str) -> None:
        """Send playstate control command to target sessions."""
        target_ids = self._get_target_session_ids()
        if not target_ids:
            _LOGGER.debug("No active session for %s, cannot send %s", self.name, command)
            return
        _LOGGER.debug("%s: sending %s to session(s): %s", self.name, command, target_ids)
        for sid in target_ids:
            await self.coordinator.api.session_control(sid, command)

    async def _send_session_seek(self, position_ticks: int) -> None:
        """Send seek command to target sessions."""
        target_ids = self._get_target_session_ids()
        if not target_ids:
            _LOGGER.debug("No active session for %s, cannot seek", self.name)
            return
        _LOGGER.debug("%s: sending seek (%d ticks) to session(s): %s", self.name, position_ticks, target_ids)
        for sid in target_ids:
            await self.coordinator.api.session_seek(sid, position_ticks)

    async def _send_session_general_command(
        self, command: str, arguments: dict[str, str] | None = None
    ) -> None:
        """Send general command to target sessions."""
        target_ids = self._get_target_session_ids()
        if not target_ids:
            _LOGGER.debug("No active session for %s, cannot send %s", self.name, command)
            return
        _LOGGER.debug("%s: sending general command %s to session(s): %s", self.name, command, target_ids)
        for sid in target_ids:
            await self.coordinator.api.session_general_command(sid, command, arguments)

    async def async_play_media(
        self,
        media_type: str,
        media_id: str,
        **kwargs: Any,
    ) -> None:
        """Play media on target session(s) using Home Assistant native play_media."""
        _LOGGER.info(
            "async_play_media requested on %s: media_type=%s, media_id=%s",
            self.name,
            media_type,
            media_id,
        )
        if not media_id:
            _LOGGER.warning("Cannot play on %s: No media_id provided", self.name)
            return

        target_ids = self._get_target_session_ids()
        if not target_ids:
            _LOGGER.warning(
                "Cannot play on %s: No active Jellyfin session found. Please make sure the app is open on the device.",
                self.name,
            )
            return

        # Parse the item ID
        category, parsed_id = parse_item_id(media_id)
        item_id = parsed_id or extract_item_id(media_id)

        if not item_id:
            _LOGGER.warning("Cannot play on %s: Invalid media_id format: %s", self.name, media_id)
            return

        api = getattr(self.coordinator, "api", None) or getattr(self.coordinator, "_api", None)
        if not api:
            _LOGGER.error("Cannot play on %s: API client unavailable on coordinator", self.name)
            return

        user_id = getattr(self, "_user_id", None) or self._entry.data.get("user_id")

        # If album or playlist, resolve first playable track
        if (category in ("album", "playlist") or media_type in ("album", "playlist")) and api and user_id:
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
            except Exception as err:
                _LOGGER.debug("Could not resolve tracks for %s %s: %s", category, item_id, err)

        # If collection or boxset, resolve first playable video
        if (category in ("collection", "boxset") or media_type in ("collection", "boxset")) and api and user_id:
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
            except Exception as err:
                _LOGGER.debug("Could not resolve item for %s %s: %s", category, item_id, err)

        # Auto-resolve series/season to Next Up episode
        if user_id and api:
            try:
                item = await api.get_item(user_id, item_id)
                if item and item.get("Type") in ("Series", "Season"):
                    series_id = item_id if item.get("Type") == "Series" else item.get("SeriesId")
                    if series_id:
                        next_ep = await api.get_next_up_episode(user_id, series_id)
                        if not next_ep:
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
                                next_ep = first_unplayed[0]
                        if next_ep:
                            item_id = next_ep.get("Id", item_id)
            except Exception as e:
                _LOGGER.debug("Could not resolve series next-up for %s: %s", item_id, e)

        _LOGGER.info("Sending session_play(%s) to session(s): %s", item_id, target_ids)
        for sid in target_ids:
            success = await api.session_play(sid, item_id)
            _LOGGER.info("session_play to %s result: %s", sid, success)

    async def async_media_play(self) -> None:
        """Send play (unpause) command to session."""
        await self._send_session_control("Unpause")

    async def async_media_pause(self) -> None:
        """Send pause command to session."""
        await self._send_session_control("Pause")

    async def async_media_stop(self) -> None:
        """Send stop command to session."""
        await self._send_session_control("Stop")

    async def async_media_seek(self, position: float) -> None:
        """Seek to a position (in seconds)."""
        position_ticks = int(position * TICKS_PER_SECOND)
        await self._send_session_seek(position_ticks)

    async def async_media_next_track(self) -> None:
        """Send next track command to session."""
        await self._send_session_control("NextTrack")

    async def async_media_previous_track(self) -> None:
        """Send previous track command to session."""
        await self._send_session_control("PreviousTrack")

    async def async_set_volume_level(self, volume: float) -> None:
        """Set volume level (0.0 to 1.0)."""
        volume_int = str(int(volume * 100))
        await self._send_session_general_command("SetVolume", {"Volume": volume_int})

    async def async_mute_volume(self, mute: bool) -> None:
        """Mute or unmute the volume."""
        command = "Mute" if mute else "Unmute"
        await self._send_session_general_command(command)

    async def async_set_shuffle(self, shuffle: bool) -> None:
        """Enable or disable shuffle mode."""
        mode = "Shuffle" if shuffle else "Sorted"
        await self._send_session_general_command("SetShuffleQueue", {"ShuffleMode": mode})

    async def async_set_repeat(self, repeat: RepeatMode) -> None:
        """Set repeat mode."""
        if repeat == RepeatMode.ALL:
            mode = "RepeatAll"
        elif repeat == RepeatMode.ONE:
            mode = "RepeatOne"
        else:
            mode = "RepeatNone"
        await self._send_session_general_command("SetRepeatMode", {"RepeatMode": mode})


class JellyHAUserMediaPlayer(JellyHABasePlaybackMediaPlayer):
    """Media player entity tracking a Jellyfin user's active playback session.

    One entity is created per Jellyfin user. When the user is not playing
    anything the entity reports IDLE. During playback it exposes the
    standard Home Assistant media_player transport controls and rich
    metadata attributes.
    """

    def __init__(
        self,
        coordinator: JellyHASessionCoordinator,
        entry: ConfigEntry,
        user_id: str,
        username: str,
        device_name: str,
    ) -> None:
        """Initialize the user media player."""
        super().__init__(coordinator, entry, device_name)
        self._user_id = user_id
        self._username = username
        self._attr_unique_id = f"{entry.entry_id}_media_player_{user_id}"
        self._attr_name = f"{username}"
        self._attr_icon = "mdi:account-play"

    def _get_active_session(self) -> dict[str, Any] | None:
        """Get the active session for this user with stable priority.

        If the user has multiple active sessions (e.g. phone + TV), prefer
        the one that is currently playing (not paused). Ties are broken by
        session ID for determinism.
        """
        if not self.coordinator.data:
            return None

        user_sessions = [
            s
            for s in self.coordinator.data
            if s.get("UserId") == self._user_id
        ]

        if not user_sessions:
            return None

        user_sessions.sort(
            key=lambda s: (
                0 if "NowPlayingItem" in s else 1,
                s.get("PlayState", {}).get("IsPaused", False),
                -_session_activity_timestamp(s),
                s.get("Id", ""),
            )
        )
        return user_sessions[0]

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return additional state attributes."""
        session = self._get_active_session()
        attrs = self._get_common_extra_attributes(session)
        attrs["user_id"] = self._user_id
        attrs["user_name"] = self._username
        return attrs


class JellyHADeviceMediaPlayer(JellyHABasePlaybackMediaPlayer):
    """Media player entity tracking a physical client device's playback session.

    Entities are created for client devices selected in integration options
    (e.g., Smart TVs, streaming boxes, media PCs). State and variables are
    tracked per client device regardless of which user is currently logged in.
    """

    def __init__(
        self,
        coordinator: JellyHASessionCoordinator,
        entry: ConfigEntry,
        device_id: str,
        custom_device_name: str,
        base_device_name: str,
    ) -> None:
        """Initialize the device media player."""
        super().__init__(coordinator, entry, base_device_name)
        self._device_id = device_id
        self._custom_device_name = custom_device_name
        self._attr_unique_id = f"{entry.entry_id}_device_player_{device_id}"
        self._attr_name = f"{custom_device_name}"
        lower_name = custom_device_name.lower()
        if any(w in lower_name for w in ("phone", "s20", "s21", "s22", "s23", "s24", "s25", "pixel", "iphone", "mobile")):
            self._attr_icon = "mdi:cellphone-play"
        elif any(w in lower_name for w in ("tablet", "ipad", "pad", "tab")):
            self._attr_icon = "mdi:tablet-play"
        else:
            self._attr_icon = "mdi:television-play"

    def _is_matching_device_session(self, s: dict[str, Any]) -> bool:
        """Check if a session belongs to this device."""
        session_dev_id = s.get("DeviceId") or ""
        # WebOS identifiers encode the user agent. Multiple unrelated clients
        # share its prefix, so prefix/name matching merges them incorrectly.
        return bool(session_dev_id and self._device_id and session_dev_id == self._device_id)

    def _get_active_session(self) -> dict[str, Any] | None:
        """Get the active session for this device with stable priority.

        If multiple sessions share the DeviceId, prefer sessions that have
        NowPlayingItem and are currently playing (not paused). Ties are broken
        by session ID for determinism.
        """
        if not self.coordinator.data:
            return None

        device_sessions = [
            s
            for s in self.coordinator.data
            if self._is_matching_device_session(s)
        ]

        if not device_sessions:
            return None

        device_sessions.sort(
            key=lambda s: (
                0 if "NowPlayingItem" in s else 1,
                s.get("PlayState", {}).get("IsPaused", False),
                -_session_activity_timestamp(s),
                s.get("Id", ""),
            )
        )
        selected = device_sessions[0]
        _LOGGER.debug(
            "Device player '%s' matched %d sessions. Selected session %s (NowPlaying=%s, Item=%s)",
            self._custom_device_name,
            len(device_sessions),
            selected.get("Id"),
            "NowPlayingItem" in selected,
            selected.get("NowPlayingItem", {}).get("Name"),
        )
        return selected

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return additional state attributes."""
        session = self._get_active_session()
        attrs = self._get_common_extra_attributes(session)
        attrs["device_id"] = self._device_id
        if not attrs.get("device_name"):
            attrs["device_name"] = self._custom_device_name
        attrs["user_id"] = session.get("UserId") if session else None
        attrs["user_name"] = session.get("UserName") if session else None
        return attrs
