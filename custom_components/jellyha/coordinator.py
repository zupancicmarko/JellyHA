"""DataUpdateCoordinator for JellyHA Library."""
from __future__ import annotations

from datetime import datetime, timedelta
import logging
import hashlib
import time
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import (
    DataUpdateCoordinator,
    UpdateFailed,
)
from homeassistant.components.http.auth import async_sign_path
import asyncio
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.issue_registry import async_create_issue, IssueSeverity
from homeassistant.util import dt as dt_util

from .api import (
    JellyfinApiClient,
    JellyfinApiError,
    JellyfinAuthError,
    JellyfinConnectionError,
)
from .ws_client import JellyfinWebSocketClient
from .const import (
    CONF_API_KEY,
    CONF_LIBRARIES,
    CONF_REFRESH_INTERVAL,
    CONF_SERVER_URL,
    CONF_USER_ID,
    DEFAULT_IMAGE_HEIGHT,
    DEFAULT_IMAGE_QUALITY,
    DEFAULT_REFRESH_INTERVAL,
    DOMAIN,
    EVENT_CHAPTER_CHANGE,
    EVENT_SEGMENT_CHANGE,
    CHAPTER_SEGMENT_PATTERNS,
    ITEM_TYPE_MOVIE,
    ITEM_TYPE_SERIES,
    RATING_SOURCE_AUTO,
    RATING_SOURCE_IMDB,
    RATING_SOURCE_TMDB,
    TICKS_PER_MINUTE,
    TICKS_PER_SECOND,
    migrate_refresh_interval,
)

_LOGGER = logging.getLogger(__name__)

# Signed URL cache TTL in seconds.
# JWTs expire after 24h; re-sign 1h early to avoid serving near-expiry tokens.
# Temporarily lower this value (e.g. 60) for quick manual testing.
_URL_CACHE_TTL = 23 * 3600  # 23 hours

class JellyHALibraryCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """Coordinator to fetch media library items from Jellyfin."""

    def __init__(
        self, 
        hass: HomeAssistant, 
        entry: ConfigEntry, 
        storage: Any = None
    ) -> None:
        """Initialize the coordinator."""
        self.entry = entry
        self.storage = storage
        self._api: JellyfinApiClient | None = None
        self._server_name: str | None = None
        self._server_version: str | None = None
        self.last_refresh_time: datetime | None = None
        self.last_data_change_time: datetime | None = None
        self.last_refresh_duration: float | None = None  # Duration of last refresh in seconds
        self._previous_item_ids: set[str] = set()
        self._previous_item_hash: str = ""
        # Cache signed URLs by (item_id, image_type, tag) -> (url, monotonic timestamp)
        self._url_cache: dict[tuple[str, str, str], tuple[str, float]] = {}

        raw_interval = entry.options.get(
            CONF_REFRESH_INTERVAL,
            entry.data.get(CONF_REFRESH_INTERVAL, DEFAULT_REFRESH_INTERVAL),
        )
        # Migrate legacy raw-seconds values to nearest valid dropdown option
        interval_seconds = migrate_refresh_interval(int(raw_interval))
        # 0 = Off: disable polling entirely
        update_interval = timedelta(seconds=interval_seconds) if interval_seconds > 0 else None

        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=update_interval,
            always_update=False,
        )

    async def _async_setup(self) -> None:
        """Set up the coordinator (called once during first refresh)."""
        session = async_get_clientsession(self.hass)
        self._api = JellyfinApiClient(
            server_url=self.entry.data[CONF_SERVER_URL],
            api_key=self.entry.data[CONF_API_KEY],
            session=session,
        )

        try:
            server_info = await self._api.validate_connection()
            self._server_name = server_info.get("ServerName", "Jellyfin")
            self._server_version = server_info.get("Version")
            _LOGGER.info(
                "Connected to Jellyfin server '%s' version %s at %s",
                self._server_name,
                self._server_version,
                self.entry.data[CONF_SERVER_URL],
            )
        except JellyfinAuthError as err:
            raise ConfigEntryAuthFailed(str(err)) from err
        except JellyfinConnectionError as err:
            raise UpdateFailed(f"Failed to connect to Jellyfin: {err}") from err
        except JellyfinApiError as err:
            raise UpdateFailed(f"Error connecting to Jellyfin: {err}") from err

    async def _async_update_data(self) -> dict[str, Any]:
        """Fetch data from Jellyfin API."""
        start_time = time.monotonic()
        
        if self._api is None:
            await self._async_setup()

        user_id = self.entry.data[CONF_USER_ID]
        libraries = self.entry.data.get(CONF_LIBRARIES, [])

        _LOGGER.debug(
            "Fetching library items for user_id=%s, libraries=%s",
            user_id,
            libraries if libraries else "(all)",
        )

        try:
            raw_items = await self._api.get_library_items(
                user_id=user_id,
                limit=0,  # 0 = no limit, fetch all items
                library_ids=libraries if libraries else None,
            )

            items = await asyncio.gather(*(self._async_transform_item(item) for item in raw_items))

            # Fetch Next Up items (limit 20)
            next_up_limit = 20
            raw_next_up = await self._api.get_next_up_items(user_id=user_id, limit=next_up_limit)
            next_up_items = []
            if raw_next_up:
                next_up_items = await asyncio.gather(*(self._async_transform_item(item) for item in raw_next_up))
                # Enhance Next Up items with season/episode info specifically
                for i, raw in zip(next_up_items, raw_next_up):
                    i["season"] = raw.get("ParentIndexNumber")
                    i["episode"] = raw.get("IndexNumber")
                    i["season_name"] = raw.get("SeasonName")
                    i["series_name"] = raw.get("SeriesName")

            # Update last refresh time (always updates)
            self.last_refresh_time = dt_util.utcnow()

            # Evict expired entries from the URL cache
            now_mono = time.monotonic()
            self._url_cache = {
                k: v for k, v in self._url_cache.items()
                if (now_mono - v[1]) < _URL_CACHE_TTL
            }

            # Check if data actually changed
            current_item_ids = {item["id"] for item in items}
            # Create a simple hash based on item IDs and key attributes
            current_hash = await self._compute_data_hash(items, next_up_items)
            
            if current_hash != self._previous_item_hash:
                self.last_data_change_time = dt_util.utcnow()
                self._previous_item_hash = current_hash
                self._previous_item_ids = current_item_ids
                _LOGGER.debug("Library data changed, updating last_data_change_time")
                
            # Persist items to storage if available
            if self.storage:
                await self.storage.update_from_coordinator(items)

            # Log timing information
            elapsed = time.monotonic() - start_time
            self.last_refresh_duration = elapsed  # Store for sensor access
            
            refresh_interval = self.entry.options.get(
                CONF_REFRESH_INTERVAL,
                self.entry.data.get(CONF_REFRESH_INTERVAL, DEFAULT_REFRESH_INTERVAL),
            )
            
            if elapsed > refresh_interval:
                _LOGGER.warning(
                    "Library refresh took %.1fs, which exceeds the configured refresh_interval of %ds. "
                    "Consider increasing refresh_interval to avoid potential data staleness.",
                    elapsed,
                    refresh_interval,
                )
            else:
                _LOGGER.debug("Library refresh completed in %.1fs for %d items", elapsed, len(items))

            return {
                "items": items,
                "count": len(items),
                "server_name": self._server_name,
                "last_refresh": self.last_refresh_time.isoformat(),
                "last_data_change": self.last_data_change_time.isoformat() if self.last_data_change_time else None,
                "next_up_items": next_up_items,
            }

        except JellyfinAuthError as err:
            async_create_issue(
                self.hass,
                DOMAIN,
                "invalid_auth",
                is_fixable=False,
                severity=IssueSeverity.ERROR,
                translation_key="invalid_auth",
                learn_more_url="https://github.com/zupancicmarko/jellyha",
            )
            raise ConfigEntryAuthFailed(str(err)) from err
        except JellyfinConnectionError as err:
            raise UpdateFailed(
                f"Cannot reach Jellyfin server at "
                f"{self.entry.data[CONF_SERVER_URL]}: {err}"
            ) from err
        except JellyfinApiError as err:
            raise UpdateFailed(
                f"Jellyfin API error (server version "
                f"{self._server_version or 'unknown'}): {err}"
            ) from err

    async def _compute_data_hash(self, items: list[dict[str, Any]], next_up_items: list[dict[str, Any]] = None) -> str:
        """Compute a hash of item data to detect changes (runs in executor)."""
        return await self.hass.async_add_executor_job(
            self._compute_data_hash_sync, items, next_up_items
        )

    def _compute_data_hash_sync(self, items: list[dict[str, Any]], next_up_items: list[dict[str, Any]] = None) -> str:
        """Synchronous implementation of hash computation."""
        # Include item IDs, count, and key changing attributes like is_played
        hash_data = []
        # Sorting is CPU intensive for large lists
        for item in sorted(items, key=lambda x: x.get("id", "")):
            hash_data.append(f"{item.get('id')}:{item.get('is_played')}:{item.get('is_favorite')}:{item.get('date_added')}")
        
        # Include Next Up in hash
        if next_up_items:
             hash_data.append("NEXT_UP")
             for item in sorted(next_up_items, key=lambda x: x.get("id", "")):
                 hash_data.append(f"{item.get('id')}:{item.get('is_played')}")

        return hashlib.sha256("|".join(hash_data).encode()).hexdigest()

    async def _async_transform_item(self, item: dict[str, Any]) -> dict[str, Any]:
        """Transform raw Jellyfin item to our schema."""
        item_id = item.get("Id", "")
        item_type = item.get("Type", "")

        # Runtime in minutes (Jellyfin returns ticks, 1 tick = 100 nanoseconds)
        runtime_ticks = item.get("RunTimeTicks", 0)
        runtime_minutes = int(runtime_ticks / TICKS_PER_MINUTE) if runtime_ticks else None

        # Simplified rating
        rating = item.get("CommunityRating")

        # Generate signed URLs with caching and TTL-based expiry
        expiration = timedelta(hours=24)
        now = time.monotonic()
        
        poster_tag = item.get('ImageTags', {}).get('Primary', '')
        poster_cache_key = (item_id, "Primary", poster_tag)
        cached = self._url_cache.get(poster_cache_key)
        if cached and (now - cached[1]) < _URL_CACHE_TTL:
            poster_url = cached[0]
        else:
            poster_path = f"/api/jellyha/image/{self.entry.entry_id}/{item_id}/Primary?tag={poster_tag}"
            poster_url = async_sign_path(self.hass, poster_path, expiration)
            self._url_cache[poster_cache_key] = (poster_url, now)

        backdrop_url = None
        backdrop_tags = item.get('BackdropImageTags', [])
        backdrop_item_id = item_id
        if not backdrop_tags:
            backdrop_tags = item.get('ParentBackdropImageTags', [])
            backdrop_item_id = item.get('ParentBackdropItemId') or item.get('SeriesId') or item_id

        if backdrop_tags and backdrop_item_id:
            backdrop_tag = backdrop_tags[0]
            backdrop_cache_key = (backdrop_item_id, "Backdrop", backdrop_tag)
            cached = self._url_cache.get(backdrop_cache_key)
            if cached and (now - cached[1]) < _URL_CACHE_TTL:
                backdrop_url = cached[0]
            else:
                backdrop_path = f"/api/jellyha/image/{self.entry.entry_id}/{backdrop_item_id}/Backdrop?tag={backdrop_tag}"
                backdrop_url = async_sign_path(self.hass, backdrop_path, expiration)
                self._url_cache[backdrop_cache_key] = (backdrop_url, now)

        # Cache series poster URL for episodes
        series_poster_url = None
        if item_type == "Episode":
            series_id = item.get("SeriesId")
            series_tag = item.get("SeriesPrimaryImageTag")
            if series_id and series_tag:
                series_cache_key = (series_id, "Primary", series_tag)
                cached = self._url_cache.get(series_cache_key)
                if cached and (now - cached[1]) < _URL_CACHE_TTL:
                    series_poster_url = cached[0]
                else:
                    series_path = f"/api/jellyha/image/{self.entry.entry_id}/{series_id}/Primary?tag={series_tag}"
                    series_poster_url = async_sign_path(self.hass, series_path, expiration)
                    self._url_cache[series_cache_key] = (series_poster_url, now)

        # Extract media streams if present
        media_streams = []
        if "MediaStreams" in item and item["MediaStreams"]:
            media_streams = item.get("MediaStreams", [])
        elif "MediaSources" in item and item["MediaSources"]:
            media_streams = item["MediaSources"][0].get("MediaStreams", [])

        # Build music-specific fields conditionally
        artist_name = None
        album_artist = None
        album = None
        if item_type in ("Audio", "MusicAlbum", "MusicVideo"):
            album_artist = item.get("AlbumArtist")
            artists = item.get("Artists", [])
            artist_name = album_artist or (artists[0] if artists else None)
            album = item.get("Album")

        return {
            "id": item_id,
            "name": item.get("Name", ""),
            "type": item_type,
            "year": item.get("ProductionYear"),
            "runtime_minutes": runtime_minutes,
            "genres": item.get("Genres", []),
            "rating": rating,
            "description": item.get("Overview", ""),
            "poster_url": poster_url,
            "backdrop_url": backdrop_url,
            "series_poster_url": series_poster_url,
            "date_added": item.get("DateCreated"),
            "jellyfin_url": self._api.get_jellyfin_url(item_id),
            "is_played": item.get("UserData", {}).get("Played", False),
            "unplayed_count": item.get("UserData", {}).get("UnplayedItemCount"),
            "is_favorite": item.get("UserData", {}).get("IsFavorite", False),
            "official_rating": item.get("OfficialRating"),
            "trailer_url": next((t["Url"] for t in item.get("RemoteTrailers", []) if t.get("Url")), None),
            "last_played_date": item.get("UserData", {}).get("LastPlayedDate"),
            "community_rating": rating,
            "season_name": item.get("SeasonName"),
            "index_number": item.get("IndexNumber"),
            "series_name": item.get("SeriesName"),
            "series_id": item.get("SeriesId"),
            "season": item.get("ParentIndexNumber"),
            "episode": item.get("IndexNumber"),
            "media_streams": media_streams,
            # Music-specific fields (None for non-music items)
            "artist_name": artist_name,
            "album_artist": album_artist,
            "album": album,
        }




class JellyHASessionCoordinator(DataUpdateCoordinator[list[dict[str, Any]]]):
    """Coordinator to fetch active sessions from Jellyfin."""

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        api: JellyfinApiClient,
        ws_client: JellyfinWebSocketClient | None = None,
    ) -> None:
        """Initialize the coordinator."""
        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN}_sessions",
            update_interval=timedelta(seconds=5),
            always_update=False,
        )
        self.entry = entry
        self._api = api
        self._ws_client = ws_client
        self.users: dict[str, str] = {}  # Map user_id to username
        self._previous_sessions: dict[str, dict[str, Any]] = {}  # Map session_id to session data
        self._device_id: str | None = None
        # Cache signed URLs by (item_id, image_type, tag) -> (url, monotonic timestamp)
        self._url_cache: dict[tuple[str, str, str], tuple[str, float]] = {}

        self._session_segments: dict[str, list[dict]] = {}
        self._session_typed_segments: dict[str, list[dict]] = {}
        self._previous_chapter_index: dict[str, int | None] = {}
        self._previous_segment_type: dict[str, str | None] = {}
        self._current_item_id: dict[str, str | None] = {}

        if self._ws_client:
            self._ws_client.set_on_session_update(self._handle_ws_session_update)
            self._ws_client.set_on_connect(self._handle_ws_connect)
            self._ws_client.set_on_disconnect(self._handle_ws_disconnect)

    @property
    def api(self) -> JellyfinApiClient:
        """Return the API client for session commands."""
        return self._api

    async def _async_setup(self) -> None:
        """Fetch users once on startup."""
        try:
            users = await self._api.get_users()
            self.users = {u["Id"]: u["Name"] for u in users}
            _LOGGER.debug("Loaded %d users", len(self.users))
        except JellyfinApiError as err:
            _LOGGER.error("Failed to fetch users: %s", err)

    async def _async_update_data(self) -> list[dict[str, Any]]:
        """Fetch sessions from Jellyfin API."""
        if not self.users:
            await self._async_setup()

        try:
            sessions = await self._api.get_sessions()
            
            # Fetch UserData for playing items since /Sessions endpoint omits it
            for s in sessions:
                user_id = s.get("UserId")
                if user_id and "NowPlayingItem" in s:
                    item_id = s["NowPlayingItem"].get("Id")
                    if item_id:
                        try:
                            item_details = await self._api.get_item(user_id, item_id)
                            user_data = item_details.get("UserData")
                            if user_data:
                                s["NowPlayingItem"]["UserData"] = user_data
                            chapters = item_details.get("Chapters")
                            if chapters:
                                s["NowPlayingItem"]["Chapters"] = chapters
                        except JellyfinApiError as err:
                            _LOGGER.debug("Failed to fetch UserData for item %s: %s", item_id, err)

            self._enrich_sessions(sessions)
            await self._process_chapters(sessions)
            
            # Fire events even during polling to ensure automation triggers work
            self._fire_session_events(sessions)
            return sessions
        except JellyfinApiError as err:
            raise UpdateFailed(f"Error fetching sessions: {err}") from err

    def _enrich_sessions(self, sessions: list[dict[str, Any]]) -> None:
        """Add signed image URLs to sessions with caching and TTL-based expiry."""
        expiration = timedelta(hours=24)
        now = time.monotonic()

        # Evict expired entries from the URL cache
        self._url_cache = {
            k: v for k, v in self._url_cache.items()
            if (now - v[1]) < _URL_CACHE_TTL
        }
        
        for s in sessions:
            if "NowPlayingItem" in s:
                item = s["NowPlayingItem"]
                item_id = item.get("Id")
                
                if item_id:
                    # Cache poster URL
                    poster_tag = item.get('ImageTags', {}).get('Primary', '')
                    poster_cache_key = (item_id, "Primary", poster_tag)
                    cached = self._url_cache.get(poster_cache_key)
                    if cached and (now - cached[1]) < _URL_CACHE_TTL:
                        s["jellyha_poster_url"] = cached[0]
                    else:
                        poster_path = f"/api/jellyha/image/{self.entry.entry_id}/{item_id}/Primary?tag={poster_tag}"
                        s["jellyha_poster_url"] = async_sign_path(self.hass, poster_path, expiration)
                        self._url_cache[poster_cache_key] = (s["jellyha_poster_url"], now)
                    
                    # Cache backdrop URL
                    backdrop_tags = item.get("BackdropImageTags", [])
                    backdrop_item_id = item_id
                    if not backdrop_tags:
                        backdrop_tags = item.get("ParentBackdropImageTags", [])
                        backdrop_item_id = item.get("ParentBackdropItemId") or item.get("SeriesId") or item_id

                    if backdrop_tags and backdrop_item_id:
                        backdrop_tag = backdrop_tags[0]
                        backdrop_cache_key = (backdrop_item_id, "Backdrop", backdrop_tag)
                        cached = self._url_cache.get(backdrop_cache_key)
                        if cached and (now - cached[1]) < _URL_CACHE_TTL:
                            s["jellyha_backdrop_url"] = cached[0]
                        else:
                            backdrop_path = f"/api/jellyha/image/{self.entry.entry_id}/{backdrop_item_id}/Backdrop?tag={backdrop_tag}"
                            s["jellyha_backdrop_url"] = async_sign_path(self.hass, backdrop_path, expiration)
                            self._url_cache[backdrop_cache_key] = (s["jellyha_backdrop_url"], now)
                    
                    # Cache series poster URL for episodes
                    if item.get("Type") == "Episode":
                        series_id = item.get("SeriesId")
                        series_tag = item.get("SeriesPrimaryImageTag")
                        if series_id and series_tag:
                            series_cache_key = (series_id, "Primary", series_tag)
                            cached = self._url_cache.get(series_cache_key)
                            if cached and (now - cached[1]) < _URL_CACHE_TTL:
                                s["jellyha_series_poster_url"] = cached[0]
                            else:
                                series_path = f"/api/jellyha/image/{self.entry.entry_id}/{series_id}/Primary?tag={series_tag}"
                                s["jellyha_series_poster_url"] = async_sign_path(self.hass, series_path, expiration)
                                self._url_cache[series_cache_key] = (s["jellyha_series_poster_url"], now)

    async def _handle_ws_session_update(self, sessions: list[dict[str, Any]]) -> None:
        """Handle session updates from WebSocket."""
        _LOGGER.debug("Coordinator received %d sessions from WS", len(sessions))
        
        # Fetch UserData for playing items since WS sessions payload omits it
        for s in sessions:
            user_id = s.get("UserId")
            if user_id and "NowPlayingItem" in s:
                item_id = s["NowPlayingItem"].get("Id")
                if item_id:
                    try:
                        item_details = await self._api.get_item(user_id, item_id)
                        user_data = item_details.get("UserData")
                        if user_data:
                            s["NowPlayingItem"]["UserData"] = user_data
                        chapters = item_details.get("Chapters")
                        if chapters:
                            s["NowPlayingItem"]["Chapters"] = chapters
                    except JellyfinApiError as err:
                        _LOGGER.debug("Failed to fetch UserData for WS item %s: %s", item_id, err)

        # Enrich with signed URLs (same as polling path)
        self._enrich_sessions(sessions)
        await self._process_chapters(sessions)
        
        # Fire events for device triggers
        self._fire_session_events(sessions)
        
        for s in sessions:
             _LOGGER.debug("Session user: %s, Device: %s, NowPlaying: %s", 
                           s.get("UserId"), s.get("DeviceName"), "Yes" if "NowPlayingItem" in s else "No")
        self.async_set_updated_data(sessions)

    def _fire_session_events(self, current_sessions: list[dict[str, Any]]) -> None:
        """Fire events based on session state changes."""
        if not self._device_id:
            dev_reg = dr.async_get(self.hass)
            device = dev_reg.async_get_device(identifiers={(DOMAIN, self.entry.entry_id)})
            if device:
                self._device_id = device.id
        
        if not self._device_id:
            return

        curr_map = {s["Id"]: s for s in current_sessions}
        
        # Check for changes
        for s_id, s in curr_map.items():
            prev = self._previous_sessions.get(s_id)
            event_type = None
            
            # Check for Play/Pause logic
            # "NowPlayingItem" must exist for it to be a relevant media session
            if "NowPlayingItem" in s:
                is_paused = s.get("PlayState", {}).get("IsPaused", False)
                
                if not prev or "NowPlayingItem" not in prev:
                    # New media session -> Play
                    event_type = "media_play" if not is_paused else "media_pause"
                else:
                    # Existing session, check state change
                    prev_paused = prev.get("PlayState", {}).get("IsPaused", False)
                    if is_paused != prev_paused:
                        event_type = "media_pause" if is_paused else "media_play"
            
            if event_type:
                self.hass.bus.async_fire(
                    f"{DOMAIN}_event",
                    {
                        "type": event_type,
                        "device_id": self._device_id,
                        "session_id": s_id,
                        "user_id": s.get("UserId"),
                        "media_title": s.get("NowPlayingItem", {}).get("Name"),
                    }
                )

        # Check for Stops (session removed or media stopped)
        for s_id, prev in self._previous_sessions.items():
            if s_id not in curr_map or "NowPlayingItem" not in curr_map[s_id]:
                if "NowPlayingItem" in prev:
                    self._cleanup_session(s_id, prev)
                    self.hass.bus.async_fire(
                        f"{DOMAIN}_event",
                        {
                            "type": "media_stop",
                            "device_id": self._device_id,
                            "session_id": s_id,
                            "user_id": prev.get("UserId"),
                            "media_title": prev.get("NowPlayingItem", {}).get("Name"),
                        }
                    )

        self._previous_sessions = curr_map

    async def _handle_ws_connect(self) -> None:
        """Handle WebSocket connection."""
        _LOGGER.info("WebSocket connected, switching to push updates")
        self.update_interval = None
        # We don't need to do anything else, WS will send data.

    async def _handle_ws_disconnect(self) -> None:
        """Handle WebSocket disconnection."""
        _LOGGER.info("WebSocket disconnected, switching to polling updates")
        self.update_interval = timedelta(seconds=5)
        # Trigger an immediate refresh to ensure we have data and restart the timer
        await self.async_request_refresh()

    async def _process_chapters(self, sessions: list[dict[str, Any]]) -> None:
        """Process chapters and segments for active sessions."""
        for session in sessions:
            session_id = session.get("Id")
            if not session_id:
                continue
            now_playing = session.get("NowPlayingItem") or {}
            play_state = session.get("PlayState") or {}
            item_id = now_playing.get("Id")
            position = play_state.get("PositionTicks", 0)
            chapters = now_playing.get("Chapters") or []
            runtime = now_playing.get("RunTimeTicks")

            # --- Detect new item ---
            if item_id and item_id != self._current_item_id.get(session_id):
                self._current_item_id[session_id] = item_id
                self._previous_chapter_index[session_id] = None
                self._previous_segment_type[session_id] = None
                await self._build_segment_cache(session_id, item_id, chapters, runtime)

            # --- Resolve current state ---
            current_chapter = self._get_current_chapter(session_id, position)
            current_seg = self._get_current_segment(session_id, position)
            current_seg_type = current_seg["type"] if current_seg else None

            if current_chapter:
                # --- Chapter transition ---
                prev_idx = self._previous_chapter_index.get(session_id)
                if current_chapter["chapter_index"] != prev_idx:
                    self._previous_chapter_index[session_id] = current_chapter["chapter_index"]
                    self._fire_chapter_event(session, current_chapter)

            # --- Segment transition ---
            prev_seg = self._previous_segment_type.get(session_id)
            if current_seg_type != prev_seg:
                self._previous_segment_type[session_id] = current_seg_type
                self._fire_segment_event(
                    session,
                    current_chapter or {"chapter_index": None, "chapter_name": ""},
                    current_seg_type,
                    prev_seg,
                    segment_entry=current_seg,
                )

    def _classify_chapter_name(self, name: str) -> str | None:
        """Apply local regex patterns to a chapter name."""
        for segment_type, pattern in CHAPTER_SEGMENT_PATTERNS:
            if pattern.search(name):
                return segment_type
        return None

    async def _build_segment_cache(
        self,
        session_id: str,
        item_id: str,
        chapters: list[dict],
        runtime_ticks: int | None,
    ) -> None:
        """Populate session segment cache."""
        segments_from_api: list[dict] = []

        if item_id:
            segments_from_api = await self._api.get_media_segments(item_id)

        # 1. Parse typed segments from MediaSegments API (Intro Skipper, etc.)
        typed_segments: list[dict] = []
        for seg in segments_from_api:
            stype = seg.get("Type")
            if stype:
                typed_segments.append({
                    "type": stype,
                    "start_ticks": seg.get("StartTicks", 0),
                    "end_ticks": seg.get("EndTicks", seg.get("StartTicks", 0)),
                })

        # 2. If no API segments, extract typed segments from chapter names
        if not typed_segments and chapters:
            for idx, ch in enumerate(chapters):
                classified = self._classify_chapter_name(ch.get("Name", ""))
                if classified:
                    start = ch.get("StartPositionTicks", 0)
                    is_last = (idx == len(chapters) - 1)
                    if not is_last:
                        end = chapters[idx + 1].get("StartPositionTicks", start)
                    elif runtime_ticks:
                        end = runtime_ticks
                    else:
                        end = start + 1
                    typed_segments.append({
                        "type": classified,
                        "start_ticks": start,
                        "end_ticks": end,
                    })

        self._session_typed_segments[session_id] = typed_segments

        # 3. If no embedded chapters but we have typed segments, build synthetic chapters
        if not chapters and typed_segments:
            chapters = self._build_synthetic_chapters(typed_segments, runtime_ticks)

        total = len(chapters)
        enriched: list[dict] = []
        for idx, chapter in enumerate(chapters):
            start = chapter.get("StartPositionTicks", 0)
            is_last = (idx == total - 1)

            if not is_last:
                end = chapters[idx + 1].get("StartPositionTicks", start)
            elif runtime_ticks:
                end = runtime_ticks
            else:
                end = start + 1  # Minimal fallback for zero-duration last chapter

            # Check if chapter overlaps any typed segment
            segment_type = None
            for s in typed_segments:
                if max(start, s["start_ticks"]) < min(end, s["end_ticks"]):
                    segment_type = s["type"]
                    break
            if segment_type is None:
                segment_type = self._classify_chapter_name(chapter.get("Name", ""))

            enriched.append({
                "chapter_index":   idx + 1,
                "chapter_count":   total,
                "chapter_name":    chapter.get("Name", ""),
                "segment_type":    segment_type,
                "start_ticks":     start,
                "end_ticks":       end,
                "is_last_chapter": is_last,
            })

        self._session_segments[session_id] = enriched

    @staticmethod
    def _build_synthetic_chapters(
        segments: list[dict], runtime_ticks: int | None
    ) -> list[dict]:
        """Build synthetic chapter entries from segment data.

        Used when a file has no embedded chapters but Intro Skipper or a
        segment provider has detected segments (e.g. Intro, Outro).
        """
        boundaries: set[int] = {0}
        for seg in segments:
            boundaries.add(seg.get("start_ticks", seg.get("StartTicks", 0)))
            end = seg.get("end_ticks", seg.get("EndTicks"))
            if end is not None:
                boundaries.add(end)
        if runtime_ticks:
            boundaries.add(runtime_ticks)

        sorted_bounds = sorted(boundaries)

        synthetic: list[dict] = []
        for i in range(len(sorted_bounds) - 1):
            start = sorted_bounds[i]
            # Find matching segment type if this slice is within a segment
            seg_type = None
            for seg in segments:
                s_start = seg.get("start_ticks", seg.get("StartTicks", 0))
                s_end = seg.get("end_ticks", seg.get("EndTicks", s_start))
                if s_start <= start < s_end:
                    seg_type = seg.get("type", seg.get("Type"))
                    break
            name = seg_type if seg_type else "Content"
            synthetic.append({
                "StartPositionTicks": start,
                "Name": name,
            })

        return synthetic

    def _get_current_chapter(self, session_id: str, position_ticks: int) -> dict | None:
        """Return the enriched chapter dict that contains position_ticks."""
        segments = self._session_segments.get(session_id)
        if not segments:
            return None

        current = None
        for entry in segments:
            if position_ticks >= entry["start_ticks"]:
                current = entry
            else:
                break
        return current

    def _get_current_segment(self, session_id: str, position_ticks: int) -> dict | None:
        """Return the active typed segment dict for position_ticks."""
        segments = self._session_typed_segments.get(session_id, [])
        for seg in segments:
            if seg["start_ticks"] <= position_ticks < seg["end_ticks"]:
                return seg
        return None

    def _get_current_segment_type(self, session_id: str, position_ticks: int) -> str | None:
        """Return the SegmentType the current position falls within."""
        seg = self._get_current_segment(session_id, position_ticks)
        return seg["type"] if seg else None

    def _get_current_segment_entry(self, session_id: str, position_ticks: int) -> dict | None:
        """Return the typed segment entry for position_ticks."""
        return self._get_current_segment(session_id, position_ticks)

    def _cleanup_session(self, session_id: str, session: dict | None = None) -> None:
        """Remove all cached state for a session that has ended.

        If the session was inside a typed segment when it ended, fire a
        media_segment_change event with in_segment=False so automations
        (e.g. lighting) get a clean exit signal.
        """
        prev_seg = self._previous_segment_type.get(session_id)
        if prev_seg is not None:
            # Build a minimal chapter context from cached data for the event
            segments = self._session_segments.get(session_id, [])
            prev_idx = self._previous_chapter_index.get(session_id)
            chapter_context = {"chapter_index": prev_idx, "chapter_name": ""}
            for entry in segments:
                if entry["chapter_index"] == prev_idx:
                    chapter_context["chapter_name"] = entry["chapter_name"]
                    break

            # Fire exit event — use provided session or build minimal context
            exit_session = session or {"Id": session_id}
            self._fire_segment_event(
                exit_session, chapter_context, None, prev_seg
            )

        self._session_segments.pop(session_id, None)
        self._session_typed_segments.pop(session_id, None)
        self._previous_chapter_index.pop(session_id, None)
        self._previous_segment_type.pop(session_id, None)
        self._current_item_id.pop(session_id, None)

    def _fire_chapter_event(self, session: dict, chapter: dict) -> None:
        """Fire jellyha_event with type=media_chapter_change."""
        now_playing = session.get("NowPlayingItem") or {}
        event_data = {
            "type":            EVENT_CHAPTER_CHANGE,
            "device_id":       self._device_id or session.get("DeviceId"),
            "session_id":      session.get("Id"),
            "user_id":         session.get("UserId"),
            "media_title":     now_playing.get("Name"),
            "chapter_index":   chapter["chapter_index"],
            "chapter_count":   chapter.get("chapter_count"),
            "chapter_name":    chapter["chapter_name"],
            "segment_type":    chapter.get("segment_type"),
            "is_last_chapter": chapter.get("is_last_chapter"),
        }
        # Add segment end position for skip automations
        end_ticks = chapter.get("end_ticks")
        if end_ticks is not None and chapter.get("segment_type"):
            event_data["segment_end_seconds"] = round(end_ticks / TICKS_PER_SECOND, 1)
        self.hass.bus.async_fire(f"{DOMAIN}_event", event_data)

    def _fire_segment_event(
        self,
        session: dict,
        chapter: dict,
        current_segment_type: str | None,
        previous_segment_type: str | None,
        segment_entry: dict | None = None,
    ) -> None:
        """Fire jellyha_event with type=media_segment_change."""
        now_playing = session.get("NowPlayingItem") or {}
        event_data = {
            "type":                  EVENT_SEGMENT_CHANGE,
            "device_id":             self._device_id or session.get("DeviceId"),
            "session_id":            session.get("Id"),
            "user_id":               session.get("UserId"),
            "media_title":           now_playing.get("Name"),
            "segment_type":          current_segment_type,
            "previous_segment_type": previous_segment_type,
            "in_segment":            current_segment_type is not None,
            "chapter_index":         chapter.get("chapter_index"),
            "chapter_name":          chapter.get("chapter_name"),
        }
        # When entering a typed segment, provide exact end position for skip automations
        if current_segment_type is not None:
            if segment_entry and "end_ticks" in segment_entry:
                event_data["segment_end_seconds"] = round(
                    segment_entry["end_ticks"] / TICKS_PER_SECOND, 1
                )
            else:
                session_id = session.get("Id")
                seg = self._get_current_segment(session_id, session.get("PlayState", {}).get("PositionTicks", 0)) if session_id else None
                if seg:
                    event_data["segment_end_seconds"] = round(
                        seg["end_ticks"] / TICKS_PER_SECOND, 1
                    )
        self.hass.bus.async_fire(f"{DOMAIN}_event", event_data)
