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
    ITEM_TYPE_MOVIE,
    ITEM_TYPE_SERIES,
    RATING_SOURCE_AUTO,
    RATING_SOURCE_IMDB,
    RATING_SOURCE_TMDB,
)

_LOGGER = logging.getLogger(__name__)


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

        refresh_interval = entry.options.get(
            CONF_REFRESH_INTERVAL,
            entry.data.get(CONF_REFRESH_INTERVAL, DEFAULT_REFRESH_INTERVAL),
        )

        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=refresh_interval),
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
            _LOGGER.debug("Connected to Jellyfin server: %s (v%s)", self._server_name, self._server_version)
        except JellyfinAuthError as err:
            raise ConfigEntryAuthFailed(str(err)) from err
        except JellyfinConnectionError as err:
            raise UpdateFailed(f"Failed to connect to Jellyfin: {err}") from err

    async def _async_update_data(self) -> dict[str, Any]:
        """Fetch data from Jellyfin API."""
        start_time = time.monotonic()
        
        if self._api is None:
            await self._async_setup()

        user_id = self.entry.data[CONF_USER_ID]
        libraries = self.entry.data.get(CONF_LIBRARIES, [])

        try:
            raw_items = await self._api.get_library_items(
                user_id=user_id,
                limit=0,  # 0 = no limit, fetch all items
                library_ids=libraries if libraries else None,
            )

            items = [self._transform_item(item) for item in raw_items]

            # Update last refresh time (always updates)
            self.last_refresh_time = dt_util.utcnow()

            # Check if data actually changed
            current_item_ids = {item["id"] for item in items}
            # Create a simple hash based on item IDs and key attributes
            current_hash = self._compute_data_hash(items)
            
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
        except JellyfinApiError as err:
            raise UpdateFailed(f"Error fetching data: {err}") from err

    def _compute_data_hash(self, items: list[dict[str, Any]]) -> str:
        """Compute a hash of item data to detect changes."""
        # Include item IDs, count, and key changing attributes like is_played
        hash_data = []
        for item in sorted(items, key=lambda x: x.get("id", "")):
            hash_data.append(f"{item.get('id')}:{item.get('is_played')}:{item.get('is_favorite')}:{item.get('date_added')}")
        return hashlib.sha256("|".join(hash_data).encode()).hexdigest()

    def _transform_item(self, item: dict[str, Any]) -> dict[str, Any]:
        """Transform raw Jellyfin item to our schema."""
        item_id = item.get("Id", "")
        item_type = item.get("Type", "")
        provider_ids = item.get("ProviderIds", {})

        # Runtime in minutes (Jellyfin returns ticks, 1 tick = 100 nanoseconds)
        runtime_ticks = item.get("RunTimeTicks", 0)
        runtime_minutes = int(runtime_ticks / 600_000_000) if runtime_ticks else None

        # Get appropriate rating based on type (IMDB for movies, TMDB for TV)
        rating = self._get_rating(item_type, provider_ids, item.get("CommunityRating"))

        return {
            "id": item_id,
            "name": item.get("Name", ""),
            "type": item_type,
            "year": item.get("ProductionYear"),
            "runtime_minutes": runtime_minutes,
            "genres": item.get("Genres", []),
            "rating": rating,
            "rating_imdb": provider_ids.get("Imdb"),
            "rating_tmdb": provider_ids.get("Tmdb"),
            "description": item.get("Overview", ""),
            "poster_url": f"/api/jellyha/image/{self.entry.entry_id}/{item_id}/Primary?tag={item.get('ImageTags', {}).get('Primary', '')}",
            "backdrop_url": f"/api/jellyha/image/{self.entry.entry_id}/{item_id}/Backdrop?tag={item.get('BackdropImageTags', [''])[0]}" if item.get('BackdropImageTags') else None,
            "date_added": item.get("DateCreated"),
            "jellyfin_url": self._api.get_jellyfin_url(item_id),
            "is_played": item.get("UserData", {}).get("Played", False),
            "unplayed_count": item.get("UserData", {}).get("UnplayedItemCount"),
            "is_favorite": item.get("UserData", {}).get("IsFavorite", False),
            "media_streams": item.get("MediaStreams", []),
            "official_rating": item.get("OfficialRating"),
            "trailer_url": next((t["Url"] for t in item.get("RemoteTrailers", []) if t.get("Url")), None),
            "last_played_date": item.get("UserData", {}).get("LastPlayedDate"),
        }

    def _get_rating(
        self,
        item_type: str,
        provider_ids: dict[str, Any],
        community_rating: float | None,
    ) -> float | None:
        """Get the appropriate rating based on item type (IMDB for movies, TMDB for TV)."""
        if item_type == ITEM_TYPE_MOVIE:
            # Prefer IMDB for movies
            if imdb_id := provider_ids.get("Imdb"):
                # Note: We have IMDB ID, but not the actual rating from IMDB
                # We'll use community rating as fallback
                pass
        elif item_type == ITEM_TYPE_SERIES:
            # Prefer TMDB for TV shows
            if tmdb_id := provider_ids.get("Tmdb"):
                pass

        # Fall back to community rating from Jellyfin
        return community_rating


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

        if self._ws_client:
            self._ws_client.set_on_session_update(self._handle_ws_session_update)
            self._ws_client.set_on_connect(self._handle_ws_connect)
            self._ws_client.set_on_disconnect(self._handle_ws_disconnect)

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
            return sessions
        except JellyfinApiError as err:
            raise UpdateFailed(f"Error fetching sessions: {err}") from err

    async def _handle_ws_session_update(self, sessions: list[dict[str, Any]]) -> None:
        """Handle session updates from WebSocket."""
        _LOGGER.debug("Coordinator received %d sessions from WS", len(sessions))
        
        # Fire events for device triggers
        await self._fire_session_events(sessions)
        
        for s in sessions:
             _LOGGER.debug("Session user: %s, Device: %s, NowPlaying: %s", 
                           s.get("UserId"), s.get("DeviceName"), "Yes" if "NowPlayingItem" in s else "No")
        self.async_set_updated_data(sessions)

    async def _fire_session_events(self, current_sessions: list[dict[str, Any]]) -> None:
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
