"""DataUpdateCoordinator for JellyHA Library."""
from __future__ import annotations

from datetime import datetime, timedelta
import logging
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import (
    DataUpdateCoordinator,
    UpdateFailed,
)
from homeassistant.util import dt as dt_util

from .api import (
    JellyfinApiClient,
    JellyfinApiError,
    JellyfinAuthError,
    JellyfinConnectionError,
)
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
        self.last_refresh_time: datetime | None = None
        self.last_data_change_time: datetime | None = None
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
        self._api = JellyfinApiClient(
            server_url=self.entry.data[CONF_SERVER_URL],
            api_key=self.entry.data[CONF_API_KEY],
        )

        try:
            server_info = await self._api.validate_connection()
            self._server_name = server_info.get("ServerName", "Jellyfin")
            _LOGGER.debug("Connected to Jellyfin server: %s", self._server_name)
        except JellyfinAuthError as err:
            raise ConfigEntryAuthFailed(str(err)) from err
        except JellyfinConnectionError as err:
            raise UpdateFailed(f"Failed to connect to Jellyfin: {err}") from err

    async def _async_update_data(self) -> dict[str, Any]:
        """Fetch data from Jellyfin API."""
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

            return {
                "items": items,
                "count": len(items),
                "server_name": self._server_name,
                "last_refresh": self.last_refresh_time.isoformat(),
                "last_data_change": self.last_data_change_time.isoformat() if self.last_data_change_time else None,
            }

        except JellyfinAuthError as err:
            raise ConfigEntryAuthFailed(str(err)) from err
        except JellyfinApiError as err:
            raise UpdateFailed(f"Error fetching data: {err}") from err

    def _compute_data_hash(self, items: list[dict[str, Any]]) -> str:
        """Compute a hash of item data to detect changes."""
        import hashlib
        # Include item IDs, count, and key changing attributes like is_played
        hash_data = []
        for item in sorted(items, key=lambda x: x.get("id", "")):
            hash_data.append(f"{item.get('id')}:{item.get('is_played')}:{item.get('is_favorite')}:{item.get('date_added')}")
        return hashlib.md5("|".join(hash_data).encode()).hexdigest()

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
            "poster_url": self._api.get_image_url(
                item_id, "Primary", DEFAULT_IMAGE_HEIGHT, DEFAULT_IMAGE_QUALITY
            ),
            "backdrop_url": self._api.get_image_url(
                item_id, "Backdrop", DEFAULT_IMAGE_HEIGHT, DEFAULT_IMAGE_QUALITY
            ),
            "date_added": item.get("DateCreated"),
            "jellyfin_url": self._api.get_jellyfin_url(item_id),
            "is_played": item.get("UserData", {}).get("Played", False),
            "unplayed_count": item.get("UserData", {}).get("UnplayedItemCount"),
            "is_favorite": item.get("UserData", {}).get("IsFavorite", False),
            "media_streams": item.get("MediaStreams", []),
            "official_rating": item.get("OfficialRating"),
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
    ) -> None:
        """Initialize the coordinator."""
        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN}_sessions",
            update_interval=timedelta(seconds=10),
            always_update=False,
        )
        self.entry = entry
        self._api = api
        self.users: dict[str, str] = {}  # Map user_id to username

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
