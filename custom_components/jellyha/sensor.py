"""Sensor platform for JellyHA Library."""
from __future__ import annotations

from typing import Any

from datetime import datetime

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity import generate_entity_id
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import (
    CONF_DEVICE_NAME,
    DEFAULT_DEVICE_NAME,
    DOMAIN,
)
from .coordinator import JellyHALibraryCoordinator, JellyHASessionCoordinator
from .device import get_device_info
from .ws_client import JellyfinWebSocketClient
from . import JellyHAConfigEntry


async def async_setup_entry(
    hass: HomeAssistant,
    entry: JellyHAConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up JellyHA Library sensors from a config entry."""
    coordinator: JellyHALibraryCoordinator = entry.runtime_data.library
    session_coordinator: JellyHASessionCoordinator = entry.runtime_data.session
    ws_client: JellyfinWebSocketClient = entry.runtime_data.ws_client
    device_name = entry.data.get(CONF_DEVICE_NAME, DEFAULT_DEVICE_NAME)

    sensors: list[SensorEntity] = [
        JellyHALibrarySensor(coordinator, entry, device_name),
        JellyHAFavoritesCountSensor(coordinator, entry, device_name),
        JellyHAUnwatchedCountSensor(coordinator, entry, device_name),
        JellyHAUnwatchedMoviesSensor(coordinator, entry, device_name),
        JellyHAUnwatchedSeriesSensor(coordinator, entry, device_name),
        JellyHAUnwatchedEpisodesSensor(coordinator, entry, device_name),
        JellyHALastRefreshSensor(coordinator, entry, device_name),
        JellyHALastDataChangeSensor(coordinator, entry, device_name),
        JellyHARefreshDurationSensor(coordinator, entry, device_name),
        JellyHAWebSocketStatusSensor(ws_client, coordinator, entry, device_name),
        JellyHAVersionSensor(coordinator, entry, device_name),
        JellyHAActiveSessionsSensor(session_coordinator, entry, device_name),
        JellyHAWatchedCountSensor(coordinator, entry, device_name),
        JellyHAWatchedEpisodesSensor(coordinator, entry, device_name),
        JellyHAWatchedSeriesSensor(coordinator, entry, device_name),
        JellyHAWatchedMoviesSensor(coordinator, entry, device_name),
    ]

    # Create sensors for each user
    if session_coordinator.users:
        for user_id, username in session_coordinator.users.items():
            sensors.append(
                JellyHAUserSensor(
                    session_coordinator, 
                    entry, 
                    user_id, 
                    username
                )
            )

    async_add_entities(sensors)


class JellyHABaseSensor(CoordinatorEntity[JellyHALibraryCoordinator], SensorEntity):
    """Base class for JellyHA sensors with common device info."""

    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: JellyHALibraryCoordinator,
        entry: ConfigEntry,
        device_name: str,
        sensor_key: str,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator)
        self._device_name = device_name
        self._entry = entry
        
        # Use entry_id as prefix for unique_id (migrated from device_name in __init__)
        self._attr_unique_id = f"{entry.entry_id}_{sensor_key}"
        
        # Set entity_id to use device_name prefix (e.g., sensor.jellyha_library)
        # self.entity_id = f"sensor.{device_name}_{sensor_key}"

    @property
    def device_info(self) -> DeviceInfo:
        """Return device info for this sensor."""
        return get_device_info(self._entry.entry_id, self._device_name)


class JellyHALibrarySensor(JellyHABaseSensor):
    """Sensor representing media library from Jellyfin."""

    _attr_translation_key = "library"
    _attr_icon = "mdi:video-vintage"

    def __init__(
        self,
        coordinator: JellyHALibraryCoordinator,
        entry: ConfigEntry,
        device_name: str,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, entry, device_name, "library")

    @property
    def native_value(self) -> int:
        """Return the number of library items."""
        if self.coordinator.data:
            return self.coordinator.data.get("count", 0)
        return 0

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return additional state attributes."""
        if not self.coordinator.data:
            return {}

        items = self.coordinator.data.get("items", [])
        movies = [i for i in items if i.get("type") == "Movie"]
        series = [i for i in items if i.get("type") == "Series"]
        # Sum up all episode counts from series items (unplayed + watched)
        total_episodes = sum(
            (i.get("unplayed_count") or 0) for i in series
        )

        return {
            "entry_id": self._entry.entry_id,
            "server_name": self.coordinator.data.get("server_name"),
            "last_updated": self.coordinator.last_refresh_time,
            "movies": len(movies),
            "series": len(series),
            "episodes": total_episodes,
        }


class JellyHAFavoritesCountSensor(JellyHABaseSensor):
    """Sensor for favorite items count."""

    _attr_translation_key = "favorites_count"
    _attr_icon = "mdi:heart"

    def __init__(
        self,
        coordinator: JellyHALibraryCoordinator,
        entry: ConfigEntry,
        device_name: str,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, entry, device_name, "favorites")

    @property
    def native_value(self) -> int:
        """Return the number of favorite items."""
        if not self.coordinator.data:
            return 0
        items = self.coordinator.data.get("items", [])
        return len([i for i in items if i.get("is_favorite", False)])


class JellyHAUnwatchedCountSensor(JellyHABaseSensor):
    """Sensor for total unwatched items count."""

    _attr_translation_key = "unwatched_count"
    _attr_icon = "mdi:eye-off"

    def __init__(
        self,
        coordinator: JellyHALibraryCoordinator,
        entry: ConfigEntry,
        device_name: str,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, entry, device_name, "unwatched")

    @property
    def native_value(self) -> int:
        """Return the number of unwatched items."""
        if not self.coordinator.data:
            return 0
        items = self.coordinator.data.get("items", [])
        return len([i for i in items if not i.get("is_played", True)])

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return breakdown by type."""
        if not self.coordinator.data:
            return {}
        items = self.coordinator.data.get("items", [])
        unwatched = [i for i in items if not i.get("is_played", True)]
        # Sum unplayed episode counts from unwatched series
        unwatched_episodes = sum(
            (i.get("unplayed_count") or 0) for i in unwatched if i.get("type") == "Series"
        )
        return {
            "movies": len([i for i in unwatched if i.get("type") == "Movie"]),
            "series": len([i for i in unwatched if i.get("type") == "Series"]),
            "episodes": unwatched_episodes,
        }


class JellyHAUnwatchedMoviesSensor(JellyHABaseSensor):
    """Sensor for unwatched movies count."""

    _attr_translation_key = "unwatched_movies"
    _attr_icon = "mdi:movie-open"

    def __init__(
        self,
        coordinator: JellyHALibraryCoordinator,
        entry: ConfigEntry,
        device_name: str,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, entry, device_name, "unwatched_movies")

    @property
    def native_value(self) -> int:
        """Return the number of unwatched movies."""
        if not self.coordinator.data:
            return 0
        items = self.coordinator.data.get("items", [])
        return len([
            i for i in items
            if i.get("type") == "Movie" and not i.get("is_played", True)
        ])


class JellyHAUnwatchedSeriesSensor(JellyHABaseSensor):
    """Sensor for unwatched series count."""

    _attr_translation_key = "unwatched_series"
    _attr_icon = "mdi:video-outline"

    def __init__(
        self,
        coordinator: JellyHALibraryCoordinator,
        entry: ConfigEntry,
        device_name: str,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, entry, device_name, "unwatched_series")

    @property
    def native_value(self) -> int:
        """Return the number of unwatched series."""
        if not self.coordinator.data:
            return 0
        items = self.coordinator.data.get("items", [])
        return len([
            i for i in items
            if i.get("type") == "Series" and not i.get("is_played", True)
        ])


class JellyHALastRefreshSensor(JellyHABaseSensor):
    """Sensor for last refresh timestamp."""

    _attr_translation_key = "last_refresh"
    _attr_icon = "mdi:clock-outline"
    _attr_device_class = SensorDeviceClass.TIMESTAMP

    def __init__(
        self,
        coordinator: JellyHALibraryCoordinator,
        entry: ConfigEntry,
        device_name: str,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, entry, device_name, "last_refresh")

    @property
    def native_value(self) -> datetime | None:
        """Return the last refresh timestamp."""
        if self.coordinator.last_refresh_time:
            return self.coordinator.last_refresh_time
        return None


class JellyHALastDataChangeSensor(JellyHABaseSensor):
    """Sensor for last library data change timestamp."""

    _attr_translation_key = "last_data_change"
    _attr_icon = "mdi:database-clock-outline"
    _attr_device_class = SensorDeviceClass.TIMESTAMP

    def __init__(
        self,
        coordinator: JellyHALibraryCoordinator,
        entry: ConfigEntry,
        device_name: str,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, entry, device_name, "last_data_change")

    @property
    def native_value(self) -> datetime | None:
        """Return the last data change timestamp."""
        if self.coordinator.last_data_change_time:
            return self.coordinator.last_data_change_time
        return None


class JellyHARefreshDurationSensor(JellyHABaseSensor):
    """Sensor for last refresh duration."""

    _attr_translation_key = "refresh_duration"
    _attr_icon = "mdi:timer-outline"

    def __init__(
        self,
        coordinator: JellyHALibraryCoordinator,
        entry: ConfigEntry,
        device_name: str,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, entry, device_name, "refresh_duration")

    @property
    def native_value(self) -> str | None:
        """Return the last refresh duration as a human-readable string."""
        duration = self.coordinator.last_refresh_duration
        if duration is None:
            return None
        
        if duration < 60:
            return f"{duration:.1f}s"
        else:
            minutes = int(duration // 60)
            seconds = duration % 60
            return f"{minutes}m {seconds:.0f}s"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return the raw duration in seconds as an attribute."""
        return {
            "duration_seconds": self.coordinator.last_refresh_duration,
        }


class JellyHAUserSensor(CoordinatorEntity[JellyHASessionCoordinator], SensorEntity):
    """Sensor tracking "Now Playing" for a specific Jellyfin user."""

    _attr_has_entity_name = True
    _attr_device_class = SensorDeviceClass.ENUM
    _attr_options = ["idle", "playing", "paused"]

    def __init__(
        self,
        coordinator: JellyHASessionCoordinator,
        entry: ConfigEntry,
        user_id: str,
        username: str,
    ) -> None:
        """Initialize the user sensor."""
        super().__init__(coordinator)
        self._user_id = user_id
        self._username = username
        self._entry = entry
        
        # Unique ID specifically for this user's viewing state
        self._attr_unique_id = f"{entry.entry_id}_now_playing_{user_id}"
        self._attr_name = f"Now Playing {username}"
        # self.entity_id = generate_entity_id(
        #     "sensor.{}", 
        #     f"jellyha_now_playing_{username}", 
        #     hass=coordinator.hass
        # )

    @property
    def device_info(self) -> DeviceInfo:
        """Return device info."""
        return get_device_info(self._entry.entry_id, "JellyHA")

    @property
    def native_value(self) -> str:
        """Return the state of the session (idle, playing, paused)."""
        session = self._get_active_session()
        if not session:
            return "idle"
        
        if session.get("PlayState", {}).get("IsPaused"):
            return "paused"
        
        return "playing"

    @property
    def icon(self) -> str:
        """Return the icon based on state."""
        state = self.native_value
        if state == "playing":
            return "mdi:play"
        if state == "paused":
            return "mdi:pause"
        return "mdi:television-play"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return additional state attributes."""
        session = self._get_active_session()
        if not session:
             return {"user_id": self._user_id}

        attributes = {
            "user_id": self._user_id,
            "session_id": session.get("Id"),
            "device_name": session.get("DeviceName"),
            "client": session.get("Client"),
            "item_id": None,
            "title": None,
            "progress_percent": 0,
            "position_ticks": 0,
            "image_url": None,
            "backdrop_url": None,
            "media_type": None,
            "is_paused": False,
        }

        if "NowPlayingItem" in session:
            item = session["NowPlayingItem"]
            item_type = item.get("Type")
            item_id = item.get("Id")
            
            attributes["item_id"] = item_id
            attributes["media_type"] = item_type
            attributes["official_rating"] = item.get("OfficialRating")
            attributes["community_rating"] = item.get("CommunityRating")
            attributes["critic_rating"] = item.get("CriticRating")
            attributes["genres"] = item.get("Genres", [])
            
            runtime_ticks = item.get("RunTimeTicks", 0)
            if runtime_ticks > 0:
                # 1 tick = 100ns, so 10,000,000 ticks = 1s
                attributes["runtime_minutes"] = int(runtime_ticks / 10000000 / 60)
            
            # Title Logic
            if item_type == "Episode":
                attributes["title"] = item.get("Name")
                attributes["series_title"] = item.get("SeriesName")
                attributes["season"] = item.get("ParentIndexNumber")
                attributes["episode"] = item.get("IndexNumber")
            else:
                # Movie, etc.
                attributes["title"] = item.get("Name")
                if item_type == "Movie":
                     attributes["year"] = item.get("ProductionYear")

            # Progress
            play_state = session.get("PlayState", {})
            position_ticks = play_state.get("PositionTicks", 0)
            duration_ticks = item.get("RunTimeTicks", 0)
            
            attributes["is_paused"] = play_state.get("IsPaused", False)
            attributes["position_ticks"] = position_ticks
            if duration_ticks and duration_ticks > 0:
                attributes["progress_percent"] = int((position_ticks / duration_ticks) * 100)

            # Image Proxy URL
            if item_id:
                # Use the HA Proxy view instead of direct Jellyfin URL
                # /api/jellyha/image/{entry_id}/{item_id}/{image_type}
                attributes["image_url"] = (
                    f"/api/jellyha/image/{self._entry.entry_id}/{item_id}/Primary"
                    f"?tag={item.get('ImageTags', {}).get('Primary', '')}"
                )
            
            # Backdrop Logic
            backdrop_tags = item.get("BackdropImageTags", [])
            if backdrop_tags and item_id:
                attributes["backdrop_url"] = (
                    f"/api/jellyha/image/{self._entry.entry_id}/{item_id}/Backdrop"
                    f"?tag={backdrop_tags[0]}"
                )

        return attributes

    def _get_active_session(self) -> dict[str, Any] | None:
        """Get the active session for this user with stable priority."""
        if not self.coordinator.data:
            return None
            
        # Find all sessions for this user that have active media
        user_sessions = [
            s for s in self.coordinator.data 
            if s.get("UserId") == self._user_id and "NowPlayingItem" in s
        ]
        
        if not user_sessions:
            return None
            
        # Sort sessions:
        # 1. Favor Playing (not paused) sessions first
        # 2. Use SessionId for deterministic fallback
        user_sessions.sort(
            key=lambda s: (
                s.get("PlayState", {}).get("IsPaused", False),
                s.get("Id", "")
            )
        )
        
        return user_sessions[0]


class JellyHAWebSocketStatusSensor(CoordinatorEntity[JellyHALibraryCoordinator], SensorEntity):
    """Sensor for WebSocket connection status."""

    _attr_has_entity_name = True
    _attr_translation_key = "websocket_status"

    def __init__(
        self,
        ws_client: JellyfinWebSocketClient,
        coordinator: JellyHALibraryCoordinator,
        entry: ConfigEntry,
        device_name: str,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator)
        self._ws_client = ws_client
        self._device_name = device_name
        self._entry = entry
        self._attr_unique_id = f"{entry.entry_id}_websocket_status"
        self._attr_unique_id = f"{entry.entry_id}_websocket_status"
        # self.entity_id = f"sensor.{device_name}_websocket"

    @property
    def native_value(self) -> str:
        """Return the WebSocket connection status."""
        return "connected" if self._ws_client.connected else "disconnected"

    @property
    def icon(self) -> str:
        """Return the icon based on connection status."""
        return "mdi:lan-connect" if self._ws_client.connected else "mdi:lan-disconnect"

    @property
    def device_info(self) -> DeviceInfo:
        """Return device info for this sensor."""
        return get_device_info(self._entry.entry_id, self._device_name)


class JellyHAVersionSensor(JellyHABaseSensor):
    """Sensor for Jellyfin server version."""

    _attr_translation_key = "version"
    _attr_icon = "mdi:information-outline"

    def __init__(
        self,
        coordinator: JellyHALibraryCoordinator,
        entry: ConfigEntry,
        device_name: str,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, entry, device_name, "version")

    @property
    def native_value(self) -> str | None:
        """Return the Jellyfin server version."""
        return self.coordinator._server_version


class JellyHAActiveSessionsSensor(CoordinatorEntity[JellyHASessionCoordinator], SensorEntity):
    """Sensor for count of active playback sessions."""

    _attr_has_entity_name = True
    _attr_translation_key = "active_sessions"
    _attr_icon = "mdi:account-multiple"

    def __init__(
        self,
        coordinator: JellyHASessionCoordinator,
        entry: ConfigEntry,
        device_name: str,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator)
        self._device_name = device_name
        self._entry = entry
        self._attr_unique_id = f"{entry.entry_id}_active_sessions"
        self._attr_unique_id = f"{entry.entry_id}_active_sessions"
        # self.entity_id = f"sensor.{device_name}_active_sessions"

    @property
    def native_value(self) -> int:
        """Return the number of active sessions with media playing."""
        if not self.coordinator.data:
            return 0
        return len([s for s in self.coordinator.data if "NowPlayingItem" in s])

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return details about active sessions."""
        if not self.coordinator.data:
            return {}
        
        active_sessions = [s for s in self.coordinator.data if "NowPlayingItem" in s]
        sessions_info = []
        for session in active_sessions:
            item = session.get("NowPlayingItem", {})
            sessions_info.append({
                "user": session.get("UserName"),
                "device": session.get("DeviceName"),
                "client": session.get("Client"),
                "title": item.get("Name"),
                "type": item.get("Type"),
            })
        
        return {"sessions": sessions_info}

    @property
    def device_info(self) -> DeviceInfo:
        """Return device info for this sensor."""
        return get_device_info(self._entry.entry_id, self._device_name)


class JellyHAUnwatchedEpisodesSensor(JellyHABaseSensor):
    """Sensor for unwatched episodes count."""

    _attr_translation_key = "unwatched_episodes"
    _attr_icon = "mdi:video"

    def __init__(
        self,
        coordinator: JellyHALibraryCoordinator,
        entry: ConfigEntry,
        device_name: str,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, entry, device_name, "unwatched_episodes")

    @property
    def native_value(self) -> int:
        """Return the number of unwatched episodes."""
        if not self.coordinator.data:
            return 0
        items = self.coordinator.data.get("items", [])
        # Sum unplayed_count from all series
        return sum(
            (i.get("unplayed_count") or 0) for i in items if i.get("type") == "Series"
        )


class JellyHAWatchedCountSensor(JellyHABaseSensor):
    """Sensor for total watched items count."""

    _attr_translation_key = "watched_count"
    _attr_icon = "mdi:eye-check"

    def __init__(
        self,
        coordinator: JellyHALibraryCoordinator,
        entry: ConfigEntry,
        device_name: str,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, entry, device_name, "watched")

    @property
    def native_value(self) -> int:
        """Return the number of watched items."""
        if not self.coordinator.data:
            return 0
        items = self.coordinator.data.get("items", [])
        return len([i for i in items if i.get("is_played", False)])

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return breakdown by type."""
        if not self.coordinator.data:
            return {}
        items = self.coordinator.data.get("items", [])
        watched = [i for i in items if i.get("is_played", False)]
        
        # For watched episodes: series that are fully watched don't have unplayed_count
        # We can't accurately calculate watched episodes without additional API calls
        # For now, count series with is_played=True
        watched_movies = len([i for i in watched if i.get("type") == "Movie"])
        watched_series = len([i for i in watched if i.get("type") == "Series"])
        
        return {
            "movies": watched_movies,
            "series": watched_series,
        }


class JellyHAWatchedEpisodesSensor(JellyHABaseSensor):
    """Sensor for watched episodes count (estimated based on fully watched series)."""

    _attr_translation_key = "watched_episodes"
    _attr_icon = "mdi:video-check"

    def __init__(
        self,
        coordinator: JellyHALibraryCoordinator,
        entry: ConfigEntry,
        device_name: str,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, entry, device_name, "watched_episodes")

    @property
    def native_value(self) -> int:
        """Return the number of watched episodes. 
        
        Note: This counts series marked as fully played (is_played=True).
        Individual episode counts require additional API queries.
        """
        if not self.coordinator.data:
            return 0
        items = self.coordinator.data.get("items", [])
        # Count fully watched series (is_played=True means all episodes watched)
        return len([
            i for i in items 
            if i.get("type") == "Series" and i.get("is_played", False)
        ])


class JellyHAWatchedSeriesSensor(JellyHABaseSensor):
    """Sensor for fully watched series count."""

    _attr_translation_key = "watched_series"
    _attr_icon = "mdi:video-check-outline"

    def __init__(
        self,
        coordinator: JellyHALibraryCoordinator,
        entry: ConfigEntry,
        device_name: str,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, entry, device_name, "watched_series")

    @property
    def native_value(self) -> int:
        """Return the number of fully watched series."""
        if not self.coordinator.data:
            return 0
        items = self.coordinator.data.get("items", [])
        return len([
            i for i in items 
            if i.get("type") == "Series" and i.get("is_played", False)
        ])


class JellyHAWatchedMoviesSensor(JellyHABaseSensor):
    """Sensor for watched movies count."""

    _attr_translation_key = "watched_movies"
    _attr_icon = "mdi:movie-check"

    def __init__(
        self,
        coordinator: JellyHALibraryCoordinator,
        entry: ConfigEntry,
        device_name: str,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, entry, device_name, "watched_movies")

    @property
    def native_value(self) -> int:
        """Return the number of watched movies."""
        if not self.coordinator.data:
            return 0
        items = self.coordinator.data.get("items", [])
        return len([
            i for i in items 
            if i.get("type") == "Movie" and i.get("is_played", False)
        ])
