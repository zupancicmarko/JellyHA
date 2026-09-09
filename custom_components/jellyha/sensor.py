"""Sensor platform for JellyHA Library."""
from __future__ import annotations

import logging
from typing import Any
from datetime import datetime

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity
from homeassistant.const import UnitOfInformation
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.dispatcher import async_dispatcher_connect
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
from .media_strategy import MediaStrategy
from . import JellyHAConfigEntry

_LOGGER = logging.getLogger(__name__)


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
        JellyHAMoviesCountSensor(coordinator, entry, device_name),
        JellyHASeriesCountSensor(coordinator, entry, device_name),
        JellyHAEpisodesCountSensor(coordinator, entry, device_name),
        JellyHALatestMovieSensor(coordinator, entry, device_name),
        JellyHALatestEpisodeSensor(coordinator, entry, device_name),
        JellyHATranscodingSessionsSensor(session_coordinator, entry, device_name),
        JellyHAMediaStorageFreeSensor(coordinator, entry, device_name),
        JellyHAMediaStorageFreePercentSensor(coordinator, entry, device_name),
    ]

    # Create sensors for each user
    if session_coordinator.users:
        for user_id, username in session_coordinator.users.items():
            sensors.append(
                JellyHAUserSensor(
                    session_coordinator, 
                    entry, 
                    user_id, 
                    username,
                    device_name
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

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return additional state attributes."""
        return {
            "entry_id": self._entry.entry_id,
            "config_entry_id": self._entry.entry_id,
        }


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
        videos = [i for i in items if i.get("type") in ("Video", "MusicVideo")]
        # Sum up all episode counts from series items
        total_episodes = sum(
            (i.get("total_episodes") or 0) for i in series
        )

        return {
            "entry_id": self._entry.entry_id,
            "config_entry_id": self._entry.entry_id,
            "server_name": self.coordinator.data.get("server_name"),
            "last_updated": self.coordinator.last_refresh_time,
            "movies": len(movies),
            "series": len(series),
            "videos": len(videos),
            "episodes": total_episodes,
            "config_external_url": self._entry.options.get(
                "external_url", self._entry.data.get("external_url", "")
            ),
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
        # Sum unplayed episode counts from series
        unwatched_episodes = sum(
            (i.get("unplayed_count") or 0) for i in items if i.get("type") == "Series"
        )
        return {
            "entry_id": self._entry.entry_id,
            "config_entry_id": self._entry.entry_id,
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
        device_name: str,
    ) -> None:
        """Initialize the user sensor."""
        super().__init__(coordinator)
        self._user_id = user_id
        self._username = username
        self._device_name = device_name
        self._entry = entry
        
        # Unique ID specifically for this user's viewing state
        self._attr_unique_id = f"{entry.entry_id}_now_playing_{user_id}"
        self._attr_name = f"Now Playing {username}"

        _LOGGER.warning(
            "The entity sensor.jellyha_now_playing_%s is deprecated in JellyHA v1.3.0 and will be removed in v2.0.0. "
            "Please migrate automations and cards to media_player.jellyha_%s",
            username.lower(),
            username.lower(),
        )

    @property
    def device_info(self) -> DeviceInfo:
        """Return device info."""
        return get_device_info(self._entry.entry_id, self._device_name)

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

    def _is_session_remote_controllable(self, session: dict[str, Any] | None) -> bool:
        """Check if a session can receive remote control commands."""
        if not session:
            return True
        # Explicit remote control flag from Jellyfin API
        if session.get("SupportsRemoteControl") is True:
            return True
        # Check nested capabilities if top-level is omitted
        caps = session.get("Capabilities") or {}
        if caps.get("SupportsRemoteControl") is True:
            return True
        # Check if there is another session for the same physical client device that supports remote control
        dev_id = session.get("DeviceId") or ""
        base_dev_id = dev_id[:16] if len(dev_id) >= 16 else dev_id
        if base_dev_id and self.coordinator.data:
            for s in self.coordinator.data:
                sid = s.get("Id")
                if sid != session.get("Id"):
                    s_dev_id = s.get("DeviceId") or ""
                    if (
                        s_dev_id == base_dev_id
                        or s_dev_id.startswith(base_dev_id)
                        or base_dev_id.startswith(s_dev_id)
                    ):
                        if s.get("SupportsRemoteControl") is True:
                            return True
        # If session explicitly declares no remote control and no controllable companion session exists
        if session.get("SupportsRemoteControl") is False:
            return False
        return True

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return additional state attributes."""
        session = self._get_active_session()
        if not session:
             return {
                 "user_id": self._user_id,
                 "user_name": self._username,
                 "entry_id": self._entry.entry_id,
                 "config_entry_id": self._entry.entry_id,
             }

        attributes = {
            "entry_id": self._entry.entry_id,
            "config_entry_id": self._entry.entry_id,
            "user_id": self._user_id,
            "user_name": self._username,
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
            "config_external_url": self._entry.options.get(
                "external_url", self._entry.data.get("external_url", "")
            ),
            "supports_remote_control": self._is_session_remote_controllable(session),
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
            
            # Video stream and dynamic range attributes
            if item_type in ("Movie", "Episode", "Video", "MusicVideo"):
                video_attrs = MediaStrategy.extract_video_stream_attributes(item)
                attributes.update(video_attrs)

            # Title Logic
            if item_type == "Episode":
                attributes["title"] = item.get("Name")
                attributes["series_title"] = item.get("SeriesName")
                attributes["season"] = item.get("ParentIndexNumber")
                attributes["episode"] = item.get("IndexNumber")
                attributes["series_image_url"] = session.get("jellyha_series_poster_url")
            elif item_type == "Audio":
                attributes["title"] = item.get("Name")
                album_artist = item.get("AlbumArtist")
                artists = item.get("Artists", [])
                attributes["artist_name"] = album_artist or (artists[0] if artists else None)
            else:
                attributes["title"] = item.get("Name")

            # Universal year resolution (with PremiereDate fallback)
            prod_year = item.get("ProductionYear")
            if not prod_year and item.get("PremiereDate") and len(item.get("PremiereDate", "")) >= 4 and item["PremiereDate"][:4].isdigit():
                prod_year = int(item["PremiereDate"][:4])
            attributes["year"] = prod_year

            # Progress
            play_state = session.get("PlayState", {})
            position_ticks = play_state.get("PositionTicks", 0)
            duration_ticks = item.get("RunTimeTicks", 0)
            
            attributes["is_paused"] = play_state.get("IsPaused", False)
            attributes["position_ticks"] = position_ticks
            attributes["duration_ticks"] = duration_ticks
            if duration_ticks and duration_ticks > 0:
                attributes["progress_percent"] = int((position_ticks / duration_ticks) * 100)

            attributes["repeat_mode"] = play_state.get("RepeatMode", "RepeatNone")
            attributes["shuffle_mode"] = "Shuffle" if play_state.get("ShuffleMethod") == "Shuffle" or play_state.get("ShuffleMode") == "Shuffle" else "Sorted"
            
            is_fav = item.get("UserData", {}).get("IsFavorite", False)
            if not is_fav and item_type == "Episode":
                series_id = item.get("SeriesId")
                lib_coord = getattr(getattr(self._entry, "runtime_data", None), "library", None)
                if series_id and lib_coord and series_id in getattr(lib_coord, "_favorite_series_ids", set()):
                    is_fav = True
            attributes["is_favorite"] = is_fav

            # Image Proxy URL (Signed URL from coordinator)
            attributes["image_url"] = session.get("jellyha_poster_url")
            
            # Backdrop Logic
            attributes["backdrop_url"] = session.get("jellyha_backdrop_url")

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
        # self.entity_id = f"sensor.{device_name}_websocket"

    async def async_added_to_hass(self) -> None:
        """Register callbacks when added to hass."""
        await super().async_added_to_hass()
        self.async_on_remove(
            async_dispatcher_connect(
                self.hass,
                f"{DOMAIN}_{self._entry.entry_id}_ws_status",
                self.async_write_ha_state,
            )
        )

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
        
        watched_movies = len([i for i in watched if i.get("type") == "Movie"])
        watched_series = len([i for i in watched if i.get("type") == "Series"])
        watched_episodes = sum(
            max(0, (i.get("total_episodes") or 0) - (i.get("unplayed_count") or 0))
            for i in items
            if i.get("type") == "Series"
        )
        
        return {
            "entry_id": self._entry.entry_id,
            "config_entry_id": self._entry.entry_id,
            "movies": watched_movies,
            "series": watched_series,
            "episodes": watched_episodes,
        }


class JellyHAWatchedEpisodesSensor(JellyHABaseSensor):
    """Sensor for watched episodes count."""

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
        """Return the number of watched episodes."""
        if not self.coordinator.data:
            return 0
        items = self.coordinator.data.get("items", [])
        return sum(
            max(0, (i.get("total_episodes") or 0) - (i.get("unplayed_count") or 0))
            for i in items
            if i.get("type") == "Series"
        )


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


class JellyHAMoviesCountSensor(JellyHABaseSensor):
    """Sensor for total movies count."""

    _attr_translation_key = "movies"
    _attr_icon = "mdi:movie"

    def __init__(
        self,
        coordinator: JellyHALibraryCoordinator,
        entry: ConfigEntry,
        device_name: str,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, entry, device_name, "movies")

    @property
    def native_value(self) -> int:
        """Return the total number of movies."""
        if not self.coordinator.data:
            return 0
        items = self.coordinator.data.get("items", [])
        return len([i for i in items if i.get("type") == "Movie"])

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return additional attributes."""
        if not self.coordinator.data:
            return {
                "entry_id": self._entry.entry_id,
                "config_entry_id": self._entry.entry_id,
            }
        items = self.coordinator.data.get("items", [])
        movies = [i for i in items if i.get("type") == "Movie"]
        watched = len([i for i in movies if i.get("is_played", False)])
        unwatched = len([i for i in movies if not i.get("is_played", False)])
        favorites = len([i for i in movies if i.get("is_favorite", False)])
        return {
            "entry_id": self._entry.entry_id,
            "config_entry_id": self._entry.entry_id,
            "watched": watched,
            "unwatched": unwatched,
            "favorites": favorites,
        }


class JellyHASeriesCountSensor(JellyHABaseSensor):
    """Sensor for total series count."""

    _attr_translation_key = "series"
    _attr_icon = "mdi:television-classic"

    def __init__(
        self,
        coordinator: JellyHALibraryCoordinator,
        entry: ConfigEntry,
        device_name: str,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, entry, device_name, "series")

    @property
    def native_value(self) -> int:
        """Return the total number of series."""
        if not self.coordinator.data:
            return 0
        items = self.coordinator.data.get("items", [])
        return len([i for i in items if i.get("type") == "Series"])

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return additional attributes."""
        if not self.coordinator.data:
            return {
                "entry_id": self._entry.entry_id,
                "config_entry_id": self._entry.entry_id,
            }
        items = self.coordinator.data.get("items", [])
        series = [i for i in items if i.get("type") == "Series"]
        watched = len([i for i in series if i.get("is_played", False)])
        unwatched = len([i for i in series if not i.get("is_played", False)])
        favorites = len([i for i in series if i.get("is_favorite", False)])
        total_episodes = sum((i.get("total_episodes") or 0) for i in series)
        unwatched_episodes = sum((i.get("unplayed_count") or 0) for i in series)
        return {
            "entry_id": self._entry.entry_id,
            "config_entry_id": self._entry.entry_id,
            "watched": watched,
            "unwatched": unwatched,
            "favorites": favorites,
            "total_episodes": total_episodes,
            "unwatched_episodes": unwatched_episodes,
        }


class JellyHAEpisodesCountSensor(JellyHABaseSensor):
    """Sensor for total episodes count across all series."""

    _attr_translation_key = "episodes"
    _attr_icon = "mdi:television-play"

    def __init__(
        self,
        coordinator: JellyHALibraryCoordinator,
        entry: ConfigEntry,
        device_name: str,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, entry, device_name, "episodes")

    @property
    def native_value(self) -> int:
        """Return the total number of episodes."""
        if not self.coordinator.data:
            return 0
        items = self.coordinator.data.get("items", [])
        return sum((i.get("total_episodes") or 0) for i in items if i.get("type") == "Series")

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return additional attributes."""
        if not self.coordinator.data:
            return {
                "entry_id": self._entry.entry_id,
                "config_entry_id": self._entry.entry_id,
            }
        items = self.coordinator.data.get("items", [])
        series = [i for i in items if i.get("type") == "Series"]
        total = sum((i.get("total_episodes") or 0) for i in series)
        unwatched = sum((i.get("unplayed_count") or 0) for i in series)
        watched = max(0, total - unwatched)
        return {
            "entry_id": self._entry.entry_id,
            "config_entry_id": self._entry.entry_id,
            "watched": watched,
            "unwatched": unwatched,
        }


class JellyHALatestMovieSensor(JellyHABaseSensor):
    """Sensor for the latest added movie."""

    _attr_translation_key = "latest_movie"
    _attr_icon = "mdi:new-box"

    def __init__(
        self,
        coordinator: JellyHALibraryCoordinator,
        entry: ConfigEntry,
        device_name: str,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, entry, device_name, "latest_movie")

    @property
    def native_value(self) -> str | None:
        """Return the name of the latest movie."""
        if not self.coordinator.data:
            return None
        movie = self.coordinator.data.get("latest_movie")
        return movie.get("name") if movie else None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return rich metadata attributes for the latest movie."""
        if not self.coordinator.data or not self.coordinator.data.get("latest_movie"):
            return {
                "entry_id": self._entry.entry_id,
                "config_entry_id": self._entry.entry_id,
            }

        movie = self.coordinator.data["latest_movie"]
        return {
            "entry_id": self._entry.entry_id,
            "config_entry_id": self._entry.entry_id,
            "item_id": movie.get("id"),
            "title": movie.get("name"),
            "name": movie.get("name"),
            "year": movie.get("year"),
            "overview": movie.get("description"),
            "description": movie.get("description"),
            "genres": movie.get("genres", []),
            "rating": movie.get("rating"),
            "community_rating": movie.get("community_rating"),
            "official_rating": movie.get("official_rating"),
            "critic_rating": movie.get("critic_rating"),
            "runtime_minutes": movie.get("runtime_minutes"),
            "date_added": movie.get("date_added"),
            "is_favorite": movie.get("is_favorite", False),
            "is_played": movie.get("is_played", False),
            "poster_url": movie.get("poster_url"),
            "backdrop_url": movie.get("backdrop_url"),
            "trailer_url": movie.get("trailer_url"),
            "dynamic_range": movie.get("dynamic_range"),
            "video_range": movie.get("video_range"),
            "video_range_type": movie.get("video_range_type"),
            "video_codec": movie.get("video_codec"),
            "video_bit_depth": movie.get("video_bit_depth"),
            "dv_profile": movie.get("dv_profile"),
            "resolution": movie.get("resolution"),
            "width": movie.get("width"),
            "height": movie.get("height"),
            "aspect_ratio": movie.get("aspect_ratio"),
            "container": movie.get("container"),
        }


class JellyHALatestEpisodeSensor(JellyHABaseSensor):
    """Sensor for the latest added episode."""

    _attr_translation_key = "latest_episode"
    _attr_icon = "mdi:new-box"

    def __init__(
        self,
        coordinator: JellyHALibraryCoordinator,
        entry: ConfigEntry,
        device_name: str,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, entry, device_name, "latest_episode")

    @property
    def native_value(self) -> str | None:
        """Return a formatted string identifying the latest episode."""
        if not self.coordinator.data:
            return None
        ep = self.coordinator.data.get("latest_episode")
        if not ep:
            return None

        title = ep.get("name")
        series = ep.get("series_name")
        season = ep.get("season")
        episode = ep.get("episode")

        if series and season is not None and episode is not None:
            formatted = f"{series} - S{season:02d}E{episode:02d}"
            if title:
                formatted = f"{formatted} - {title}"
            return formatted[:255]
        elif series:
            return f"{series} - {title}"[:255] if title else series[:255]
        return title[:255] if title else None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return rich metadata attributes for the latest episode."""
        if not self.coordinator.data or not self.coordinator.data.get("latest_episode"):
            return {
                "entry_id": self._entry.entry_id,
                "config_entry_id": self._entry.entry_id,
            }

        ep = self.coordinator.data["latest_episode"]
        return {
            "entry_id": self._entry.entry_id,
            "config_entry_id": self._entry.entry_id,
            "item_id": ep.get("id"),
            "title": ep.get("name"),
            "episode_name": ep.get("name"),
            "series_name": ep.get("series_name"),
            "series_id": ep.get("series_id"),
            "season": ep.get("season"),
            "episode": ep.get("episode"),
            "season_name": ep.get("season_name"),
            "year": ep.get("year"),
            "overview": ep.get("description"),
            "description": ep.get("description"),
            "genres": ep.get("genres", []),
            "rating": ep.get("rating"),
            "community_rating": ep.get("community_rating"),
            "official_rating": ep.get("official_rating"),
            "critic_rating": ep.get("critic_rating"),
            "runtime_minutes": ep.get("runtime_minutes"),
            "date_added": ep.get("date_added"),
            "is_favorite": ep.get("is_favorite", False),
            "is_played": ep.get("is_played", False),
            "poster_url": ep.get("poster_url"),
            "series_poster_url": ep.get("series_poster_url"),
            "backdrop_url": ep.get("backdrop_url"),
            "dynamic_range": ep.get("dynamic_range"),
            "video_range": ep.get("video_range"),
            "video_range_type": ep.get("video_range_type"),
            "video_codec": ep.get("video_codec"),
            "video_bit_depth": ep.get("video_bit_depth"),
            "dv_profile": ep.get("dv_profile"),
            "resolution": ep.get("resolution"),
            "width": ep.get("width"),
            "height": ep.get("height"),
            "aspect_ratio": ep.get("aspect_ratio"),
            "container": ep.get("container"),
        }


class JellyHATranscodingSessionsSensor(CoordinatorEntity[JellyHASessionCoordinator], SensorEntity):
    """Sensor for count of active transcoding sessions."""

    _attr_has_entity_name = True
    _attr_translation_key = "transcoding_streams"
    _attr_icon = "mdi:sync"

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
        self._attr_unique_id = f"{entry.entry_id}_transcoding_streams"

    @property
    def device_info(self) -> DeviceInfo:
        """Return device info for this sensor."""
        return get_device_info(self._entry.entry_id, self._device_name)

    @property
    def native_value(self) -> int:
        """Return the count of active transcoding sessions."""
        if not self.coordinator.data:
            return 0
        count = 0
        for s in self.coordinator.data:
            if not s.get("NowPlayingItem"):
                continue
            play_state = s.get("PlayState", {})
            ti = s.get("TranscodingInfo")
            if play_state.get("PlayMethod") == "Transcode" or ti is not None:
                count += 1
        return count

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return details of currently transcoding sessions."""
        if not self.coordinator.data:
            return {
                "entry_id": self._entry.entry_id,
                "config_entry_id": self._entry.entry_id,
                "transcode_sessions": [],
            }

        transcodes = []
        for s in self.coordinator.data:
            if not s.get("NowPlayingItem"):
                continue
            play_state = s.get("PlayState", {})
            ti = s.get("TranscodingInfo")
            if play_state.get("PlayMethod") == "Transcode" or ti is not None:
                item = s.get("NowPlayingItem", {})
                transcodes.append({
                    "user": s.get("UserName"),
                    "device": s.get("DeviceName"),
                    "client": s.get("Client"),
                    "title": item.get("Name"),
                    "container": ti.get("Container") if ti else None,
                    "video_codec": ti.get("VideoCodec") if ti else None,
                    "audio_codec": ti.get("AudioCodec") if ti else None,
                    "reasons": ti.get("TranscodeReasons", []) if ti else [],
                    "is_video_direct": ti.get("IsVideoDirect", False) if ti else None,
                    "is_audio_direct": ti.get("IsAudioDirect", False) if ti else None,
                    "framerate": ti.get("Framerate") if ti else None,
                    "bitrate": ti.get("Bitrate") if ti else None,
                })

        return {
            "entry_id": self._entry.entry_id,
            "config_entry_id": self._entry.entry_id,
            "transcode_sessions": transcodes,
        }


class JellyHAMediaStorageFreeSensor(JellyHABaseSensor):
    """Sensor for media storage free space."""

    _attr_translation_key = "storage_free"
    _attr_icon = "mdi:harddisk"
    _attr_device_class = SensorDeviceClass.DATA_SIZE
    _attr_native_unit_of_measurement = UnitOfInformation.GIGABYTES
    _attr_suggested_display_precision = 1

    def __init__(
        self,
        coordinator: JellyHALibraryCoordinator,
        entry: ConfigEntry,
        device_name: str,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, entry, device_name, "storage_free")

    def _get_unique_storage_folders(self) -> list[dict[str, Any]]:
        """Get unique storage devices from libraries to avoid double counting shared volumes."""
        if not self.coordinator.data:
            return []
        storage = self.coordinator.data.get("storage")
        if not storage or not isinstance(storage, dict):
            return []

        configured_libraries = self._entry.options.get(
            "libraries", self._entry.data.get("libraries", [])
        )
        libs = storage.get("Libraries", [])
        if configured_libraries:
            filtered_libs = [l for l in libs if l.get("Id") in configured_libraries]
            if filtered_libs:
                libs = filtered_libs

        unique_devices: dict[str, dict[str, Any]] = {}
        for lib in libs:
            for folder in lib.get("Folders", []):
                # Unique key by DeviceId or Path
                dev_id = folder.get("DeviceId") or folder.get("Path")
                if dev_id and dev_id not in unique_devices:
                    unique_devices[dev_id] = folder

        return list(unique_devices.values())

    @property
    def native_value(self) -> float | None:
        """Return free storage space in gigabytes."""
        folders = self._get_unique_storage_folders()
        if not folders:
            return None
        free_bytes = sum(f.get("FreeSpace", 0) for f in folders)
        # 1 GB in binary prefix is 1024^3 bytes
        return round(free_bytes / (1024 ** 3), 1)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return detailed storage breakdown attributes."""
        folders = self._get_unique_storage_folders()
        if not folders:
            return {
                "entry_id": self._entry.entry_id,
                "config_entry_id": self._entry.entry_id,
            }

        total_free_bytes = sum(f.get("FreeSpace", 0) for f in folders)
        total_used_bytes = sum(f.get("UsedSpace", 0) for f in folders)
        total_bytes = total_free_bytes + total_used_bytes

        used_percent = round((total_used_bytes / total_bytes) * 100, 1) if total_bytes > 0 else 0
        free_percent = round((total_free_bytes / total_bytes) * 100, 1) if total_bytes > 0 else 0

        free_tb = round(total_free_bytes / (1024 ** 4), 2)
        total_tb = round(total_bytes / (1024 ** 4), 2)
        used_tb = round(total_used_bytes / (1024 ** 4), 2)

        devices_info = []
        for f in folders:
            f_free = f.get("FreeSpace", 0)
            f_used = f.get("UsedSpace", 0)
            f_total = f_free + f_used
            devices_info.append({
                "path": f.get("Path"),
                "device_id": f.get("DeviceId"),
                "storage_type": f.get("StorageType"),
                "free_gb": round(f_free / (1024 ** 3), 1),
                "used_gb": round(f_used / (1024 ** 3), 1),
                "total_gb": round(f_total / (1024 ** 3), 1),
            })

        return {
            "entry_id": self._entry.entry_id,
            "config_entry_id": self._entry.entry_id,
            "free_bytes": total_free_bytes,
            "used_bytes": total_used_bytes,
            "total_bytes": total_bytes,
            "free_tb": free_tb,
            "used_tb": used_tb,
            "total_tb": total_tb,
            "used_percent": used_percent,
            "free_percent": free_percent,
            "devices": devices_info,
        }


class JellyHAMediaStorageFreePercentSensor(JellyHABaseSensor):
    """Sensor for media storage free percentage."""

    _attr_translation_key = "storage_free_percent"
    _attr_icon = "mdi:pie-chart"
    _attr_native_unit_of_measurement = "%"
    _attr_suggested_display_precision = 0

    def __init__(
        self,
        coordinator: JellyHALibraryCoordinator,
        entry: ConfigEntry,
        device_name: str,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, entry, device_name, "storage_free_percent")

    def _get_unique_storage_folders(self) -> list[dict[str, Any]]:
        """Get unique storage devices from libraries to avoid double counting shared volumes."""
        if not self.coordinator.data:
            return []
        storage = self.coordinator.data.get("storage")
        if not storage or not isinstance(storage, dict):
            return []

        configured_libraries = self._entry.options.get(
            "libraries", self._entry.data.get("libraries", [])
        )
        libs = storage.get("Libraries", [])
        if configured_libraries:
            filtered_libs = [l for l in libs if l.get("Id") in configured_libraries]
            if filtered_libs:
                libs = filtered_libs

        unique_devices: dict[str, dict[str, Any]] = {}
        for lib in libs:
            for folder in lib.get("Folders", []):
                # Unique key by DeviceId or Path
                dev_id = folder.get("DeviceId") or folder.get("Path")
                if dev_id and dev_id not in unique_devices:
                    unique_devices[dev_id] = folder

        return list(unique_devices.values())

    @property
    def native_value(self) -> int | None:
        """Return free storage percentage as a clean integer."""
        folders = self._get_unique_storage_folders()
        if not folders:
            return None
        total_free_bytes = sum(f.get("FreeSpace", 0) for f in folders)
        total_used_bytes = sum(f.get("UsedSpace", 0) for f in folders)
        total_bytes = total_free_bytes + total_used_bytes
        if total_bytes <= 0:
            return None
        return int(round((total_free_bytes / total_bytes) * 100))

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return detailed storage breakdown attributes."""
        folders = self._get_unique_storage_folders()
        if not folders:
            return {
                "entry_id": self._entry.entry_id,
                "config_entry_id": self._entry.entry_id,
            }

        total_free_bytes = sum(f.get("FreeSpace", 0) for f in folders)
        total_used_bytes = sum(f.get("UsedSpace", 0) for f in folders)
        total_bytes = total_free_bytes + total_used_bytes

        used_percent = round((total_used_bytes / total_bytes) * 100, 1) if total_bytes > 0 else 0
        free_percent = round((total_free_bytes / total_bytes) * 100, 1) if total_bytes > 0 else 0

        free_tb = round(total_free_bytes / (1024 ** 4), 2)
        total_tb = round(total_bytes / (1024 ** 4), 2)
        used_tb = round(total_used_bytes / (1024 ** 4), 2)
        free_gb = round(total_free_bytes / (1024 ** 3), 1)
        total_gb = round(total_bytes / (1024 ** 3), 1)
        used_gb = round(total_used_bytes / (1024 ** 3), 1)

        devices_info = []
        for f in folders:
            f_free = f.get("FreeSpace", 0)
            f_used = f.get("UsedSpace", 0)
            f_total = f_free + f_used
            devices_info.append({
                "path": f.get("Path"),
                "device_id": f.get("DeviceId"),
                "storage_type": f.get("StorageType"),
                "free_gb": round(f_free / (1024 ** 3), 1),
                "used_gb": round(f_used / (1024 ** 3), 1),
                "total_gb": round(f_total / (1024 ** 3), 1),
            })

        return {
            "entry_id": self._entry.entry_id,
            "config_entry_id": self._entry.entry_id,
            "free_bytes": total_free_bytes,
            "used_bytes": total_used_bytes,
            "total_bytes": total_bytes,
            "free_gb": free_gb,
            "used_gb": used_gb,
            "total_gb": total_gb,
            "free_tb": free_tb,
            "used_tb": used_tb,
            "total_tb": total_tb,
            "used_percent": used_percent,
            "free_percent": free_percent,
            "devices": devices_info,
        }


