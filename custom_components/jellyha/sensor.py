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


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up JellyHA Library sensors from a config entry."""
    coordinators = hass.data[DOMAIN][entry.entry_id]
    coordinator: JellyHALibraryCoordinator = coordinators["library"]
    session_coordinator: JellyHASessionCoordinator = coordinators["session"]
    device_name = entry.data.get(CONF_DEVICE_NAME, DEFAULT_DEVICE_NAME)

    sensors: list[SensorEntity] = [
        JellyHALibrarySensor(coordinator, entry, device_name),
        JellyHAFavoritesCountSensor(coordinator, entry, device_name),
        JellyHAUnwatchedCountSensor(coordinator, entry, device_name),
        JellyHAUnwatchedMoviesSensor(coordinator, entry, device_name),
        JellyHAUnwatchedSeriesSensor(coordinator, entry, device_name),
        JellyHALastRefreshSensor(coordinator, entry, device_name),
        JellyHALastDataChangeSensor(coordinator, entry, device_name),
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
        
        # Use device_name as prefix for unique_id
        self._attr_unique_id = f"{device_name}_{sensor_key}"
        
        # Set entity_id to use device_name prefix (e.g., sensor.jellyha_library)
        self.entity_id = f"sensor.{device_name}_{sensor_key}"

    @property
    def device_info(self) -> DeviceInfo:
        """Return device info for this sensor."""
        return DeviceInfo(
            identifiers={(DOMAIN, self._entry.entry_id)},
            name=self._device_name.title(),
            manufacturer="JellyHA",
            model="Jellyfin Integration",
            sw_version="1.0.0",
        )


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

        return {
            "entry_id": self._entry.entry_id,
            "server_name": self.coordinator.data.get("server_name"),
            "last_updated": self.coordinator.last_refresh_time,
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
    _attr_icon = "mdi:eye-off-outline"

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
        return {
            "movies": len([i for i in unwatched if i.get("type") == "Movie"]),
            "series": len([i for i in unwatched if i.get("type") == "Series"]),
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
    _attr_icon = "mdi:television-classic"

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


class JellyHAUserSensor(CoordinatorEntity[JellyHASessionCoordinator], SensorEntity):
    """Sensor tracking "Now Playing" for a specific Jellyfin user."""

    _attr_has_entity_name = True

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
        self._attr_name = f"JellyHA Now Playing {username}"
        self.entity_id = generate_entity_id(
            "sensor.{}", 
            f"jellyha_now_playing_{username}", 
            hass=coordinator.hass
        )

    @property
    def device_info(self) -> DeviceInfo:
        """Return device info."""
        return DeviceInfo(
            identifiers={(DOMAIN, self._entry.entry_id)},
            name="JellyHA Users",
            manufacturer="JellyHA",
            model="User Session Tracker",
            sw_version="1.0.0",
        )

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
        return "mdi:television-off"

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
            "item_id": "",
            "title": "",
            "progress_percent": 0,
            "position_ticks": 0,
            "image_url": None,
            "media_type": None,
            "is_paused": False,
        }

        if "NowPlayingItem" in session:
            item = session["NowPlayingItem"]
            item_type = item.get("Type")
            
            attributes["item_id"] = item.get("Id")
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
            if duration_ticks > 0:
                attributes["progress_percent"] = int((position_ticks / duration_ticks) * 100)

            # Image
            image_id = item.get("Id")
            if image_id:
                # Use session coordinator's API client reference
                server_url = self.coordinator._api._server_url
                attributes["image_url"] = (
                    f"{server_url}/Items/{image_id}/Images/Primary"
                    f"?maxHeight=300&quality=90"
                )
            
            # Backdrop Logic
            backdrop_tags = item.get("BackdropImageTags", [])
            if backdrop_tags:
                server_url = self.coordinator._api._server_url
                attributes["backdrop_url"] = (
                    f"{server_url}/Items/{image_id}/Images/Backdrop/0"
                    f"?maxWidth=800&quality=60"
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
        
        return None
