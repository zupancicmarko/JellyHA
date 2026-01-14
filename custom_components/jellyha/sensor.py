"""Sensor platform for JellyHA Library."""
from __future__ import annotations

from typing import Any

from homeassistant.components.sensor import SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import JellyHALibraryCoordinator


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up JellyHA Library sensor from a config entry."""
    coordinator: JellyHALibraryCoordinator = hass.data[DOMAIN][entry.entry_id]

    async_add_entities([JellyHALibrarySensor(coordinator, entry)])


class JellyHALibrarySensor(
    CoordinatorEntity[JellyHALibraryCoordinator], SensorEntity
):
    """Sensor representing media library from Jellyfin."""

    _attr_has_entity_name = True
    _attr_translation_key = "library"
    _attr_icon = "mdi:new-box"

    def __init__(
        self,
        coordinator: JellyHALibraryCoordinator,
        entry: ConfigEntry,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator)
        self._attr_unique_id = f"{entry.entry_id}_library"
        self._entry = entry

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
            "items": self.coordinator.data.get("items", []),
            "server_name": self.coordinator.data.get("server_name"),
            "last_updated": self.coordinator.last_update_success,
        }
