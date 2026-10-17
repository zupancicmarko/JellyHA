"""Persistent storage for JellyHA library data."""
from __future__ import annotations

import logging
from typing import Any, Callable

from homeassistant.core import HomeAssistant
from homeassistant.helpers.storage import Store

_LOGGER = logging.getLogger(__name__)

STORAGE_VERSION = 1
STORAGE_KEY = "jellyha.items"


class JellyfinLibraryData:
    """Persistent library data storage."""

    def __init__(self, hass: HomeAssistant, entry_id: str) -> None:
        """Initialize storage."""
        self._hass = hass
        self._store = Store(hass, STORAGE_VERSION, f"jellyha.{entry_id}.items")
        self._items: dict[str, dict[str, Any]] = {}
        self._callbacks: list[Callable[[], None]] = []

    async def async_load(self) -> None:
        """Load data from storage."""
        data = await self._store.async_load()
        if data:
            self._items = data.get("items", {})

    async def async_save(self) -> None:
        """Save data to storage."""
        await self._store.async_save({"items": self._items})

    async def async_remove_item(self, item_id: str) -> bool:
        """Remove single item from storage and save immediately."""
        if item_id in self._items:
            del self._items[item_id]
            await self.async_save()
            self._notify_listeners()
            return True
        return False

    def get_item(self, item_id: str) -> dict[str, Any] | None:
        """Get single item by ID."""
        return self._items.get(item_id)

    def get_all_items(self) -> list[dict[str, Any]]:
        """Get all items as list."""
        return list(self._items.values())

    def get_favorites(self) -> list[dict[str, Any]]:
        """Get items marked as favorite."""
        return [
            item for item in self._items.values()
            if item.get("is_favorite", False)
        ]

    def get_unwatched(self, media_type: str | None = None) -> list[dict[str, Any]]:
        """Get unwatched items, optionally filtered by type."""
        items = [
            item for item in self._items.values()
            if not item.get("is_played", True)
        ]
        if media_type:
            items = [i for i in items if i.get("type") == media_type]
        return items

    def register_callback(self, callback: Callable[[], None]) -> None:
        """Register callback for data changes."""
        self._callbacks.append(callback)

    def _notify_listeners(self) -> None:
        """Notify all registered callbacks."""
        for callback in self._callbacks:
            callback()

    async def update_from_coordinator(self, items: list[dict[str, Any]]) -> None:
        """Update storage from coordinator data."""
        self._items = {item["id"]: item for item in items}
        await self.async_save()
        self._notify_listeners()
