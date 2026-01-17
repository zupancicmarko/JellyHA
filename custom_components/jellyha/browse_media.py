"""Browse media support for JellyHA."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.media_player import BrowseMedia
from homeassistant.components.media_player.const import MediaClass, MediaType
from homeassistant.core import HomeAssistant

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


def build_item_id(media_type: str, item_id: str = "") -> str:
    """Build a unique media content ID."""
    if item_id:
        return f"jellyha://{media_type}/{item_id}"
    return f"jellyha://{media_type}"


def parse_item_id(content_id: str) -> tuple[str, str]:
    """Parse media content ID into type and item_id."""
    if not content_id or not content_id.startswith("jellyha://"):
        return "", ""
    path = content_id.replace("jellyha://", "")
    parts = path.split("/", 1)
    media_type = parts[0] if parts else ""
    item_id = parts[1] if len(parts) > 1 else ""
    return media_type, item_id


async def async_browse_media(
    hass: HomeAssistant,
    entry_id: str,
    media_content_type: str | None = None,
    media_content_id: str | None = None,
) -> BrowseMedia:
    """Browse Jellyfin media library."""
    coordinators = hass.data[DOMAIN].get(entry_id)
    if not coordinators:
        raise ValueError("JellyHA coordinator not found")
    coordinator = coordinators["library"]

    # Root level - show categories
    if media_content_id is None or media_content_id == "":
        return _build_root_menu(entry_id)

    # Parse the content ID
    category, item_id = parse_item_id(media_content_id)

    if category == "movies":
        return await _build_movies_list(coordinator, entry_id)
    elif category == "series":
        return await _build_series_list(coordinator, entry_id)
    elif category == "recent":
        return await _build_recent_list(coordinator, entry_id)
    elif category == "favorites":
        return await _build_favorites_list(coordinator, entry_id)
    elif category == "item" and item_id:
        # Return item details for playback
        return await _build_item_details(coordinator, entry_id, item_id)

    # Default to root
    return _build_root_menu(entry_id)


def _build_root_menu(entry_id: str) -> BrowseMedia:
    """Build root browse menu."""
    return BrowseMedia(
        title="JellyHA",
        media_class=MediaClass.DIRECTORY,
        media_content_id=build_item_id("root"),
        media_content_type=MediaType.CHANNELS,
        can_play=False,
        can_expand=True,
        children=[
            BrowseMedia(
                title="📽️ Movies",
                media_class=MediaClass.DIRECTORY,
                media_content_id=build_item_id("movies"),
                media_content_type=MediaType.MOVIE,
                can_play=False,
                can_expand=True,
                thumbnail=None,
            ),
            BrowseMedia(
                title="📺 TV Series",
                media_class=MediaClass.DIRECTORY,
                media_content_id=build_item_id("series"),
                media_content_type=MediaType.TVSHOW,
                can_play=False,
                can_expand=True,
                thumbnail=None,
            ),
            BrowseMedia(
                title="🆕 Recently Added",
                media_class=MediaClass.DIRECTORY,
                media_content_id=build_item_id("recent"),
                media_content_type=MediaType.CHANNELS,
                can_play=False,
                can_expand=True,
                thumbnail=None,
            ),
            BrowseMedia(
                title="❤️ Favorites",
                media_class=MediaClass.DIRECTORY,
                media_content_id=build_item_id("favorites"),
                media_content_type=MediaType.CHANNELS,
                can_play=False,
                can_expand=True,
                thumbnail=None,
            ),
        ],
    )


async def _build_movies_list(coordinator, entry_id: str) -> BrowseMedia:
    """Build list of movies."""
    items = coordinator.data.get("items", []) if coordinator.data else []
    movies = [i for i in items if i.get("type") == "Movie"]

    children = []
    for movie in movies:
        children.append(
            BrowseMedia(
                title=f"{movie.get('name', 'Unknown')} ({movie.get('year', '')})",
                media_class=MediaClass.MOVIE,
                media_content_id=build_item_id("item", movie.get("id", "")),
                media_content_type=MediaType.MOVIE,
                can_play=True,
                can_expand=False,
                thumbnail=movie.get("poster_url"),
            )
        )

    return BrowseMedia(
        title="Movies",
        media_class=MediaClass.DIRECTORY,
        media_content_id=build_item_id("movies"),
        media_content_type=MediaType.MOVIE,
        can_play=False,
        can_expand=True,
        children=children,
    )


async def _build_series_list(coordinator, entry_id: str) -> BrowseMedia:
    """Build list of TV series."""
    items = coordinator.data.get("items", []) if coordinator.data else []
    series = [i for i in items if i.get("type") == "Series"]

    children = []
    for show in series:
        children.append(
            BrowseMedia(
                title=f"{show.get('name', 'Unknown')} ({show.get('year', '')})",
                media_class=MediaClass.TV_SHOW,
                media_content_id=build_item_id("item", show.get("id", "")),
                media_content_type=MediaType.TVSHOW,
                can_play=True,
                can_expand=False,
                thumbnail=show.get("poster_url"),
            )
        )

    return BrowseMedia(
        title="TV Series",
        media_class=MediaClass.DIRECTORY,
        media_content_id=build_item_id("series"),
        media_content_type=MediaType.TVSHOW,
        can_play=False,
        can_expand=True,
        children=children,
    )


async def _build_recent_list(coordinator, entry_id: str) -> BrowseMedia:
    """Build list of recently added items."""
    items = coordinator.data.get("items", []) if coordinator.data else []
    # Items are already sorted by date_added descending
    recent = items[:20]

    children = []
    for item in recent:
        is_movie = item.get("type") == "Movie"
        children.append(
            BrowseMedia(
                title=f"{item.get('name', 'Unknown')} ({item.get('year', '')})",
                media_class=MediaClass.MOVIE if is_movie else MediaClass.TV_SHOW,
                media_content_id=build_item_id("item", item.get("id", "")),
                media_content_type=MediaType.MOVIE if is_movie else MediaType.TVSHOW,
                can_play=True,
                can_expand=False,
                thumbnail=item.get("poster_url"),
            )
        )

    return BrowseMedia(
        title="Recently Added",
        media_class=MediaClass.DIRECTORY,
        media_content_id=build_item_id("recent"),
        media_content_type=MediaType.CHANNELS,
        can_play=False,
        can_expand=True,
        children=children,
    )


async def _build_favorites_list(coordinator, entry_id: str) -> BrowseMedia:
    """Build list of favorite items."""
    items = coordinator.data.get("items", []) if coordinator.data else []
    favorites = [i for i in items if i.get("is_favorite", False)]

    children = []
    for item in favorites:
        is_movie = item.get("type") == "Movie"
        children.append(
            BrowseMedia(
                title=f"{item.get('name', 'Unknown')} ({item.get('year', '')})",
                media_class=MediaClass.MOVIE if is_movie else MediaClass.TV_SHOW,
                media_content_id=build_item_id("item", item.get("id", "")),
                media_content_type=MediaType.MOVIE if is_movie else MediaType.TVSHOW,
                can_play=True,
                can_expand=False,
                thumbnail=item.get("poster_url"),
            )
        )

    return BrowseMedia(
        title="Favorites",
        media_class=MediaClass.DIRECTORY,
        media_content_id=build_item_id("favorites"),
        media_content_type=MediaType.CHANNELS,
        can_play=False,
        can_expand=True,
        children=children,
    )


async def _build_item_details(coordinator, entry_id: str, item_id: str) -> BrowseMedia:
    """Build details for a single item."""
    items = coordinator.data.get("items", []) if coordinator.data else []
    item = next((i for i in items if i.get("id") == item_id), None)

    if not item:
        return BrowseMedia(
            title="Not Found",
            media_class=MediaClass.VIDEO,
            media_content_id=build_item_id("item", item_id),
            media_content_type=MediaType.VIDEO,
            can_play=False,
            can_expand=False,
        )

    is_movie = item.get("type") == "Movie"
    return BrowseMedia(
        title=item.get("name", "Unknown"),
        media_class=MediaClass.MOVIE if is_movie else MediaClass.TV_SHOW,
        media_content_id=build_item_id("item", item_id),
        media_content_type=MediaType.MOVIE if is_movie else MediaType.TVSHOW,
        can_play=True,
        can_expand=False,
        thumbnail=item.get("poster_url"),
    )


async def async_browse_media_search(
    hass: HomeAssistant,
    entry_id: str,
    search_term: str,
) -> BrowseMedia:
    """Browse media with search."""
    coordinators = hass.data[DOMAIN].get(entry_id)
    if not coordinators:
        _LOGGER.error("JellyHA coordinator or API not found for search")
        raise ValueError("JellyHA coordinator or API not found")
    
    coordinator = coordinators["library"]

    user_id = coordinator.config_entry.data.get("user_id")
    api = coordinator._api

    # Search for Movies and Series
    items = await api.get_library_items(
        user_id,
        limit=20,
        search_term=search_term
    )

    children = []
    for item in items:
        # Check type - API returns "Movie", "Series", "Episode" etc.
        item_type = item.get("Type")
        is_movie = item_type == "Movie"

        media_class = MediaClass.MOVIE if is_movie else MediaClass.TV_SHOW
        media_type = MediaType.MOVIE if is_movie else MediaType.TVSHOW

        children.append(
            BrowseMedia(
                title=f"{item.get('Name', 'Unknown')} ({item.get('ProductionYear', '')})",
                media_class=media_class,
                media_content_id=build_item_id("item", item.get("Id", "")),
                media_content_type=media_type,
                can_play=True,
                can_expand=False,
                thumbnail=api.get_image_url(item.get("Id"), "Primary"),
            )
        )

    return BrowseMedia(
        title=f"Search: {search_term}",
        media_class=MediaClass.DIRECTORY,
        media_content_id=build_item_id("search"),
        media_content_type=MediaType.CHANNELS,
        can_play=False,
        can_expand=True,
        children=children,
    )
