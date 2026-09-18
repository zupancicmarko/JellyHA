"""Browse media support for JellyHA."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.media_player import (
    BrowseMedia,
    MediaClass,
    MediaType,
)
from homeassistant.components.http.auth import async_sign_path
from homeassistant.core import HomeAssistant

from datetime import timedelta

from .const import DOMAIN
from .media_strategy import MediaStrategy

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


def _signed_image_url(
    hass: HomeAssistant, entry_id: str, item_id: str, image_type: str = "Primary"
) -> str:
    """Build a signed proxy URL for a Jellyfin image (no API key leaked)."""
    path = f"/api/jellyha/image/{entry_id}/{item_id}/{image_type}"
    return async_sign_path(hass, path, timedelta(hours=24))


async def async_browse_media(
    hass: HomeAssistant,
    entry_id: str,
    media_content_type: str | None = None,
    media_content_id: str | None = None,
) -> BrowseMedia:
    """Browse Jellyfin media library."""
    entry = hass.config_entries.async_get_entry(entry_id)
    if not entry or not hasattr(entry, "runtime_data"):
        raise ValueError("JellyHA integration not loaded")
    
    coordinator = entry.runtime_data.library

    # Root level - show categories
    if media_content_id is None or media_content_id == "":
        return await _build_root_menu(coordinator, entry_id)

    # Parse the content ID
    category, item_id = parse_item_id(media_content_id)

    if category == "movies":
        return await _build_movies_list(coordinator, entry_id)
    elif category == "series":
        return await _build_series_list(coordinator, entry_id)
    elif category == "show" and item_id:
        return await _build_show_seasons(coordinator, entry_id, item_id)
    elif category == "season" and item_id:
        return await _build_season_episodes(coordinator, entry_id, item_id)
    elif category == "music":
        return await _build_music_root(coordinator, entry_id)
    elif category == "artists":
        return await _build_artists_list(coordinator, entry_id)
    elif category == "albums":
        return await _build_albums_list(coordinator, entry_id)
    elif category == "artist" and item_id:
        return await _build_artist_albums(coordinator, entry_id, item_id)
    elif category == "album" and item_id:
        return await _build_album_tracks(coordinator, entry_id, item_id)
    elif category == "homevideos":
        return await _build_homevideos_list(coordinator, entry_id)
    elif category == "playlists":
        return await _build_playlists_list(coordinator, entry_id)
    elif category == "playlist" and item_id:
        return await _build_playlist_items(coordinator, entry_id, item_id)
    elif category == "collections":
        return await _build_collections_list(coordinator, entry_id)
    elif category == "collection" and item_id:
        return await _build_collection_items(coordinator, entry_id, item_id)
    elif category == "recent":
        return await _build_recent_list(coordinator, entry_id)
    elif category == "favorites":
        return await _build_favorites_list(coordinator, entry_id)
    elif category in ("livetv", "live_tv"):
        return await _build_livetv_list(coordinator, entry_id)
    elif category == "item" and item_id:
        # Return item details for playback
        return await _build_item_details(coordinator, entry_id, item_id)

    # Default to root
    return await _build_root_menu(coordinator, entry_id)


async def _build_root_menu(coordinator, entry_id: str) -> BrowseMedia:
    """Build root browse menu dynamically based on user's authorized libraries."""
    api = coordinator._api
    user_id = coordinator.entry.data.get("user_id")
    device_name = coordinator.entry.data.get("device_name", "JellyHA")
    selected_libraries = coordinator.entry.data.get("libraries", [])
    
    # Fetch user libraries to determine available collection types
    try:
        raw_views = await api.get_libraries(user_id)
    except Exception:
        raw_views = []

    # If specific libraries were selected during setup, filter out the views
    if selected_libraries:
        views = [v for v in raw_views if v.get("Id") in selected_libraries]
    else:
        views = raw_views

    collection_types = {v.get("CollectionType") for v in views if v.get("CollectionType")}

    children = []
    
    if "movies" in collection_types:
        children.append(
            BrowseMedia(
                title="📽️ Movies",
                media_class=MediaClass.DIRECTORY,
                media_content_id=build_item_id("movies"),
                media_content_type=MediaType.MOVIE,
                can_play=False,
                can_expand=True,
                thumbnail=None,
            )
        )
        
    if "tvshows" in collection_types:
        children.append(
            BrowseMedia(
                title="📺 TV Series",
                media_class=MediaClass.DIRECTORY,
                media_content_id=build_item_id("series"),
                media_content_type=MediaType.TVSHOW,
                can_play=False,
                can_expand=True,
                thumbnail=None,
            )
        )
        
    if "music" in collection_types or "musicvideos" in collection_types:
        children.append(
            BrowseMedia(
                title="🎵 Music",
                media_class=MediaClass.DIRECTORY,
                media_content_id=build_item_id("music"),
                media_content_type=MediaType.MUSIC,
                can_play=False,
                can_expand=True,
                thumbnail=None,
            )
        )

    if "homevideos" in collection_types:
        children.append(
            BrowseMedia(
                title="🎥 Home Videos",
                media_class=MediaClass.DIRECTORY,
                media_content_id=build_item_id("homevideos"),
                media_content_type=MediaType.VIDEO,
                can_play=False,
                can_expand=True,
                thumbnail=None,
            )
        )

    if "playlists" in collection_types:
        children.append(
            BrowseMedia(
                title="📋 Playlists",
                media_class=MediaClass.DIRECTORY,
                media_content_id=build_item_id("playlists"),
                media_content_type=MediaType.PLAYLIST,
                can_play=False,
                can_expand=True,
                thumbnail=None,
            )
        )

    if "boxsets" in collection_types or "boxset" in collection_types:
        children.append(
            BrowseMedia(
                title="📦 Collections",
                media_class=MediaClass.DIRECTORY,
                media_content_id=build_item_id("collections"),
                media_content_type=MediaType.PLAYLIST,
                can_play=False,
                can_expand=True,
                thumbnail=None,
            )
        )

    # Live TV channels (if configured and available)
    live_tv_channels = coordinator.data.get("live_tv_channels", []) if coordinator.data else []
    if live_tv_channels:
        children.append(
            BrowseMedia(
                title="📡 Live TV",
                media_class=MediaClass.DIRECTORY,
                media_content_id=build_item_id("livetv"),
                media_content_type=MediaType.CHANNEL,
                can_play=False,
                can_expand=True,
                thumbnail=None,
            )
        )

    # We always show Recently Added and Favorites if the user has ANY library synced
    if views:
        children.extend([
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
            )
        ])
    
    return BrowseMedia(
        title=device_name,
        media_class=MediaClass.DIRECTORY,
        media_content_id=build_item_id("root"),
        media_content_type=MediaType.CHANNELS,
        can_play=False,
        can_expand=True,
        children=children,
    )


async def _build_livetv_list(coordinator, entry_id: str) -> BrowseMedia:
    """Build list of Live TV channels."""
    channels = coordinator.data.get("live_tv_channels", []) if coordinator.data else []

    def channel_sort_key(ch: dict[str, Any]) -> tuple[int, float, str]:
        num_str = str(ch.get("ChannelNumber") or ch.get("number") or "")
        name = str(ch.get("Name") or ch.get("name") or "").lower()
        try:
            return (0, float(num_str), name)
        except ValueError:
            return (1, 0.0, name)

    sorted_channels = sorted(channels, key=channel_sort_key)

    children = []
    for ch in sorted_channels:
        channel_id = ch.get("Id") or ch.get("id")
        if not channel_id:
            continue
        number = ch.get("ChannelNumber") or ch.get("number")
        name = ch.get("Name") or ch.get("name") or "Unknown Channel"
        display_title = f"{number} - {name}" if number is not None and str(number).strip() else name

        image_tags = ch.get("ImageTags") or {}
        has_primary = "Primary" in image_tags
        thumbnail = (
            _signed_image_url(coordinator.hass, entry_id, channel_id, "Primary")
            if has_primary
            else None
        )

        children.append(
            BrowseMedia(
                title=display_title,
                media_class=MediaClass.CHANNEL,
                media_content_id=build_item_id("item", channel_id),
                media_content_type=MediaType.CHANNEL,
                can_play=True,
                can_expand=False,
                thumbnail=thumbnail,
            )
        )

    return BrowseMedia(
        title="📡 Live TV",
        media_class=MediaClass.DIRECTORY,
        media_content_id=build_item_id("livetv"),
        media_content_type=MediaType.CHANNEL,
        can_play=False,
        can_expand=True,
        children=children,
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
                media_content_id=build_item_id("show", show.get("id", "")),
                media_content_type=MediaType.TVSHOW,
                can_play=True,
                can_expand=True,
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


async def _build_show_seasons(coordinator, entry_id: str, show_id: str) -> BrowseMedia:
    """Build list of seasons for a TV show."""
    api = coordinator._api
    user_id = coordinator.entry.data.get("user_id")

    try:
        show_info = await api._request("GET", f"/Items/{show_id}", params={"UserId": user_id})
        show_name = show_info.get("Name", "Unknown Show")
    except Exception:
        show_name = "Unknown Show"

    params = {
        "UserId": user_id,
        "SortBy": "SortName",
        "SortOrder": "Ascending",
        "ParentId": show_id,
        "IncludeItemTypes": "Season",
        "Fields": "PrimaryImageAspectRatio",
    }
    result = await api._request("GET", "/Items", params=params)
    raw_seasons = result.get("Items", [])

    children = []
    for season in raw_seasons:
        season_id = season.get("Id", "")
        season_name = season.get("Name", "Unknown Season")

        children.append(
            BrowseMedia(
                title=season_name,
                media_class=MediaClass.SEASON,
                media_content_id=build_item_id("season", season_id),
                media_content_type=MediaType.TVSHOW,
                can_play=True,
                can_expand=True,
                thumbnail=_signed_image_url(coordinator.hass, entry_id, season_id),
            )
        )

    return BrowseMedia(
        title=show_name,
        media_class=MediaClass.TV_SHOW,
        media_content_id=build_item_id("show", show_id),
        media_content_type=MediaType.TVSHOW,
        can_play=True,
        can_expand=True,
        children=children,
    )


async def _build_season_episodes(coordinator, entry_id: str, season_id: str) -> BrowseMedia:
    """Build list of episodes for a season."""
    api = coordinator._api
    user_id = coordinator.entry.data.get("user_id")

    try:
        season_info = await api._request("GET", f"/Items/{season_id}", params={"UserId": user_id})
        season_name = season_info.get("Name", "Unknown Season")
        show_name = season_info.get("SeriesName", "Unknown Show")
    except Exception:
        season_name = "Unknown Season"
        show_name = ""

    params = {
        "UserId": user_id,
        "SortBy": "IndexNumber",
        "SortOrder": "Ascending",
        "ParentId": season_id,
        "IncludeItemTypes": "Episode",
        "Fields": "PrimaryImageAspectRatio",
    }
    result = await api._request("GET", "/Items", params=params)
    raw_episodes = result.get("Items", [])

    children = []
    for ep in raw_episodes:
        ep_id = ep.get("Id", "")
        ep_name = ep.get("Name", f"Episode {ep.get('IndexNumber', '')}")
        index = ep.get("IndexNumber")
        title = f"{index}. {ep_name}" if index else ep_name

        children.append(
            BrowseMedia(
                title=title,
                media_class=MediaClass.EPISODE,
                media_content_id=build_item_id("item", ep_id),
                media_content_type=MediaType.EPISODE,
                can_play=True,
                can_expand=False,
                thumbnail=_signed_image_url(coordinator.hass, entry_id, ep_id),
            )
        )

    title = f"{show_name} - {season_name}" if show_name else season_name
    return BrowseMedia(
        title=title,
        media_class=MediaClass.SEASON,
        media_content_id=build_item_id("season", season_id),
        media_content_type=MediaType.TVSHOW,
        can_play=False,
        can_expand=True,
        children=children,
    )


# ─── Music browsing (API-direct, not cached) ─────────────────────────────────

async def _build_music_root(coordinator, entry_id: str) -> BrowseMedia:
    """Build music sub-menu with Artists and Albums."""
    return BrowseMedia(
        title="Music",
        media_class=MediaClass.DIRECTORY,
        media_content_id=build_item_id("music"),
        media_content_type=MediaType.MUSIC,
        can_play=False,
        can_expand=True,
        children=[
            BrowseMedia(
                title="🎤 Artists",
                media_class=MediaClass.DIRECTORY,
                media_content_id=build_item_id("artists"),
                media_content_type=MediaType.MUSIC,
                can_play=False,
                can_expand=True,
                thumbnail=None,
            ),
            BrowseMedia(
                title="💿 Albums",
                media_class=MediaClass.DIRECTORY,
                media_content_id=build_item_id("albums"),
                media_content_type=MediaType.MUSIC,
                can_play=False,
                can_expand=True,
                thumbnail=None,
            ),
        ],
    )


async def _build_artists_list(coordinator, entry_id: str) -> BrowseMedia:
    """Build list of music artists from Jellyfin API directly."""
    api = coordinator._api
    user_id = coordinator.entry.data.get("user_id")

    # Use Jellyfin's dedicated AlbumArtists endpoint (not Items)
    params = {
        "SortBy": "SortName",
        "SortOrder": "Ascending",
        "Recursive": "true",
        "Fields": "PrimaryImageAspectRatio",
    }
    result = await api._request("GET", f"/Artists/AlbumArtists", params=params)
    raw_artists = result.get("Items", [])

    children = []
    for artist in raw_artists:
        artist_id = artist.get("Id", "")
        children.append(
            BrowseMedia(
                title=artist.get("Name", "Unknown Artist"),
                media_class=MediaClass.ARTIST,
                media_content_id=build_item_id("artist", artist_id),
                media_content_type=MediaType.MUSIC,
                can_play=False,
                can_expand=True,
                thumbnail=_signed_image_url(coordinator.hass, entry_id, artist_id),
            )
        )

    return BrowseMedia(
        title="Artists",
        media_class=MediaClass.DIRECTORY,
        media_content_id=build_item_id("artists"),
        media_content_type=MediaType.MUSIC,
        can_play=False,
        can_expand=True,
        children=children,
    )


async def _build_albums_list(coordinator, entry_id: str) -> BrowseMedia:
    """Build list of music albums from Jellyfin API directly."""
    api = coordinator._api
    user_id = coordinator.entry.data.get("user_id")

    raw_albums = await api.get_library_items(
        user_id=user_id,
        limit=100,
        item_types=["MusicAlbum"],
    )

    # Sort albums alphabetically by name
    raw_albums.sort(key=lambda a: (a.get("SortName") or a.get("Name", "")).lower())

    children = []
    for album in raw_albums:
        album_id = album.get("Id", "")
        artist_name = album.get("AlbumArtist", "")
        album_name = album.get("Name", "Unknown Album")
        title = f"{album_name} — {artist_name}" if artist_name else album_name

        children.append(
            BrowseMedia(
                title=title,
                media_class=MediaClass.ALBUM,
                media_content_id=build_item_id("album", album_id),
                media_content_type=MediaType.MUSIC,
                can_play=False,
                can_expand=True,
                thumbnail=_signed_image_url(coordinator.hass, entry_id, album_id),
            )
        )

    return BrowseMedia(
        title="Albums",
        media_class=MediaClass.DIRECTORY,
        media_content_id=build_item_id("albums"),
        media_content_type=MediaType.MUSIC,
        can_play=False,
        can_expand=True,
        children=children,
    )


async def _build_artist_albums(coordinator, entry_id: str, artist_id: str) -> BrowseMedia:
    """Build list of albums for a specific artist."""
    api = coordinator._api
    user_id = coordinator.entry.data.get("user_id")

    # Get the artist name first
    try:
        artist_info = await api._request("GET", f"/Items/{artist_id}", params={"UserId": user_id})
        artist_name = artist_info.get("Name", "Unknown Artist")
    except Exception:
        artist_name = "Unknown Artist"

    # Get albums by this artist using AlbumArtistIds filter
    params = {
        "UserId": user_id,
        "SortBy": "ProductionYear,SortName",
        "SortOrder": "Descending",
        "Recursive": "true",
        "IncludeItemTypes": "MusicAlbum",
        "AlbumArtistIds": artist_id,
        "Fields": "AlbumArtist,Artists",
    }
    result = await api._request("GET", "/Items", params=params)
    raw_albums = result.get("Items", [])

    children = []
    for album in raw_albums:
        album_id = album.get("Id", "")
        album_name = album.get("Name", "Unknown Album")
        year = album.get("ProductionYear", "")
        title = f"{album_name} ({year})" if year else album_name

        children.append(
            BrowseMedia(
                title=title,
                media_class=MediaClass.ALBUM,
                media_content_id=build_item_id("album", album_id),
                media_content_type=MediaType.MUSIC,
                can_play=False,
                can_expand=True,
                thumbnail=_signed_image_url(coordinator.hass, entry_id, album_id),
            )
        )

    return BrowseMedia(
        title=artist_name,
        media_class=MediaClass.ARTIST,
        media_content_id=build_item_id("artist", artist_id),
        media_content_type=MediaType.MUSIC,
        can_play=False,
        can_expand=True,
        children=children,
    )


async def _build_album_tracks(coordinator, entry_id: str, album_id: str) -> BrowseMedia:
    """Build list of tracks in an album."""
    api = coordinator._api
    user_id = coordinator.entry.data.get("user_id")

    # Get album info
    try:
        album_info = await api._request("GET", f"/Items/{album_id}", params={"UserId": user_id})
        album_name = album_info.get("Name", "Unknown Album")
        album_artist = album_info.get("AlbumArtist", "")
    except Exception:
        album_name = "Unknown Album"
        album_artist = ""

    # Get tracks in this album
    params = {
        "UserId": user_id,
        "SortBy": "IndexNumber",
        "SortOrder": "Ascending",
        "Recursive": "true",
        "IncludeItemTypes": "Audio",
        "ParentId": album_id,
        "Fields": "AlbumArtist,Artists,RunTimeTicks,Container",
    }
    result = await api._request("GET", "/Items", params=params)
    raw_tracks = result.get("Items", [])

    children = []
    for track in raw_tracks:
        track_id = track.get("Id", "")
        track_name = track.get("Name", "Unknown Track")
        index = track.get("IndexNumber")
        track_artists = track.get("Artists", [])
        artist = ", ".join(track_artists) if track_artists else (track.get("AlbumArtist") or album_artist)
        title = MediaStrategy.format_audio_title(artist, track_name)
        mime_type = _audio_mime_type(track.get("Container"))

        children.append(
            BrowseMedia(
                title=title,
                media_class=MediaClass.TRACK,
                media_content_id=build_item_id("item", track_id),
                media_content_type=mime_type,
                can_play=True,
                can_expand=False,
                thumbnail=_signed_image_url(coordinator.hass, entry_id, album_id),
            )
        )

    album_title = f"{album_name} — {album_artist}" if album_artist else album_name
    return BrowseMedia(
        title=album_title,
        media_class=MediaClass.ALBUM,
        media_content_id=build_item_id("album", album_id),
        media_content_type=MediaType.ALBUM,
        can_play=False,
        can_expand=True,
        children=children,
    )


# ─── Home Videos browsing ─────────────────────────────────────────────────────

async def _build_homevideos_list(coordinator, entry_id: str) -> BrowseMedia:
    """Build list of home videos from local cache."""
    items = coordinator.data.get("items", []) if coordinator.data else []
    videos = [i for i in items if i.get("type") in ("Video", "MusicVideo")]

    children = []
    for video in videos:
        children.append(
            BrowseMedia(
                title=f"{video.get('name', 'Unknown')} ({video.get('year', '')})",
                media_class=MediaClass.VIDEO,
                media_content_id=build_item_id("item", video.get("id", "")),
                media_content_type=MediaType.VIDEO,
                can_play=True,
                can_expand=False,
                thumbnail=video.get("poster_url"),
            )
        )

    return BrowseMedia(
        title="Home Videos",
        media_class=MediaClass.DIRECTORY,
        media_content_id=build_item_id("homevideos"),
        media_content_type=MediaType.VIDEO,
        can_play=False,
        can_expand=True,
        children=children,
    )


# ─── Recently Added & Favorites ───────────────────────────────────────────────

async def _build_recent_list(coordinator, entry_id: str) -> BrowseMedia:
    """Build list of recently added items scoped to integration's authorized libraries."""
    api = coordinator._api
    user_id = coordinator.entry.data.get("user_id")
    selected_libraries = coordinator.entry.options.get("libraries") or coordinator.entry.data.get("libraries", [])

    raw_recent = []
    if api and user_id:
        try:
            raw_recent = await api.get_latest_items(
                user_id=user_id,
                limit=20,
                library_ids=selected_libraries if selected_libraries else None,
            )
        except Exception as err:
            _LOGGER.debug("Could not fetch latest items from API: %s", err)

    children = []
    if raw_recent:
        for item in raw_recent:
            item_id = item.get("Id", "")
            item_type = item.get("Type", "")
            container = item.get("Container")
            media_class, media_type = _classify_raw_item(item_type, container)

            name = item.get("Name", "Unknown")
            if item_type == "Audio":
                artists = item.get("Artists", [])
                artist = ", ".join(artists) if artists else item.get("AlbumArtist", "")
                title = MediaStrategy.format_audio_title(artist, name)
            elif item_type == "Episode":
                series_name = item.get("SeriesName", "")
                season_num = item.get("ParentIndexNumber")
                ep_num = item.get("IndexNumber")
                if series_name and season_num is not None and ep_num is not None:
                    title = f"{series_name} S{season_num:02d}E{ep_num:02d} - {name}"
                elif series_name:
                    title = f"{series_name} - {name}"
                else:
                    title = name
            elif item_type == "MusicAlbum":
                year = item.get("ProductionYear", "")
                artists = item.get("Artists", [])
                artist = ", ".join(artists) if artists else item.get("AlbumArtist", "")
                if artist and year:
                    title = f"{artist} - {name} ({year})"
                elif artist:
                    title = f"{artist} - {name}"
                elif year:
                    title = f"{name} ({year})"
                else:
                    title = name
            elif item_type in ("Movie", "Series"):
                year = item.get("ProductionYear", "")
                title = f"{name} ({year})" if year else name
            else:
                title = name

            can_expand = item_type in ("Series", "Season", "MusicAlbum", "MusicArtist", "Playlist", "BoxSet")
            can_play = not can_expand

            if item_type == "Series":
                content_id = build_item_id("show", item_id)
            elif item_type == "MusicAlbum":
                content_id = build_item_id("album", item_id)
            elif item_type == "MusicArtist":
                content_id = build_item_id("artist", item_id)
            elif item_type == "Playlist":
                content_id = build_item_id("playlist", item_id)
            else:
                content_id = build_item_id("item", item_id)

            children.append(
                BrowseMedia(
                    title=title,
                    media_class=media_class,
                    media_content_id=content_id,
                    media_content_type=media_type,
                    can_play=can_play,
                    can_expand=can_expand,
                    thumbnail=_signed_image_url(coordinator.hass, entry_id, item_id),
                )
            )
    else:
        # Fallback to local coordinator items
        items = coordinator.data.get("items", []) if coordinator.data else []
        for item in items[:20]:
            media_class, media_type = _classify_item(item)
            children.append(
                BrowseMedia(
                    title=f"{item.get('name', 'Unknown')} ({item.get('year', '')})",
                    media_class=media_class,
                    media_content_id=build_item_id("item", item.get("id", "")),
                    media_content_type=media_type,
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
    """Build list of favorite items scoped to the integration's selected libraries."""
    import asyncio
    api = coordinator._api
    user_id = coordinator.entry.data.get("user_id")
    selected_libraries = coordinator.entry.options.get("libraries") or coordinator.entry.data.get("libraries", [])

    raw_favorites = []
    if api and user_id:
        try:
            if selected_libraries:
                # Query favorites scoped to each selected library in this integration
                results = await asyncio.gather(*(
                    api.get_favorite_items(user_id, parent_id=lib_id)
                    for lib_id in selected_libraries
                ))
                seen_ids = set()
                for lib_items in results:
                    for it in lib_items:
                        it_id = it.get("Id")
                        if it_id and it_id not in seen_ids:
                            seen_ids.add(it_id)
                            raw_favorites.append(it)
            else:
                raw_favorites = await api.get_favorite_items(user_id)
        except Exception as err:
            _LOGGER.debug("Could not fetch favorites from API: %s", err)

    children = []
    if raw_favorites:
        for item in raw_favorites:
            item_id = item.get("Id", "")
            item_type = item.get("Type", "")
            container = item.get("Container")
            media_class, media_type = _classify_raw_item(item_type, container)

            name = item.get("Name", "Unknown")
            if item_type == "Audio":
                artists = item.get("Artists", [])
                artist = ", ".join(artists) if artists else item.get("AlbumArtist", "")
                title = MediaStrategy.format_audio_title(artist, name)
            elif item_type == "Episode":
                series_name = item.get("SeriesName", "")
                season_num = item.get("ParentIndexNumber")
                ep_num = item.get("IndexNumber")
                if series_name and season_num is not None and ep_num is not None:
                    title = f"{series_name} S{season_num:02d}E{ep_num:02d} - {name}"
                elif series_name:
                    title = f"{series_name} - {name}"
                else:
                    title = name
            elif item_type in ("Movie", "Series", "MusicAlbum"):
                year = item.get("ProductionYear", "")
                title = f"{name} ({year})" if year else name
            else:
                title = name

            can_expand = item_type in ("Series", "Season", "MusicAlbum", "MusicArtist", "Playlist", "BoxSet")
            can_play = not can_expand

            if item_type == "Series":
                content_id = build_item_id("show", item_id)
            elif item_type == "MusicAlbum":
                content_id = build_item_id("album", item_id)
            elif item_type == "MusicArtist":
                content_id = build_item_id("artist", item_id)
            elif item_type == "Playlist":
                content_id = build_item_id("playlist", item_id)
            else:
                content_id = build_item_id("item", item_id)

            children.append(
                BrowseMedia(
                    title=title,
                    media_class=media_class,
                    media_content_id=content_id,
                    media_content_type=media_type,
                    can_play=can_play,
                    can_expand=can_expand,
                    thumbnail=_signed_image_url(coordinator.hass, entry_id, item_id),
                )
            )
    else:
        # Fallback to local coordinator items
        items = coordinator.data.get("items", []) if coordinator.data else []
        favorites = [i for i in items if i.get("is_favorite", False)]
        for item in favorites:
            media_class, media_type = _classify_item(item)
            children.append(
                BrowseMedia(
                    title=f"{item.get('name', 'Unknown')} ({item.get('year', '')})",
                    media_class=media_class,
                    media_content_id=build_item_id("item", item.get("id", "")),
                    media_content_type=media_type,
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


# ─── Item details & search ────────────────────────────────────────────────────

async def _build_item_details(coordinator, entry_id: str, item_id: str) -> BrowseMedia:
    """Build details for a single item."""
    items = coordinator.data.get("items", []) if coordinator.data else []
    item = next((i for i in items if i.get("id") == item_id), None)

    if not item:
        # Music tracks and deeper items might not be in the library sync cache;
        # fetch directly from API
        try:
            api = coordinator._api
            user_id = coordinator.entry.data.get("user_id")
            if api and user_id:
                raw = await api.get_item(user_id, item_id)
                if raw:
                    media_class, media_type = _classify_raw_item(raw.get("Type"), raw.get("Container"))
                    return BrowseMedia(
                        title=raw.get("Name", "Unknown"),
                        media_class=media_class,
                        media_content_id=build_item_id("item", item_id),
                        media_content_type=media_type,
                        can_play=True,
                        can_expand=False,
                        thumbnail=_signed_image_url(coordinator.hass, entry_id, item_id),
                    )
        except Exception as err:
            _LOGGER.debug("Could not fetch item details from API for %s: %s", item_id, err)

        return BrowseMedia(
            title="Not Found",
            media_class=MediaClass.VIDEO,
            media_content_id=build_item_id("item", item_id),
            media_content_type=MediaType.VIDEO,
            can_play=False,
            can_expand=False,
        )

    media_class, media_type = _classify_item(item)
    return BrowseMedia(
        title=item.get("name", "Unknown"),
        media_class=media_class,
        media_content_id=build_item_id("item", item_id),
        media_content_type=media_type,
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
    entry = hass.config_entries.async_get_entry(entry_id)
    if not entry or not hasattr(entry, "runtime_data"):
        _LOGGER.error("JellyHA integration not loaded for search")
        raise ValueError("JellyHA integration not loaded")
    
    coordinator = entry.runtime_data.library

    user_id = coordinator.config_entry.data.get("user_id")
    api = coordinator._api

    # Search for Movies, Series, and Audio
    items = await api.get_library_items(
        user_id,
        limit=20,
        search_term=search_term
    )

    children = []
    for item in items:
        item_type = item.get("Type")
        media_class, media_type = _classify_raw_item(item_type)

        # Build title with artist info for music
        name = item.get("Name", "Unknown")
        year = item.get("ProductionYear", "")
        artist = item.get("AlbumArtist", "")

        if item_type == "Audio":
            artists = item.get("Artists", [])
            artist_name = ", ".join(artists) if artists else artist
            title = MediaStrategy.format_audio_title(artist_name, name)
        elif item_type == "MusicAlbum" and artist:
            title = f"{name} — {artist}"
        elif year:
            title = f"{name} ({year})"
        else:
            title = name

        # Albums and Artists can be expanded
        can_expand = item_type in ("MusicAlbum", "MusicArtist")
        content_category = "album" if item_type == "MusicAlbum" else ("artist" if item_type == "MusicArtist" else "item")

        children.append(
            BrowseMedia(
                title=title,
                media_class=media_class,
                media_content_id=build_item_id(content_category, item.get("Id", "")),
                media_content_type=media_type,
                can_play=not can_expand or item_type == "MusicAlbum",
                can_expand=can_expand,
                thumbnail=_signed_image_url(coordinator.hass, entry_id, item.get("Id", "")),
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


def _audio_mime_type(container: str | None = None) -> str:
    """Return the audio MIME type for a given container."""
    c = (container or "").lower()
    if c == "flac":
        return "audio/flac"
    if c in ("m4a", "aac"):
        return "audio/mp4"
    if c in ("ogg", "oga"):
        return "audio/ogg"
    if c == "wav":
        return "audio/wav"
    return "audio/mpeg"


def _classify_item(item: dict[str, Any]) -> tuple[MediaClass, str]:
    """Classify a cached item (lowercase 'type' key) into MediaClass and MediaType."""
    item_type = item.get("type", "")
    container = item.get("container")
    return _classify_raw_item(item_type, container)


def _classify_raw_item(item_type: str, container: str | None = None) -> tuple[MediaClass, str]:
    """Classify a Jellyfin item type string into MediaClass and MediaType."""
    if item_type == "Audio":
        return (MediaClass.TRACK, _audio_mime_type(container))
    mapping = {
        "Movie": (MediaClass.MOVIE, MediaType.MOVIE),
        "Series": (MediaClass.TV_SHOW, MediaType.TVSHOW),
        "Episode": (MediaClass.EPISODE, MediaType.EPISODE),
        "MusicAlbum": (MediaClass.ALBUM, MediaType.ALBUM),
        "MusicArtist": (MediaClass.ARTIST, MediaType.ARTIST),
        "MusicVideo": (MediaClass.VIDEO, MediaType.VIDEO),
        "Video": (MediaClass.VIDEO, MediaType.VIDEO),
        "Playlist": (MediaClass.PLAYLIST, MediaType.PLAYLIST),
        "BoxSet": (MediaClass.DIRECTORY, MediaType.CHANNELS),
    }
    return mapping.get(item_type, (MediaClass.VIDEO, MediaType.VIDEO))


# ─── Playlist browsing ────────────────────────────────────────────────────────

async def _build_playlists_list(coordinator, entry_id: str) -> BrowseMedia:
    """Build list of playlists from Jellyfin API."""
    api = coordinator._api
    user_id = coordinator.entry.data.get("user_id")

    raw_playlists = await api.get_library_items(
        user_id=user_id,
        limit=100,
        item_types=["Playlist"],
    )

    children = []
    for playlist in raw_playlists:
        playlist_id = playlist.get("Id", "")
        children.append(
            BrowseMedia(
                title=playlist.get("Name", "Unknown Playlist"),
                media_class=MediaClass.PLAYLIST,
                media_content_id=build_item_id("playlist", playlist_id),
                media_content_type=MediaType.PLAYLIST,
                can_play=True,
                can_expand=True,
                thumbnail=_signed_image_url(coordinator.hass, entry_id, playlist_id),
            )
        )

    return BrowseMedia(
        title="Playlists",
        media_class=MediaClass.DIRECTORY,
        media_content_id=build_item_id("playlists"),
        media_content_type=MediaType.PLAYLIST,
        can_play=False,
        can_expand=True,
        children=children,
    )


async def _build_playlist_items(coordinator, entry_id: str, playlist_id: str) -> BrowseMedia:
    """Build list of items in a playlist."""
    api = coordinator._api
    user_id = coordinator.entry.data.get("user_id")

    # Get playlist info
    try:
        playlist_info = await api._request("GET", f"/Items/{playlist_id}", params={"UserId": user_id})
        playlist_name = playlist_info.get("Name", "Unknown Playlist")
    except Exception:
        playlist_name = "Unknown Playlist"

    # Get items inside the playlist
    params = {
        "UserId": user_id,
        "ParentId": playlist_id,
        "Recursive": "true",
        "Fields": "AlbumArtist,Artists,RunTimeTicks,Genres,ProductionYear,Container",
    }
    result = await api._request("GET", "/Items", params=params)
    raw_items = result.get("Items", [])

    children = []
    for item in raw_items:
        item_id = item.get("Id", "")
        item_type = item.get("Type", "")
        media_class, media_type = _classify_raw_item(item_type, item.get("Container"))

        name = item.get("Name", "Unknown")
        artist = item.get("AlbumArtist", "")
        if item_type == "Audio":
            artists = item.get("Artists", [])
            artist_name = ", ".join(artists) if artists else artist
            title = MediaStrategy.format_audio_title(artist_name, name)
        else:
            title = name

        children.append(
            BrowseMedia(
                title=title,
                media_class=media_class,
                media_content_id=build_item_id("item", item_id),
                media_content_type=media_type,
                can_play=True,
                can_expand=False,
                thumbnail=_signed_image_url(coordinator.hass, entry_id, item_id),
            )
        )

    return BrowseMedia(
        title=playlist_name,
        media_class=MediaClass.PLAYLIST,
        media_content_id=build_item_id("playlist", playlist_id),
        media_content_type=MediaType.PLAYLIST,
        can_play=False,
        can_expand=True,
        children=children,
    )


# ─── BoxSet / Collection browsing ─────────────────────────────────────────────

async def _build_collections_list(coordinator, entry_id: str) -> BrowseMedia:
    """Build list of collections (BoxSets) from Jellyfin API."""
    api = coordinator._api
    user_id = coordinator.entry.data.get("user_id")

    raw_collections = await api.get_library_items(
        user_id=user_id,
        limit=100,
        item_types=["BoxSet"],
    )

    children = []
    for collection in raw_collections:
        collection_id = collection.get("Id", "")
        children.append(
            BrowseMedia(
                title=collection.get("Name", "Unknown Collection"),
                media_class=MediaClass.DIRECTORY,
                media_content_id=build_item_id("collection", collection_id),
                media_content_type=MediaType.PLAYLIST,
                can_play=True,
                can_expand=True,
                thumbnail=_signed_image_url(coordinator.hass, entry_id, collection_id),
            )
        )

    return BrowseMedia(
        title="Collections",
        media_class=MediaClass.DIRECTORY,
        media_content_id=build_item_id("collections"),
        media_content_type=MediaType.PLAYLIST,
        can_play=False,
        can_expand=True,
        children=children,
    )


async def _build_collection_items(coordinator, entry_id: str, collection_id: str) -> BrowseMedia:
    """Build list of items inside a collection (BoxSet)."""
    api = coordinator._api
    user_id = coordinator.entry.data.get("user_id")

    # Get collection info
    try:
        collection_info = await api._request("GET", f"/Items/{collection_id}", params={"UserId": user_id})
        collection_name = collection_info.get("Name", "Unknown Collection")
    except Exception:
        collection_name = "Unknown Collection"

    # Get items inside the collection
    params = {
        "UserId": user_id,
        "ParentId": collection_id,
        "Recursive": "true",
        "Fields": "Genres,RunTimeTicks,CommunityRating,ProductionYear",
        "SortBy": "SortName",
        "SortOrder": "Ascending",
    }
    result = await api._request("GET", "/Items", params=params)
    raw_items = result.get("Items", [])

    children = []
    for item in raw_items:
        item_id = item.get("Id", "")
        item_type = item.get("Type", "")
        media_class, media_type = _classify_raw_item(item_type)

        name = item.get("Name", "Unknown")
        year = item.get("ProductionYear", "")
        title = f"{name} ({year})" if year else name

        children.append(
            BrowseMedia(
                title=title,
                media_class=media_class,
                media_content_id=build_item_id("item", item_id),
                media_content_type=media_type,
                can_play=True,
                can_expand=False,
                thumbnail=_signed_image_url(coordinator.hass, entry_id, item_id),
            )
        )

    return BrowseMedia(
        title=collection_name,
        media_class=MediaClass.DIRECTORY,
        media_content_id=build_item_id("collection", collection_id),
        media_content_type=MediaType.CHANNELS,
        can_play=False,
        can_expand=True,
        children=children,
    )
