"""Jellyfin API client for JellyHA integration."""
from __future__ import annotations

import asyncio
import logging
from typing import Any
from urllib.parse import urljoin

import aiohttp

from .const import (
    API_TIMEOUT,
    MAX_RETRIES,
    RETRY_BACKOFF_FACTOR,
    ITEM_TYPE_MOVIE,
    ITEM_TYPE_SERIES,
)

_LOGGER = logging.getLogger(__name__)


class JellyfinApiError(Exception):
    """Base exception for Jellyfin API errors."""


class JellyfinAuthError(JellyfinApiError):
    """Authentication error."""


class JellyfinConnectionError(JellyfinApiError):
    """Connection error."""


class JellyfinApiClient:
    """Async client for Jellyfin API."""

    def __init__(
        self,
        server_url: str,
        session: aiohttp.ClientSession,
        api_key: str | None = None,
    ) -> None:
        """Initialize the API client."""
        self._server_url = server_url.rstrip("/")
        self._api_key = api_key
        self._session = session
        self._user_id: str | None = None

    @property
    def _headers(self) -> dict[str, str]:
        """Get authentication headers."""
        headers = {
            "Authorization": f'MediaBrowser Client="Home Assistant", '
            f'Device="HACS Integration", '
            f'DeviceId="jellyha", '
            f'Version="1.0.0"',
            "Content-Type": "application/json",
        }

        if self._api_key:
            headers["Authorization"] += f', Token="{self._api_key}"'

        return headers



    async def _request(
        self,
        method: str,
        endpoint: str,
        **kwargs: Any,
    ) -> Any:
        """Make an API request with retry logic."""
        url = urljoin(self._server_url + "/", endpoint.lstrip("/"))

        for attempt in range(MAX_RETRIES):
            try:
                async with self._session.request(
                    method,
                    url,
                    headers=self._headers,
                    timeout=aiohttp.ClientTimeout(total=API_TIMEOUT),
                    **kwargs,
                ) as response:
                    if response.status == 401:
                        raise JellyfinAuthError("Invalid API key or unauthorized")
                    if response.status == 403:
                        raise JellyfinAuthError("Access forbidden")
                    response.raise_for_status()
                    
                    # Handle 204 No Content responses (no body to parse)
                    if response.status == 204:
                        return None
                    
                    return await response.json()

            except RuntimeError as err:
                 if "Session is closed" in str(err):
                     raise JellyfinConnectionError("Session is closed") from err
                 raise err
            except aiohttp.ClientError as err:
                if attempt == MAX_RETRIES - 1:
                    raise JellyfinConnectionError(
                        f"Failed to connect after {MAX_RETRIES} attempts: {err}"
                    ) from err
                wait_time = RETRY_BACKOFF_FACTOR ** attempt
                _LOGGER.debug(
                    "Request failed (attempt %d/%d), retrying in %ds: %s",
                    attempt + 1,
                    MAX_RETRIES,
                    wait_time,
                    err,
                )
                await asyncio.sleep(wait_time)

    async def validate_connection(self) -> dict[str, Any]:
        """Validate the connection and return server info."""
        return await self._request("GET", "/System/Info/Public")

    async def authenticate(self, username: str, password: str) -> dict[str, Any]:
        """Authenticate with username and password."""
        headers = {
            "Content-Type": "application/json",
            "X-Emby-Authorization": (
                'MediaBrowser Client="Home Assistant", '
                'Device="HACS Integration", '
                'DeviceId="jellyha", '
                'Version="1.0.0"'
            ),
        }
        
        url = urljoin(self._server_url + "/", "Users/AuthenticateByName")
        url = urljoin(self._server_url + "/", "Users/AuthenticateByName")
        
        try:
            async with self._session.post(
                url,
                json={"Username": username, "Pw": password},
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=API_TIMEOUT),
            ) as response:
                if response.status == 401:
                    raise JellyfinAuthError("Invalid username or password")
                response.raise_for_status()
                data = await response.json()
                
                self._api_key = data.get("AccessToken")
                self._user_id = data.get("User", {}).get("Id")
                return data
                
        except aiohttp.ClientError as err:
            raise JellyfinConnectionError(f"Connection failed: {err}") from err

    async def get_users(self) -> list[dict[str, Any]]:
        """Get list of users."""
        return await self._request("GET", "/Users")

    async def get_user(self, user_id: str) -> dict[str, Any]:
        """Get user by ID."""
        return await self._request("GET", f"/Users/{user_id}")

    async def get_libraries(self, user_id: str) -> list[dict[str, Any]]:
        """Get user's media libraries."""
        result = await self._request("GET", f"/Users/{user_id}/Views")
        return result.get("Items", [])

    async def get_library_items(
        self,
        user_id: str,
        limit: int = 0,  # 0 = no limit, fetch all items
        item_types: list[str] | None = None,
        library_ids: list[str] | None = None,
        search_term: str | None = None,
        is_played: bool | None = None,
        is_favorite: bool | None = None,
        genre: str | None = None,
        year: int | None = None,
        min_rating: float | None = None,
        season: int | None = None,
        episode: int | None = None,
    ) -> list[dict[str, Any]]:
        """Get library items."""
        if item_types is None:
            item_types = [ITEM_TYPE_MOVIE, ITEM_TYPE_SERIES]

        params = {
            "SortBy": "DateCreated",
            "SortOrder": "Descending",
            "Recursive": "true",
            "IncludeItemTypes": ",".join(item_types),
            "Fields": "PrimaryImageAspectRatio,ProviderIds,Genres,RunTimeTicks,DateCreated,CommunityRating,Overview,MediaStreams,UserData,RemoteTrailers",
        }

        if limit > 0:
            params["Limit"] = limit

        if search_term:
            params["SearchTerm"] = search_term
            
        if is_played is not None:
             params["IsPlayed"] = str(is_played).lower()
        
        if is_favorite is not None:
             params["IsFavorite"] = str(is_favorite).lower()

        if genre:
             params["Genres"] = genre

        if year:
             params["Years"] = str(year)

        if min_rating is not None:
             params["MinCommunityRating"] = str(min_rating)

        if season is not None:
             params["ParentIndexNumber"] = str(season)
             
        if episode is not None:
             params["IndexNumber"] = str(episode)

        if library_ids:
            params["ParentId"] = ",".join(library_ids)

        result = await self._request("GET", f"/Users/{user_id}/Items", params=params)
        return result.get("Items", [])

    async def get_item(self, user_id: str, item_id: str) -> dict[str, Any]:
        """Get details for a single item."""
        params = {
            "Fields": "Chapters,DateCreated,Genres,MediaSources,MediaStreams,Overview,ParentId,Path,People,ProviderIds,PrimaryImageAspectRatio,RemoteTrailers,SortName,Studios,Taglines,TrailerUrls,UserData,SeasonUserData,OfficialRating,CommunityRating,CumulativeRunTimeTicks,RunTimeTicks,ProductionYear,PremiereDate,ExternalUrls"
        }
        return await self._request("GET", f"/Users/{user_id}/Items/{item_id}", params=params)

    async def get_sessions(self) -> list[dict[str, Any]]:
        """Get all active sessions."""
        return await self._request("GET", "/Sessions")

    async def get_next_up_episode(self, user_id: str, series_id: str) -> dict[str, Any] | None:
        """Get the next unplayed episode for a series."""
        params = {
            "UserId": user_id,
            "SeriesId": series_id,
            "Limit": 1,
            "Fields": "MediaSources,MediaStreams,Overview,RunTimeTicks,OfficialRating,CommunityRating"
        }
        result = await self._request("GET", "/Shows/NextUp", params=params)
        items = result.get("Items", [])
        return items[0] if items else None

    async def get_next_up_items(self, user_id: str, limit: int | None = None) -> list[dict[str, Any]]:
        """Get the user's Next Up list (shows in progress)."""
        params = {
            "UserId": user_id,
            "SortBy": "DatePlayed",
            "SortOrder": "Descending",
            "Dependencies": "true",
            "Fields": "PrimaryImageAspectRatio,ProviderIds,Genres,RunTimeTicks,DateCreated,CommunityRating,Overview,MediaStreams,UserData,RemoteTrailers,SeriesInfo,ParentId",
        }
        if limit:
            params["Limit"] = limit
            
        result = await self._request("GET", "/Shows/NextUp", params=params)
        return result.get("Items", [])

    async def get_episodes_by_season(
        self, user_id: str, series_id: str, season: int | None = None
    ) -> list[dict[str, Any]]:
        """Get all episodes for a specific season (or all if None)."""
        params = {
            "UserId": user_id,
            "ParentId": series_id,
            "IncludeItemTypes": "Episode",
            "SortBy": "SortName", # Sort by episode number typically via SortName or index
            "SortOrder": "Ascending",
            "Fields": "PrimaryImageAspectRatio,Overview,MediaStreams,RunTimeTicks,OfficialRating,CommunityRating,UserData",
        }
        
        if season is not None:
            params["ParentIndexNumber"] = str(season)
            
        # Recursive true is needed to find episodes inside seasons inside series
        params["Recursive"] = "true"

        result = await self._request("GET", f"/Users/{user_id}/Items", params=params)
        return result.get("Items", [])

    async def get_similar_items(self, user_id: str, item_id: str, limit: int = 5) -> list[dict[str, Any]]:
        """Get similar items (recommendations) for a specific item."""
        # Reduced fields for optimization
        # Removed: MediaStreams, ProviderIds, BackdropImageTags (Used for details/playback only)
        # Kept: Overview, RemoteTrailers, DateCreated
        params = {
            "IncludeItemTypes": "Movie,Series,Episode",
            "Recursive": "true",
            "Fields": "Overview,RemoteTrailers,DateCreated",
            "ImageTypeLimit": 1,
            "EnableImageTypes": "Primary,Banner,Thumb",
            "Limit": limit,
        }
        result = await self._request("GET", f"/Items/{item_id}/Similar", params=params)
        
        # Normalize result to list
        items = []
        if isinstance(result, list):
            items = result
        else:
            items = result.get("Items", [])

        # Enforce limit client-side
        safe_limit = int(limit) if limit else 5
        final_result = items[:safe_limit]
        
        return final_result

    async def get_playback_info(
        self, user_id: str, item_id: str, profile: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Get playback info for an item."""
        params = {"UserId": user_id}
        if profile:
            return await self._request("POST", f"/Items/{item_id}/PlaybackInfo", params=params, json=profile)
        return await self._request("GET", f"/Items/{item_id}/PlaybackInfo", params=params)

    def get_image_url(
        self,
        item_id: str,
        image_type: str = "Primary",
        max_height: int = 300,
        quality: int = 90,
    ) -> str:
        """Build image URL for an item."""
        return (
            f"{self._server_url}/Items/{item_id}/Images/{image_type}"
            f"?maxHeight={max_height}&quality={quality}&api_key={self._api_key}"
        )

    def get_jellyfin_url(self, item_id: str) -> str:
        """Build deep link URL to open item in Jellyfin web UI."""
        return f"{self._server_url}/web/index.html#!/details?id={item_id}"

    def get_content_url(self, item_id: str) -> str:
        """Get direct stream URL for an item."""
        # Simple direct stream URL. Transcoding parameters could be added here.
        # We append api_key so the player can access without header auth.
        return f"{self._server_url}/Videos/{item_id}/stream?static=true&api_key={self._api_key}"

    async def update_favorite(self, user_id: str, item_id: str, is_favorite: bool) -> bool:
        """Update favorite status for an item."""
        method = "POST" if is_favorite else "DELETE"
        endpoint = f"/Users/{user_id}/FavoriteItems/{item_id}"
        
        try:
            await self._request(method, endpoint)
            return True
        except JellyfinApiError as err:
            _LOGGER.error("Failed to update favorite status: %s", err)
            return False

    async def update_played_status(self, user_id: str, item_id: str, is_played: bool) -> bool:
        """Update played status for an item."""
        method = "POST" if is_played else "DELETE"
        endpoint = f"/Users/{user_id}/PlayedItems/{item_id}"
        
        try:
            await self._request(method, endpoint)
            return True
        except JellyfinApiError as err:
            _LOGGER.error("Failed to update played status: %s", err)
            return False

    async def session_control(self, session_id: str, command: str) -> bool:
        """Send a control command to a playback session."""
        # Command: Pause, Unpause, TogglePause, Stop
        endpoint = f"/Sessions/{session_id}/Playing/{command}"
        try:
            await self._request("POST", endpoint)
            return True
        except JellyfinApiError as err:
            _LOGGER.error("Failed to send session command %s: %s", command, err)
            return False

    async def session_seek(self, session_id: str, position_ticks: int) -> bool:
        """Seek to a position in a playback session."""
        endpoint = f"/Sessions/{session_id}/Playing/Seek"
        params = {"SeekPositionTicks": position_ticks}
        try:
            await self._request("POST", endpoint, params=params)
            return True
        except JellyfinApiError as err:
            _LOGGER.error("Failed to seek session: %s", err)
            return False

    async def logout(self) -> None:
        """Logout from Jellyfin server."""
        try:
            headers = self._headers
            headers["X-Emby-Authorization"] = (
                f'MediaBrowser Client="Home Assistant", '
                f'Device="HACS Integration", '
                f'DeviceId="jellyha", '
                f'Version="1.0.0", '
                f'Token="{self._api_key}"'
            )
            await self._request("POST", "/Sessions/Logout", headers=headers)
        except Exception as err:
            _LOGGER.warning("Logout failed: %s", err)

    async def close(self) -> None:
        """Close the session."""
        # Do not close the shared session provided by Home Assistant
        pass
