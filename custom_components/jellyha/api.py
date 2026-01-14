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
        api_key: str,
        session: aiohttp.ClientSession | None = None,
    ) -> None:
        """Initialize the API client."""
        self._server_url = server_url.rstrip("/")
        self._api_key = api_key
        self._session = session
        self._user_id: str | None = None

    @property
    def _headers(self) -> dict[str, str]:
        """Get authentication headers."""
        return {
            "Authorization": f'MediaBrowser Client="Home Assistant", '
            f'Device="HACS Integration", '
            f'DeviceId="jellyha", '
            f'Version="1.0.0", '
            f'Token="{self._api_key}"',
            "Content-Type": "application/json",
        }

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    async def _request(
        self,
        method: str,
        endpoint: str,
        **kwargs: Any,
    ) -> Any:
        """Make an API request with retry logic."""
        url = urljoin(self._server_url + "/", endpoint.lstrip("/"))
        session = await self._get_session()

        for attempt in range(MAX_RETRIES):
            try:
                async with session.request(
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
                    return await response.json()

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
        limit: int = 20,
        item_types: list[str] | None = None,
        library_ids: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Get library items."""
        if item_types is None:
            item_types = [ITEM_TYPE_MOVIE, ITEM_TYPE_SERIES]

        params = {
            "SortBy": "DateCreated",
            "SortOrder": "Descending",
            "Limit": limit,
            "Recursive": "true",
            "IncludeItemTypes": ",".join(item_types),
            "Fields": "PrimaryImageAspectRatio,ProviderIds,Genres,RunTimeTicks,DateCreated,CommunityRating,Overview,MediaStreams",
        }

        if library_ids:
            params["ParentId"] = ",".join(library_ids)

        result = await self._request("GET", f"/Users/{user_id}/Items", params=params)
        return result.get("Items", [])

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
            f"?maxHeight={max_height}&quality={quality}"
        )

    def get_jellyfin_url(self, item_id: str) -> str:
        """Build deep link URL to open item in Jellyfin web UI."""
        return f"{self._server_url}/web/index.html#!/details?id={item_id}"

    async def close(self) -> None:
        """Close the session."""
        if self._session and not self._session.closed:
            await self._session.close()
