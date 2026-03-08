from __future__ import annotations

import logging
import aiohttp
from aiohttp import web
from homeassistant.components.http import HomeAssistantView
from homeassistant.core import HomeAssistant
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

class JellyHAImageView(HomeAssistantView):
    """View to proxy Jellyfin images."""

    url = "/api/jellyha/image/{entry_id}/{item_id}/{image_type}"
    name = "api:jellyha:image"
    requires_auth = False 

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize."""
        self.hass = hass

    async def get(
        self, request: web.Request, entry_id: str, item_id: str, image_type: str
    ) -> web.Response:
        """Handle image request."""
        # Retrieve config entry (case-insensitive fallback for ULIDs modified by routers)
        entry = self.hass.config_entries.async_get_entry(entry_id)
        if not entry:
            for e in self.hass.config_entries.async_entries(DOMAIN):
                if e.entry_id.lower() == entry_id.lower():
                    entry = e
                    break
                    
        if not entry:
             return web.Response(status=404, text=f"Instance not found for ID: {entry_id}")
        
        # Access runtime_data safely
        try:
            client = entry.runtime_data.library._api
        except AttributeError:
             return web.Response(status=404, text="Integration not loaded")

        if not client:
             return web.Response(status=404, text="API not available")

        # Check authentication:
        # 1. Standard HA user session (logged in via UI)
        # 2. Valid signed path (HA sets hass_refresh_token_id when authSig is valid)
        # If neither, reject the request.
        is_authenticated = request.get("hass_user") is not None
        has_valid_signature = request.get("hass_refresh_token_id") is not None
        
        _LOGGER.debug(
            "Image request: entry=%s, item=%s, type=%s, user=%s, refresh_token=%s, query=%s",
            entry_id, item_id, image_type,
            request.get("hass_user"),
            request.get("hass_refresh_token_id"),
            dict(request.query)
        )
        
        if not is_authenticated and not has_valid_signature:
            _LOGGER.warning("Unauthorized image request - no user session or valid signature")
            return web.Response(status=401, text="Unauthorized")


        width = request.query.get("width")
        height = request.query.get("height")
        # Default to WebP if format not specified (Standard 2026 practice)
        # WebP is supported by all relevant HA clients (Mobile, Chrome, Safari)
        format_type = request.query.get("format", "webp")
        
        # Default quality to 80 to save bandwidth
        quality = request.query.get("quality", "80")
        
        tag = request.query.get("tag")

        params = {}
        if width: params["width"] = width
        if height: params["height"] = height
        if quality: params["quality"] = quality
        if tag: params["tag"] = tag
        
        # Force the requested format
        params["format"] = format_type

        # Fix: Ensure we correctly map 'Primary' to actual endpoint logic if needed
        # But for now, passing to Jellyfin as-is.
        
        url = f"{client.server_url}/Items/{item_id}/Images/{image_type}"
        
        try:
            session = client.session
            async with session.get(
                url, 
                headers=client._headers, 
                params=params, 
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status != 200:
                    return web.Response(status=resp.status, text=resp.reason)
                
                response = web.StreamResponse(status=200, reason='OK')
                
                # Correct Content-Type based on format
                content_type = resp.headers.get("Content-Type", "image/jpeg")
                    
                response.headers["Content-Type"] = content_type
                if "Cache-Control" in resp.headers:
                    response.headers["Cache-Control"] = resp.headers["Cache-Control"]
                if "ETag" in resp.headers:
                    response.headers["ETag"] = resp.headers["ETag"]
                
                # If a tag is provided, we can cache aggressively (1 year)
                if tag:
                    response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
                
                await response.prepare(request)
                
                # Increase chunk size to 64KB for better throughput
                async for chunk in resp.content.iter_chunked(65536):
                    await response.write(chunk)
                
                return response

        except Exception as err:
            return web.Response(status=500, text=str(err))
