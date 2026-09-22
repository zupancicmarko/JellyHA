from __future__ import annotations

import asyncio
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
        
        prepared = False
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
                prepared = True
                
                # Increase chunk size to 64KB for better throughput
                async for chunk in resp.content.iter_chunked(65536):
                    await response.write(chunk)
                
                return response

        except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError):
            if prepared:
                return response
            raise
        except Exception as err:
            if prepared:
                _LOGGER.debug("Image request disconnected for %s: %s", item_id, err)
                return response
            return web.Response(status=500, text=str(err))


class JellyHAStreamView(HomeAssistantView):
    """View to proxy Jellyfin media streams without exposing the API key."""

    url = "/api/jellyha/stream/{entry_id}/{item_id}"
    extra_urls = [
        "/api/jellyha/stream/{entry_id}/{item_id}/{filename}",
        "/api/jellyha/stream/{entry_id}/{media_type}/{item_id}/{filename}",
    ]
    name = "api:jellyha:stream"
    requires_auth = False

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize."""
        self.hass = hass

    async def head(
        self,
        request: web.Request,
        entry_id: str,
        item_id: str,
        media_type: str | None = None,
        filename: str | None = None,
    ) -> web.Response:
        """Handle HEAD stream request to inspect stream headers without streaming body."""
        return await self._handle_stream(request, entry_id, item_id, media_type, filename, is_head=True)

    async def get(
        self,
        request: web.Request,
        entry_id: str,
        item_id: str,
        media_type: str | None = None,
        filename: str | None = None,
    ) -> web.Response:
        """Handle GET stream request."""
        return await self._handle_stream(request, entry_id, item_id, media_type, filename, is_head=False)

    @staticmethod
    def _guess_audio_mime(filename: str | None) -> str:
        """Guess audio mime type from filename extension."""
        if filename:
            lower = filename.lower()
            if lower.endswith(".flac"):
                return "audio/flac"
            if lower.endswith(".mp3"):
                return "audio/mpeg"
            if lower.endswith((".m4a", ".aac")):
                return "audio/mp4"
            if lower.endswith((".ogg", ".oga")):
                return "audio/ogg"
            if lower.endswith(".wav"):
                return "audio/wav"
        return "audio/mpeg"

    async def _handle_stream(
        self,
        request: web.Request,
        entry_id: str,
        item_id: str,
        media_type: str | None = None,
        filename: str | None = None,
        is_head: bool = False,
    ) -> web.Response:
        """Handle stream request for both GET and HEAD."""
        is_authenticated = request.get("hass_user") is not None
        has_valid_signature = request.get("hass_refresh_token_id") is not None
        has_auth_sig = bool(request.query.get("authSig"))

        if not is_authenticated and not has_valid_signature and not has_auth_sig:
            _LOGGER.warning("Unauthorized stream request for item %s", item_id)
            return web.Response(status=401, text="Unauthorized")

        # Handle 3-segment route if item_id was matched as media_type
        # e.g. /api/jellyha/stream/{entry_id}/{media_type}/{item_id}
        if item_id in ("Audio", "Videos"):
            media_type = item_id
            item_id = filename or ""
            filename = None

        if not item_id:
            return web.Response(status=400, text="Missing item_id")

        # media_type can be in path or query parameters (fallback)
        if not media_type:
            media_type = request.query.get("media_type", "Videos")
        if media_type not in ("Audio", "Videos"):
            return web.Response(status=400, text="Invalid media_type")

        # Retrieve config entry
        entry = self.hass.config_entries.async_get_entry(entry_id)
        if not entry:
            for e in self.hass.config_entries.async_entries(DOMAIN):
                if e.entry_id.lower() == entry_id.lower():
                    entry = e
                    break

        if not entry:
            return web.Response(status=404, text=f"Instance not found for ID: {entry_id}")

        try:
            client = entry.runtime_data.library._api
        except AttributeError:
            return web.Response(status=404, text="Integration not loaded")

        if not client:
            return web.Response(status=404, text="API not available")

        url = f"{client.server_url}/{media_type}/{item_id}/stream?static=true"

        session = client.session
        req_headers = dict(client._headers)
        if "Range" in request.headers:
            req_headers["Range"] = request.headers["Range"]

        _LOGGER.info(
            "JellyHA stream %s: item=%s, media_type=%s, filename=%s, Range=%s, authSig=%s",
            "HEAD" if is_head else "GET",
            item_id,
            media_type,
            filename,
            request.headers.get("Range"),
            bool(has_auth_sig),
        )

        if is_head:
            try:
                async with session.head(
                    url,
                    headers=req_headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status not in (200, 206):
                        return web.Response(status=resp.status, text=resp.reason)

                    headers: dict[str, str] = {
                        "Access-Control-Allow-Origin": "*",
                        "Accept-Ranges": "bytes",
                    }
                    content_type = resp.headers.get("Content-Type")
                    if not content_type or content_type == "application/octet-stream":
                        if media_type == "Audio":
                            content_type = self._guess_audio_mime(filename)
                        else:
                            content_type = "video/mp4"
                    headers["Content-Type"] = content_type

                    for header_key in ("Content-Length", "Content-Range", "Last-Modified", "ETag"):
                        if header_key in resp.headers:
                            headers[header_key] = resp.headers[header_key]

                    if filename:
                        import urllib.parse
                        display_filename = urllib.parse.unquote(filename).replace('"', '')
                        headers["Content-Disposition"] = f'inline; filename="{display_filename}"'

                    return web.Response(status=resp.status, headers=headers)
            except Exception as err:
                _LOGGER.error("Stream HEAD error for %s: %s", item_id, err)
                return web.Response(status=500, text=str(err))

        prepared = False
        try:
            async with session.get(
                url,
                headers=req_headers,
                timeout=aiohttp.ClientTimeout(total=None),
            ) as resp:
                if resp.status not in (200, 206):
                    return web.Response(status=resp.status, text=resp.reason)

                response = web.StreamResponse(status=resp.status, reason=resp.reason)
                content_type = resp.headers.get("Content-Type")
                if not content_type or content_type == "application/octet-stream":
                    if media_type == "Audio":
                        content_type = self._guess_audio_mime(filename)
                    else:
                        content_type = "video/mp4"
                response.headers["Content-Type"] = content_type
                response.headers["Access-Control-Allow-Origin"] = "*"
                response.headers["Accept-Ranges"] = "bytes"
                for header_key in ("Content-Length", "Content-Range", "Last-Modified", "ETag"):
                    if header_key in resp.headers:
                        response.headers[header_key] = resp.headers[header_key]
                if filename:
                    import urllib.parse
                    display_filename = urllib.parse.unquote(filename).replace('"', '')
                    response.headers["Content-Disposition"] = f'inline; filename="{display_filename}"'

                await response.prepare(request)
                prepared = True

                async for chunk in resp.content.iter_chunked(65536):
                    await response.write(chunk)

                return response

        except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError):
            if prepared:
                return response
            raise
        except Exception as err:
            if prepared:
                _LOGGER.debug("Stream playback disconnected for %s: %s", item_id, err)
                return response
            _LOGGER.error("Stream proxy error for %s: %s", item_id, err)
            return web.Response(status=500, text=str(err))


class JellyHASubtitleView(HomeAssistantView):
    """View to proxy Jellyfin WebVTT subtitles without exposing the API key."""

    url = "/api/jellyha/subtitles/{entry_id}/{item_id}/{stream_index}"
    extra_urls = [
        "/api/jellyha/subtitles/{entry_id}/{item_id}/{stream_index}/{filename}",
    ]
    name = "api:jellyha:subtitles"
    requires_auth = False

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize."""
        self.hass = hass

    async def get(
        self,
        request: web.Request,
        entry_id: str,
        item_id: str,
        stream_index: str,
        filename: str | None = None,
    ) -> web.Response:
        """Handle subtitle request."""
        is_authenticated = request.get("hass_user") is not None
        has_valid_signature = request.get("hass_refresh_token_id") is not None
        has_auth_sig = bool(request.query.get("authSig"))

        # Allow requests initiated from within the Home Assistant frontend (e.g. browser video tracks)
        referer = request.headers.get("Referer", "")
        is_ha_referer = bool(referer and ("/lovelace" in referer or "/dashboard" in referer or "/api" in referer or ":8123" in referer))

        if not is_authenticated and not has_valid_signature and not has_auth_sig and not is_ha_referer:
            _LOGGER.warning(
                "Unauthorized subtitle request for item %s, stream %s (referer: %s)",
                item_id, stream_index, referer
            )
            return web.Response(status=401, text="Unauthorized")

        entry = self.hass.config_entries.async_get_entry(entry_id)
        if not entry:
            for e in self.hass.config_entries.async_entries(DOMAIN):
                if e.entry_id.lower() == entry_id.lower():
                    entry = e
                    break

        if not entry:
            return web.Response(status=404, text=f"Instance not found for ID: {entry_id}")

        try:
            client = entry.runtime_data.library._api
        except AttributeError:
            return web.Response(status=404, text="Integration not loaded")

        if not client:
            return web.Response(status=404, text="API not available")

        # In Jellyfin, the primary WebVTT path is /Videos/{itemId}/{mediaSourceId}/Subtitles/{index}/Stream.vtt
        media_source_id = request.query.get("media_source_id") or item_id
        url = f"{client.server_url}/Videos/{item_id}/{media_source_id}/Subtitles/{stream_index}/Stream.vtt"

        _LOGGER.debug(
            "Fetching subtitle from Jellyfin for item=%s, ms_id=%s, stream=%s: %s",
            item_id, media_source_id, stream_index, url
        )

        req_headers = {"Accept": "text/vtt, text/plain, */*"}
        if client._api_key:
            req_headers["X-Emby-Token"] = client._api_key

        try:
            session = client.session
            async with session.get(
                url,
                headers=req_headers,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                # If 404, fallback to 3-part URL without media_source_id
                if resp.status == 404:
                    fallback_url = f"{client.server_url}/Videos/{item_id}/Subtitles/{stream_index}/Stream.vtt"
                    _LOGGER.debug("Subtitle 404, retrying with fallback URL: %s", fallback_url)
                    async with session.get(
                        fallback_url,
                        headers=req_headers,
                        timeout=aiohttp.ClientTimeout(total=10),
                    ) as fb_resp:
                        if fb_resp.status != 200:
                            _LOGGER.warning("Subtitle fallback fetch failed with status %s: %s", fb_resp.status, fallback_url)
                            return web.Response(status=fb_resp.status, text=fb_resp.reason)
                        body = await fb_resp.read()
                        return web.Response(
                            body=body,
                            content_type="text/vtt",
                            charset="utf-8",
                            headers={
                                "Access-Control-Allow-Origin": "*",
                                "Cache-Control": "public, max-age=86400",
                            },
                        )

                if resp.status != 200:
                    _LOGGER.warning("Subtitle fetch from Jellyfin failed with status %s: %s", resp.status, url)
                    return web.Response(status=resp.status, text=resp.reason)

                body = await resp.read()
                return web.Response(
                    body=body,
                    content_type="text/vtt",
                    charset="utf-8",
                    headers={
                        "Access-Control-Allow-Origin": "*",
                        "Cache-Control": "public, max-age=86400",
                    },
                )
        except Exception as err:
            _LOGGER.exception("Subtitle proxy error for item %s, stream %s", item_id, stream_index)
            return web.Response(status=500, text=str(err))

