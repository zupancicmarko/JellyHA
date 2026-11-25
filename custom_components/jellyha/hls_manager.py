"""HLS Session Manager for JellyHA."""
from __future__ import annotations

import asyncio
import logging
import re
import secrets
import time
import uuid
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urlparse

from homeassistant.core import HomeAssistant

from .api import CHROMECAST_LIVE_TV_PROFILE
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

SESSION_TTL_SECONDS = 900  # 15 minutes of inactivity before reap
LIVE_TV_SESSION_TTL_SECONDS = 90  # 90 seconds of inactivity before releasing Live TV tuner
MAX_SESSION_LIFETIME_SECONDS = 14400  # 4 hours hard maximum lifetime cap
MAX_ACTIVE_SESSIONS = 64  # Hard cap on concurrent in-memory HLS capability sessions

_SENSITIVE_QUERY_KEYS = frozenset({"api_key", "apikey", "token"})


def is_live_tv_item(item_info: dict[str, Any] | None) -> bool:
    """Return True if a Jellyfin item represents a Live TV channel / infinite live stream."""
    if not item_info or not isinstance(item_info, dict):
        return False
    item_type = str(item_info.get("Type") or "")
    if item_type in ("TvChannel", "LiveTvChannel"):
        return True
    media_sources = item_info.get("MediaSources") or []
    if media_sources and isinstance(media_sources[0], dict):
        ms = media_sources[0]
        if ms.get("IsInfiniteStream") is True or ms.get("RequiresOpening") is True:
            return True
    return False


def _extract_playlist_path(transcoding_url: str, item_id: str) -> str:
    """Extract HLS playlist path relative to JellyHAHlsView from Jellyfin's TranscodingUrl."""
    if not transcoding_url:
        return "master.m3u8"
    parsed_path = urlparse(transcoding_url).path.lstrip("/")
    if not parsed_path:
        return "master.m3u8"

    parts = parsed_path.split("/")
    normalized_item_id = item_id.replace("-", "").lower()
    if len(parts) >= 3 and parts[0].lower() == "videos":
        if parts[1].replace("-", "").lower() == normalized_item_id:
            rel = "/".join(parts[2:])
            return rel if rel.lower().endswith(".m3u8") else "master.m3u8"
        normalized = "Videos/" + "/".join(parts[1:])
        return normalized if normalized.lower().endswith(".m3u8") else "master.m3u8"
    if parsed_path.lower().endswith(".m3u8"):
        return parsed_path
    return "master.m3u8"


def _sanitize_alias_name(display_name: str | None) -> str | None:
    """Sanitize a friendly channel/title name for safe use as a single URL path segment."""
    if not display_name or not isinstance(display_name, str):
        return None
    safe = re.sub(r'[/\\?%*:|"<>#]', "_", display_name).strip(" ._")
    if not safe or ".." in safe:
        return None
    return safe


async def open_live_tv_hls_session(
    hass: HomeAssistant,
    entry_id: str,
    user_id: str,
    item_id: str,
    api: Any,
    *,
    profile: dict[str, Any] | None = None,
    device_id: str = "jellyha",
    max_streaming_bitrate: int = 40000000,
    direct_live_playlist: bool = False,
    display_name: str | None = None,
) -> dict[str, Any]:
    """Open a Jellyfin Live TV stream and register a proxied HLS session.

    Follows the Jellyfin Cast receiver flow:
    1. POST /Items/{item_id}/PlaybackInfo with AutoOpenLiveStream=true.
    2. If MediaSource still has RequiresOpening=true without LiveStreamId, call POST /LiveStreams/Open.
    3. Register an HlsSession (with LiveStreamId + short inactivity TTL) and return the proxy HLS URL.
    """
    effective_profile = profile or CHROMECAST_LIVE_TV_PROFILE
    playback_info = await api.get_playback_info(
        user_id,
        item_id,
        profile=effective_profile,
        auto_open_live_stream=True,
        max_streaming_bitrate=max_streaming_bitrate,
    )

    play_session_id = playback_info.get("PlaySessionId") or uuid.uuid4().hex
    media_sources = playback_info.get("MediaSources") or []
    media_source: dict[str, Any] = media_sources[0] if media_sources else {}

    if (
        media_source.get("RequiresOpening")
        and not media_source.get("LiveStreamId")
        and media_source.get("OpenToken")
    ):
        open_res = await api.open_live_stream(
            user_id=user_id,
            item_id=item_id,
            open_token=media_source["OpenToken"],
            play_session_id=play_session_id,
            profile=effective_profile,
            max_streaming_bitrate=max_streaming_bitrate,
        )
        if isinstance(open_res, dict) and open_res.get("MediaSource"):
            media_source = open_res["MediaSource"]

    live_stream_id = media_source.get("LiveStreamId")
    media_source_id = media_source.get("Id") or item_id
    transcoding_url = media_source.get("TranscodingUrl") or ""

    playlist_path = _extract_playlist_path(transcoding_url, item_id)
    if direct_live_playlist and playlist_path.lower().endswith("master.m3u8"):
        playlist_path = playlist_path[:-len("master.m3u8")] + "live.m3u8"

    query_params: dict[str, str] = {}
    if transcoding_url:
        for k, v in parse_qsl(urlparse(transcoding_url).query):
            if k.lower() in _SENSITIVE_QUERY_KEYS:
                continue
            if direct_live_playlist and k.lower() == "starttimeticks":
                continue
            query_params[k] = v

    if not query_params:
        query_params = {
            "DeviceId": device_id,
            "MediaSourceId": str(media_source_id),
            "VideoCodec": "h264",
            "AudioCodec": "aac",
            "AudioBitrate": "256000",
            "VideoBitrate": str(max_streaming_bitrate),
            "MaxStreamingBitrate": str(max_streaming_bitrate),
            "TranscodingMaxAudioChannels": "2",
            "SegmentContainer": "ts",
            "MinSegments": "1",
            "BreakOnNonKeyFrames": "False",
        }

    query_params["PlaySessionId"] = play_session_id
    if live_stream_id:
        query_params["LiveStreamId"] = str(live_stream_id)
    if not query_params.get("DeviceId"):
        query_params["DeviceId"] = device_id
    if not query_params.get("MediaSourceId"):
        query_params["MediaSourceId"] = str(media_source_id)

    effective_device_id = query_params.get("DeviceId") or device_id

    manager = hass.data.get(DOMAIN, {}).get("hls_manager")
    if not manager:
        hass.data.setdefault(DOMAIN, {})
        manager = HlsSessionManager(hass)
        hass.data[DOMAIN]["hls_manager"] = manager

    alias_path = _sanitize_alias_name(display_name)

    session = manager.create_session(
        entry_id=entry_id,
        item_id=item_id,
        play_session_id=play_session_id,
        media_source_id=str(media_source_id),
        server_url=api.server_url,
        api_key=api.api_key,
        api=api,
        device_id=effective_device_id,
        live_stream_id=live_stream_id,
        ttl_seconds=LIVE_TV_SESSION_TTL_SECONDS,
        alias_path=alias_path,
        upstream_playlist=playlist_path,
        initial_params=dict(query_params),
    )

    if alias_path:
        # Clean URL without query string so HA Media Browser / Cast Default Media Receiver
        # displays the friendly channel name instead of "master.m3u8?DeviceId=..."
        hls_path = f"/api/jellyha/hls/{session.token}/{quote(alias_path, safe='')}"
    else:
        hls_path = f"/api/jellyha/hls/{session.token}/{playlist_path}?{urlencode(query_params)}"
    return {
        "url": hls_path,
        "mime_type": "application/x-mpegURL",
        "play_session_id": play_session_id,
        "live_stream_id": live_stream_id,
        "token": session.token,
    }


@dataclass
class HlsSession:
    """Represents an active HLS transcode capability session."""

    token: str
    entry_id: str
    item_id: str
    play_session_id: str
    media_source_id: str
    server_url: str
    api_key: str
    created_at: float
    last_accessed: float
    api: Any
    device_id: str = "jellyha-browser"
    max_expires_at: float = 0.0
    live_stream_id: str | None = None
    ttl_seconds: int = SESSION_TTL_SECONDS
    stream_started: bool = False
    alias_path: str | None = None
    upstream_playlist: str | None = None
    initial_params: dict[str, str] = field(default_factory=dict)

    def is_expired(self, now: float | None = None) -> bool:
        """Check if the session has timed out from inactivity or exceeded max lifetime."""
        ts = now or time.time()
        max_exp = self.max_expires_at or (self.created_at + MAX_SESSION_LIFETIME_SECONDS)
        return ts > max_exp or (ts - self.last_accessed) > self.ttl_seconds

    def touch(self) -> None:
        """Update last accessed timestamp to extend the active TTL."""
        self.last_accessed = time.time()


class HlsSessionManager:
    """Manages active capability tokens for HLS playback."""

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize session manager."""
        self.hass = hass
        self._sessions: dict[str, HlsSession] = {}
        self._cleanup_task: asyncio.Task | None = None

    def create_session(
        self,
        entry_id: str,
        item_id: str,
        play_session_id: str,
        media_source_id: str,
        server_url: str,
        api_key: str,
        api: Any,
        device_id: str = "jellyha-browser",
        live_stream_id: str | None = None,
        ttl_seconds: int | None = None,
        alias_path: str | None = None,
        upstream_playlist: str | None = None,
        initial_params: dict[str, str] | None = None,
    ) -> HlsSession:
        """Create a new HLS playback capability session."""
        now = time.time()

        # Reap expired sessions first, then enforce MAX_ACTIVE_SESSIONS via LRU eviction
        for exp_token in [t for t, s in list(self._sessions.items()) if s.is_expired(now)]:
            self._sessions.pop(exp_token, None)

        while len(self._sessions) >= MAX_ACTIVE_SESSIONS:
            oldest_token = min(self._sessions, key=lambda t: self._sessions[t].last_accessed)
            if hasattr(self.hass, "async_create_task"):
                coro = self.terminate_session(oldest_token)
                res = self.hass.async_create_task(coro)
                if not isinstance(res, asyncio.Task):
                    coro.close()
                    self._sessions.pop(oldest_token, None)
            else:
                self._sessions.pop(oldest_token, None)

        token = secrets.token_urlsafe(24)
        session = HlsSession(
            token=token,
            entry_id=entry_id,
            item_id=item_id,
            play_session_id=play_session_id,
            media_source_id=media_source_id,
            server_url=server_url,
            api_key=api_key,
            created_at=now,
            last_accessed=now,
            api=api,
            device_id=device_id,
            max_expires_at=now + MAX_SESSION_LIFETIME_SECONDS,
            live_stream_id=live_stream_id,
            ttl_seconds=ttl_seconds if ttl_seconds is not None else SESSION_TTL_SECONDS,
            alias_path=alias_path,
            upstream_playlist=upstream_playlist,
            initial_params=dict(initial_params) if initial_params else {},
        )
        self._sessions[token] = session
        self._ensure_cleanup_task()
        return session

    def get_session(self, token: str) -> HlsSession | None:
        """Retrieve and refresh an active HLS session by capability token."""
        session = self._sessions.get(token)
        if not session:
            return None
        if session.is_expired():
            # Trigger background cleanup for expired session
            if hasattr(self.hass, "async_create_task"):
                coro = self.terminate_session(token)
                res = self.hass.async_create_task(coro)
                if not isinstance(res, asyncio.Task):
                    coro.close()
            return None
        session.touch()
        return session

    async def terminate_session(
        self, token_or_play_session_id: str, *, explicit_stop: bool = False
    ) -> bool:
        """Terminate an active HLS session and kill active ffmpeg transcode on Jellyfin.

        For Live TV sessions:
        - Jellyfin shares a single LiveStreamId (with a consumer count) across concurrent
          viewers of the same channel, and its built-in ~60s Transcoding kill timer
          automatically decrements the consumer count when HLS requests stop.
        - On explicit stop (e.g. browser player closed before Jellyfin's kill timer),
          pass live_stream_id ONCE to stop_playback_session (never double-closing via
          LiveStreams/Close).
        - On inactivity timeout reap: only pass live_stream_id if FFmpeg never started
          (stream_started is False) and no other active session shares that live_stream_id.
        """
        session: HlsSession | None = self._sessions.pop(token_or_play_session_id, None)
        if not session:
            for t, s in list(self._sessions.items()):
                if s.play_session_id == token_or_play_session_id:
                    session = self._sessions.pop(t, None)
                    break
        if not session:
            return False

        _LOGGER.info(
            "Terminating HLS session for item %s (play_session: %s, live_stream: %s, explicit: %s, started: %s)",
            session.item_id,
            session.play_session_id,
            session.live_stream_id,
            explicit_stop,
            session.stream_started,
        )
        if session.api:
            try:
                try:
                    await session.api.stop_active_encoding(
                        session.play_session_id, device_id=getattr(session, "device_id", "jellyha-browser")
                    )
                except TypeError:
                    await session.api.stop_active_encoding(session.play_session_id)

                should_report_live_stop = False
                if session.live_stream_id:
                    if explicit_stop:
                        should_report_live_stop = True
                    elif not session.stream_started:
                        shared_active = any(
                            s.live_stream_id == session.live_stream_id
                            for s in self._sessions.values()
                        )
                        should_report_live_stop = not shared_active

                if should_report_live_stop and session.live_stream_id:
                    try:
                        await session.api.stop_playback_session(
                            session.play_session_id,
                            session.item_id,
                            live_stream_id=session.live_stream_id,
                        )
                    except TypeError:
                        await session.api.stop_playback_session(session.play_session_id, session.item_id)
                else:
                    await session.api.stop_playback_session(session.play_session_id, session.item_id)
            except Exception as err:
                _LOGGER.debug("Error during HLS transcode cleanup: %s", err)
        return True

    def _ensure_cleanup_task(self) -> None:
        """Ensure periodic cleanup background task is active."""
        if hasattr(self.hass, "async_create_background_task"):
            if self._cleanup_task is None or self._cleanup_task.done():
                coro = self._periodic_cleanup()
                res = self.hass.async_create_background_task(coro, "jellyha_hls_cleanup")
                if isinstance(res, asyncio.Task):
                    self._cleanup_task = res
                else:
                    coro.close()

    async def _periodic_cleanup(self) -> None:
        """Periodically reap expired inactive HLS sessions."""
        while self._sessions:
            await asyncio.sleep(30)
            now = time.time()
            expired = [t for t, s in list(self._sessions.items()) if s.is_expired(now)]
            for token in expired:
                await self.terminate_session(token)
