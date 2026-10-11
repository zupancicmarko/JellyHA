"""HLS Session Manager for JellyHA."""
from __future__ import annotations

import asyncio
import logging
import secrets
import time
from dataclasses import dataclass
from typing import Any

from homeassistant.core import HomeAssistant

_LOGGER = logging.getLogger(__name__)

SESSION_TTL_SECONDS = 900  # 15 minutes of inactivity before reap


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

    def is_expired(self, now: float | None = None) -> bool:
        """Check if the session has timed out from inactivity."""
        ts = now or time.time()
        return (ts - self.last_accessed) > SESSION_TTL_SECONDS

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
    ) -> HlsSession:
        """Create a new HLS playback capability session."""
        now = time.time()
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

    async def terminate_session(self, token_or_play_session_id: str) -> bool:
        """Terminate an active HLS session and kill active ffmpeg transcode on Jellyfin."""
        session: HlsSession | None = self._sessions.pop(token_or_play_session_id, None)
        if not session:
            for t, s in list(self._sessions.items()):
                if s.play_session_id == token_or_play_session_id:
                    session = self._sessions.pop(t, None)
                    break
        if not session:
            return False

        _LOGGER.info(
            "Terminating HLS session for item %s (play_session: %s)",
            session.item_id,
            session.play_session_id,
        )
        if session.api:
            try:
                await session.api.stop_active_encoding(session.play_session_id)
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
            await asyncio.sleep(60)
            now = time.time()
            expired = [t for t, s in list(self._sessions.items()) if s.is_expired(now)]
            for token in expired:
                await self.terminate_session(token)
