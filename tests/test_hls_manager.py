import sys
import os
import time
import unittest
from unittest.mock import MagicMock, AsyncMock

# Ensure repo root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import tests.ha_mock

from custom_components.jellyha.hls_manager import HlsSessionManager, HlsSession, SESSION_TTL_SECONDS


class TestHlsSessionManager(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.hass = MagicMock()
        self.api = MagicMock()
        self.api.stop_active_encoding = AsyncMock(return_value=True)
        self.api.stop_playback_session = AsyncMock(return_value=True)
        self.manager = HlsSessionManager(self.hass)

    async def test_create_and_get_session(self):
        """Verify creating a session returns a valid token and can be retrieved."""
        session = self.manager.create_session(
            entry_id="entry_123",
            item_id="item_456",
            play_session_id="play_789",
            media_source_id="ms_001",
            server_url="https://jellyfin.local",
            api_key="secret_key",
            api=self.api,
        )

        self.assertIsNotNone(session.token)
        self.assertEqual(len(session.token), 32)  # urlsafe 24 bytes produces 32 chars
        self.assertEqual(session.item_id, "item_456")

        retrieved = self.manager.get_session(session.token)
        self.assertIs(retrieved, session)

    async def test_get_session_touch_updates_timestamp(self):
        """Verify get_session touches the session's last_accessed time."""
        session = self.manager.create_session(
            entry_id="entry_123",
            item_id="item_456",
            play_session_id="play_789",
            media_source_id="ms_001",
            server_url="https://jellyfin.local",
            api_key="secret_key",
            api=self.api,
        )
        old_access = session.last_accessed - 10
        session.last_accessed = old_access

        retrieved = self.manager.get_session(session.token)
        self.assertGreater(retrieved.last_accessed, old_access)

    async def test_get_session_expired_returns_none(self):
        """Verify that an expired session is rejected."""
        session = self.manager.create_session(
            entry_id="entry_123",
            item_id="item_456",
            play_session_id="play_789",
            media_source_id="ms_001",
            server_url="https://jellyfin.local",
            api_key="secret_key",
            api=self.api,
        )
        # Force expiration
        session.last_accessed = time.time() - (SESSION_TTL_SECONDS + 10)

        retrieved = self.manager.get_session(session.token)
        self.assertIsNone(retrieved)

    async def test_terminate_session_calls_api_stop(self):
        """Verify terminating a session calls stop_active_encoding and removes it."""
        session = self.manager.create_session(
            entry_id="entry_123",
            item_id="item_456",
            play_session_id="play_789",
            media_source_id="ms_001",
            server_url="https://jellyfin.local",
            api_key="secret_key",
            api=self.api,
        )

        result = await self.manager.terminate_session(session.token)
        self.assertTrue(result)
        self.assertIsNone(self.manager.get_session(session.token))

        self.api.stop_active_encoding.assert_called_once_with("play_789")
        self.api.stop_playback_session.assert_called_once_with("play_789", "item_456")

    async def test_terminate_session_by_play_session_id(self):
        """Verify terminating a session by play_session_id works."""
        session = self.manager.create_session(
            entry_id="entry_123",
            item_id="item_456",
            play_session_id="play_789",
            media_source_id="ms_001",
            server_url="https://jellyfin.local",
            api_key="secret_key",
            api=self.api,
        )

        result = await self.manager.terminate_session("play_789")
        self.assertTrue(result)
        self.assertIsNone(self.manager.get_session(session.token))


if __name__ == "__main__":
    unittest.main()
