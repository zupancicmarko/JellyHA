import sys
import os
import unittest
from unittest.mock import MagicMock, AsyncMock

# Ensure repo root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import tests.ha_mock

from custom_components.jellyha.const import DOMAIN
from custom_components.jellyha.hls_manager import HlsSessionManager
from custom_components.jellyha.websocket import (
    websocket_resolve_playback,
    websocket_stop_playback,
)


class TestWebsocketPlayback(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.hass = MagicMock()
        self.connection = MagicMock()
        self.connection.send_result = MagicMock()
        self.connection.send_error = MagicMock()

        self.manager = HlsSessionManager(self.hass)
        self.hass.data = {DOMAIN: {"hls_manager": self.manager}}

        # Mock coordinator and api
        self.mock_api = MagicMock()
        self.mock_api.server_url = "https://jellyfin.local"
        self.mock_api._api_key = "test_key"
        self.mock_api.get_item = AsyncMock(return_value={"Id": "item_123", "Type": "Movie", "Container": "avi"})
        self.mock_api.get_stream_path = MagicMock(return_value="/api/jellyha/stream/entry_1/Videos/item_123")

        self.mock_coordinator = MagicMock()
        self.mock_coordinator._api = self.mock_api
        self.mock_coordinator.entry = MagicMock()
        self.mock_coordinator.entry.entry_id = "entry_1"
        self.mock_coordinator.entry.data = {"user_id": "user_456"}

        self.mock_entry = MagicMock()
        self.mock_entry.domain = DOMAIN
        self.mock_entry.entry_id = "entry_1"
        self.mock_entry.runtime_data = MagicMock()
        self.mock_entry.runtime_data.library = self.mock_coordinator
        self.hass.config_entries.async_get_entry.return_value = self.mock_entry
        self.hass.config_entries.async_entries.return_value = [self.mock_entry]

    async def test_resolve_playback_direct_play(self):
        """Verify resolve_playback returns DirectPlay when Jellyfin indicates direct play."""
        self.mock_api.get_playback_info = AsyncMock(return_value={
            "MediaSources": [
                {
                    "Id": "ms_direct",
                    "SupportsDirectPlay": True,
                    "SupportsDirectStream": True,
                    "SupportsTranscoding": True,
                }
            ]
        })

        # Mock async_sign_path
        sys.modules["homeassistant.components.http.auth"].async_sign_path.return_value = "/api/jellyha/stream/entry_1/Videos/item_123?authSig=valid"

        msg = {
            "id": 1,
            "type": "jellyha/resolve_playback",
            "item_id": "item_123",
            "config_entry_id": "entry_1",
        }

        await websocket_resolve_playback(self.hass, self.connection, msg)

        self.connection.send_result.assert_called_once()
        args = self.connection.send_result.call_args[0]
        res = args[1]
        self.assertEqual(res["play_method"], "DirectPlay")
        self.assertIn("/api/jellyha/stream/", res["url"])
        self.assertEqual(res["mime_type"], "video/mp4")

    async def test_resolve_playback_transcode(self):
        """Verify resolve_playback creates HLS session when transcode is required."""
        self.mock_api.get_playback_info = AsyncMock(return_value={
            "MediaSources": [
                {
                    "Id": "ms_transcode",
                    "SupportsDirectPlay": False,
                    "SupportsDirectStream": False,
                    "SupportsTranscoding": True,
                }
            ]
        })

        msg = {
            "id": 2,
            "type": "jellyha/resolve_playback",
            "item_id": "item_123",
            "config_entry_id": "entry_1",
        }

        await websocket_resolve_playback(self.hass, self.connection, msg)

        self.connection.send_result.assert_called_once()
        args = self.connection.send_result.call_args[0]
        res = args[1]
        self.assertEqual(res["play_method"], "Transcode")
        self.assertIn("/api/jellyha/hls/", res["url"])
        self.assertIn("master.m3u8", res["url"])
        self.assertEqual(res["mime_type"], "application/x-mpegURL")
        self.assertIsNotNone(res["token"])
        self.assertIsNotNone(res["play_session_id"])

        # Check session was registered in HlsSessionManager
        session = self.manager.get_session(res["token"])
        self.assertIsNotNone(session)
        self.assertEqual(session.item_id, "item_123")

    async def test_stop_playback(self):
        """Verify stop_playback terminates active session."""
        session = self.manager.create_session(
            entry_id="entry_1",
            item_id="item_123",
            play_session_id="play_session_abc",
            media_source_id="ms_001",
            server_url="https://jellyfin.local",
            api_key="key",
            api=self.mock_api,
        )
        self.mock_api.stop_active_encoding = AsyncMock(return_value=True)
        self.mock_api.stop_playback_session = AsyncMock(return_value=True)

        msg = {
            "id": 3,
            "type": "jellyha/stop_playback",
            "token": session.token,
        }

        await websocket_stop_playback(self.hass, self.connection, msg)

        self.connection.send_result.assert_called_once_with(3, {"success": True})
        self.assertIsNone(self.manager.get_session(session.token))


if __name__ == "__main__":
    unittest.main()
