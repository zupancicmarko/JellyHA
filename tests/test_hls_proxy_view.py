import sys
import os
import unittest
from unittest.mock import MagicMock, AsyncMock

# Ensure repo root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import tests.ha_mock

from custom_components.jellyha.const import DOMAIN
from custom_components.jellyha.views import JellyHAHlsView
from custom_components.jellyha.hls_manager import HlsSessionManager


class TestHlsProxyView(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.hass = MagicMock()
        self.manager = HlsSessionManager(self.hass)
        self.hass.data = {DOMAIN: {"hls_manager": self.manager}}
        self.api = MagicMock()
        self.api.session = MagicMock()
        self.api._headers = {"X-Emby-Token": "secret"}
        self.hls_view = JellyHAHlsView(self.hass)

    async def test_unknown_token_returns_404(self):
        """Verify request with unknown token returns 404."""
        request = MagicMock()
        request.query = {}
        request.headers = {}

        response = await self.hls_view.get(request, token="invalid_token_123", path="master.m3u8")
        self.assertEqual(response.status, 404)

    async def test_playlist_rewriting_strips_api_keys(self):
        """Verify playlist rewriting strips api_key and ApiKey query parameters."""
        session = self.manager.create_session(
            entry_id="entry_123",
            item_id="item_456",
            play_session_id="play_789",
            media_source_id="ms_001",
            server_url="https://jellyfin.local",
            api_key="secret_key",
            api=self.api,
        )

        mock_jellyfin_playlist = (
            "#EXTM3U\n"
            "#EXT-X-VERSION:3\n"
            "#EXT-X-STREAM-INF:BANDWIDTH=3000000\n"
            "main.m3u8?MediaSourceId=ms_001&PlaySessionId=play_789&api_key=secret_key\n"
            "#EXT-X-STREAM-INF:BANDWIDTH=1500000\n"
            "main_low.m3u8?MediaSourceId=ms_001&ApiKey=secret_key&other=param\n"
        )

        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.text = AsyncMock(return_value=mock_jellyfin_playlist)

        # Context manager for session.get
        self.api.session.get.return_value.__aenter__.return_value = mock_resp

        request = MagicMock()
        request.query = {}
        request.headers = {}

        response = await self.hls_view.get(request, token=session.token, path="master.m3u8")

        self.assertEqual(response.status, 200)
        self.assertIn("application/vnd.apple.mpegurl", response.content_type)
        body = response.text

        # Ensure api_key and ApiKey are nowhere in the output body
        self.assertNotIn("secret_key", body)
        self.assertNotIn("api_key=", body)
        self.assertNotIn("ApiKey=", body)

        # Verify other query parameters remain intact
        self.assertIn("main.m3u8?MediaSourceId=ms_001&PlaySessionId=play_789", body)
        self.assertIn("other=param", body)


if __name__ == "__main__":
    unittest.main()
