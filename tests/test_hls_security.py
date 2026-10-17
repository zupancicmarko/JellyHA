import sys
import os
import time
import unittest
from unittest.mock import MagicMock, AsyncMock

# Ensure repo root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import tests.ha_mock

from custom_components.jellyha.const import DOMAIN
from custom_components.jellyha.hls_manager import (
    HlsSessionManager,
    MAX_SESSION_LIFETIME_SECONDS,
)
from custom_components.jellyha.views import JellyHAHlsView


class TestHlsSecurity(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.hass = MagicMock()
        self.manager = HlsSessionManager(self.hass)
        self.hass.data = {DOMAIN: {"hls_manager": self.manager}}
        self.api = MagicMock()
        self.api.session = MagicMock()
        self.api._headers = {"X-Emby-Token": "secret"}
        self.hls_view = JellyHAHlsView(self.hass)

        self.session = self.manager.create_session(
            entry_id="01KMBE8QY54E8PPTNKYYD3FXGT",
            item_id="0123456789abcdef0123456789abcdef",
            play_session_id="play_session_123",
            media_source_id="0123456789abcdef0123456789abcdef",
            server_url="https://jellyfin.local",
            api_key="secret_key",
            api=self.api,
        )

    def test_session_hard_lifetime_cap(self):
        """Test that session expires after MAX_SESSION_LIFETIME_SECONDS even if touched."""
        now = time.time()
        # Session is initially not expired
        self.assertFalse(self.session.is_expired(now))

        # Simulated touch at 2 hours
        self.session.last_accessed = now + 7200
        self.assertFalse(self.session.is_expired(now + 7200))

        # At 4 hours + 1 second, it must be expired regardless of last_accessed
        future_ts = now + MAX_SESSION_LIFETIME_SECONDS + 1
        self.session.last_accessed = future_ts - 10  # touched 10 seconds ago
        self.assertTrue(self.session.is_expired(future_ts))

    async def test_hls_view_rejects_path_traversal(self):
        """Test that requests with .. in path return 400."""
        req = MagicMock()
        req.query = {}
        req.headers = {}
        resp = await self.hls_view.get(
            req, token=self.session.token, path="../secret.m3u8"
        )
        self.assertEqual(resp.status, 400)
        self.assertIn("Invalid path", resp.text)

    async def test_hls_view_rejects_unauthorized_extension(self):
        """Test that requests with unauthorized extensions return 400."""
        req = MagicMock()
        req.query = {}
        req.headers = {}
        resp = await self.hls_view.get(
            req, token=self.session.token, path="config.xml"
        )
        self.assertEqual(resp.status, 400)
        self.assertIn("Invalid HLS file type", resp.text)

    async def test_hls_view_rejects_cross_item_access(self):
        """Test that requests referencing a different item_id return 403."""
        req = MagicMock()
        req.query = {}
        req.headers = {}
        other_item_id = "fedcba9876543210fedcba9876543210"
        resp = await self.hls_view.get(
            req,
            token=self.session.token,
            path=f"Videos/{other_item_id}/stream.ts",
        )
        self.assertEqual(resp.status, 403)
        self.assertIn("Forbidden", resp.text)

    async def test_hls_view_sanitizes_500_errors(self):
        """Test that internal exceptions return generic 500 error."""
        self.api.session.get.side_effect = RuntimeError("sensitive internal backend failure")
        req = MagicMock()
        req.query = {}
        req.headers = {}
        resp = await self.hls_view.get(
            req, token=self.session.token, path="master.m3u8"
        )
        self.assertEqual(resp.status, 500)
        self.assertEqual(resp.text, "HLS proxy error")
        self.assertNotIn("sensitive internal", resp.text)


if __name__ == "__main__":
    unittest.main()
