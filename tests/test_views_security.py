import sys
import os
import unittest
from unittest.mock import MagicMock, AsyncMock

# Ensure repo root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import tests.ha_mock

from custom_components.jellyha.const import DOMAIN
from custom_components.jellyha.views import (
    JellyHAImageView,
    JellyHAStreamView,
    JellyHASubtitleView,
)


class TestViewsSecurity(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.hass = MagicMock()
        self.mock_entry = MagicMock()
        self.mock_entry.entry_id = "01KMBE8QY54E8PPTNKYYD3FXGT"
        self.mock_client = MagicMock()
        self.mock_client.server_url = "http://jellyfin.local:8096"
        self.mock_client._headers = {"X-Emby-Token": "secret"}
        self.mock_client._api_key = "secret"
        self.mock_client.session = MagicMock()
        self.mock_entry.runtime_data.library._api = self.mock_client
        self.hass.config_entries.async_get_entry.return_value = self.mock_entry

        self.image_view = JellyHAImageView(self.hass)
        self.stream_view = JellyHAStreamView(self.hass)
        self.subtitle_view = JellyHASubtitleView(self.hass)

    def _authenticated_request(self, query=None, headers=None):
        req = MagicMock()
        data = {"hass_user": MagicMock(), "hass_refresh_token_id": "valid_token"}
        req.get.side_effect = lambda k, default=None: data.get(k, default)
        req.query = query or {}
        req.headers = headers or {}
        return req

    # --- JellyHAImageView Tests ---

    async def test_image_view_rejects_invalid_entry_id(self):
        req = self._authenticated_request()
        resp = await self.image_view.get(
            req,
            entry_id="../../etc/passwd",
            item_id="0123456789abcdef0123456789abcdef",
            image_type="Primary",
        )
        self.assertEqual(resp.status, 400)
        self.assertIn("Invalid entry ID", resp.text)

    async def test_image_view_rejects_path_traversal_item_id(self):
        req = self._authenticated_request()
        resp = await self.image_view.get(
            req,
            entry_id="01KMBE8QY54E8PPTNKYYD3FXGT",
            item_id="../../System/Info",
            image_type="Primary",
        )
        self.assertEqual(resp.status, 400)
        self.assertIn("Invalid item ID", resp.text)

    async def test_image_view_rejects_disallowed_image_type(self):
        req = self._authenticated_request()
        resp = await self.image_view.get(
            req,
            entry_id="01KMBE8QY54E8PPTNKYYD3FXGT",
            item_id="0123456789abcdef0123456789abcdef",
            image_type="../../secret",
        )
        self.assertEqual(resp.status, 400)
        self.assertIn("Invalid image type", resp.text)

    async def test_image_view_rejects_malformed_dimensions(self):
        req = self._authenticated_request(query={"width": "100;DROP", "height": "abc"})
        resp = await self.image_view.get(
            req,
            entry_id="01KMBE8QY54E8PPTNKYYD3FXGT",
            item_id="0123456789abcdef0123456789abcdef",
            image_type="Primary",
        )
        self.assertEqual(resp.status, 400)
        self.assertIn("Invalid query parameters", resp.text)

    async def test_image_view_sanitizes_500_error(self):
        req = self._authenticated_request()
        self.mock_client.session.get.side_effect = RuntimeError("sensitive internal db connection failed")
        resp = await self.image_view.get(
            req,
            entry_id="01KMBE8QY54E8PPTNKYYD3FXGT",
            item_id="0123456789abcdef0123456789abcdef",
            image_type="Primary",
        )
        self.assertEqual(resp.status, 500)
        self.assertEqual(resp.text, "Image proxy error")
        self.assertNotIn("sensitive internal", resp.text)

    # --- JellyHAStreamView Tests ---

    async def test_stream_view_rejects_invalid_entry_id(self):
        req = self._authenticated_request()
        resp = await self.stream_view._handle_stream(
            req,
            entry_id="../malicious",
            item_id="0123456789abcdef0123456789abcdef",
            media_type="Videos",
        )
        self.assertEqual(resp.status, 400)
        self.assertIn("Invalid entry ID", resp.text)

    async def test_stream_view_rejects_path_traversal_item_id(self):
        req = self._authenticated_request()
        resp = await self.stream_view._handle_stream(
            req,
            entry_id="01KMBE8QY54E8PPTNKYYD3FXGT",
            item_id="../../System/Configuration",
            media_type="Videos",
        )
        self.assertEqual(resp.status, 400)
        self.assertIn("Invalid item ID", resp.text)

    async def test_stream_view_rejects_disallowed_media_type(self):
        req = self._authenticated_request()
        resp = await self.stream_view._handle_stream(
            req,
            entry_id="01KMBE8QY54E8PPTNKYYD3FXGT",
            item_id="0123456789abcdef0123456789abcdef",
            media_type="System",
        )
        self.assertEqual(resp.status, 400)
        self.assertIn("Invalid media_type", resp.text)

    async def test_stream_view_sanitizes_500_error(self):
        req = self._authenticated_request()
        self.mock_client.session.get.side_effect = RuntimeError("database token leakage")
        resp = await self.stream_view._handle_stream(
            req,
            entry_id="01KMBE8QY54E8PPTNKYYD3FXGT",
            item_id="0123456789abcdef0123456789abcdef",
            media_type="Videos",
        )
        self.assertEqual(resp.status, 500)
        self.assertEqual(resp.text, "Stream proxy error")
        self.assertNotIn("database token leakage", resp.text)

    # --- JellyHASubtitleView Tests ---

    async def test_subtitle_view_rejects_invalid_entry_id(self):
        req = self._authenticated_request()
        resp = await self.subtitle_view.get(
            req,
            entry_id="../../malicious",
            item_id="0123456789abcdef0123456789abcdef",
            stream_index="0",
        )
        self.assertEqual(resp.status, 400)
        self.assertIn("Invalid entry ID", resp.text)

    async def test_subtitle_view_rejects_path_traversal_item_id(self):
        req = self._authenticated_request()
        resp = await self.subtitle_view.get(
            req,
            entry_id="01KMBE8QY54E8PPTNKYYD3FXGT",
            item_id="../../System/Info",
            stream_index="0",
        )
        self.assertEqual(resp.status, 400)
        self.assertIn("Invalid item ID", resp.text)

    async def test_subtitle_view_rejects_malformed_stream_index(self):
        req = self._authenticated_request()
        resp = await self.subtitle_view.get(
            req,
            entry_id="01KMBE8QY54E8PPTNKYYD3FXGT",
            item_id="0123456789abcdef0123456789abcdef",
            stream_index="0/../../traversal",
        )
        self.assertEqual(resp.status, 400)
        self.assertIn("Invalid stream index", resp.text)

    async def test_subtitle_view_rejects_invalid_media_source_id(self):
        req = self._authenticated_request(query={"media_source_id": "../../evil"})
        resp = await self.subtitle_view.get(
            req,
            entry_id="01KMBE8QY54E8PPTNKYYD3FXGT",
            item_id="0123456789abcdef0123456789abcdef",
            stream_index="0",
        )
        self.assertEqual(resp.status, 400)
        self.assertIn("Invalid media_source_id", resp.text)

    async def test_subtitle_view_sanitizes_500_error(self):
        req = self._authenticated_request()
        self.mock_client.session.get.side_effect = RuntimeError("secret server info exposed")
        resp = await self.subtitle_view.get(
            req,
            entry_id="01KMBE8QY54E8PPTNKYYD3FXGT",
            item_id="0123456789abcdef0123456789abcdef",
            stream_index="0",
        )
        self.assertEqual(resp.status, 500)
        self.assertEqual(resp.text, "Subtitle proxy error")
        self.assertNotIn("secret server info exposed", resp.text)


if __name__ == "__main__":
    unittest.main()
