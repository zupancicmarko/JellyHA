import sys
import os
import unittest
from unittest.mock import MagicMock

# Ensure repo root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import tests.ha_mock

from custom_components.jellyha.views import JellyHAStreamView, JellyHASubtitleView


class TestViewsAuthentication(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.hass = MagicMock()
        self.hass.config_entries.async_get_entry.return_value = None
        self.hass.config_entries.async_entries.return_value = []
        self.stream_view = JellyHAStreamView(self.hass)
        self.subtitle_view = JellyHASubtitleView(self.hass)

    async def test_stream_view_rejects_unvalidated_auth_sig_query(self):
        """Verify that passing ?authSig=fake does NOT grant access without valid signature."""
        request = {
            "hass_user": None,
            "hass_refresh_token_id": None,
        }
        mock_request = MagicMock()
        mock_request.get.side_effect = lambda k, default=None: request.get(k, default)
        mock_request.query = {"authSig": "arbitrary_fake_token"}
        mock_request.headers = {}

        response = await self.stream_view._handle_stream(
            mock_request,
            entry_id="01KMBE8QY54E8PPTNKYYD3FXGT",
            item_id="test_item_id",
            media_type="Videos",
            is_head=False,
        )
        self.assertEqual(response.status, 401, f"Expected 401 Unauthorized, got {response.status}")

    async def test_stream_view_rejects_unauthenticated_request(self):
        """Verify that requests without user or signature return 401."""
        request = {
            "hass_user": None,
            "hass_refresh_token_id": None,
        }
        mock_request = MagicMock()
        mock_request.get.side_effect = lambda k, default=None: request.get(k, default)
        mock_request.query = {}
        mock_request.headers = {}

        response = await self.stream_view._handle_stream(
            mock_request,
            entry_id="01KMBE8QY54E8PPTNKYYD3FXGT",
            item_id="test_item_id",
            media_type="Videos",
            is_head=False,
        )
        self.assertEqual(response.status, 401)

    async def test_subtitle_view_rejects_spoofed_referer_and_unvalidated_auth_sig(self):
        """Verify that spoofing Referer or passing ?authSig=fake returns 401."""
        request = {
            "hass_user": None,
            "hass_refresh_token_id": None,
        }
        mock_request = MagicMock()
        mock_request.get.side_effect = lambda k, default=None: request.get(k, default)
        mock_request.query = {"authSig": "arbitrary_fake_token"}
        mock_request.headers = {"Referer": "http://ha.local:8123/lovelace/home"}

        response = await self.subtitle_view.get(
            mock_request,
            entry_id="01KMBE8QY54E8PPTNKYYD3FXGT",
            item_id="test_item_id",
            stream_index="2",
        )
        self.assertEqual(response.status, 401, f"Expected 401 Unauthorized, got {response.status}")


if __name__ == "__main__":
    unittest.main()
