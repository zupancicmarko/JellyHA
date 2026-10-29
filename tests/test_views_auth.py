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

    async def test_coordinator_signs_cached_image_urls_with_content_user(self):
        """Verify coordinator signs cached Primary and Backdrop URLs with use_content_user=True so closing a private browser WS session does not invalidate cached URLs."""
        import custom_components.jellyha.coordinator as coord_mod
        from unittest.mock import patch

        mock_entry = MagicMock()
        mock_entry.entry_id = "01KMBE8QY54E8PPTNKYYD3FXGT"
        mock_entry.data = {"refresh_interval": 300}
        mock_entry.options = {}

        coordinator = coord_mod.JellyHALibraryCoordinator(self.hass, mock_entry)
        calls = []

        def fake_sign_path(hass, path, expiration=None, *, refresh_token_id=None, use_content_user=False):
            calls.append({"path": path, "use_content_user": use_content_user})
            return f"{path}&authSig={'content_user_sig' if use_content_user else 'ws_session_sig'}"

        raw_item = {
            "Id": "ep_123",
            "Name": "Pilot",
            "Type": "Episode",
            "SeriesId": "series_456",
            "SeriesPrimaryImageTag": "stag1",
            "ImageTags": {"Primary": "ptag1"},
            "BackdropImageTags": ["btag1"],
        }

        with patch.object(coord_mod, "async_sign_path", side_effect=fake_sign_path):
            transformed = await coordinator._async_transform_item(raw_item)

        self.assertTrue(len(calls) >= 3)
        for call in calls:
            self.assertTrue(
                call["use_content_user"],
                f"Expected use_content_user=True for {call['path']} to prevent 401 when WS session ends",
            )
        self.assertIn("content_user_sig", transformed["poster_url"])
        self.assertIn("content_user_sig", transformed["backdrop_url"])
        self.assertIn("content_user_sig", transformed["series_poster_url"])


if __name__ == "__main__":
    unittest.main()
