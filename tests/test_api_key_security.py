"""Tests to verify that Jellyfin API keys and tokens are never leaked to clients, services, or logs."""
import unittest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch

import tests.ha_mock  # Load HA mock environment
from custom_components.jellyha.coordinator import JellyHALibraryCoordinator
from custom_components.jellyha.diagnostics import TO_REDACT
from custom_components.jellyha.services import async_register_services
from custom_components.jellyha.const import DOMAIN


class TestApiKeySecurity(unittest.IsolatedAsyncioTestCase):
    """Test suite ensuring zero unauthorized API key leakage."""

    async def asyncSetUp(self):
        self.mock_hass = MagicMock()
        self.mock_hass.data = {}
        self.mock_hass.services = MagicMock()
        self.registered_services = {}

        def mock_async_register(domain, service, func, schema=None, supports_response=None):
            self.registered_services[service] = func

        self.mock_hass.services.async_register = mock_async_register
        self.mock_hass.services.has_service = lambda domain, s: False

    async def test_coordinator_transform_audio_item_does_not_leak_api_key(self):
        """Verify that audio stream_url does NOT expose cleartext API keys."""
        mock_entry = MagicMock()
        mock_entry.entry_id = "test_entry_123"
        mock_entry.data = {
            "api_key": "SECRET_JELLYFIN_KEY_999",
            "url": "http://jellyfin.local:8096",
            "user_id": "test_user_id",
        }
        mock_entry.options = {}

        mock_api = MagicMock()
        mock_api._server_url = "http://jellyfin.local:8096"
        mock_api._api_key = "SECRET_JELLYFIN_KEY_999"
        mock_api.get_stream_path = lambda entry_id, item_id, item_type="Video", filename=None: (
            f"/api/jellyha/stream/{entry_id}/{item_id}?media_type={item_type}"
        )

        coordinator = JellyHALibraryCoordinator(self.mock_hass, mock_entry)
        coordinator._api = mock_api

        raw_audio_item = {
            "Id": "audio_track_001",
            "Name": "Sample Track",
            "Type": "Audio",
            "RunTimeTicks": 1800000000,
            "MediaSources": [{"Path": "/music/sample.flac", "MediaStreams": []}],
        }

        transformed = await coordinator._async_transform_item(raw_audio_item)
        stream_url = transformed.get("stream_url")

        self.assertIsNotNone(stream_url)
        self.assertNotIn("SECRET_JELLYFIN_KEY_999", stream_url)
        self.assertNotIn("api_key=", stream_url)
        self.assertNotIn("ApiKey=", stream_url)
        self.assertIn("/api/jellyha/stream/test_entry_123/audio_track_001", stream_url)
        self.assertIn("authSig=", stream_url)

    async def test_get_playlists_service_does_not_leak_api_key(self):
        """Verify that async_get_playlists returns signed proxy image URLs without API keys."""
        await async_register_services(self.mock_hass)
        get_playlists_func = self.registered_services.get("get_playlists")
        self.assertIsNotNone(get_playlists_func)

        mock_coordinator = MagicMock()
        mock_coordinator.entry.entry_id = "entry_playlists_456"
        mock_coordinator.entry.data = {
            "api_key": "SUPER_SECRET_KEY_777",
            "user_id": "user_123",
        }
        mock_api = AsyncMock()
        mock_api._api_key = "SUPER_SECRET_KEY_777"
        mock_api.get_library_items.return_value = [
            {
                "Id": "playlist_999",
                "Name": "Favorites Mix",
                "ChildCount": 15,
                "RunTimeTicks": 36000000000,
            }
        ]
        mock_coordinator._api = mock_api
        mock_coordinator.api = mock_api

        with patch("custom_components.jellyha.services._get_coordinator", return_value=mock_coordinator):
            call = MagicMock()
            call.data = {"config_entry_id": "entry_playlists_456"}
            response = await get_playlists_func(call)

            playlists = response.get("playlists", [])
            self.assertEqual(len(playlists), 1)
            img_url = playlists[0].get("image_url")

            self.assertIsNotNone(img_url)
            self.assertNotIn("SUPER_SECRET_KEY_777", img_url)
            self.assertNotIn("api_key=", img_url)
            self.assertNotIn("ApiKey=", img_url)
            self.assertIn("/api/jellyha/image/entry_playlists_456/playlist_999/Primary", img_url)
            self.assertIn("authSig=", img_url)

    async def test_get_collections_service_does_not_leak_api_key(self):
        """Verify that async_get_collections returns signed proxy URLs without API keys."""
        await async_register_services(self.mock_hass)
        get_collections_func = self.registered_services.get("get_collections")
        self.assertIsNotNone(get_collections_func)

        mock_coordinator = MagicMock()
        mock_coordinator.entry.entry_id = "entry_collections_789"
        mock_coordinator.entry.data = {
            "api_key": "CONFIDENTIAL_KEY_555",
            "user_id": "user_456",
        }
        mock_api = AsyncMock()
        mock_api._api_key = "CONFIDENTIAL_KEY_555"
        mock_api.get_library_items.return_value = [
            {
                "Id": "boxset_101",
                "Name": "Marvel Cinematic Universe",
                "ChildCount": 30,
                "Overview": "All movies in MCU",
            }
        ]
        mock_api._request.return_value = {"Items": []}
        mock_coordinator._api = mock_api
        mock_coordinator.api = mock_api

        with patch("custom_components.jellyha.services._get_coordinator", return_value=mock_coordinator):
            call = MagicMock()
            call.data = {"config_entry_id": "entry_collections_789", "include_items": False}
            response = await get_collections_func(call)

            collections = response.get("collections", [])
            self.assertEqual(len(collections), 1)
            col = collections[0]

            img_url = col.get("image_url")
            bd_url = col.get("backdrop_url")

            self.assertIsNotNone(img_url)
            self.assertIsNotNone(bd_url)

            for url in (img_url, bd_url):
                self.assertNotIn("CONFIDENTIAL_KEY_555", url)
                self.assertNotIn("api_key=", url)
                self.assertNotIn("ApiKey=", url)
                self.assertIn("authSig=", url)

            self.assertIn("/api/jellyha/image/entry_collections_789/boxset_101/Primary", img_url)
            self.assertIn("/api/jellyha/image/entry_collections_789/boxset_101/Backdrop", bd_url)

    def test_diagnostics_redacts_all_key_variants(self):
        """Verify that diagnostics TO_REDACT contains all key variants."""
        self.assertIn("api_key", TO_REDACT)
        self.assertIn("ApiKey", TO_REDACT)
        self.assertIn("token", TO_REDACT)
        self.assertIn("Token", TO_REDACT)
        self.assertIn("access_token", TO_REDACT)
        self.assertIn("password", TO_REDACT)
        self.assertIn("secret", TO_REDACT)
        self.assertIn("auth_key", TO_REDACT)
