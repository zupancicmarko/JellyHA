import sys
import os
import unittest
from unittest.mock import MagicMock, AsyncMock

# Ensure repo root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import tests.ha_mock

from custom_components.jellyha.api import JellyfinApiClient, BROWSER_DEVICE_PROFILE


class TestApiPlaybackInfo(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.session = MagicMock()
        self.api = JellyfinApiClient(
            server_url="https://jellyfin.example.com",
            api_key="test_api_key",
            session=self.session,
        )

    def test_browser_device_profile_structure(self):
        """Verify device profile specifies correct DirectPlay and Transcode profiles."""
        self.assertIn("DirectPlayProfiles", BROWSER_DEVICE_PROFILE)
        self.assertIn("TranscodingProfiles", BROWSER_DEVICE_PROFILE)

        direct_play = BROWSER_DEVICE_PROFILE["DirectPlayProfiles"]
        video_dp = next((p for p in direct_play if p.get("Type") == "Video"), None)
        self.assertIsNotNone(video_dp)
        self.assertIn("mp4", video_dp["Container"])
        self.assertIn("h264", video_dp["VideoCodec"])
        self.assertIn("aac", video_dp["AudioCodec"])

        transcode = BROWSER_DEVICE_PROFILE["TranscodingProfiles"]
        hls_profile = next((p for p in transcode if p.get("Protocol") == "hls"), None)
        self.assertIsNotNone(hls_profile)
        self.assertEqual(hls_profile["Container"], "ts")
        self.assertEqual(hls_profile["VideoCodec"], "h264")
        self.assertEqual(hls_profile["AudioCodec"], "aac")

    async def test_stop_active_encoding(self):
        """Verify stop_active_encoding sends DELETE /Videos/ActiveEncodings."""
        self.api._request = AsyncMock(return_value={})

        result = await self.api.stop_active_encoding("session_12345")
        self.assertTrue(result)
        self.api._request.assert_called_once_with(
            "DELETE",
            "/Videos/ActiveEncodings",
            params={"PlaySessionId": "session_12345"},
        )

    async def test_stop_playback_session(self):
        """Verify stop_playback_session sends POST /Sessions/Playing/Stopped."""
        self.api._request = AsyncMock(return_value={})

        result = await self.api.stop_playback_session("session_12345", "item_6789")
        self.assertTrue(result)
        self.api._request.assert_called_once_with(
            "POST",
            "/Sessions/Playing/Stopped",
            json={"PlaySessionId": "session_12345", "ItemId": "item_6789"},
        )


if __name__ == "__main__":
    unittest.main()
