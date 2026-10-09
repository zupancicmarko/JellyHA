"""Unit tests for MediaStrategy playback analysis and Chromecast strategy generation."""
import unittest

import tests.ha_mock  # Load HA mock environment
from custom_components.jellyha.media_strategy import MediaStrategy


class TestMediaStrategy(unittest.TestCase):
    """Test suite for MediaStrategy."""

    def setUp(self):
        self.server_url = "http://jellyfin.local:8096"
        self.api_key = "test_access_token_123"
        self.user_id = "test_user_guid_456"

    def test_chromecast_ultra_transcode_parameters(self):
        """Verify Chromecast Ultra uses stereo AAC downmix, RFC HLS mime, and consistent device ID (Issue #63)."""
        # MPEG2 video with 5.1 AC3 audio (matches the user's movie from Issue #63)
        media_info = {
            "video_codec": "mpeg2video",
            "video_height": 480,
            "bit_depth": 8,
            "audio_codec": "ac3",
            "audio_channels": 6,
            "container": "mp4",
        }

        playback_info = MediaStrategy.get_playback_info(
            server_url=self.server_url,
            api_key=self.api_key,
            item_id="movie_item_001",
            media_info=media_info,
            device_model="Chromecast Ultra",
            item_type="Movie",
            user_id=self.user_id,
        )

        media_url = playback_info["media_url"]
        content_type = playback_info["content_type"]

        # 1. Content type must be canonical RFC HLS MIME type
        self.assertEqual(content_type, "application/vnd.apple.mpegurl")

        # 2. Audio channels must be 2 (stereo) because Chromecast hardware cannot decode 6-channel AAC
        self.assertIn("TranscodingMaxAudioChannels=2", media_url)
        self.assertIn("AudioCodec=aac", media_url)

        # 3. DeviceId must match integration session DeviceId ('jellyha')
        self.assertIn("DeviceId=jellyha", media_url)

        # 4. User context must be included
        self.assertIn(f"UserId={self.user_id}", media_url)

        # 5. Token variants must be present
        self.assertIn(f"api_key={self.api_key}", media_url)
        self.assertIn(f"token={self.api_key}", media_url)

    def test_legacy_chromecast_transcode_parameters(self):
        """Verify legacy Chromecast (Gen 1) uses 720p and stereo downmix."""
        media_info = {
            "video_codec": "mpeg2video",
            "video_height": 1080,
            "bit_depth": 8,
            "audio_codec": "dts",
            "audio_channels": 6,
            "container": "mkv",
        }

        playback_info = MediaStrategy.get_playback_info(
            server_url=self.server_url,
            api_key=self.api_key,
            item_id="legacy_item_002",
            media_info=media_info,
            device_model="Chromecast",  # Gen 1
            item_type="Movie",
            user_id=self.user_id,
        )

        media_url = playback_info["media_url"]
        self.assertEqual(playback_info["content_type"], "application/vnd.apple.mpegurl")
        self.assertIn("Width=1280", media_url)
        self.assertIn("Height=720", media_url)
        self.assertIn("TranscodingMaxAudioChannels=2", media_url)
        self.assertIn("DeviceId=jellyha", media_url)
        self.assertIn(f"UserId={self.user_id}", media_url)

    def test_direct_play_h264_stereo(self):
        """Verify standard H.264 video with AAC stereo is direct-played."""
        media_info = {
            "video_codec": "h264",
            "video_height": 1080,
            "bit_depth": 8,
            "audio_codec": "aac",
            "audio_channels": 2,
            "container": "mp4",
        }

        playback_info = MediaStrategy.get_playback_info(
            server_url=self.server_url,
            api_key=self.api_key,
            item_id="direct_item_003",
            media_info=media_info,
            device_model="Chromecast Ultra",
            item_type="Movie",
            user_id=self.user_id,
        )

        self.assertEqual(playback_info["content_type"], "video/mp4")
        self.assertIn("Static=true", playback_info["media_url"])
        self.assertIn(f"UserId={self.user_id}", playback_info["media_url"])


if __name__ == "__main__":
    unittest.main()
