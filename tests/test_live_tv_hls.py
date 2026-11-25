import sys
import os
import time
import unittest
from unittest.mock import MagicMock, AsyncMock

# Ensure repo root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import tests.ha_mock

from custom_components.jellyha.api import JellyfinApiClient, CHROMECAST_LIVE_TV_PROFILE
from custom_components.jellyha.const import DOMAIN
from custom_components.jellyha.hls_manager import (
    HlsSessionManager,
    LIVE_TV_SESSION_TTL_SECONDS,
    is_live_tv_item,
    open_live_tv_hls_session,
)
from custom_components.jellyha.media_source import JellyHAMediaSource
from custom_components.jellyha.views import JellyHAHlsView
from custom_components.jellyha.websocket import websocket_resolve_playback


CHANNEL_ID = "0123456789abcdef0123456789abcdef"
MOVIE_ID = "fedcba9876543210fedcba9876543210"


class TestLiveTvDetection(unittest.TestCase):
    def test_detects_tv_channel_types(self):
        self.assertTrue(is_live_tv_item({"Type": "TvChannel"}))
        self.assertTrue(is_live_tv_item({"Type": "LiveTvChannel"}))

    def test_detects_infinite_stream_or_requires_opening(self):
        self.assertTrue(
            is_live_tv_item({"Type": "Video", "MediaSources": [{"IsInfiniteStream": True}]})
        )
        self.assertTrue(
            is_live_tv_item({"Type": "Video", "MediaSources": [{"RequiresOpening": True}]})
        )

    def test_non_live_items_return_false(self):
        self.assertFalse(is_live_tv_item(None))
        self.assertFalse(is_live_tv_item({}))
        self.assertFalse(is_live_tv_item({"Type": "Movie", "MediaSources": [{"IsInfiniteStream": False}]}))
        self.assertFalse(is_live_tv_item({"Type": "Episode"}))
        self.assertFalse(is_live_tv_item({"Type": "Audio"}))


class TestLiveTvApiAndHls(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.hass = MagicMock()
        self.manager = HlsSessionManager(self.hass)
        self.hass.data = {DOMAIN: {"hls_manager": self.manager}}

        self.session = MagicMock()
        self.api = JellyfinApiClient(
            server_url="https://jellyfin.local",
            api_key="super_secret_key",
            session=self.session,
        )

    async def test_api_playback_info_auto_open_and_live_stream_endpoints(self):
        self.api._request = AsyncMock(return_value={"MediaSources": []})

        await self.api.get_playback_info(
            "user_1",
            CHANNEL_ID,
            profile=CHROMECAST_LIVE_TV_PROFILE,
            auto_open_live_stream=True,
            max_streaming_bitrate=15000000,
        )
        args, kwargs = self.api._request.call_args
        self.assertEqual(args, ("POST", f"/Items/{CHANNEL_ID}/PlaybackInfo"))
        self.assertTrue(kwargs["json"]["AutoOpenLiveStream"])
        self.assertEqual(kwargs["json"]["MaxStreamingBitrate"], 15000000)

        self.api._request.reset_mock()
        await self.api.open_live_stream(
            user_id="user_1",
            item_id=CHANNEL_ID,
            open_token="tok_abc",
            play_session_id="ps_123",
            profile=CHROMECAST_LIVE_TV_PROFILE,
        )
        args, kwargs = self.api._request.call_args
        self.assertEqual(args, ("POST", "/LiveStreams/Open"))
        self.assertEqual(kwargs["json"]["OpenToken"], "tok_abc")
        self.assertEqual(kwargs["json"]["PlaySessionId"], "ps_123")

        self.api._request.reset_mock()
        closed = await self.api.close_live_stream("live_999")
        self.assertTrue(closed)
        self.api._request.assert_called_once_with(
            "POST", "/LiveStreams/Close", params={"liveStreamId": "live_999"}
        )

    async def test_open_live_tv_hls_session_auto_opened(self):
        mock_api = MagicMock()
        mock_api.server_url = "https://jellyfin.local"
        mock_api.api_key = "super_secret_key"
        mock_api.get_playback_info = AsyncMock(return_value={
            "PlaySessionId": "ps_live_1",
            "MediaSources": [
                {
                    "Id": "ms_ch_1",
                    "IsInfiniteStream": True,
                    "RequiresOpening": False,
                    "LiveStreamId": "ls_abc123",
                    "TranscodingUrl": (
                        f"/videos/{CHANNEL_ID}/live.m3u8"
                        "?DeviceId=jellyha&MediaSourceId=ms_ch_1&LiveStreamId=ls_abc123"
                        "&PlaySessionId=ps_live_1&api_key=super_secret_key"
                    ),
                }
            ],
        })
        mock_api.open_live_stream = AsyncMock()

        res = await open_live_tv_hls_session(
            self.hass, "entry_1", "user_1", CHANNEL_ID, mock_api, device_id="jellyha"
        )

        mock_api.open_live_stream.assert_not_called()
        self.assertEqual(res["mime_type"], "application/x-mpegURL")
        self.assertEqual(res["live_stream_id"], "ls_abc123")
        self.assertIn(f"/api/jellyha/hls/{res['token']}/live.m3u8?", res["url"])
        self.assertIn("LiveStreamId=ls_abc123", res["url"])
        self.assertNotIn("super_secret_key", res["url"])
        self.assertNotIn("api_key=", res["url"])

        session = self.manager.get_session(res["token"])
        self.assertIsNotNone(session)
        self.assertEqual(session.live_stream_id, "ls_abc123")
        self.assertEqual(session.ttl_seconds, LIVE_TV_SESSION_TTL_SECONDS)

    async def test_open_live_tv_hls_session_falls_back_to_open_live_stream(self):
        mock_api = MagicMock()
        mock_api.server_url = "https://jellyfin.local"
        mock_api.api_key = "super_secret_key"
        mock_api.get_playback_info = AsyncMock(return_value={
            "PlaySessionId": "ps_live_2",
            "MediaSources": [
                {
                    "Id": "ms_ch_2",
                    "IsInfiniteStream": True,
                    "RequiresOpening": True,
                    "OpenToken": "open_tok_42",
                }
            ],
        })
        mock_api.open_live_stream = AsyncMock(return_value={
            "MediaSource": {
                "Id": "ms_ch_2",
                "LiveStreamId": "ls_opened_42",
                "TranscodingUrl": f"/videos/{CHANNEL_ID}/live.m3u8?LiveStreamId=ls_opened_42&api_key=super_secret_key",
            }
        })

        res = await open_live_tv_hls_session(
            self.hass, "entry_1", "user_1", CHANNEL_ID, mock_api
        )

        mock_api.open_live_stream.assert_called_once()
        self.assertEqual(res["live_stream_id"], "ls_opened_42")
        self.assertIn("LiveStreamId=ls_opened_42", res["url"])
        self.assertNotIn("super_secret_key", res["url"])

    async def test_terminate_live_session_avoids_double_close_and_respects_shared_stream(self):
        mock_api = MagicMock()
        mock_api.stop_active_encoding = AsyncMock(return_value=True)
        mock_api.stop_playback_session = AsyncMock(return_value=True)
        mock_api.close_live_stream = AsyncMock(return_value=True)

        # Case 1: Stream never started (no FFmpeg job) & no other active viewer -> report live_stream_id once (no close_live_stream duplicate)
        session = self.manager.create_session(
            entry_id="entry_1",
            item_id=CHANNEL_ID,
            play_session_id="ps_live_3",
            media_source_id="ms_3",
            server_url="https://jellyfin.local",
            api_key="secret",
            api=mock_api,
            device_id="jellyha",
            live_stream_id="ls_tuner_1",
            ttl_seconds=LIVE_TV_SESSION_TTL_SECONDS,
        )

        # Verify shorter TTL triggers expiry
        session.last_accessed = time.time() - (LIVE_TV_SESSION_TTL_SECONDS + 5)
        self.assertTrue(session.is_expired())

        terminated = await self.manager.terminate_session(session.token)
        self.assertTrue(terminated)
        mock_api.stop_active_encoding.assert_called_once_with("ps_live_3", device_id="jellyha")
        mock_api.stop_playback_session.assert_called_once_with(
            "ps_live_3", CHANNEL_ID, live_stream_id="ls_tuner_1"
        )
        mock_api.close_live_stream.assert_not_called()

        # Case 2: Stream had started (FFmpeg ran, Jellyfin kill timer handles consumer count) ->
        # inactivity reap must NOT pass live_stream_id (prevents killing other viewers on same channel)
        mock_api.reset_mock()
        started_session = self.manager.create_session(
            entry_id="entry_1",
            item_id=CHANNEL_ID,
            play_session_id="ps_live_started",
            media_source_id="ms_3",
            server_url="https://jellyfin.local",
            api_key="secret",
            api=mock_api,
            device_id="jellyha",
            live_stream_id="ls_shared",
            ttl_seconds=LIVE_TV_SESSION_TTL_SECONDS,
        )
        started_session.stream_started = True
        await self.manager.terminate_session(started_session.token, explicit_stop=False)
        mock_api.stop_playback_session.assert_called_once_with("ps_live_started", CHANNEL_ID)
        mock_api.close_live_stream.assert_not_called()

        # Case 3: Explicit user stop -> reports live_stream_id once (matching jellyfin-chromecast)
        mock_api.reset_mock()
        explicit_session = self.manager.create_session(
            entry_id="entry_1",
            item_id=CHANNEL_ID,
            play_session_id="ps_live_explicit",
            media_source_id="ms_3",
            server_url="https://jellyfin.local",
            api_key="secret",
            api=mock_api,
            device_id="jellyha",
            live_stream_id="ls_explicit",
            ttl_seconds=LIVE_TV_SESSION_TTL_SECONDS,
        )
        explicit_session.stream_started = True
        await self.manager.terminate_session(explicit_session.token, explicit_stop=True)
        mock_api.stop_playback_session.assert_called_once_with(
            "ps_live_explicit", CHANNEL_ID, live_stream_id="ls_explicit"
        )
        mock_api.close_live_stream.assert_not_called()

    async def test_hls_view_forwards_live_stream_id(self):
        mock_api = MagicMock()
        mock_api.session = MagicMock()
        mock_api._headers = {"X-Emby-Token": "secret"}

        session = self.manager.create_session(
            entry_id="entry_1",
            item_id=CHANNEL_ID,
            play_session_id="ps_live_4",
            media_source_id="ms_4",
            server_url="https://jellyfin.local",
            api_key="secret_key",
            api=mock_api,
            live_stream_id="ls_xyz",
        )

        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.text = AsyncMock(return_value="#EXTM3U\n#EXTINF:3.0,\nseg0.ts?api_key=secret_key\n")
        mock_api.session.get.return_value.__aenter__.return_value = mock_resp

        view = JellyHAHlsView(self.hass)
        request = MagicMock()
        request.query = {}
        request.headers = {}

        resp = await view.get(request, token=session.token, path="live.m3u8")
        self.assertEqual(resp.status, 200)
        self.assertNotIn("secret_key", resp.text)

        _, kwargs = mock_api.session.get.call_args
        self.assertEqual(kwargs["params"]["LiveStreamId"], "ls_xyz")
        self.assertEqual(kwargs["params"]["PlaySessionId"], "ps_live_4")

    async def test_hyphenated_uuid_in_transcoding_url_and_hls_view(self):
        """Regression test for #79: Jellyfin returns hyphenated UUIDs while validate_item_id strips hyphens."""
        hyphenated_id = "d7d19313-4fae-47d9-c266-9e78f21eb246"
        compact_id = "d7d193134fae47d9c2669e78f21eb246"

        mock_api = MagicMock()
        mock_api.server_url = "https://jellyfin.local"
        mock_api.api_key = "super_secret_key"
        mock_api.session = MagicMock()
        mock_api._headers = {"X-Emby-Token": "super_secret_key"}
        mock_api.get_playback_info = AsyncMock(return_value={
            "PlaySessionId": "ps_hyph_1",
            "MediaSources": [
                {
                    "Id": "ms_hyph_1",
                    "IsInfiniteStream": True,
                    "LiveStreamId": "ls_hyph_1",
                    "TranscodingUrl": (
                        f"/videos/{hyphenated_id}/master.m3u8"
                        "?DeviceId=jellyha&LiveStreamId=ls_hyph_1&api_key=super_secret_key"
                    ),
                }
            ],
        })

        res = await open_live_tv_hls_session(
            self.hass, "entry_1", "user_1", compact_id, mock_api, device_id="jellyha"
        )
        # Should extract clean relative master.m3u8 without redundant /Videos/<hyphenated-id>/
        self.assertIn(f"/api/jellyha/hls/{res['token']}/master.m3u8?", res["url"])
        self.assertNotIn(hyphenated_id, res["url"])

        # Even if a client or sub-playlist requests /Videos/<hyphenated-id>/main.m3u8,
        # JellyHAHlsView must NOT return 403 Token item mismatch.
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.text = AsyncMock(
            return_value=f"#EXTM3U\n/videos/{hyphenated_id}/live.m3u8?api_key=super_secret_key\n"
        )
        mock_api.session.get.return_value.__aenter__.return_value = mock_resp

        view = JellyHAHlsView(self.hass)
        request = MagicMock()
        request.query = {}
        request.headers = {}

        resp = await view.get(request, token=res["token"], path=f"Videos/{hyphenated_id}/master.m3u8")
        self.assertEqual(resp.status, 200)
        self.assertIn(f"/api/jellyha/hls/{res['token']}/live.m3u8", resp.text)
        self.assertNotIn("super_secret_key", resp.text)

    async def test_hls_view_strips_leading_api_key_preserving_query_mark(self):
        """Ensure stripping leading ?api_key=... preserves '?' before remaining query params."""
        mock_api = MagicMock()
        mock_api.session = MagicMock()
        mock_api._headers = {"X-Emby-Token": "secret"}

        session = self.manager.create_session(
            entry_id="entry_1",
            item_id=CHANNEL_ID,
            play_session_id="ps_first_key",
            media_source_id="ms_1",
            server_url="https://jellyfin.local",
            api_key="secret_key",
            api=mock_api,
            live_stream_id="ls_1",
        )

        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.text = AsyncMock(
            return_value=(
                "#EXTM3U\n"
                "#EXT-X-STREAM-INF:BANDWIDTH=5000000\n"
                "live.m3u8?api_key=secret_key&PlaySessionId=ps_first_key&LiveStreamId=ls_1\n"
            )
        )
        mock_api.session.get.return_value.__aenter__.return_value = mock_resp

        view = JellyHAHlsView(self.hass)
        request = MagicMock()
        request.query = {}
        request.headers = {}

        resp = await view.get(request, token=session.token, path="master.m3u8")
        self.assertEqual(resp.status, 200)
        self.assertIn("live.m3u8?PlaySessionId=ps_first_key&LiveStreamId=ls_1", resp.text)
        self.assertNotIn("live.m3u8&", resp.text)
        self.assertNotIn("secret_key", resp.text)

        # Verify live playlist uses extended 45s timeout for tuner startup
        _, kwargs = mock_api.session.get.call_args
        self.assertEqual(kwargs["timeout"].total, 45)

    async def test_hls_view_supports_head_probes(self):
        """Ensure Chromecast HEAD probes succeed cleanly without defining conflicting OPTIONS."""
        mock_api = MagicMock()
        session = self.manager.create_session(
            entry_id="entry_1",
            item_id=CHANNEL_ID,
            play_session_id="ps_cors",
            media_source_id="ms_1",
            server_url="https://jellyfin.local",
            api_key="secret_key",
            api=mock_api,
            live_stream_id="ls_cors",
        )

        view = JellyHAHlsView(self.hass)
        self.assertFalse(hasattr(view, "options"))

        request = MagicMock()
        request.query = {}
        request.headers = {}

        head_resp = await view.head(request, token=session.token, path="master.m3u8")
        self.assertEqual(head_resp.status, 200)
        self.assertEqual(head_resp.headers["Content-Type"], "application/vnd.apple.mpegurl")
        self.assertEqual(head_resp.headers["Access-Control-Allow-Origin"], "*")

    def test_chromecast_live_tv_profile_matches_cast_constraints(self):
        """Verify CHROMECAST_LIVE_TV_PROFILE sets MinSegments=1, 40Mbps cap (for remux), and H.264/AAC CodecProfiles."""
        self.assertGreaterEqual(CHROMECAST_LIVE_TV_PROFILE["MaxStreamingBitrate"], 40000000)
        ts_profile = CHROMECAST_LIVE_TV_PROFILE["TranscodingProfiles"][0]
        self.assertEqual(ts_profile["MinSegments"], 1)
        self.assertEqual(ts_profile["Protocol"], "hls")
        self.assertEqual(ts_profile["Container"], "ts")

        codec_profiles = CHROMECAST_LIVE_TV_PROFILE["CodecProfiles"]
        h264_cp = next(cp for cp in codec_profiles if cp["Codec"] == "h264")
        props = {c["Property"]: c["Value"] for c in h264_cp["Conditions"]}
        self.assertEqual(props["VideoLevel"], "41")
        self.assertEqual(props["VideoBitDepth"], "8")
        self.assertEqual(props["IsInterlaced"], "true")

        aac_cp = next(cp for cp in codec_profiles if cp["Codec"] == "aac")
        aac_props = {c["Property"]: c["Value"] for c in aac_cp["Conditions"]}
        self.assertEqual(aac_props["AudioChannels"], "2")

    async def test_media_source_resolves_live_tv_as_hls_and_movie_as_static(self):
        mock_api = MagicMock()
        mock_api.server_url = "https://jellyfin.local"
        mock_api.api_key = "secret_key"
        mock_api.get_stream_path = MagicMock(
            return_value=f"/api/jellyha/stream/entry_1/Videos/{MOVIE_ID}/Test_Movie"
        )
        mock_api.get_playback_info = AsyncMock(return_value={
            "PlaySessionId": "ps_ms_1",
            "MediaSources": [
                {
                    "Id": "ms_tv",
                    "IsInfiniteStream": True,
                    "LiveStreamId": "ls_ms_1",
                    "TranscodingUrl": f"/videos/{CHANNEL_ID}/master.m3u8?LiveStreamId=ls_ms_1&StartTimeTicks=0&api_key=secret_key",
                }
            ],
        })

        mock_coordinator = MagicMock()
        mock_coordinator._api = mock_api
        mock_coordinator.entry = MagicMock()
        mock_coordinator.entry.entry_id = "entry_1"
        mock_coordinator.entry.data = {"user_id": "user_1"}

        mock_entry = MagicMock()
        mock_entry.entry_id = "entry_1"
        mock_entry.runtime_data = MagicMock()
        mock_entry.runtime_data.library = mock_coordinator
        self.hass.config_entries.async_get_entry.return_value = mock_entry

        source = JellyHAMediaSource(self.hass)

        # 1a. Live TV channel targeting Chromecast -> clean alias URL (no master.m3u8?DeviceId=...)
        mock_api.get_item = AsyncMock(return_value={
            "Id": CHANNEL_ID,
            "Name": "One Adria",
            "Type": "TvChannel",
            "MediaSources": [{"IsInfiniteStream": True, "RequiresOpening": True}],
        })
        cast_item = MagicMock()
        cast_item.identifier = f"entry_1/item/{CHANNEL_ID}"
        cast_item.target_media_player = "media_player.living_room_tv"
        cast_res = await source.async_resolve_media(cast_item)
        self.assertEqual(cast_res.mime_type, "application/x-mpegURL")
        self.assertTrue(cast_res.url.startswith("/api/jellyha/hls/"))
        self.assertTrue(cast_res.url.endswith("/One%20Adria"))
        self.assertNotIn("?", cast_res.url)
        self.assertNotIn("secret_key", cast_res.url)

        cast_token = cast_res.url.split("/")[4]
        cast_session = self.manager.get_session(cast_token)
        self.assertEqual(cast_session.alias_path, "One Adria")
        self.assertEqual(cast_session.upstream_playlist, "master.m3u8")
        self.assertEqual(cast_session.initial_params["LiveStreamId"], "ls_ms_1")

        # 1b. Live TV channel targeting HA Web Browser (target_media_player=None) -> clean alias backed by live.m3u8
        browser_item = MagicMock()
        browser_item.identifier = f"entry_1/item/{CHANNEL_ID}"
        browser_item.target_media_player = None
        browser_res = await source.async_resolve_media(browser_item)
        self.assertEqual(browser_res.mime_type, "application/x-mpegURL")
        self.assertTrue(browser_res.url.endswith("/One%20Adria"))
        self.assertNotIn("?", browser_res.url)

        browser_token = browser_res.url.split("/")[4]
        browser_session = self.manager.get_session(browser_token)
        self.assertEqual(browser_session.upstream_playlist, "live.m3u8")
        self.assertNotIn("StartTimeTicks", browser_session.initial_params)

        # Verify JellyHAHlsView proxies the alias path to Jellyfin with stored initial_params
        mock_api.session = MagicMock()
        mock_api._headers = {"X-Emby-Token": "secret_key"}
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.text = AsyncMock(return_value="#EXTM3U\n#EXTINF:3.0,\nhls/abc/abc0.ts\n")
        mock_api.session.get.return_value.__aenter__.return_value = mock_resp

        view = JellyHAHlsView(self.hass)
        req = MagicMock()
        req.query = {}
        req.headers = {}

        head_resp = await view.head(req, token=browser_token, path="One Adria")
        self.assertEqual(head_resp.status, 200)
        self.assertEqual(head_resp.headers["Content-Type"], "application/vnd.apple.mpegurl")

        get_resp = await view.get(req, token=browser_token, path="One Adria")
        self.assertEqual(get_resp.status, 200)
        call_url = mock_api.session.get.call_args[0][0]
        call_params = mock_api.session.get.call_args[1]["params"]
        self.assertTrue(call_url.endswith(f"/Videos/{CHANNEL_ID}/live.m3u8"))
        self.assertEqual(call_params["LiveStreamId"], "ls_ms_1")
        self.assertTrue(browser_session.stream_started)

        # Other non-HLS extensions on the same token must still be rejected with 400
        bad_resp = await view.get(req, token=browser_token, path="config.xml")
        self.assertEqual(bad_resp.status, 400)

        # 2. Regular movie -> existing static signed stream URL unchanged
        mock_api.get_item = AsyncMock(return_value={
            "Id": MOVIE_ID,
            "Name": "Test Movie",
            "Type": "Movie",
            "Container": "mp4",
        })
        movie_item = MagicMock()
        movie_item.identifier = f"entry_1/item/{MOVIE_ID}"
        movie_res = await source.async_resolve_media(movie_item)
        self.assertEqual(movie_res.mime_type, "video/mp4")
        self.assertIn("/api/jellyha/stream/entry_1/Videos/", movie_res.url)

    async def test_websocket_resolve_playback_live_tv(self):
        connection = MagicMock()
        mock_api = MagicMock()
        mock_api.server_url = "https://jellyfin.local"
        mock_api.api_key = "secret_key"
        mock_api.get_item = AsyncMock(return_value={
            "Id": CHANNEL_ID,
            "Name": "3sat",
            "Type": "TvChannel",
            "MediaSources": [{"IsInfiniteStream": True, "RequiresOpening": True}],
        })
        mock_api.get_playback_info = AsyncMock(return_value={
            "PlaySessionId": "ps_ws_live",
            "MediaSources": [
                {
                    "Id": "ms_ws_tv",
                    "LiveStreamId": "ls_ws_1",
                    "TranscodingUrl": f"/videos/{CHANNEL_ID}/live.m3u8?LiveStreamId=ls_ws_1&api_key=secret_key",
                }
            ],
        })

        mock_coordinator = MagicMock()
        mock_coordinator._api = mock_api
        mock_coordinator.entry = MagicMock()
        mock_coordinator.entry.entry_id = "entry_1"
        mock_coordinator.entry.data = {"user_id": "user_1"}

        mock_entry = MagicMock()
        mock_entry.domain = DOMAIN
        mock_entry.entry_id = "entry_1"
        mock_entry.runtime_data = MagicMock()
        mock_entry.runtime_data.library = mock_coordinator
        self.hass.config_entries.async_get_entry.return_value = mock_entry
        self.hass.config_entries.async_entries.return_value = [mock_entry]

        msg = {
            "id": 99,
            "type": "jellyha/resolve_playback",
            "item_id": CHANNEL_ID,
            "config_entry_id": "entry_1",
        }
        await websocket_resolve_playback(self.hass, connection, msg)

        connection.send_result.assert_called_once()
        res = connection.send_result.call_args[0][1]
        self.assertEqual(res["play_method"], "Transcode")
        self.assertEqual(res["mime_type"], "application/x-mpegURL")
        self.assertIn("/api/jellyha/hls/", res["url"])
        self.assertIn("LiveStreamId=ls_ws_1", res["url"])
        self.assertNotIn("secret_key", res["url"])


if __name__ == "__main__":
    unittest.main()

