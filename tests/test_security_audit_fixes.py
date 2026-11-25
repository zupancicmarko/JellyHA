"""Regression tests for security audit fixes."""
import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import tests.ha_mock  # Load HA mock environment
from homeassistant.components.media_player import ATTR_MEDIA_CONTENT_ID
from homeassistant.exceptions import HomeAssistantError
from homeassistant.components.media_source.error import Unresolvable
from homeassistant.components.media_source.models import MediaSourceItem

from custom_components.jellyha.api import JellyfinApiClient
from custom_components.jellyha.const import DOMAIN
from custom_components.jellyha.hls_manager import HlsSessionManager, MAX_ACTIVE_SESSIONS
from custom_components.jellyha.media_source import JellyHAMediaSource
from custom_components.jellyha.services import async_register_services
from custom_components.jellyha.views import JellyHAImageView, JellyHAStreamView, JellyHASubtitleView
from custom_components.jellyha.websocket import websocket_get_item, websocket_get_next_up, websocket_resolve_playback
from custom_components.jellyha.ws_client import JellyfinWebSocketClient


VALID_UUID = "11d6bf041f2b4cfbbae8d4f17fa2ab2e"
VALID_ENTRY_ID = "01KM6Z3F4HPQZ6QED9SJP1RWA9"


class TestSecurityAuditFixes(unittest.IsolatedAsyncioTestCase):
    """Verify all 6 security audit remediations."""

    async def test_play_on_chromecast_never_exposes_api_key(self) -> None:
        """Finding #1: play_on_chromecast must proxy media_url and vtt_url without api_key."""
        mock_hass = MagicMock()
        mock_hass.data = {DOMAIN: {}}
        mock_hass.states = MagicMock()
        mock_hass.states.get = MagicMock(return_value=None)
        mock_hass.services = MagicMock()
        registered = {}

        def _reg(domain, name, func, schema=None, supports_response=None):
            registered[name] = func

        mock_hass.services.has_service = lambda d, n: n in registered
        mock_hass.services.async_register = _reg
        mock_hass.services.async_call = AsyncMock()

        async def _run_exec(fn, *args):
            return ("Chromecast Ultra", False)

        mock_hass.async_add_executor_job = _run_exec

        secret_key = "SUPER_SECRET_ADMIN_KEY_987654"
        mock_api = MagicMock()
        mock_api._server_url = "http://jellyfin.local:8096"
        mock_api.server_url = "http://jellyfin.local:8096"
        mock_api._api_key = secret_key
        mock_api.api_key = secret_key
        mock_api.get_stream_path = (
            lambda entry_id, item_id, item_type="Video", filename=None:
            f"/api/jellyha/stream/{entry_id}/{item_id}?media_type={'Audio' if item_type == 'Audio' else 'Videos'}"
        )
        mock_api.get_user = AsyncMock(return_value={"Configuration": {}})
        # Transcode case (HEVC -> HLS) + text subtitle -> WebVTT
        mock_api.get_item = AsyncMock(return_value={
            "Id": VALID_UUID,
            "Name": "Test Movie",
            "Type": "Movie",
            "Container": "mkv",
            "MediaSources": [{"Id": VALID_UUID, "MediaStreams": []}],
            "MediaStreams": [
                {"Type": "Video", "Codec": "hevc", "Height": 2160, "BitDepth": 10},
                {"Type": "Audio", "Codec": "dts", "Channels": 6, "Index": 1},
                {"Type": "Subtitle", "Codec": "subrip", "Language": "en", "Index": 2},
            ],
        })

        mock_coord = MagicMock()
        mock_coord._api = mock_api
        mock_coord.entry = MagicMock()
        mock_coord.entry.entry_id = VALID_ENTRY_ID
        mock_coord.entry.data = {"user_id": "user_1"}

        await async_register_services(mock_hass)
        play_fn = registered["play_on_chromecast"]

        call = MagicMock()
        call.data = {
            "entity_id": "media_player.living_room_tv",
            "item_id": VALID_UUID,
            "subtitle_mode": "auto",
        }

        with (
            patch("custom_components.jellyha.services._get_coordinator", return_value=mock_coord),
            patch("custom_components.jellyha.services.get_url", return_value="http://ha.local:8123"),
        ):
            await play_fn(call)

        mock_hass.services.async_call.assert_called()
        payload = mock_hass.services.async_call.call_args[0][2]
        media_url = payload[ATTR_MEDIA_CONTENT_ID]
        sub_url = payload["extra"]["subtitles"]

        for url in (media_url, sub_url):
            self.assertNotIn(secret_key, url)
            self.assertNotIn("api_key=", url.lower())
            self.assertNotIn("token=", url.lower())

        self.assertIn("/api/jellyha/hls/", media_url)
        self.assertIn("/api/jellyha/subtitles/", sub_url)
        self.assertIn("authSig=", sub_url)

    async def test_resolve_playback_strips_api_key_from_transcoding_url(self) -> None:
        """Finding #2: websocket_resolve_playback must strip api_key/ApiKey/token from TranscodingUrl."""
        mock_hass = MagicMock()
        hls_manager = HlsSessionManager(mock_hass)
        mock_hass.data = {DOMAIN: {"hls_manager": hls_manager}}

        secret_key = "LEAKED_TRANS_KEY_42"
        mock_api = MagicMock()
        mock_api.server_url = "http://jellyfin.local:8096"
        mock_api.api_key = secret_key
        mock_api.get_item = AsyncMock(return_value={"Id": VALID_UUID, "Type": "Movie", "Name": "Demo"})
        mock_api.get_playback_info = AsyncMock(return_value={
            "PlaySessionId": "ps_123",
            "MediaSources": [{
                "Id": VALID_UUID,
                "SupportsDirectPlay": False,
                "TranscodingUrl": (
                    f"/Videos/{VALID_UUID}/master.m3u8"
                    f"?api_key={secret_key}&ApiKey={secret_key}&token={secret_key}&VideoCodec=h264"
                ),
            }],
        })

        mock_coord = MagicMock()
        mock_coord._api = mock_api
        mock_coord.entry = MagicMock()
        mock_coord.entry.entry_id = VALID_ENTRY_ID
        mock_coord.entry.data = {"user_id": "user_1"}

        conn = MagicMock()
        msg = {"id": 1, "type": "jellyha/resolve_playback", "item_id": VALID_UUID}

        with patch("custom_components.jellyha.websocket._get_coordinator_from_msg", return_value=(mock_coord, None)):
            await websocket_resolve_playback(mock_hass, conn, msg)

        conn.send_result.assert_called_once()
        result = conn.send_result.call_args[0][1]
        self.assertNotIn(secret_key, result["url"])
        self.assertNotIn("api_key=", result["url"].lower())
        self.assertNotIn("token=", result["url"].lower())

    async def test_api_request_blocks_path_traversal(self) -> None:
        """Finding #3: JellyfinApiClient._request rejects path traversal endpoints."""
        session = MagicMock()
        client = JellyfinApiClient("http://jellyfin.local:8096", session=session, api_key="k")
        with self.assertRaises(ValueError):
            await client._request("GET", "/Items/../../Users")
        with self.assertRaises(ValueError):
            await client._request("POST", "/Sessions/../System/Shutdown/Playing")
        session.request.assert_not_called()

    async def test_services_and_ws_reject_invalid_ids(self) -> None:
        """Finding #3: play_music, play_live_tv_channel, media_source, and get_next_up validate IDs."""
        mock_hass = MagicMock()
        mock_hass.data = {DOMAIN: {}}
        mock_hass.services = MagicMock()
        registered = {}
        mock_hass.services.has_service = lambda d, n: n in registered
        mock_hass.services.async_register = lambda d, n, f, schema=None, supports_response=None: registered.__setitem__(n, f)

        mock_coord = MagicMock()
        mock_coord._api = MagicMock()
        mock_coord.entry = MagicMock()
        mock_coord.entry.data = {"user_id": "u1"}

        await async_register_services(mock_hass)

        # play_music with traversal item_id
        call_music = MagicMock()
        call_music.data = {"entity_id": "media_player.speaker", "item_id": "../Users"}
        with (
            patch("custom_components.jellyha.services._get_coordinator", return_value=mock_coord),
            self.assertRaises(HomeAssistantError),
        ):
            await registered["play_music"](call_music)

        # play_live_tv_channel with traversal session_id
        call_tv = MagicMock()
        call_tv.data = {"channel_name": "BBC", "session_id": "../../System/Shutdown"}
        with (
            patch("custom_components.jellyha.services._get_coordinator", return_value=mock_coord),
            self.assertRaises(HomeAssistantError),
        ):
            await registered["play_live_tv_channel"](call_tv)

        # media_source with traversal item_id
        ms = JellyHAMediaSource(mock_hass)
        with self.assertRaises(Unresolvable):
            await ms.async_resolve_media(MediaSourceItem(mock_hass, DOMAIN, f"{VALID_ENTRY_ID}/item/../../Users", None))

        # websocket_get_next_up with traversal series_id
        conn = MagicMock()
        await websocket_get_next_up(mock_hass, conn, {"id": 7, "type": "jellyha/get_next_up", "series_id": "../Users"})
        conn.send_error.assert_called_once()

    def test_ws_client_redacts_token_and_exceptions(self) -> None:
        """Finding #4: ws_client._redact_secret strips both api_key and token from URLs & exceptions."""
        secret = "WS_SECRET_TOKEN_XYZ"
        ws = JellyfinWebSocketClient(MagicMock(), "http://jellyfin.local:8096", secret, "jellyha")
        raw_url = f"ws://jellyfin.local:8096/socket?api_key={secret}&token={secret}&deviceId=jellyha"
        safe = ws._redact_secret(raw_url)
        self.assertNotIn(secret, safe)
        self.assertIn("api_key=REDACTED", safe)
        self.assertIn("token=REDACTED", safe)

        raw_err = f"403, message='Invalid response status', url='{raw_url}'"
        safe_err = ws._redact_secret(raw_err)
        self.assertNotIn(secret, safe_err)

    def test_hls_manager_enforces_max_active_sessions(self) -> None:
        """Finding #5: HlsSessionManager caps concurrent sessions at MAX_ACTIVE_SESSIONS."""
        mock_hass = MagicMock()
        manager = HlsSessionManager(mock_hass)
        for i in range(MAX_ACTIVE_SESSIONS + 10):
            manager.create_session(
                entry_id=VALID_ENTRY_ID,
                item_id=VALID_UUID,
                play_session_id=f"ps_{i}",
                media_source_id=VALID_UUID,
                server_url="http://jellyfin.local:8096",
                api_key="k",
                api=MagicMock(),
            )
        self.assertLessEqual(len(manager._sessions), MAX_ACTIVE_SESSIONS)

    async def test_stream_head_sanitizes_filename_and_hides_raw_error(self) -> None:
        """Finding #6: JellyHAStreamView.head hides raw exceptions and strips CRLF/semicolons in filename."""
        mock_hass = MagicMock()
        mock_entry = MagicMock()
        mock_api = MagicMock()
        mock_api.server_url = "http://jellyfin.local:8096"
        mock_api._headers = {}
        mock_api.session.head = MagicMock(side_effect=RuntimeError("internal secret host details"))
        mock_entry.runtime_data.library._api = mock_api
        mock_hass.config_entries.async_get_entry = MagicMock(return_value=mock_entry)

        view = JellyHAStreamView(mock_hass)
        req = MagicMock()
        req.get = lambda k, d=None: True if k == "hass_user" else d
        req.headers = {}
        req.query = {}

        resp = await view.head(req, VALID_ENTRY_ID, VALID_UUID, filename="evil%0d%0aX-Injected:1;foo.mp4")
        self.assertEqual(resp.status, 500)
        self.assertEqual(resp.text, "Stream proxy error")
        self.assertNotIn("internal secret host details", resp.text)

    async def test_websocket_get_item_resolves_hls_token_for_live_tv_artwork(self) -> None:
        """Verify jellyha/get_item resolves an active HLS token to channel artwork and CurrentProgram."""
        mock_hass = MagicMock()
        hls_manager = HlsSessionManager(mock_hass)
        session = hls_manager.create_session(
            entry_id=VALID_ENTRY_ID,
            item_id=VALID_UUID,
            play_session_id="ps_live_1",
            media_source_id=VALID_UUID,
            server_url="http://jellyfin.local:8096",
            api_key="k",
            api=MagicMock(),
            alias_path="TV Veseljak Golica HD",
        )
        mock_hass.data = {DOMAIN: {"hls_manager": hls_manager}}

        mock_api = MagicMock()
        mock_api.get_item = AsyncMock(return_value={
            "Id": VALID_UUID,
            "Name": "TV Veseljak Golica HD",
            "Type": "TvChannel",
            "ImageTags": {"Primary": "tag123"},
            "CurrentProgram": {"Name": "Morning Music", "Overview": "Live folk music"},
        })

        mock_coord = MagicMock()
        mock_coord._api = mock_api
        mock_coord.entry = MagicMock()
        mock_coord.entry.entry_id = VALID_ENTRY_ID
        mock_coord.entry.data = {"user_id": "user_1"}
        mock_coord._async_transform_item = AsyncMock(return_value={
            "id": VALID_UUID,
            "name": "TV Veseljak Golica HD",
            "type": "TvChannel",
            "poster_url": f"/api/jellyha/image/{VALID_ENTRY_ID}/{VALID_UUID}/Primary?tag=tag123&authSig=abc",
            "description": "",
        })

        conn = MagicMock()
        msg = {"id": 9, "type": "jellyha/get_item", "hls_token": session.token}
        with patch("custom_components.jellyha.websocket._get_coordinator_from_msg", return_value=(mock_coord, None)):
            await websocket_get_item(mock_hass, conn, msg)

        conn.send_result.assert_called_once()
        item = conn.send_result.call_args[0][1]["item"]
        self.assertEqual(item["name"], "TV Veseljak Golica HD")
        self.assertIn(f"/api/jellyha/image/{VALID_ENTRY_ID}/{VALID_UUID}/Primary", item["poster_url"])
        self.assertEqual(item["current_program"], "Morning Music")
        self.assertEqual(item["description"], "Live folk music")


if __name__ == "__main__":
    unittest.main()
