"""Unit tests for Play on Jellyfin Client and session delegation (Issue #62)."""
import sys
import os
import unittest
from unittest.mock import MagicMock, AsyncMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import tests.ha_mock

from custom_components.jellyha.services import async_register_services


class TestPlayOnClientDelegation(unittest.IsolatedAsyncioTestCase):
    """Test suite ensuring play_on_chromecast delegates to session_play for Jellyfin client entities."""

    async def test_play_on_chromecast_delegates_to_session_play_for_jellyha_client(self):
        """When target is a native JellyHA device media player, play_on_chromecast routes to session_play."""
        mock_hass = MagicMock()
        registered_services = {}

        def mock_register(domain, service, func, **kwargs):
            registered_services[service] = func

        mock_hass.services.has_service = MagicMock(return_value=False)
        mock_hass.services.async_register = mock_register

        # Mock entity state for media_player.jellyha_device_living_room_tv
        target_entity = "media_player.jellyha_device_living_room_tv"
        mock_state = MagicMock()
        mock_state.state = "idle"
        mock_state.attributes = {
            "device_id": "living_room_guid",
            "device_name": "Living Room TV",
            "session_id": "session_999",
        }
        mock_hass.states.get = MagicMock(side_effect=lambda eid: mock_state if eid == target_entity else None)

        # Mock coordinator
        mock_coordinator = MagicMock()
        mock_api = MagicMock()
        mock_api.session_play = AsyncMock(return_value=True)
        mock_api.get_item = AsyncMock(return_value={"Id": "movie_123", "Type": "Movie", "Name": "Inception"})
        mock_coordinator._api = mock_api
        mock_coordinator.entry.data = {"user_id": "user_abc"}
        mock_coordinator.entry.runtime_data.session.data = [{"Id": "session_999", "DeviceId": "living_room_guid"}]

        with patch("custom_components.jellyha.services._get_coordinator", return_value=mock_coordinator):
            await async_register_services(mock_hass)

            play_on_chromecast_func = registered_services["play_on_chromecast"]

            call = MagicMock()
            call.data = {
                "entity_id": target_entity,
                "item_id": "movie_123",
            }

            # Invoke play_on_chromecast
            await play_on_chromecast_func(call)

            # It should have called session_play on mock_api with target session and item
            mock_api.session_play.assert_called_once_with(
                "session_999",
                "movie_123",
                play_command="PlayNow",
                start_position_ticks=None,
            )

    async def test_session_play_raises_when_no_active_session_found(self):
        """When target device has no active session, session_play raises HomeAssistantError."""
        from homeassistant.exceptions import HomeAssistantError

        mock_hass = MagicMock()
        registered_services = {}

        def mock_register(domain, service, func, **kwargs):
            registered_services[service] = func

        mock_hass.services.has_service = MagicMock(return_value=False)
        mock_hass.services.async_register = mock_register

        target_entity = "media_player.jellyha_device_samsung_sm_s911b"
        mock_state = MagicMock()
        mock_state.state = "idle"
        mock_state.attributes = {
            "device_id": "samsung_guid",
            "device_name": "Samsung SM-S911B",
            "session_id": None,
        }
        mock_hass.states.get = MagicMock(side_effect=lambda eid: mock_state if eid == target_entity else None)

        mock_coordinator = MagicMock()
        mock_api = MagicMock()
        mock_api._request = AsyncMock(return_value=[])  # Empty live sessions
        mock_coordinator._api = mock_api
        mock_coordinator.entry.data = {"user_id": "user_abc"}
        mock_coordinator.entry.runtime_data.session.data = []

        with patch("custom_components.jellyha.services._get_coordinator", return_value=mock_coordinator):
            await async_register_services(mock_hass)

            session_play_func = registered_services["session_play"]

            call = MagicMock()
            call.data = {
                "entity_id": target_entity,
                "item_id": "movie_123",
            }

            with self.assertRaises(HomeAssistantError) as ctx:
                await session_play_func(call)

            self.assertIn("No active Jellyfin session found", str(ctx.exception))
            self.assertIn("Make sure the device is on and the app is open on the device", str(ctx.exception))

    async def test_session_play_raises_when_command_rejected(self):
        """When device rejects session_play, session_play raises HomeAssistantError."""
        from homeassistant.exceptions import HomeAssistantError

        mock_hass = MagicMock()
        registered_services = {}

        def mock_register(domain, service, func, **kwargs):
            registered_services[service] = func

        mock_hass.services.has_service = MagicMock(return_value=False)
        mock_hass.services.async_register = mock_register

        target_entity = "media_player.jellyha_device_living_room_tv"
        mock_state = MagicMock()
        mock_state.state = "idle"
        mock_state.attributes = {
            "device_id": "living_room_guid",
            "device_name": "Living Room TV",
            "session_id": "session_999",
        }
        mock_hass.states.get = MagicMock(side_effect=lambda eid: mock_state if eid == target_entity else None)

        mock_coordinator = MagicMock()
        mock_api = MagicMock()
        mock_api.session_play = AsyncMock(return_value=False)  # Device rejected command
        mock_api.get_item = AsyncMock(return_value={"Id": "movie_123", "Type": "Movie", "Name": "Inception"})
        mock_coordinator._api = mock_api
        mock_coordinator.entry.data = {"user_id": "user_abc"}
        mock_coordinator.entry.runtime_data.session.data = [{"Id": "session_999", "DeviceId": "living_room_guid"}]

        with patch("custom_components.jellyha.services._get_coordinator", return_value=mock_coordinator):
            await async_register_services(mock_hass)

            session_play_func = registered_services["session_play"]

            call = MagicMock()
            call.data = {
                "entity_id": target_entity,
                "item_id": "movie_123",
            }

            with self.assertRaises(HomeAssistantError) as ctx:
                await session_play_func(call)

            self.assertIn("The device rejected the playback command", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
