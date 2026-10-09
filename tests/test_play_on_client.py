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


if __name__ == "__main__":
    unittest.main()
