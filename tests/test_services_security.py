"""Tests for service hardening, admin permissions, and input validation."""
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import tests.ha_mock
from homeassistant.core import Context, HomeAssistant, ServiceCall
from homeassistant.exceptions import HomeAssistantError

from custom_components.jellyha.const import DOMAIN
from custom_components.jellyha.services import async_register_services


class TestServicesSecurity(unittest.IsolatedAsyncioTestCase):
    """Test suite ensuring services are secure against unauthorized calls and traversal."""

    async def asyncSetUp(self) -> None:
        self.mock_hass = MagicMock()
        self.mock_hass.data = {DOMAIN: {}}
        self.mock_hass.states = MagicMock()
        self.mock_hass.services = MagicMock()
        self.mock_hass.auth = MagicMock()
        self.registered_services = {}

        def mock_has_service(domain, name):
            return name in self.registered_services

        def mock_async_register(domain, service, func, schema=None, supports_response=None):
            self.registered_services[service] = func

        self.mock_hass.services.has_service = mock_has_service
        self.mock_hass.services.async_register = mock_async_register

        # Mock coordinator and api
        self.mock_api = MagicMock()
        self.mock_api._request = AsyncMock()
        self.mock_api.update_favorite = AsyncMock()
        self.mock_api.update_played_status = AsyncMock()

        self.mock_coordinator = MagicMock()
        self.mock_coordinator._api = self.mock_api
        self.mock_coordinator.entry = MagicMock()
        self.mock_coordinator.entry.data = {"user_id": "test_user_id"}
        self.mock_coordinator.async_refresh = AsyncMock()
        self.mock_coordinator.async_remove_item_from_cache = AsyncMock()

        # Config entry mock
        self.mock_entry = MagicMock()
        self.mock_entry.entry_id = "01KM6Z3F4HPQZ6QED9SJP1RWA9"
        self.mock_entry.runtime_data = MagicMock()
        self.mock_entry.runtime_data.library = self.mock_coordinator

        self.mock_hass.config_entries = MagicMock()
        self.mock_hass.config_entries.async_get_entry = MagicMock(return_value=self.mock_entry)
        self.mock_hass.config_entries.async_entries = MagicMock(return_value=[self.mock_entry])

        # Register services
        await async_register_services(self.mock_hass)

    async def test_delete_item_rejected_for_non_admin_user(self) -> None:
        """Ensure delete_item raises HomeAssistantError when called by a non-admin user."""
        delete_func = self.registered_services["delete_item"]

        # Mock non-admin user
        mock_user = MagicMock()
        mock_user.is_admin = False
        self.mock_hass.auth.async_get_user = AsyncMock(return_value=mock_user)

        call = MagicMock()
        call.data = {"item_id": "11d6bf041f2b4cfbbae8d4f17fa2ab2e"}
        call.context = MagicMock()
        call.context.user_id = "regular_user_123"

        with self.assertRaises(HomeAssistantError) as cm:
            await delete_func(call)
        self.assertIn("Only administrators can delete", str(cm.exception))
        self.mock_api._request.assert_not_called()

    async def test_delete_item_allowed_for_admin_user(self) -> None:
        """Ensure delete_item succeeds when called by an administrator."""
        delete_func = self.registered_services["delete_item"]

        # Mock admin user
        mock_user = MagicMock()
        mock_user.is_admin = True
        self.mock_hass.auth.async_get_user = AsyncMock(return_value=mock_user)

        call = MagicMock()
        call.data = {"item_id": "11d6bf041f2b4cfbbae8d4f17fa2ab2e"}
        call.context = MagicMock()
        call.context.user_id = "admin_user_456"

        await delete_func(call)
        self.mock_api._request.assert_called_once_with(
            "DELETE", "/Items/11d6bf041f2b4cfbbae8d4f17fa2ab2e"
        )

    async def test_delete_item_rejects_path_traversal(self) -> None:
        """Ensure delete_item rejects malicious path traversal item_id."""
        delete_func = self.registered_services["delete_item"]

        # Even with admin context, traversal must be blocked
        mock_user = MagicMock()
        mock_user.is_admin = True
        self.mock_hass.auth.async_get_user = AsyncMock(return_value=mock_user)

        call = MagicMock()
        call.data = {"item_id": "../Users/target_user_id"}
        call.context = MagicMock()
        call.context.user_id = "admin_user_456"

        with self.assertRaises(HomeAssistantError) as cm:
            await delete_func(call)
        self.assertIn("Invalid item ID", str(cm.exception))
        self.mock_api._request.assert_not_called()

    async def test_update_favorite_rejects_path_traversal(self) -> None:
        """Ensure update_favorite validates item_id."""
        fav_func = self.registered_services["update_favorite"]
        call = MagicMock()
        call.data = {"item_id": "../../System/Config", "is_favorite": True}
        call.context = MagicMock(user_id=None)

        with self.assertRaises(HomeAssistantError) as cm:
            await fav_func(call)
        self.assertIn("Invalid item ID", str(cm.exception))
        self.mock_api.update_favorite.assert_not_called()

    async def test_mark_watched_rejects_path_traversal(self) -> None:
        """Ensure mark_watched validates item_id."""
        watched_func = self.registered_services["mark_watched"]
        call = MagicMock()
        call.data = {"item_id": "malicious/../id", "is_played": True}
        call.context = MagicMock(user_id=None)

        with self.assertRaises(HomeAssistantError) as cm:
            await watched_func(call)
        self.assertIn("Invalid item ID", str(cm.exception))
        self.mock_api.update_played_status.assert_not_called()


    async def test_session_control_rejects_invalid_session_id(self) -> None:
        """Ensure session_control validates session_id."""
        ctrl_func = self.registered_services["session_control"]
        call = MagicMock()
        call.data = {"session_id": "../../sessions/1", "command": "Pause"}

        with self.assertRaises(HomeAssistantError) as cm:
            await ctrl_func(call)
        self.assertIn("Invalid session ID", str(cm.exception))

    async def test_session_general_command_validation(self) -> None:
        """Ensure session_general_command validates session_id and restricts commands."""
        gen_func = self.registered_services["session_general_command"]

        # Traversal session_id
        call = MagicMock()
        call.data = {"session_id": "../root", "command": "SetVolume"}
        with self.assertRaises(HomeAssistantError) as cm:
            await gen_func(call)
        self.assertIn("Invalid session ID", str(cm.exception))

        # Disallowed command
        call = MagicMock()
        call.data = {"session_id": "valid_session_1", "command": "ExecuteCustomShell"}
        with self.assertRaises(HomeAssistantError) as cm:
            await gen_func(call)
        self.assertIn("Invalid command", str(cm.exception))

    async def test_play_on_chromecast_rejects_invalid_item_id(self) -> None:
        """Ensure play_on_chromecast validates item_id."""
        play_func = self.registered_services["play_on_chromecast"]
        call = MagicMock()
        call.data = {
            "entity_id": "media_player.living_room_tv",
            "item_id": "../evil_path",
        }

        with self.assertRaises(HomeAssistantError) as cm:
            await play_func(call)
        self.assertIn("Invalid item ID", str(cm.exception))

    async def test_get_item_rejects_invalid_item_id(self) -> None:
        """Ensure get_item validates item_id."""
        get_item_func = self.registered_services["get_item"]
        call = MagicMock()
        call.data = {"item_id": "../bad_item"}

        with self.assertRaises(ValueError) as cm:
            await get_item_func(call)
        self.assertIn("Invalid item ID", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
