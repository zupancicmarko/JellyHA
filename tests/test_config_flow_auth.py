"""Unit tests for JellyHA config flow authentication (Issue #64)."""
import unittest
from unittest.mock import MagicMock, AsyncMock, patch

import tests.ha_mock  # Load HA mock environment
from custom_components.jellyha.config_flow import JellyHAConfigFlow
from custom_components.jellyha.api import JellyfinAuthError, JellyfinConnectionError
from custom_components.jellyha.const import CONF_USERNAME, CONF_PASSWORD, CONF_SERVER_URL


class TestConfigFlowAuth(unittest.IsolatedAsyncioTestCase):
    """Test suite ensuring non-admin and admin users can authenticate seamlessly."""

    def setUp(self):
        self.flow = JellyHAConfigFlow()
        self.flow.hass = MagicMock()
        self.flow.context = {}
        self.flow._server_url = "http://jellyfin.local:8096"
        self.flow.async_step_user_select = AsyncMock(return_value={"type": "form", "step_id": "user_select"})
        self.flow.async_step_library_select = AsyncMock(return_value={"type": "form", "step_id": "library_select"})
        self.flow.async_show_form = MagicMock(return_value={"type": "form", "step_id": "auth_login"})

    @patch("custom_components.jellyha.config_flow.JellyfinApiClient")
    async def test_non_admin_login_succeeds(self, mock_api_cls):
        """Verify non-admin user login succeeds even when get_users returns 403 Forbidden (Issue #64)."""
        mock_api = MagicMock()
        mock_api_cls.return_value = mock_api

        # 1. authenticate succeeds with AccessToken and user metadata
        mock_api.authenticate = AsyncMock(return_value={
            "AccessToken": "valid_session_token_789",
            "ServerId": "server_guid_123",
            "User": {
                "Id": "alice_guid_456",
                "Name": "Alice",
            },
        })

        # 2. get_users raises 403 Forbidden because Alice is not a server admin
        mock_api.get_users = AsyncMock(side_effect=JellyfinAuthError("Access forbidden"))

        # 3. get_libraries succeeds for Alice
        mock_api.get_libraries = AsyncMock(return_value=[
            {"Id": "lib_movies", "Name": "Movies", "CollectionType": "movies"}
        ])

        # Execute auth_login step with Alice's credentials
        result = await self.flow.async_step_auth_login({
            CONF_USERNAME: "Alice",
            CONF_PASSWORD: "CorrectPassword123",
        })

        # Verify authentication succeeded and advanced to library_select
        self.assertEqual(self.flow._api_key, "valid_session_token_789")
        self.assertEqual(self.flow._user_id, "alice_guid_456")
        self.assertEqual(self.flow._username, "Alice")
        self.assertEqual(len(self.flow._users), 1)
        self.assertEqual(self.flow._users[0]["Id"], "alice_guid_456")

        mock_api.get_libraries.assert_called_once_with("alice_guid_456")
        self.flow.async_step_library_select.assert_called_once()
        self.assertEqual(result, {"type": "form", "step_id": "library_select"})

    @patch("custom_components.jellyha.config_flow.JellyfinApiClient")
    async def test_admin_login_proceeds_to_user_select(self, mock_api_cls):
        """Verify admin user login can list all users and proceeds to user_select."""
        mock_api = MagicMock()
        mock_api_cls.return_value = mock_api

        mock_api.authenticate = AsyncMock(return_value={
            "AccessToken": "admin_session_token",
            "ServerId": "server_guid_123",
            "User": {
                "Id": "admin_guid",
                "Name": "Admin",
            },
        })

        # get_users succeeds for admin
        mock_api.get_users = AsyncMock(return_value=[
            {"Id": "admin_guid", "Name": "Admin"},
            {"Id": "alice_guid", "Name": "Alice"},
        ])

        result = await self.flow.async_step_auth_login({
            CONF_USERNAME: "Admin",
            CONF_PASSWORD: "AdminPassword",
        })

        self.assertEqual(len(self.flow._users), 2)
        mock_api.get_users.assert_called_once()
        self.flow.async_step_user_select.assert_called_once()
        self.assertEqual(result, {"type": "form", "step_id": "user_select"})

    @patch("custom_components.jellyha.config_flow.JellyfinApiClient")
    async def test_invalid_credentials_returns_error(self, mock_api_cls):
        """Verify truly invalid credentials still return invalid_auth error."""
        mock_api = MagicMock()
        mock_api_cls.return_value = mock_api

        mock_api.authenticate = AsyncMock(side_effect=JellyfinAuthError("Invalid username or password"))

        result = await self.flow.async_step_auth_login({
            CONF_USERNAME: "WrongUser",
            CONF_PASSWORD: "WrongPassword",
        })

        # async_show_form should be called with invalid_auth in errors
        self.flow.async_show_form.assert_called_once()
        call_kwargs = self.flow.async_show_form.call_args[1]
        self.assertEqual(call_kwargs["errors"]["base"], "invalid_auth")

    @patch("custom_components.jellyha.config_flow.JellyfinApiClient")
    async def test_non_admin_device_select_skips_cleanly(self, mock_api_cls):
        """Verify device selection step advances directly to instance label when get_devices returns 403."""
        mock_api = MagicMock()
        mock_api_cls.return_value = mock_api
        mock_api.get_devices = AsyncMock(side_effect=JellyfinAuthError("Access forbidden to /Devices"))

        self.flow._server_url = "http://jellyfin.local:8096"
        self.flow._api_key = "non_admin_token"
        self.flow.async_step_instance_label = AsyncMock(return_value={"type": "form", "step_id": "instance_label"})

        result = await self.flow.async_step_device_select()

        # Should automatically skip showing the empty device picker
        self.flow.async_step_instance_label.assert_called_once()
        self.assertEqual(result, {"type": "form", "step_id": "instance_label"})

    @patch("custom_components.jellyha.config_flow.JellyfinApiClient")
    async def test_admin_device_select_shows_devices(self, mock_api_cls):
        """Verify device selection step displays available devices when user is admin."""
        mock_api = MagicMock()
        mock_api_cls.return_value = mock_api
        mock_api.get_devices = AsyncMock(return_value=[
            {"Id": "dev_1", "Name": "Living Room TV", "AppName": "AndroidTV"},
            {"Id": "dev_2", "Name": "Chrome Browser", "AppName": "Jellyfin Web"},
        ])

        self.flow._server_url = "http://jellyfin.local:8096"
        self.flow._api_key = "admin_token"
        self.flow.async_show_form = MagicMock(return_value={"type": "form", "step_id": "device_select"})

        result = await self.flow.async_step_device_select()

        self.flow.async_show_form.assert_called_once()
        self.assertEqual(result["step_id"], "device_select")

    async def test_non_admin_instance_label_creates_entry(self):
        """Verify instance label step correctly creates the config entry with user metadata."""
        self.flow._server_url = "http://jellyfin.local:8096"
        self.flow._api_key = "non_admin_token"
        self.flow._user_id = "alice_guid"
        self.flow._username = "Alice"
        self.flow._server_id = "server_123"
        self.flow._users = [{"Id": "alice_guid", "Name": "Alice"}]
        self.flow._selected_libraries = ["lib_1"]
        self.flow.async_set_unique_id = AsyncMock()
        self.flow._abort_if_unique_id_configured = MagicMock()
        self.flow.async_create_entry = MagicMock(return_value={"type": "create_entry"})

        result = await self.flow.async_step_instance_label({"instance_label": "Bedroom"})

        self.flow.async_set_unique_id.assert_called_once_with("server_123_alice_guid_bedroom")
        self.flow.async_create_entry.assert_called_once()
        create_kwargs = self.flow.async_create_entry.call_args[1]
        self.assertEqual(create_kwargs["title"], "JellyHA Bedroom (Alice)")
        self.assertEqual(create_kwargs["data"]["username"], "Alice")
        self.assertEqual(create_kwargs["data"]["user_id"], "alice_guid")
        self.assertEqual(create_kwargs["data"]["api_key"], "non_admin_token")
        self.assertEqual(result, {"type": "create_entry"})


if __name__ == "__main__":
    unittest.main()
