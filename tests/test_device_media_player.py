"""Unit tests for JellyHA device media player naming, icon resolution, and session matching."""
import os
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import tests.ha_mock

from custom_components.jellyha.const import CONF_DEVICE_NAMES, CONF_DEVICE_PLAYERS
from custom_components.jellyha.media_player import (
    JellyHADeviceMediaPlayer,
    async_setup_entry as media_player_async_setup_entry,
)
from custom_components.jellyha.config_flow import JellyHAConfigFlow


class TestDeviceMediaPlayer(unittest.IsolatedAsyncioTestCase):
    """Test suite for device media player client name display and matching."""

    def setUp(self):
        self.mock_coordinator = MagicMock()
        self.mock_entry = MagicMock()
        self.mock_entry.entry_id = "test_entry_id"

    def test_device_name_formatting(self):
        """Verify device entity names preserve client/app info and avoid double Device prefixes."""
        player_moonfin = JellyHADeviceMediaPlayer(
            self.mock_coordinator,
            self.mock_entry,
            "dev_1",
            "samsung SM-S911B (Moonfin for Android)",
            "JellyHA",
        )
        self.assertEqual(
            player_moonfin._attr_name,
            "Device samsung SM-S911B (Moonfin for Android)",
        )

        player_android = JellyHADeviceMediaPlayer(
            self.mock_coordinator,
            self.mock_entry,
            "dev_2",
            "samsung SM-S911B (Android)",
            "JellyHA",
        )
        self.assertEqual(
            player_android._attr_name,
            "Device samsung SM-S911B (Android)",
        )

        player_prefixed = JellyHADeviceMediaPlayer(
            self.mock_coordinator,
            self.mock_entry,
            "dev_3",
            "Device LG Smart TV (Jellyfin Web)",
            "JellyHA",
        )
        self.assertEqual(
            player_prefixed._attr_name,
            "Device LG Smart TV (Jellyfin Web)",
        )

    def test_device_icon_detection(self):
        """Verify phone, tablet, and TV icon detection for various devices."""
        # Samsung SM-S911B model code should resolve to phone icon
        player_phone = JellyHADeviceMediaPlayer(
            self.mock_coordinator,
            self.mock_entry,
            "dev_1",
            "samsung SM-S911B (Android)",
            "JellyHA",
        )
        self.assertEqual(player_phone._attr_icon, "mdi:cellphone-play")

        # Tablet
        player_tab = JellyHADeviceMediaPlayer(
            self.mock_coordinator,
            self.mock_entry,
            "dev_2",
            "Galaxy Tab S8 (Android)",
            "JellyHA",
        )
        self.assertEqual(player_tab._attr_icon, "mdi:tablet-play")

        # TV
        player_tv = JellyHADeviceMediaPlayer(
            self.mock_coordinator,
            self.mock_entry,
            "dev_3",
            "LG Smart TV (Jellyfin Web)",
            "JellyHA",
        )
        self.assertEqual(player_tv._attr_icon, "mdi:television-play")

    def test_device_session_matching_distinguishes_clients_on_same_device(self):
        """Verify sessions on the same physical hardware match the correct client entity."""
        moonfin_player = JellyHADeviceMediaPlayer(
            self.mock_coordinator,
            self.mock_entry,
            "dev_db_id_1",
            "samsung SM-S911B (Moonfin for Android)",
            "JellyHA",
        )
        android_player = JellyHADeviceMediaPlayer(
            self.mock_coordinator,
            self.mock_entry,
            "dev_db_id_2",
            "samsung SM-S911B (Android)",
            "JellyHA",
        )

        moonfin_session = {
            "Id": "sess_1",
            "DeviceId": "client_hardware_uuid",
            "DeviceName": "samsung SM-S911B",
            "Client": "Moonfin for Android",
        }
        android_session = {
            "Id": "sess_2",
            "DeviceId": "client_hardware_uuid",
            "DeviceName": "samsung SM-S911B",
            "Client": "Android",
        }
        jellyfin_android_session = {
            "Id": "sess_3",
            "DeviceId": "client_hardware_uuid",
            "DeviceName": "samsung SM-S911B",
            "Client": "Jellyfin Android",
        }

        # Moonfin session matches Moonfin player, NOT Android player
        self.assertTrue(moonfin_player._is_matching_device_session(moonfin_session))
        self.assertFalse(android_player._is_matching_device_session(moonfin_session))

        # Android session matches Android player, NOT Moonfin player
        self.assertTrue(android_player._is_matching_device_session(android_session))
        self.assertFalse(moonfin_player._is_matching_device_session(android_session))

        # Jellyfin Android session matches Android player due to prefix normalization
        self.assertTrue(android_player._is_matching_device_session(jellyfin_android_session))
        self.assertFalse(moonfin_player._is_matching_device_session(jellyfin_android_session))

    def test_config_flow_device_select_preserves_client_in_device_map(self):
        """Verify config flow device select step maps device ID to full label with client info."""
        flow = JellyHAConfigFlow()
        flow._server_url = "http://jellyfin.local:8096"
        flow._api_key = "admin_token"
        flow._devices = [
            {"Id": "dev_1", "Name": "samsung SM-S911B", "AppName": "Moonfin for Android"},
            {"Id": "dev_2", "Name": "samsung SM-S911B", "AppName": "Android"},
            {"Id": "dev_3", "Name": "LG Smart TV", "AppName": "Jellyfin Web"},
        ]
        flow.async_show_form = MagicMock(return_value={"type": "form", "step_id": "device_select"})

        # Step into device select (get form)
        flow.hass = MagicMock()
        import asyncio
        asyncio.run(flow.async_step_device_select())

        self.assertEqual(
            flow._device_map["dev_1"],
            "samsung SM-S911B (Moonfin for Android)",
        )
        self.assertEqual(
            flow._device_map["dev_2"],
            "samsung SM-S911B (Android)",
        )
        self.assertEqual(
            flow._device_map["dev_3"],
            "LG Smart TV (Jellyfin Web)",
        )

    async def test_async_setup_entry_enriches_device_names(self):
        """Verify media player setup dynamically enriches configured device names from Jellyfin API."""
        mock_hass = MagicMock()
        mock_entry = MagicMock()
        mock_entry.data = {}
        mock_entry.options = {
            CONF_DEVICE_PLAYERS: ["dev_1", "dev_2"],
            CONF_DEVICE_NAMES: {
                "dev_1": "samsung SM-S911B",
                "dev_2": "samsung SM-S911B",
            },
        }

        mock_api = MagicMock()
        mock_api.get_devices = AsyncMock(return_value=[
            {"Id": "dev_1", "Name": "samsung SM-S911B", "AppName": "Moonfin for Android"},
            {"Id": "dev_2", "Name": "samsung SM-S911B", "AppName": "Android"},
        ])

        mock_session_coord = MagicMock()
        mock_session_coord.api = mock_api
        mock_session_coord.users = {}

        mock_lib_coord = MagicMock()

        mock_entry.runtime_data = MagicMock()
        mock_entry.runtime_data.library = mock_lib_coord
        mock_entry.runtime_data.session = mock_session_coord

        added_entities = []
        def async_add_entities(entities):
            added_entities.extend(entities)

        await media_player_async_setup_entry(mock_hass, mock_entry, async_add_entities)

        device_players = [e for e in added_entities if isinstance(e, JellyHADeviceMediaPlayer)]
        self.assertEqual(len(device_players), 2)

        names = {dp._attr_name for dp in device_players}
        self.assertIn("Device samsung SM-S911B (Moonfin for Android)", names)
        self.assertIn("Device samsung SM-S911B (Android)", names)


if __name__ == "__main__":
    unittest.main()
