import unittest
import tests.ha_mock  # Load HA mock environment

from custom_components.jellyha.security import (
    ALLOWED_GENERAL_COMMANDS,
    ALLOWED_HLS_EXTENSIONS,
    ALLOWED_IMAGE_FORMATS,
    ALLOWED_IMAGE_TYPES,
    ALLOWED_MEDIA_TYPES,
    is_valid_entry_id,
    is_valid_general_command,
    is_valid_item_id,
    is_valid_session_id,
    is_valid_stream_index,
    validate_entry_id,
    validate_general_command,
    validate_item_id,
    validate_session_id,
)


class TestSecurityValidation(unittest.TestCase):
    """Test security validation rules."""

    def test_valid_item_ids(self) -> None:
        """Ensure standard 32-hex and hyphenated UUIDs pass and normalize."""
        # Standard 32-hex
        hex_id = "11d6bf041f2b4cfbbae8d4f17fa2ab2e"
        self.assertTrue(is_valid_item_id(hex_id))
        self.assertEqual(validate_item_id(hex_id), hex_id)

        # Hyphenated UUID
        uuid_id = "11d6bf04-1f2b-4cfb-bae8-d4f17fa2ab2e"
        self.assertTrue(is_valid_item_id(uuid_id))
        self.assertEqual(validate_item_id(uuid_id), hex_id)

        # Uppercase normalized to lowercase
        upper_id = "11D6BF041F2B4CFBBAE8D4F17FA2AB2E"
        self.assertTrue(is_valid_item_id(upper_id))
        self.assertEqual(validate_item_id(upper_id), hex_id)

    def test_invalid_and_traversal_item_ids(self) -> None:
        """Ensure path traversal payloads and malformed IDs are strictly rejected."""
        traversal_payloads = [
            "../Users/admin",
            "..%2F..%2FSystem%2FConfiguration",
            "/etc/passwd",
            "item_id/../../",
            "11d6bf041f2b4cfbbae8d4f17fa2ab2e/delete",
            "; DROP TABLE items; --",
            "<script>alert(1)</script>",
            "",
            None,
            "short",
            "11d6bf041f2b4cfbbae8d4f17fa2ab2e0000",  # 36 chars non-uuid
        ]
        for payload in traversal_payloads:
            with self.subTest(payload=payload):
                self.assertFalse(is_valid_item_id(payload))
                with self.assertRaises(ValueError):
                    validate_item_id(payload)

    def test_entry_id_validation(self) -> None:
        """Ensure config entry IDs accept alphanumeric identifiers and reject traversals."""
        valid_entries = [
            "01KM6Z3F4HPQZ6QED9SJP1RWA9",
            "01KMBE8QY54E8PPTNKYYD3FXGT",
            "01M4JX4RYHYJFCAKEZHM1NY1XE",
            "entry_1234567890",
        ]
        for entry_id in valid_entries:
            with self.subTest(entry_id=entry_id):
                self.assertTrue(is_valid_entry_id(entry_id))
                self.assertEqual(validate_entry_id(entry_id), entry_id)

        invalid_entries = [
            "../entry_id",
            "01KM6Z3F4HPQZ6QED9SJP1RWA9/../",
            "",
            None,
            "short",
            "invalid entry spaces",
        ]
        for entry_id in invalid_entries:
            with self.subTest(entry_id=entry_id):
                self.assertFalse(is_valid_entry_id(entry_id))
                with self.assertRaises(ValueError):
                    validate_entry_id(entry_id)

    def test_session_id_validation(self) -> None:
        """Ensure session IDs accept valid alphanumerics and reject traversal payloads."""
        self.assertTrue(is_valid_session_id("session_999"))
        self.assertTrue(is_valid_session_id("c03b1234abcd5678ef90123456789abc"))
        self.assertTrue(is_valid_session_id("my-device-session-123"))
        self.assertEqual(validate_session_id("session_999"), "session_999")

        invalid_sessions = [
            "../sessions/other",
            "..%2F..%2FSystem",
            "/root/session",
            "session/../",
            "; rm -rf",
            "",
            None,
            "a" * 65,
        ]
        for s in invalid_sessions:
            with self.subTest(session=s):
                self.assertFalse(is_valid_session_id(s))
                with self.assertRaises(ValueError):
                    validate_session_id(s)

    def test_general_command_validation(self) -> None:
        """Ensure general commands only allow whitelisted Jellyfin commands."""
        for cmd in ["SetVolume", "Mute", "Unmute", "ToggleMute", "VolumeUp", "VolumeDown", "DisplayMessage"]:
            with self.subTest(cmd=cmd):
                self.assertTrue(is_valid_general_command(cmd))
                self.assertEqual(validate_general_command(cmd), cmd)

        invalid_commands = [
            "ArbitraryCommand",
            "DeleteMedia",
            "ExecuteScript",
            "../Command",
            "",
            None,
        ]
        for cmd in invalid_commands:
            with self.subTest(cmd=cmd):
                self.assertFalse(is_valid_general_command(cmd))
                with self.assertRaises(ValueError):
                    validate_general_command(cmd)

    def test_allowed_types(self) -> None:
        """Ensure allowed image types and media types match Jellyfin standards."""
        self.assertIn("Primary", ALLOWED_IMAGE_TYPES)
        self.assertIn("Backdrop", ALLOWED_IMAGE_TYPES)
        self.assertIn("Thumb", ALLOWED_IMAGE_TYPES)
        self.assertNotIn("../../secret", ALLOWED_IMAGE_TYPES)
        self.assertNotIn("System", ALLOWED_IMAGE_TYPES)

        self.assertIn("Videos", ALLOWED_MEDIA_TYPES)
        self.assertIn("Audio", ALLOWED_MEDIA_TYPES)
        self.assertNotIn("Users", ALLOWED_MEDIA_TYPES)
        self.assertNotIn("System", ALLOWED_MEDIA_TYPES)

        self.assertIn("webp", ALLOWED_IMAGE_FORMATS)
        self.assertIn("jpg", ALLOWED_IMAGE_FORMATS)
        self.assertIn("png", ALLOWED_IMAGE_FORMATS)

        self.assertIn(".m3u8", ALLOWED_HLS_EXTENSIONS)
        self.assertIn(".ts", ALLOWED_HLS_EXTENSIONS)
        self.assertIn(".vtt", ALLOWED_HLS_EXTENSIONS)
        self.assertIn(".webvtt", ALLOWED_HLS_EXTENSIONS)

    def test_stream_index_validation(self) -> None:
        """Ensure stream indices only accept positive integer values."""
        self.assertTrue(is_valid_stream_index("0"))
        self.assertTrue(is_valid_stream_index("1"))
        self.assertTrue(is_valid_stream_index(2))
        self.assertTrue(is_valid_stream_index("12"))

        self.assertFalse(is_valid_stream_index("-1"))
        self.assertFalse(is_valid_stream_index("0/../"))
        self.assertFalse(is_valid_stream_index("abc"))
        self.assertFalse(is_valid_stream_index(None))
        self.assertFalse(is_valid_stream_index(""))


if __name__ == "__main__":
    unittest.main()
