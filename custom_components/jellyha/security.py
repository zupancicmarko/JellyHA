"""Centralized security and input validation module for JellyHA."""
from __future__ import annotations

import re
from typing import Any

UUID_HEX_RE = re.compile(
    r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
ENTRY_ID_RE = re.compile(r"^[0-9a-zA-Z_]{16,36}$")
STREAM_INDEX_RE = re.compile(r"^\d{1,5}$")

ALLOWED_IMAGE_TYPES: frozenset[str] = frozenset({
    "Primary",
    "Backdrop",
    "Banner",
    "Thumb",
    "Logo",
    "Art",
    "Disc",
    "Box",
    "Screenshot",
})

ALLOWED_IMAGE_FORMATS: frozenset[str] = frozenset({"webp", "jpg", "jpeg", "png", "gif"})
ALLOWED_MEDIA_TYPES: frozenset[str] = frozenset({"Audio", "Videos"})
ALLOWED_HLS_EXTENSIONS: frozenset[str] = frozenset({".m3u8", ".ts", ".m4s", ".mp4", ".key", ".vtt", ".webvtt"})

SESSION_ID_RE = re.compile(r"^[0-9a-zA-Z_-]{1,64}$")

ALLOWED_GENERAL_COMMANDS: frozenset[str] = frozenset({
    "SetVolume",
    "Mute",
    "Unmute",
    "ToggleMute",
    "VolumeUp",
    "VolumeDown",
    "SetAudioStreamIndex",
    "SetSubtitleStreamIndex",
    "SetRepeatMode",
    "SetShuffleQueue",
    "DisplayContent",
    "DisplayMessage",
    "GoHome",
    "GoToSettings",
    "GoToSearch",
    "SendString",
    "Back",
    "MoveUp",
    "MoveDown",
    "MoveLeft",
    "MoveRight",
    "Select",
    "Guide",
    "ToggleFullscreen",
    "TakeScreenshot",
    "Play",
    "Playstate",
})


def is_valid_item_id(val: Any) -> bool:
    """Return True if val is a valid 32-hex or hyphenated UUID item ID."""
    if not val or not isinstance(val, str):
        return False
    val = val.strip()
    return bool(UUID_HEX_RE.match(val))


def validate_item_id(val: Any) -> str:
    """Validate and return normalized lowercase 32-character hex item ID.

    Raises ValueError if val is invalid or contains traversal characters.
    """
    if not is_valid_item_id(val):
        raise ValueError(f"Invalid Jellyfin item ID: {val!r}")
    return str(val).strip().replace("-", "").lower()


def is_valid_session_id(val: Any) -> bool:
    """Return True if val is a valid session ID."""
    if not val or not isinstance(val, str):
        return False
    val = val.strip()
    return bool(SESSION_ID_RE.match(val))


def validate_session_id(val: Any) -> str:
    """Validate and return sanitized session ID, or raise ValueError."""
    if not is_valid_session_id(val):
        raise ValueError(f"Invalid Jellyfin session ID: {val!r}")
    return str(val).strip()


def is_valid_general_command(val: Any) -> bool:
    """Return True if val is an allowed Jellyfin general command."""
    if not val or not isinstance(val, str):
        return False
    return val.strip() in ALLOWED_GENERAL_COMMANDS


def validate_general_command(val: Any) -> str:
    """Validate and return allowed general command name, or raise ValueError."""
    if not is_valid_general_command(val):
        raise ValueError(f"Invalid or disallowed session general command: {val!r}")
    return str(val).strip()


def is_valid_entry_id(val: Any) -> bool:
    """Return True if val is a valid alphanumeric/ULID config entry ID."""
    if not val or not isinstance(val, str):
        return False
    val = val.strip()
    return bool(ENTRY_ID_RE.match(val))


def validate_entry_id(val: Any) -> str:
    """Validate and return config entry ID, or raise ValueError."""
    if not is_valid_entry_id(val):
        raise ValueError(f"Invalid config entry ID: {val!r}")
    return str(val).strip()


def is_valid_stream_index(val: Any) -> bool:
    """Return True if val represents a non-negative integer stream index."""
    if val is None or val == "":
        return False
    if isinstance(val, int):
        return 0 <= val <= 99999
    if isinstance(val, str):
        return bool(STREAM_INDEX_RE.match(val.strip()))
    return False
