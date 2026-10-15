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

ALLOWED_MEDIA_TYPES: frozenset[str] = frozenset({"Audio", "Videos"})
ALLOWED_HLS_EXTENSIONS: frozenset[str] = frozenset({".m3u8", ".ts", ".m4s", ".mp4", ".key"})


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
