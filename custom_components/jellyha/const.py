"""Constants for JellyHA integration."""

DOMAIN = "jellyha"
# Configuration keys
CONF_SERVER_URL = "server_url"
CONF_EXTERNAL_URL = "external_url"
CONF_API_KEY = "api_key"
CONF_USERNAME = "username"
CONF_PASSWORD = "password"
CONF_AUTH_METHOD = "auth_method"
CONF_USER_ID = "user_id"
CONF_LIBRARIES = "libraries"
CONF_REFRESH_INTERVAL = "refresh_interval"
CONF_DEVICE_NAME = "device_name"
CONF_INSTANCE_LABEL = "instance_label"

# Defaults
DEFAULT_REFRESH_INTERVAL = 3600  # 1 hour
DEFAULT_DEVICE_NAME = "JellyHA"

# Refresh interval dropdown options: list of (label, seconds)
# Value 0 = Off (disables polling)
REFRESH_INTERVAL_OPTIONS: list[tuple[str, int]] = [
    ("Off", 0),
    ("1 minute", 60),
    ("5 minutes", 300),
    ("15 minutes", 900),
    ("30 minutes", 1800),
    ("1 hour", 3600),
    ("2 hours", 7200),
    ("6 hours", 21600),
    ("12 hours", 43200),
    ("24 hours", 86400),
]

# Set of valid refresh interval values (for migration/validation)
REFRESH_INTERVAL_VALUES: set[int] = {v for _, v in REFRESH_INTERVAL_OPTIONS}


def migrate_refresh_interval(raw_value: int) -> int:
    """Convert a legacy seconds value to the nearest valid dropdown option.

    This ensures backward compatibility when upgrading from the old
    seconds-based number slider to the new dropdown.
    """
    if raw_value in REFRESH_INTERVAL_VALUES:
        return raw_value
    # Find the closest valid non-zero value (never snap to 0/Off automatically)
    valid_sorted = sorted(v for v in REFRESH_INTERVAL_VALUES if v > 0)
    return min(valid_sorted, key=lambda v: abs(v - raw_value))
DEFAULT_IMAGE_QUALITY = 90
DEFAULT_IMAGE_HEIGHT = 500

# API
API_TIMEOUT = 10
MAX_RETRIES = 3
RETRY_BACKOFF_FACTOR = 2

# Item types
ITEM_TYPE_MOVIE = "Movie"
ITEM_TYPE_SERIES = "Series"
ITEM_TYPE_EPISODE = "Episode"
ITEM_TYPE_AUDIO = "Audio"
ITEM_TYPE_MUSIC_ALBUM = "MusicAlbum"
ITEM_TYPE_MUSIC_ARTIST = "MusicArtist"
ITEM_TYPE_MUSIC_VIDEO = "MusicVideo"
ITEM_TYPE_VIDEO = "Video"
ITEM_TYPE_PHOTO = "Photo"
TICKS_PER_MINUTE = 600000000
TICKS_PER_SECOND = 10000000

# Rating sources
RATING_SOURCE_IMDB = "imdb"
RATING_SOURCE_TMDB = "tmdb"
RATING_SOURCE_AUTO = "auto"

# WebSocket Events
EVENT_SESSIONS = "Sessions"
