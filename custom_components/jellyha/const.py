"""Constants for JellyHA integration."""

DOMAIN = "jellyha"

# Configuration keys
CONF_SERVER_URL = "server_url"
CONF_API_KEY = "api_key"
CONF_USERNAME = "username"
CONF_PASSWORD = "password"
CONF_AUTH_METHOD = "auth_method"
CONF_USER_ID = "user_id"
CONF_LIBRARIES = "libraries"
CONF_REFRESH_INTERVAL = "refresh_interval"
CONF_DEVICE_NAME = "device_name"

# Defaults
DEFAULT_REFRESH_INTERVAL = 300  # 5 minutes
DEFAULT_DEVICE_NAME = "JellyHA"
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

# Rating sources
RATING_SOURCE_IMDB = "imdb"
RATING_SOURCE_TMDB = "tmdb"
RATING_SOURCE_AUTO = "auto"

# WebSocket Events
EVENT_SESSIONS = "Sessions"
