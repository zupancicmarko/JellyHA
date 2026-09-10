# Entities & Sensors Reference

JellyHA automatically generates and maintains a rich set of Home Assistant entities, including `media_player` devices, library statistics sensors, real-time stream monitors, disk storage meters, and latest media trackers.

All entities are prefixed with `sensor.jellyha_` or `media_player.jellyha_` (or custom prefix if configured).

---

## Media Players

JellyHA provides three classes of `media_player` entities:

### 1. Per-User Media Players

| Entity ID Pattern | Description | Supported Features |
|---|---|---|
| `media_player.jellyha_[username]` | Tracks and controls active playback for a specific user | **Transport:** Play, Pause, Stop, Seek, Next Track, Previous Track<br>**Volume:** Volume Set, Mute/Unmute<br>**Controls:** Shuffle, Repeat<br>**Metadata:** Title, Series/Season/Episode, Poster, Backdrop, Position, Chapters, Segments |

### 2. Client and Device Media Players

| Entity ID Pattern | Description | Supported Features |
|---|---|---|
| `media_player.jellyha_[device_name]` | Tracks playback on a specific physical device (e.g. Living Room TV, Bedroom Android Box) regardless of which user is watching | Full transport, volume, and metadata parity with per-user players, plus active `user_name`, `user_id`, and client device context |

> **Setup:** Enable client devices in **Settings -> Devices & Services -> JellyHA -> Configure** under **Client/Device Media Players**.

### 3. Library Browser Media Player

| Entity ID | Description | Supported Features |
|---|---|---|
| `media_player.jellyha_library_browser` | Browse and search your Jellyfin library | Browse Media, Play Media, Search Media |

Integrates directly with Home Assistant's Media Browser panel in the sidebar, supporting library exploration, search, and direct in-browser streaming.

---

### Remote Control on Mobile and TV Clients

- **Smart TVs** (LG webOS, Samsung Tizen), **Android TV streaming boxes** (Wholphin, Moonfin, Shield TV), and **Web Browsers** (Chrome, Firefox, Safari) support remote control (`supports_remote_control: true`) out of the box.
- The official **Jellyfin for Android** mobile app defaults to the **"Integrated player" (native ExoPlayer)**, which only reports progress to the server and ignores incoming remote control directives (`supports_remote_control: false`).
- **To enable full remote control on Android mobile devices:**
  1. Open the **Jellyfin** app on your phone or tablet.
  2. Tap your user avatar / gear icon to open **Settings**.
  3. Under **App**, select **Client Settings**.
  4. Tap **Video player type** and select **Web player**.

In Web player mode, playback maintains a full two-way WebSocket connection, allowing Home Assistant and dashboard cards to pause, resume, seek, and adjust volume seamlessly.

---

### Media Player States and Attributes

#### States
- `idle`: No active session
- `playing`: Media currently playing
- `paused`: Media currently paused

#### Key Attributes

| Attribute | Type | Description |
|---|---|---|
| `item_id` | string | Jellyfin item GUID |
| `media_title` | string | Current title or episode name |
| `media_series_title` | string | TV show title (episodes only) |
| `media_season` | number | Season number (episodes only) |
| `media_episode` | number | Episode number (episodes only) |
| `media_content_type` | string | `movie`, `tvshow`, `music`, or `video` |
| `media_image_url` | string | Authenticated poster image URL |
| `backdrop_url` | string | Authenticated backdrop/fanart image URL |
| `media_duration` | number | Total duration in seconds |
| `media_position` | number | Current position in seconds |
| `progress_percent` | number | Playback progress (0 - 100 %) |
| `runtime_minutes` | number | Total duration in minutes |
| `session_id` | string | Active Jellyfin session ID |
| `device_id` | string | Client hardware device GUID |
| `device_name` | string | Client device name |
| `client` | string | Client application name |
| `user_name` | string | Current viewer username (device players) |
| `user_id` | string | Current viewer user GUID |
| `genres` | list | Media genre array |
| `year` | number | Release or premiere year |
| `is_favorite` | boolean | Favorite status |
| `official_rating` | string | Certification rating (e.g. `R`, `PG-13`, `TV-MA`) |
| `community_rating` | number | Community score (0 - 10) |
| `media_chapter_name` | string | Active chapter title |
| `media_chapter_index` | number | Current chapter index |
| `media_segment_type` | string | Intro, Outro, or Recap scene marker |
| `segment_end_seconds` | number | Timestamp when current segment ends |
| `dynamic_range` | string | Classification: `SDR`, `HDR10`, `HDR10+`, `Dolby Vision`, `HLG` |
| `video_range_type` | string | Raw Jellyfin classification (e.g. `DOVIWithHDR10`, `HDR10`, `SDR`) |
| `dv_profile` | number | Dolby Vision profile number (e.g. `5`, `7`, `8`) |
| `video_codec` | string | Video codec (e.g. `hevc`, `av1`, `h264`) |
| `video_bit_depth` | number | Color bit depth (`8`, `10`) |
| `supports_remote_control` | boolean | Indicates whether client accepts remote commands |
| `config_entry_id` | string | Target JellyHA instance GUID |

#### Action Call Examples

```yaml
# Pause playback
service: media_player.media_pause
target:
  entity_id: media_player.jellyha_admin

# Seek to 5 minutes (300 seconds)
service: media_player.media_seek
target:
  entity_id: media_player.jellyha_admin
data:
  seek_position: 300

# Set volume to 50%
service: media_player.volume_set
target:
  entity_id: media_player.jellyha_admin
data:
  volume_level: 0.5
```

---

## Sensors

### Library Sensors

| Entity ID | Description | State | Key Attributes |
|---|---|---|---|
| `sensor.jellyha_library` | Primary library sensor | Total items count | `server_name`, `movies`, `series`, `videos`, `episodes`, `entry_id` |
| `sensor.jellyha_movies` | Total movies in library | Count of movies | `watched`, `unwatched`, `favorites`, `entry_id` |
| `sensor.jellyha_series` | Total TV series in library | Count of series | `watched`, `unwatched`, `favorites`, `total_episodes`, `unwatched_episodes`, `entry_id` |
| `sensor.jellyha_episodes` | Total episodes across all series | Count of episodes | `watched`, `unwatched`, `entry_id` |
| `sensor.jellyha_favorites` | Total favorite items | Count | `entry_id` |
| `sensor.jellyha_unwatched` | Total unwatched items | Count | `movies`, `series`, `episodes`, `entry_id` |
| `sensor.jellyha_unwatched_movies` | Unwatched movies | Count | `entry_id` |
| `sensor.jellyha_unwatched_series` | Unwatched TV series | Count | `entry_id` |
| `sensor.jellyha_unwatched_episodes` | Unwatched individual episodes | Count | `entry_id` |
| `sensor.jellyha_watched` | Total watched items | Count | `movies`, `series`, `episodes`, `entry_id` |
| `sensor.jellyha_watched_movies` | Watched movies | Count | `entry_id` |
| `sensor.jellyha_watched_series` | Watched TV series | Count | `entry_id` |
| `sensor.jellyha_watched_episodes` | Watched episodes | Count | `entry_id` |

### Latest Content Sensors

| Entity ID | Description | State | Key Attributes |
|---|---|---|---|
| `sensor.jellyha_latest_movie` | Most recently added movie | Movie title (e.g. `28 Years Later`) | `item_id`, `title`, `year`, `overview`, `genres`, `rating`, `runtime_minutes`, `date_added`, `poster_url`, `backdrop_url`, `dynamic_range`, `resolution`, `video_codec`, `container` |
| `sensor.jellyha_latest_episode` | Most recently added TV episode | Formatted episode name (e.g. `Severance - S02E01 - Hello`) | `item_id`, `title`, `series_name`, `series_id`, `season`, `episode`, `year`, `overview`, `genres`, `rating`, `runtime_minutes`, `date_added`, `poster_url`, `series_poster_url`, `backdrop_url`, `dynamic_range`, `resolution`, `video_codec`, `container` |

### Server and Storage Sensors

| Entity ID | Description | State | Attributes |
|---|---|---|---|
| `sensor.jellyha_websocket_status` | Connection state | `connected` / `disconnected` | - |
| `sensor.jellyha_jellyfin_version` | Jellyfin server version | e.g. `12.0.0` or `10.10.6` | - |
| `sensor.jellyha_active_sessions` | Active playback sessions | Count | `sessions` (list of active playback metadata) |
| `sensor.jellyha_connected_clients` | All connected Jellyfin clients (regardless of play state) | Count | `clients` (list: `user`, `device`, `client`, `last_activity_date`, `is_playing`) |
| `sensor.jellyha_transcoding_streams` | Active transcoding streams | Count | `transcode_sessions` (video/audio codecs, transcode reasons, framerate) |
| `sensor.jellyha_media_storage_free` | Free disk space on media drive | GB (e.g. `13853.9`) | `free_bytes`, `used_bytes`, `total_bytes`, `free_tb`, `used_tb`, `total_tb`, `used_percent`, `free_percent`, `devices` |
| `sensor.jellyha_media_storage_free_percentage` | Free disk space percentage | Percentage (e.g. `62` %) | `free_bytes`, `used_bytes`, `total_bytes`, `free_gb`, `used_gb`, `free_tb`, `used_tb`, `total_tb`, `used_percent`, `free_percent`, `devices` |
| `sensor.jellyha_last_refresh` | Last API sync timestamp | Timestamp | - |
| `sensor.jellyha_last_library_update` | Last library change timestamp | Timestamp | - |
| `sensor.jellyha_refresh_duration` | Duration of last sync cycle | e.g. `0.9s` | `duration_seconds` |

### User Sensors

| Entity ID Pattern | Description | State |
|---|---|---|
| `sensor.jellyha_now_playing_[user]` | Legacy real-time monitor for specific user | `playing`, `paused`, `idle` |

> Note: `sensor.jellyha_now_playing_[user]` is retained for backward compatibility. We recommend using `media_player.jellyha_[user]` for new dashboards and automations.

---

## Real-Time Updates Architecture

JellyHA uses a **WebSocket-first, API-fallback** architecture to minimize network traffic while maintaining instant state sync:

| Connection State | Update Mechanism | Latency |
|---|---|---|
| **WebSocket Connected** | Event push from Jellyfin | Instant (~100 ms) |
| **WebSocket Disconnected** | API polling every 5 seconds | Near real-time |

When JellyHA starts, it connects to the Jellyfin WebSocket and subscribes to session, playback, and library change events. If the connection is disrupted (e.g., server restart or network interruption), JellyHA automatically switches to 5-second polling until the WebSocket reconnects.
