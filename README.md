# JellyHA

[![HACS][hacs-badge]][hacs-url]
[![GitHub Release][release-badge]][release-url]

A Home Assistant integration and Lovelace card that displays media from your Jellyfin server.

**JellyHA Library** provides a beautiful way to showcase your media collection in Home Assistant.

![Card Preview](./docs/JellyHA-Library.png)

## Features

- 🎬 Display movies and TV shows from your library
- ⏭️ "Next Up" support to resume TV shows
- 🎨 Three layouts: Carousel, Grid, List
- 🌙 Automatic dark/light theme adaptation
- 🔗 Click to open in Jellyfin (new tab)
- ⭐ IMDB ratings for movies, TMDB for TV shows
- 🆕 "New" badge for recently added items
- 📂 Full integration with Home Assistant Media Browser
- 💾 Efficient local storage caching (no database bloat)
- ⚡ Instant loading via WebSocket
- 🌍 7 languages: English, German, French, Spanish, Italian, Dutch, Slovenian
- 🎛️ Graphical card editor (no YAML required)

## Session & Now Playing Updates

JellyHA uses a **WebSocket-first, API-fallback** strategy for real-time session monitoring. This powers the `active_sessions` sensor and per-user `now_playing` sensors.

| Connection State | Update Method | Speed |
|------------------|---------------|-------|
| **WebSocket Connected** | Push updates from Jellyfin | Instant (~100ms) |
| **WebSocket Disconnected** | API polling every 5 seconds | Near real-time |

**How it works:**
1. On startup, JellyHA connects to the Jellyfin WebSocket and subscribes to session events
2. While connected, session updates are pushed instantly — no polling required
3. If WebSocket disconnects (network issue, server restart), it automatically falls back to API polling
4. When WebSocket reconnects, polling stops and push updates resume

The `sensor.jellyha_websocket` sensor shows the current connection status (`connected`/`disconnected`).


## Media Browser

JellyHA integrates directly with the Home Assistant Media Browser. You can explore your Jellyfin libraries, play media on supported players, and even stream directly to your browser, all without leaving Home Assistant.

1. Go to **Media** in the sidebar.
2. Select **JellyHA**.
3. Browse your Movies, Series, and Music collections.

## Installation

JellyHA requires **two installation steps**: installing the integration and adding the dashboard card resource.

### Step 1: Install the Integration

[![My Home Assistant][my-ha-badge]][my-ha-url]

#### Via HACS (Recommended)

1. Open HACS in Home Assistant
2. Go to **Integrations** → **⋮** → **Custom repositories**
3. Add repository URL: `https://github.com/zupancicmarko/JellyHA`
4. Select Type: **Integration**
5. Click **ADD**
6. Search for **JellyHA** in HACS Integrations
7. Click **Download**
8. **Restart Home Assistant**

#### Manual Installation

1. Copy `custom_components/jellyha` to your `config/custom_components/` directory
2. **Restart Home Assistant**

### Step 2: Add Dashboard Card Resource

> **⚠️ Important:** This step is **required** even if you installed via HACS. The dashboard card will not work without it.

1. Go to **Settings** → **Dashboards**
2. Click **⋮** (three-dot menu) → **Resources**
3. Click **+ Add Resource**
4. Enter the URL based on your installation method:
   - **HACS:** `/hacsfiles/jellyha/jellyha-cards.js`
   - **Manual:** `/local/community/jellyha/jellyha-cards.js` (ensure you copied `dist/jellyha-cards.js` to `config/www/community/jellyha/`)
5. Select Resource type: **JavaScript Module**
6. Click **Create**

> **Note:** If you don't see the Resources menu, enable **Advanced Mode** in your user profile settings.

## Setup

1. Go to **Settings** → **Devices & Services** → **Add Integration**
2. Search for "JellyHA"
3. Enter your Jellyfin server URL and API key
4. Select the user and libraries to monitor

## Sensors

JellyHA provides several sensors to monitor your Jellyfin server and library. All sensors are prefixed with `sensor.jellyha_` (unless a custom device name was used during setup).

### Library Sensors

| Entity ID | Description | State | Attributes |
|-----------|-------------|-------|------------|
| `sensor.jellyha_library` | Primary library sensor | Count of items | `server_name`, `movies`, `series`, `episodes` |
| `sensor.jellyha_favorites` | Favorite items | Count | - |
| `sensor.jellyha_unwatched` | Total unwatched content | Count | `movies`, `series`, `episodes` |
| `sensor.jellyha_unwatched_movies` | Unwatched movies | Count | - |
| `sensor.jellyha_unwatched_series` | Unwatched TV series | Count | - |
| `sensor.jellyha_unwatched_episodes` | Unwatched individual episodes | Count | - |
| `sensor.jellyha_watched` | Total watched content | Count | `movies`, `series` |
| `sensor.jellyha_watched_movies` | Fully watched movies | Count | - |
| `sensor.jellyha_watched_series` | Fully watched TV series | Count | - |
| `sensor.jellyha_watched_episodes` | Fully watched series count | Count | - |

### Server Status Sensors

| Entity ID | Description | State | Attributes |
|-----------|-------------|-------|------------|
| `sensor.jellyha_websocket` | WebSocket connection status | `connected`/`disconnected` | - |
| `sensor.jellyha_version` | Jellyfin server version | e.g. `10.11.6` | - |
| `sensor.jellyha_active_sessions` | Number of active playbacks | Count | `sessions` (list of active session info) |
| `sensor.jellyha_last_refresh` | Last time data was fetched | Timestamp | - |
| `sensor.jellyha_last_data_change` | Last time library data changed | Timestamp | - |
| `sensor.jellyha_refresh_duration` | Duration of the last library refresh | `5.2s`, `1m 30s` | `duration_seconds` (float) |

### User Sensors

| Entity ID Prefix | Description | State | Key Attributes |
|-----------|-------------|-------|------------|
| `sensor.jellyha_now_playing_[user]` | Real-time monitoring for specific user | `playing`, `paused`, `idle` | `title`, `series_title`, `season`, `episode`, `progress_percent`, `image_url`, `media_type`, `client`, `device_name` |


## Card Configuration

Add the card to your dashboard:

```yaml
type: custom:jellyha-library-card
entity: sensor.jellyha_library
title: Jellyfin Library
layout: carousel
media_type: both
items_per_page: 3
max_pages: 5
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `entity` | string | **Required** | The sensor entity ID (e.g. `sensor.jellyha_library`) |
| `title` | string | `Jellyfin Library` | Card title |
| `layout` | string | `carousel` | Layout mode: `carousel`, `grid`, or `list` |
| `media_type` | string | `both` | Filter: `movies`, `series`, `next_up`, or `both` |
| `items_per_page` | number | `3` | Items visible per page (carousel) or initial Load (list) or **Rows** (grid). **Note for Grid:** Use YAML editor to set > 8 rows. |
| `max_pages` | number | `5` | Maximum number of pages to display |
| `columns` | number | `4` | Number of columns for grid layout |
| `auto_swipe_interval` | number | `0` | Auto-scroll interval in seconds (0 = disabled) |
| `show_title` | boolean | `true` | Show media title |
| `show_year` | boolean | `true` | Show release year |
| `show_runtime` | boolean | `true` | Show runtime duration |
| `show_ratings` | boolean | `true` | Show combined rating |
| `show_media_type_badge` | boolean | `true` | Show Movie/Series badge |
| `show_watched_status` | boolean | `true` | Show watched checkmarks (Movies) and unplayed counts (Series) |
| `show_genres` | boolean | `true` | Show genres list |
| `show_description_on_hover` | boolean | `true` | Show overview when hovering/tapping |
| `enable_pagination` | boolean | `true` | Enable pagination dots |
| `show_date_added` | boolean | `false` | Show the date item was added in List view |
| `show_now_playing` | boolean | `true` | Show currently playing item banner if active |
| `metadata_position` | string | `below` | Position of text: `below` or `above` image |
| `rating_source` | string | `auto` | Rating source: `auto`, `imdb`, `tmdb`, or `jellyfin` |
| `new_badge_days` | number | `3` | Items added within X days show "New" badge |
| `theme` | string | `auto` | Theme: `auto`, `dark`, or `light` |
| `click_action` | string | `jellyfin` | Action on click: `jellyfin`, `more-info`, `cast`, `trailer`, or `none` |
| `hold_action` | string | `cast` | Action on hold: `jellyfin`, `cast`, `more-info`, `trailer`, or `none` |
| `double_tap_action` | string | `none` | Action on double tap: `jellyfin`, `cast`, `more-info`, `trailer`, or `none` |
| `default_cast_device` | string | `''` | Default media_player entity for casting |
| `filter_favorites` | boolean | `false` | Filter Favorites (Show only favorite items) |
| `status_filter` | string | `all` | Filter Watch Status: `all`, `unwatched`, `watched` |
| `filter_newly_added` | boolean | `false` | Filter New Items (Show only new items) |
| `sort_option` | string | `date_added_desc` | Sort order options |

## API Key

To get your Jellyfin API key:

1. Open Jellyfin Dashboard
2. Go to **Administration** → **API Keys**
3. Click **+** to create a new key
4. Copy the generated key

## Services

JellyHA provides several services to control and manage your library.

| Service | Description | Parameters |
|---------|-------------|------------|
| `jellyha.play_on_chromecast` | Play an item on Chromecast with optimized transcoding. | `entity_id` (Req), `item_id` (Req) |
| `jellyha.refresh_library` | Force refresh library data from Jellyfin. | - |
| `jellyha.delete_item` | Delete an item from library/disk. ⚠️ **Use with caution.** | `item_id` (Req) |
| `jellyha.mark_watched` | Mark an item as watched or unwatched. | `item_id` (Req), `is_played` (Req) |
| `jellyha.update_favorite` | Add or remove an item from favorites. | `item_id` (Req), `is_favorite` (Req) |
| `jellyha.session_control` | Control playback (`Pause`, `Unpause`, `TogglePause`, `Stop`). | `session_id` (Req), `command` (Req) |
| `jellyha.session_seek` | Seek to position in ticks. Use `0` to rewind. | `session_id` (Req), `position_ticks` (Req) |


## Troubleshooting

### Card is empty ("No recent media found")
If the card shows "No recent media found" but you know you have items:
1. **Check Filters**: Ensure "Filter Favorites" or "Filter Unwatched" are not enabled in the card configuration if your items don't match those criteria.
2. **Check Logs**: Open the browser console (F12) to see if there are any specific errors.
3. **Verify Sensor**: Check `sensor.jellyha_library` in Developer Tools to ensure it has attributes (entry_id, etc.).

### "Connection lost" on startup
This usually indicates a duplicate command registration. Ensure you are running the latest version. We have implemented safeguards against this in v1.0.

## Support

- [Report an issue](https://github.com/zupancicmarko/jellyha/issues)
- [Home Assistant Community](https://community.home-assistant.io/)

## License

MIT

## Disclaimer

**Personal Use Only**
This integration is provided as a neutral interface for your private media library. JellyHA does not provide, facilitate, or encourage the use of unauthorized or pirated content. By using this software, you agree that you are solely responsible for the legality of the media you host and stream.

[hacs-badge]: https://img.shields.io/badge/HACS-Custom-orange.svg
[hacs-url]: https://github.com/hacs/integration
[release-badge]: https://img.shields.io/github/v/release/zupancicmarko/jellyha
[release-url]: https://github.com/zupancicmarko/jellyha/releases
[my-ha-badge]: https://my.home-assistant.io/badges/config_flow_start.svg
[my-ha-url]: https://my.home-assistant.io/redirect/config_flow_start?domain=jellyha
