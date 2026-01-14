# JellyHA

[![HACS][hacs-badge]][hacs-url]
[![GitHub Release][release-badge]][release-url]

A Home Assistant integration and Lovelace card that displays media from your Jellyfin server.

**JellyHA Library** provides a beautiful way to showcase your media collection in Home Assistant.

![Card Preview](./docs/JellyHA-Library.png)

## Features

- 🎬 Display movies and TV shows from your library
- 🎨 Three layouts: Carousel, Grid, List
- 🌙 Automatic dark/light theme adaptation
- 🔗 Click to open in Jellyfin (new tab)
- ⭐ IMDB ratings for movies, TMDB for TV shows
- 🆕 "New" badge for recently added items
- 🌍 6 languages: English, German, French, Spanish, Italian, Dutch
- 🎛️ Graphical card editor (no YAML required)

## Installation

JellyHA requires **two installation steps**: installing the integration and adding the dashboard card resource.

### Step 1: Install the Integration

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
| `media_type` | string | `both` | Filter: `movies`, `series`, or `both` |
| `items_per_page` | number | `3` | Items visible per page (carousel) or initial Load (list) |
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
| `show_pagination` | boolean | `true` | Show pagination dots |
| `show_date_added` | boolean | `false` | Show the date item was added |
| `metadata_position` | string | `below` | Position of text: `below` or `above` image |
| `new_badge_days` | number | `3` | Items added within X days show "New" badge |
| `click_action` | string | `jellyfin` | Action on click: `jellyfin`, `more-info`, or `none` |

## API Key

To get your Jellyfin API key:

1. Open Jellyfin Dashboard
2. Go to **Administration** → **API Keys**
3. Click **+** to create a new key
4. Copy the generated key

## Support

- [Report an issue](https://github.com/zupancicmarko/jellyha/issues)
- [Home Assistant Community](https://community.home-assistant.io/)

## License

MIT

[hacs-badge]: https://img.shields.io/badge/HACS-Custom-orange.svg
[hacs-url]: https://github.com/hacs/integration
[release-badge]: https://img.shields.io/github/v/release/zupancicmarko/jellyha
[release-url]: https://github.com/zupancicmarko/jellyha/releases
