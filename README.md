# JellyHA

[![HACS][hacs-badge]][hacs-url]
[![GitHub Release][release-badge]][release-url]

A Home Assistant integration and Lovelace card that displays media from your Jellyfin server.

**JellyHA Library** provides a beautiful way to showcase your media collection in Home Assistant.

![Card Preview](./docs/preview.png)

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

### HACS (Recommended)

1. Open HACS in Home Assistant
2. Go to "Integrations" → "⋮" → "Custom repositories"
3. Add this repository URL
4. Click "Download"
5. Restart Home Assistant

### Manual Installation

1. Copy `custom_components/jellyha` to your `config/custom_components/` directory
2. Copy `dist/jellyha-cards.js` to `config/www/community/jellyha/`
3. Add the card as a resource in Lovelace:
   ```yaml
   resources:
     - url: /local/community/jellyha/jellyha-cards.js
       type: module
   ```
4. Restart Home Assistant

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
limit: 10
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `entity` | string | **Required** | The sensor entity ID |
| `title` | string | `Jellyfin Library` | Card title |
| `layout` | string | `carousel` | `carousel`, `grid`, or `list` |
| `media_type` | string | `both` | `movies`, `series`, or `both` |
| `limit` | number | `10` | Maximum items to display |
| `columns` | number | `4` | Columns for grid layout |
| `show_title` | boolean | `true` | Show media title |
| `show_year` | boolean | `true` | Show release year |
| `show_runtime` | boolean | `false` | Show runtime |
| `show_ratings` | boolean | `true` | Show ratings |
| `new_badge_days` | number | `7` | Days to show "New" badge |
| `click_action` | string | `jellyfin` | `jellyfin`, `more-info`, or `none` |

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
