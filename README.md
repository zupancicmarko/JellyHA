# JellyHA

[![HACS][hacs-badge]][hacs-url]
[![GitHub Release][release-badge]][release-url]

Jellyfin for Home Assistant

<div align="center">
  <img src="./docs/JellyHA-Library-Grid.png" width="48%" alt="Library Card - Grid View" />
  <img src="./docs/JellyHA-Now-Playing-Card.png" width="48%" alt="Now Playing Card" />
</div>

<details>
  <summary><b>📸 Click to view all layout variations & screenshots (Carousel, List, Next Up, Details Modal, Card Selector)</b></summary>
  <br>
  <div align="center">
    <img src="./docs/JellyHA-Library-Carousel.png" width="48%" alt="Carousel View" />
    <img src="./docs/JellyHA-Library-Next-Up.png" width="48%" alt="Next Up View" />
    <img src="./docs/JellyHA-Library-List.png" width="48%" alt="List View" />
    <img src="./docs/JellyHA-Library-More-Information.png" width="48%" alt="More Information" />
    <img src="./docs/JellyHA-Cards.png" width="48%" alt="Add to dashboard" />
    <img src="./docs/JellyHA-Latest-Movie-Card-Mod.png" width="48%" alt="Latest Movie Card Mod" />
  </div>
</details>

## Features

- 🎬 Display movies and TV shows from your library
- 📺 Cast media directly to Chromecast (Gen 1 supported)
- 📡 Live TV Support: Visual channel browsing in Media Browser
- 🎵 Music Support
- 📂 Full integration with Home Assistant Media Browser
- ⏯️ Full playback control: Play, Pause, Stop, Seek, Next/Previous Track, Shuffle, Repeat
- 🎮 Per-user media players with transport and volume controls
- 📺 Dedicated per-device media players with custom Jellyfin nicknames
- 🌈 Real-time Dynamic Range detection: Reporting of `SDR`, `HDR10`, `HDR10+`, `Dolby Vision`, and `HLG`
- 🎨 Three Library Card layouts: Carousel, Grid, List
- 🔍 Built-in Search Bar with Title and Genre filtering
- 🤖 Advanced automation triggers via custom sensors & services
- 🌍 7 languages: English, German, French, Spanish, Italian, Dutch, Slovenian

- 🚀 Multi-Instance Support: Run multiple servers concurrently

## Documentation

For detailed references, configuration options, entity catalogs, and services, explore the dedicated documentation:

| Guide | Description |
|---|---|
| **[Dashboard Cards Configuration](docs/cards.md)** | Full YAML options, layout guides, and custom script execution variables for Library and Now Playing cards |
| **[Entities & Sensors Reference](docs/entities.md)** | Complete catalog of media players, library statistics, disk storage meters, and real-time updates architecture |
| **[Services Reference](docs/services.md)** | Playback, casting, search, library manipulation actions, and multi-instance targeting |
| **[Examples & Cookbook](examples/README.md)** | Ready-to-use automations, external player scripts (Android TV ADB, Apple TV, Kodi), and Lovelace layouts |
| **[AI Assistant Context (`llms.txt`)](llms.txt)** | Compact, authoritative reference file designed for prompt context in ChatGPT, Claude, and Cursor |
| **[Troubleshooting & FAQ](docs/troubleshooting.md)** | Solutions for custom element errors, browser caching, and diagnostic logging |

## Installation

JellyHA requires two setup steps: installing the integration and registering the dashboard card frontend resource.

### Step 1: Install the Integration

#### Via HACS (Recommended)

Before installing JellyHA, ensure you have **HACS (Home Assistant Community Store)** installed. Please follow the [official HACS installation guide](https://www.hacs.xyz/docs/use/download/download/) if needed.

**Option A: Using the Quick Link**

[![Open your Home Assistant instance and open a repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=zupancicmarko&repository=jellyha&category=Integration)

**Option B: Manual Search**

1. Open **HACS** in Home Assistant.
2. In the search bar, type **JellyHA**.
3. Select the **JellyHA** integration and click **Download**.
4. **Restart Home Assistant**.

#### Manual Installation

1. Copy `custom_components/jellyha` to your `config/custom_components/` directory.
2. **Restart Home Assistant**.

### Step 2: Add Dashboard Card Resource

> **Important:** This step is required for the dashboard cards to display.

1. Go to **Settings** -> **Dashboards**.
2. Click the three-dot menu (**⋮**) in the top right -> **Resources**.
3. Click **+ Add Resource**.
4. Enter the URL:
   - URL: `/jellyha/jellyha-cards.js`
5. Select Resource type: **JavaScript Module**.
6. Click **Create**.

> Note: If you do not see the Resources menu, enable **Advanced Mode** in your Home Assistant user profile settings.

## Setup

### Connect via Quick Link

[![My Home Assistant][my-ha-badge]][my-ha-url]

### Manual Setup

1. Go to **Settings** -> **Devices & Services** -> **Add Integration**.
2. Search for **JellyHA**.
3. Enter your Jellyfin server URL and select authentication method (**Username/Password** or **API Key**).
   - Optional: Enter an **External URL** if accessing via a reverse proxy or WAN address.
4. Enter your credentials or API key.
5. Select the user and libraries to monitor.
6. **Instance Label (Optional)**: Add a custom label (e.g., `4K Server`, `Kids`) when connecting multiple Jellyfin instances.
7. Click **Submit**.

### Integration Options

To adjust settings after initial configuration:

1. Go to **Settings** -> **Devices & Services** -> **JellyHA** -> **Configure**.
2. Adjust the **Library Refresh Interval** (from pure WebSocket push to periodic polling).
3. Select **Client/Device Media Players** to create dedicated media players for physical hardware (e.g. Smart TVs, Android TV boxes).
4. Set an **External URL** or trigger an immediate cache refresh.

### Getting a Jellyfin API Key

1. Open the Jellyfin Web Dashboard.
2. Go to **Administration** -> **Dashboard** -> **Advanced** -> **API Keys**.
3. Click **+** to generate a new key, and paste it into Home Assistant.

### Supported Library Types

| Library Type | Library Card Support | Background Sync | Search Service | Now Playing & Playback |
|---|---|---|---|---|
| Movies | ✅ | ✅ | ✅ (`jellyha.search`) | ✅ |
| TV Shows | ✅ | ✅ | ✅ (`jellyha.search`) | ✅ |
| Music | ❌ *(Media Browser & Services)* | ✅ *(Count & Cache)* | ✅ (`jellyha.music_search`) | ✅ (`jellyha.play_music`) |
| Live TV | ❌ *(Media Browser & Services)* | ✅ *(Channels)* | ✅ (`jellyha.get_live_tv_channels`) | ✅ (`jellyha.play_live_tv_channel`) |
| Playlists | ❌ *(Media Browser & Services)* | ✅ *(On-Demand)* | ✅ (`jellyha.get_playlists`) | ✅ (`jellyha.play_playlist`) |
| BoxSets / Collections | ❌ *(Media Browser & Services)* | ✅ *(On-Demand)* | ✅ (`jellyha.get_collections`) | ✅ *(1-Tap Playback)* |

> [!NOTE]
> The **JellyHA Library Card** (`custom:jellyha-library-card`) is intentionally optimized for rich visual browsing of **Movies** and **TV Shows** (posters, episodes, Next Up badges). Music, Live TV, Playlists, and BoxSets/Collections are supported natively via the **Home Assistant Media Browser** (`/media-browser`), all media player entities, and dedicated automation actions.

## Dashboard Cards at a Glance

JellyHA includes two custom Lovelace cards with full visual UI editors (Add Card -> search for "JellyHA").

### Library Card (`custom:jellyha-library-card`)

Browse movies, series, episodes, and Next Up items with Carousel, Grid, or List layouts.

```yaml
type: custom:jellyha-library-card
entity: sensor.jellyha_library
title: Jellyfin Library
layout: carousel
media_type: both
items_per_page: 3
max_pages: 5
```

Supports custom click, hold, and double-tap actions (Cast, More Info, Open in Jellyfin, Play Trailer, or Run Script with complete item metadata passed automatically).

👉 **[See full Library Card configuration and script variables in docs/cards.md](docs/cards.md)**

### Now Playing Card (`custom:jellyha-now-playing-card`)

Display active playback status, progress bars, and transport controls with dynamic blurred backdrops.

```yaml
type: custom:jellyha-now-playing-card
entity: media_player.jellyha_admin # Supports per-user or per-device media players
title: Now Playing
show_background: true
```

#### 🔄 Migrating from Legacy Now Playing Sensors to Media Players

Starting in **JellyHA v1.3.0**, per-user `media_player.jellyha_<user>` entities are the primary, official entities for tracking and controlling user playback. Legacy `sensor.jellyha_now_playing_<user>` entities remain active for backward compatibility until **v2.0.0**.

**Migrating existing cards requires changing only one line:**

```diff
type: custom:jellyha-now-playing-card
-entity: sensor.jellyha_now_playing_<user>
+entity: media_player.jellyha_<user>
title: Now Playing
show_background: true
```

**Why this migration is 100% safe and non-breaking:**
- **Exact Visual & Feature Parity**: `custom:jellyha-now-playing-card` provides identical styling, dynamic fanart backdrops, poster art, season/episode badges (`S01E05`), IMDB/TMDB ratings, elapsed/remaining runtime, live scrubbing, and tap-to-rewind.
- **Identical State Values**: `media_player.jellyha_<user>` outputs the exact same state values (`playing`, `paused`, `idle`). Any dashboard conditional visibility rules (e.g. `state: playing` or `state_not: idle`) continue to work seamlessly without modifying your conditions.
- **Direct Playback Controls**: `media_player.jellyha_<user>` enables native Home Assistant services (`media_player.media_play_pause`, `media_player.media_seek`, `media_player.media_stop`), physical client device tracking (`media_player.jellyha_<device_name>`), and voice commands via Home Assistant Assist.

👉 **[See full Now Playing Card options in docs/cards.md](docs/cards.md)**

## Media Browser

JellyHA integrates natively with Home Assistant's Media Browser:

1. Open **Media** in the Home Assistant sidebar.
2. Select **JellyHA**.
3. Choose your server (if multiple are connected).
4. Browse your media with instant 1-tap playback to your browser or Cast players:
   - 🎬 **Movies & TV Series**: Unwatched items and Next Up episodes.
   - 📦 **Collections / BoxSets**: 1-tap playback automatically resolves and plays the first movie.
   - 📡 **Live TV Channels**: Authenticated channel logos, channel numbers, and live stream tuning.
   - 🎵 **Music & Playlists**: Artists, albums, tracks, and playlists with bit-perfect audio streaming.

*(If "Media" is not visible in the sidebar, see [Media Browser Entry Not Visible in Sidebar](docs/troubleshooting.md#media-browser-entry-not-visible-in-sidebar).)*

## Examples & Cookbook

Explore ready-to-use recipes in the dedicated **[Examples & Cookbook Library](examples/)**:

- **[Skip Intro Automatically](examples/automations/skip_intro.yaml)**: Jumps past TV show intros using segment detection.
- **[Cinema Lighting Experience](examples/automations/cinema_lighting_segments.yaml)**: Dims lights on playback and raises lights when credits roll.
- **[New Media Push Notification](examples/automations/new_movie_notification.yaml)**: Sends mobile notifications with artwork and dynamic range badges when new media is added.
- **[Play on Android TV / Wholphin (ADB)](examples/scripts/card_action_play_on_wholpin.yaml)**: Card click action to play directly on Wholphin via ADB without confirmation prompts.
- **[Cast with Custom Subtitles](examples/scripts/card_action_cast_with_subtitles.yaml)**: Routes library card clicks to Chromecast with prioritized subtitle selection (e.g. `sl, en`) and automatic server-side transcode burn-in.
- **[Play on Apple TV (Infuse)](examples/scripts/card_action_play_on_apple_tv.yaml)**: Routes library card clicks to Apple TV.
- **[Play on Kodi (JellyCon & Direct Path)](examples/scripts/card_action_play_on_kodi.yaml)**: Routes library card clicks to Kodi via JellyCon streaming or direct file path.
- **[System & Library Monitoring Stack](examples/dashboards/system_monitoring_card.yaml)**: Lovelace dashboard with server health, storage percentage meters, and library breakdown.

## Troubleshooting

For solutions to common issues, browser cache clearing, Android TV & Wholphin playback setup, and diagnostic logging:

👉 **[Read the complete Troubleshooting Guide in docs/troubleshooting.md](docs/troubleshooting.md)**

## Support

- [Report an issue](https://github.com/zupancicmarko/jellyha/issues)
- [Home Assistant Community](https://community.home-assistant.io/t/jellyha-jellyfin-custom-integration-for-home-assistant/981271/30)

## Acknowledgments

This project was developed with the assistance of AI.

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
