# JellyHA — Jellyfin for Home Assistant

**v1.5.7** · [Full Changelog](https://github.com/zupancicmarko/JellyHA/blob/main/CHANGELOG.md) · [Documentation](https://github.com/zupancicmarko/JellyHA/tree/main/docs)

![JellyHA Library Card](https://github.com/zupancicmarko/JellyHA/raw/main/docs/JellyHA-Library-Grid.png)

JellyHA integrates your Jellyfin media server directly into Home Assistant with a full-featured Lovelace card, rich media player entities, and powerful automation sensors.

---

### 🆕 What's new in v1.5.7

- 🎵 **Play Music Service Parameter Binding (Fixes [#43](https://github.com/zupancicmarko/JellyHA/issues/43))** — Fixed `ServiceCall` construction in `jellyha.play_music` by providing the required Home Assistant core context argument (`hass`). Music search parameters (`query`, `artist`, `album`, etc.) are now correctly retained in service execution rather than falling back to default unfiltered searches.
- 🎬 **Now Playing Idle Showcase & Spotlights** — Screensaver mode can showcase your newest movie, newest episode, or recently added media with flexible filters (Movies, TV Shows, Episodes) and dynamic `LATEST MOVIE` and `LATEST EPISODE` badges.
- 🏷️ **Unified Badge Typography & Styling** — Standardized font size (`0.8rem`), corner radius (`4px`), and applied a clean, subtle font drop shadow across all badge types (Media Type, NEW, List, Watched, Unplayed, and Ratings).
- 📐 **Metadata Alignment & Spacing Polish** — Perfectly centered rating pill with star icon, uniform `22px` height across all metadata row elements, and improved typography spacing hierarchy across Fanart and Poster layouts.

---

### ✨ Features

- 🎬 **Library Card** — Browse movies & shows in Carousel, Grid, or List view with Next Up support
- ⏯️ **Full Playback Control** — Play, pause, stop, seek, shuffle, repeat, volume via `media_player` entities
- 📡 **Chromecast** — Cast with subtitle burn-in and language selection
- 🔍 **Search Service** — Filter by genre, studio, person, and more
- 📊 **Rich Sensors** — Library stats, storage, transcoding streams, connected clients, latest media
- 🤖 **Automation-Ready** — Device triggers, segment events, chapter events, HDR detection
- 🌐 **Multi-Instance** — Multiple Jellyfin servers in one HA instance
- 🃏 **Community Card Compatible** — Works with Mini Media Player, Mushroom, Universal Media Player

---

### 📦 Installation

1. Install via HACS.
2. **Restart Home Assistant**.
3. Go to **Settings → Devices & Services → Add Integration → JellyHA**.
*(Dashboard cards are registered automatically—no manual Lovelace resource entry required!)*

[📖 Full documentation](https://github.com/zupancicmarko/JellyHA/tree/main/docs) · [💬 Community](https://github.com/zupancicmarko/JellyHA/discussions) · [🐛 Issues](https://github.com/zupancicmarko/JellyHA/issues)
