# JellyHA — Jellyfin for Home Assistant

**v1.7.0** · [Full Changelog](https://github.com/zupancicmarko/JellyHA/blob/main/CHANGELOG.md) · [Documentation](https://github.com/zupancicmarko/JellyHA/tree/main/docs)

![JellyHA Library Card](https://github.com/zupancicmarko/JellyHA/raw/main/docs/JellyHA-Library-Grid.png)

JellyHA integrates your Jellyfin media server directly into Home Assistant with a full-featured Lovelace card, rich media player entities, and powerful automation sensors.

---

### 🆕 What's new in v1.7.0

- 🌟 **Featured Layout Multi-Column & Configurable Rows (2, 3, or 4 rows)** — Multi-column side queue cards (1 to 4 columns) with proportional hero poster scaling, responsive compact mode, and customizable 2, 3, or 4 row arrangements.
- 📋 **List Layout Modernization & Ergonomics** — Standardized 136px card height, 76px posters, dynamic 2-line title wrapping, 1-2 line description clamping, subtle backdrop blur, and tactile click press feedback.
- 🎨 **Glassmorphic Rating & Runtime Poster Badges** — Extended rating and runtime glassmorphic pill badges to Carousel and Grid view posters with optical vertical centering.
- 📺 **Now Playing Poster Screensaver Badge Placement (`badge_style`)** — Screensaver poster mode now fully supports `badge_style: poster` (runtime and rating badges on the poster corners) and `badge_style: inline` (all metadata inline), identical to active playback.
- 🔤 **Typography & Metadata Font Standardization** — Unified metadata and description font size to 11px across Featured and List layouts, and 12px across Screensaver modes.

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
