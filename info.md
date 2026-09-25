# JellyHA — Jellyfin for Home Assistant

**v1.5.2** · [Full Changelog](https://github.com/zupancicmarko/JellyHA/blob/main/CHANGELOG.md) · [Documentation](https://github.com/zupancicmarko/JellyHA/tree/main/docs)

![JellyHA Library Card](https://github.com/zupancicmarko/JellyHA/raw/main/docs/JellyHA-Library-Grid.png)

JellyHA integrates your Jellyfin media server directly into Home Assistant with a full-featured Lovelace card, rich media player entities, and powerful automation sensors.

---

### 🆕 What's new in v1.5.2

- 🌌 **Now Playing Ambient Idle Showcase** — Turn idle cards into an ambient digital photo frame / screensaver that cycles through your movie and TV library covers and fanart backdrops with full fanart (`backdrop`) or poster spotlight (`card`) layout styles.
- 🏷️ **Modernized Active Playback Metadata** — Replaced plain comma-separated text strings with modern frosted-glass genre pills (`.genre-pill`), clean release year, and refined typography.
- 🎨 **Unified Vertical Spacing & Rhythm** — Harmonized spacing across active playback and idle layouts (5px title-to-meta, 10px meta-to-description).
- ✨ **Hardware-Accelerated Dual-Layer Crossfades** — Zero-flicker, zero-dimming backdrop and poster transitions with automatic upcoming slide preloading.
- ⏱️ **Resource Efficient Slideshow** — Rotation timer pauses automatically during active playback, when cards disconnect, or when dashboard tabs are hidden (`visibilitychange`).

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
4. Add the Lovelace resource:
   - **URL**: `/jellyha/jellyha-cards.js`
   - **Type**: JavaScript Module

[📖 Full documentation](https://github.com/zupancicmarko/JellyHA/tree/main/docs) · [💬 Community](https://github.com/zupancicmarko/JellyHA/discussions) · [🐛 Issues](https://github.com/zupancicmarko/JellyHA/issues)
