# JellyHA — Jellyfin for Home Assistant

**v1.7.6** · [Full Changelog](https://github.com/zupancicmarko/JellyHA/blob/main/CHANGELOG.md) · [Documentation](https://github.com/zupancicmarko/JellyHA/tree/main/docs)

![JellyHA Library Card](https://github.com/zupancicmarko/JellyHA/raw/main/docs/JellyHA-Library-Grid.png)

JellyHA integrates your Jellyfin media server directly into Home Assistant with a full-featured Lovelace card, rich media player entities, and powerful automation sensors.

---

### 🆕 What's new in v1.7.6

- 🎧 **Play in Browser Audio Track Selector** — Added an audio language switcher in the browser player modal header (`🎧 <LANG> ▾`), allowing instant switching across multi-audio HLS streams and seamless fallback transcode reload with exact playback timestamp preservation.
- ⚡ **Play in Browser PlaybackInfo & Transcoding Improvements** ([#75](https://github.com/zupancicmarko/JellyHA/issues/75)) — Fixed Jellyfin 500 errors by stripping invalid non-GUID device profile IDs on playback info requests, ensured browser HLS transcode streams include required hardware-acceleration baseline parameters (`h264`, `aac`, bitrate limits), and fixed `ActiveEncodings` cleanup so active FFmpeg transcoding jobs terminate properly when closing the browser player modal.

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
