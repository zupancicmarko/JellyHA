# JellyHA — Jellyfin for Home Assistant

**v1.5.0** · [Full Changelog](https://github.com/zupancicmarko/JellyHA/blob/main/CHANGELOG.md) · [Documentation](https://github.com/zupancicmarko/JellyHA/tree/main/docs)

![JellyHA Library Card](https://github.com/zupancicmarko/JellyHA/raw/main/docs/JellyHA-Library-Grid.png)

JellyHA integrates your Jellyfin media server directly into Home Assistant with a full-featured Lovelace card, rich media player entities, and powerful automation sensors.

---

### 🆕 What's new in v1.5.0

- 🖥️ **Play in Browser (In-Dashboard Player)** — Stream movies, episodes, and audio directly inside Home Assistant dashboards using an HTML5 dialog player, native subtitle proxy (SRT, ASS, VTT), Closed Captions (CC) menu, and language pre-selection.
- 🎯 **Dynamic Play Actions & Target Picker** — Sleek Action Sheet picker and HA script trigger support in the More Info dialog for multi-device routing (#42).
- 📑 **Playlists & BoxSet Collections** — Dedicated services to play and query playlists (`jellyha.play_playlist`, `jellyha.get_playlists`) and movie BoxSets (`jellyha.get_collections`) with 1-tap playback in Media Browser.
- 🗂️ **Native Media Browsing on Players** — Direct library browsing and container auto-resolution on all user and device `media_player` entities (#11).
- 🏷️ **Now Playing Badge Placement Styles** — Configurable badge placement (`poster`, `header`, `inline`, `none`) for movies and TV episodes (#20).
- 🔊 **Volume Level & Voice Search Fixes** — Fixed `volume_level` state reporting on media players (#44) and restored modern Voice Assist query compatibility (#43).

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
