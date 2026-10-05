# JellyHA — Jellyfin for Home Assistant

**v1.5.5** · [Full Changelog](https://github.com/zupancicmarko/JellyHA/blob/main/CHANGELOG.md) · [Documentation](https://github.com/zupancicmarko/JellyHA/tree/main/docs)

![JellyHA Library Card](https://github.com/zupancicmarko/JellyHA/raw/main/docs/JellyHA-Library-Grid.png)

JellyHA integrates your Jellyfin media server directly into Home Assistant with a full-featured Lovelace card, rich media player entities, and powerful automation sensors.

---

### 🆕 What's new in v1.5.5

- 🛡️ **HA 2026.10 Compatibility & Scoped Registry Sync** — Fixed an issue where cards could report "Custom element doesn't exist" in Home Assistant Core 2026.10+ due to the frontend's scoped custom element registry polyfill replacing the native registry after initial script evaluation (fixes #56).
- ⚡ **Resilient Custom Element Lifecycle** — Added dynamic hooks on `window.customElements` and just-in-time element definition to ensure cards and dialogs are always available regardless of whether loaded via `add_extra_js_url`, Lovelace resources, or both.
- 🔧 **Seek Polyfill Hardening** — Added capability guarding for custom element promise methods across all browser environments.

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
