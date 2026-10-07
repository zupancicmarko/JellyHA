# JellyHA — Jellyfin for Home Assistant

**v1.6.0** · [Full Changelog](https://github.com/zupancicmarko/JellyHA/blob/main/CHANGELOG.md) · [Documentation](https://github.com/zupancicmarko/JellyHA/tree/main/docs)

![JellyHA Library Card](https://github.com/zupancicmarko/JellyHA/raw/main/docs/JellyHA-Library-Grid.png)

JellyHA integrates your Jellyfin media server directly into Home Assistant with a full-featured Lovelace card, rich media player entities, and powerful automation sensors.

---

### 🆕 What's new in v1.6.0

- ⚡ **TV & Display Power Button with Dual-Entity Pairing (Issue [#60](https://github.com/zupancicmarko/JellyHA/issues/60))** — Uniform `36px` frosted glass power button across Active Playback, Ambient Showcase, and Idle states. State-responsive white (ON) / dimmed (OFF) styling with script support, dual-entity pairing (`power_state_entity`), haptic feedback, and auto-stopping Jellyfin sessions when powering off.
- 🔊 **Option 1 Capsule Volume Slider with Tactile Scrubbing** — Sleek translucent pillow capsule row above the timeline bar with continuous track, 5% haptic notches while scrubbing, discrete `−`/`+` step buttons, mute toggle, and AVR/soundbar routing (`volume_entity`).
- 🛠️ **Visual Card Editor Enhancements** — Dedicated TV Power and Volume settings sections, dynamic placeholders, contextual helpers, and seamless clearing with native `✕` button support.
- 🔄 **Automatic Lovelace Resource Version Cache-Busting** — Auto-registers and updates `/jellyha/jellyha-cards.js?v={version}` in Home Assistant Lovelace resources on startup, eliminating stale frontend caches across releases.

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
