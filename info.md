# JellyHA

**Jellyfin for Home Assistant**

![Grid View](https://github.com/zupancicmarko/JellyHA/raw/main/docs/JellyHA-Library-Grid.png)

JellyHA integrates your Jellyfin media server directly into Home Assistant.

### Features
- 🎬 **Library Card**: Browse and play movies/shows (Carousel, Grid, List views).
- ⏭️ **Next Up**: Resume TV shows right where you left off.
- ⏯️ **Playback Control**: Play, pause, seek, and cast to devices.
- 🔍 **Search**: Find content by title or genre.
- 🤖 **Automation**: Powerful sensors (`jellyha_now_playing`, `jellyha_library`) for automations.

### Installation
1. Install via HACS (you are here!).
2. **Restart Home Assistant**.
3. Go to **Settings** > **Devices & Services** > **Add Integration** > "JellyHA".

**Important:** You must also add the dashboard resource:
- URL: `/jellyha/jellyha-cards.js`
- Type: `JavaScript Module`

[Read the full documentation on GitHub](https://github.com/zupancicmarko/jellyha)
