# 📚 JellyHA Examples & Cookbook

Welcome to the **JellyHA Examples & Recipe Library**! Here you will find copy-paste ready automations, scripts, Lovelace dashboard setups, and smart home recipes designed to get the most out of your Jellyfin media system in Home Assistant.

> 🤖 **Prompting an AI assistant (ChatGPT, Claude, Cursor)?**  
> Feed our official [**`llms.txt`**](../llms.txt) into your prompt to get 100% accurate, hallucination-free Home Assistant automations tailored for JellyHA.

---

## ⚡ Automations

| Recipe | Description | Trigger Method |
|:---|:---|:---|
| **[Skip Intro Automatically](automations/skip_intro.yaml)** | Detects TV show intro markers and automatically seeks directly past the opening theme. | `jellyha_event` (`media_segment_change`) |
| **[Cinema Lighting by Segment](automations/cinema_lighting_segments.yaml)** | Dims lights to 10% on play, warms lights on pause, raises lights to 35% during credits (Outro), and restores 100% on stop. | State + `media_segment_change` |
| **[New Movie & Episode Mobile Notification](automations/new_movie_notification.yaml)** | Sends a smartphone push notification with artwork, resolution, HDR/DV badges, and ratings when new media is added. | State (`sensor.jellyha_latest_movie` or `sensor.jellyha_unwatched_movies`) |
| **[Play TV Show / Cartridge (Next Up)](automations/play_cartridge_show.yaml)** | Plays the next unplayed episode of a TV show when an NFC cartridge is inserted (Stock Pots / tag scan). | Tag trigger / `jellyha.play_on_chromecast` |
| **[Pause Movie on Doorbell](automations/pause_on_doorbell.yaml)** | Pauses active playback immediately when someone rings the doorbell. | State (`binary_sensor.doorbell`) |
| **[Simple Movie Time Lights](automations/movie_night_lights.yaml)** | Basic starter automation to turn off room lights when playback starts. | State (`media_player.jellyha_*`) |
| **[Dynamic Range TV Picture Mode & Lighting](automations/tv_picture_mode_hdr.yaml)** | Adjusts TV picture mode and bias lighting dynamically when HDR10 or Dolby Vision is detected. | State attribute (`dynamic_range`) |

---

## 📜 Scripts

| Script | Description | Invocation |
|:---|:---|:---|
| **[Play on Android TV (Wholphin)](scripts/card_action_play_on_wholpin.yaml)** | Plays selected movie or episode on Android TV (Wholphin client) via Android Debug Bridge (ADB) when clicking an item in the library card. | Library card click action (`call-service`) |
| **[Play on Apple TV](scripts/card_action_play_on_apple_tv.yaml)** | Routes JellyHA Library Card click actions to Apple TV (Infuse or native player) passing full media metadata. | Card click / hold / double-tap action |
| **[Play on Kodi](scripts/card_action_play_on_kodi.yaml)** | Routes JellyHA Library Card click actions to Kodi (via JellyCon add-on or direct stream) passing full media metadata. | Card click / hold / double-tap action |
| **[Play Random Top Movie](scripts/play_random_movie.yaml)** | Dynamically searches your library for high-rated unwatched movies (by year/rating) and casts one to Chromecast or media player. | Action call / voice command / button |
| **[Search and Play Specific Episode](scripts/search_and_play_episode.yaml)** | Searches for a specific TV show and episode name (or season/episode number) and starts playback on your target player. | Action call / voice command / NFC tag |

---

## 🎛️ Lovelace Dashboard Cards

| Layout Example | Description | Card Type |
|:---|:---|:---|
| **[System & Library Monitoring Stack](dashboards/system_monitoring_card.yaml)** | Comprehensive vertical stack with server version, WebSocket health, full library breakdown (movies/series/episodes), latest content additions, active & transcoding session gauges, modern storage percentage meter, and sync diagnostics. | `vertical-stack` (Native HA Cards) |
| **[Library Card Variations](dashboards/library_cards.yaml)** | Curated setups for `jellyha-library-card`: Hero Carousel with auto-swipe, Binge-watching "Next Up", Grid with search bar, and Favorites view. | `custom:jellyha-library-card` |
| **[Now Playing Card Variations](dashboards/now_playing_cards.yaml)** | Curated setups for `jellyha-now-playing-card` (Backdrop, Minimal, Multi-Instance, Device Player). | `custom:jellyha-now-playing-card` |

---

## 🛠️ How to Use These Examples

### Adding Automations
1. Open your Home Assistant dashboard and navigate to **Settings** → **Automations & Scenes** → **Automations**.
2. Click **Create Automation** → **Create new automation**.
3. Click the **⋮** (three dots) menu in the top-right corner and select **Edit in YAML**.
4. Copy and paste the contents from any `.yaml` file in the [`automations/`](automations/) folder.
5. Update entity names (e.g. `media_player.office_tv`, `light.living_room`, or `media_player.jellyha_admin`) to match your setup, and save!

### Adding Scripts
1. Navigate to **Settings** → **Automations & Scenes** → **Scripts** (or edit `scripts.yaml` directly).
2. Click **Add Script** and select **Edit in YAML** from the top-right **⋮** menu.
3. Copy and paste the contents from any `.yaml` file in the [`scripts/`](scripts/) folder.
4. Call your script from dashboard buttons, cards, NFC tags, or voice assistants!

### Adding Dashboard Cards
1. Edit any Home Assistant dashboard and click **+ Add Card**.
2. Scroll to the bottom and select **Manual** (or click **Edit in YAML** if editing an existing card).
3. Copy and paste the configuration from [`dashboards/`](dashboards/).
4. Adjust options to fit your screen size or preferences.

