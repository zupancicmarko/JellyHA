# 📚 JellyHA Examples & Cookbook

Welcome to the **JellyHA Examples & Recipe Library**! Here you will find copy-paste ready automations, Lovelace dashboard setups, and smart home recipes designed to get the most out of your Jellyfin media system in Home Assistant.

---

## ⚡ Automations

| Recipe | Description | Trigger Method |
|:---|:---|:---|
| **[Skip Intro Automatically](automations/skip_intro.yaml)** | Detects TV show intro markers and automatically seeks directly past the opening theme. | `jellyha_event` (`media_segment_change`) |
| **[Cinema Lighting by Segment](automations/cinema_lighting_segments.yaml)** | Dims lights to 10% on play, warms lights on pause, raises lights to 35% during credits (Outro), and restores 100% on stop. | State + `media_segment_change` |
| **[Play Random Top Movie](automations/play_random_movie.yaml)** | Dynamically searches your library for high-rated unwatched movies from a specific year and casts one to Chromecast. | Service call / script (`jellyha.search`) |
| **[Pause Movie on Doorbell](automations/pause_on_doorbell.yaml)** | Pauses active playback immediately when someone rings the doorbell. | State (`binary_sensor.doorbell`) |
| **[Simple Movie Time Lights](automations/movie_night_lights.yaml)** | Basic starter automation to turn off room lights when playback starts. | State (`media_player.jellyha_*`) |
| **[New Movie Mobile Notification](automations/new_movie_notification.yaml)** | Sends a smartphone push notification with movie artwork and rating whenever new content is added. | State (`sensor.jellyha_unwatched_movies`) |

---

## 🎛️ Lovelace Dashboard Cards

| Layout Example | Description | Card Type |
|:---|:---|:---|
| **[System & Library Monitoring Stack](dashboards/system_monitoring_card.yaml)** | Comprehensive vertical stack with server version, WebSocket health, library breakdown, active sessions gauge, and refresh times. | `vertical-stack` (Native HA Cards) |
| **[Library Card Variations](dashboards/library_cards.yaml)** | Curated setups for `jellyha-library-card`: Hero Carousel with auto-swipe, Binge-watching "Next Up", Grid with search bar, and Favorites view. | `custom:jellyha-library-card` |
| **[Now Playing Card Variations](dashboards/now_playing_cards.yaml)** | Curated setups for `jellyha-now-playing-card`, plus Mini Media Player and Mushroom Media Card. | `custom:jellyha-now-playing-card`, `custom:mini-media-player`, `custom:mushroom-media-player-card` |

---

## 🛠️ How to Use These Examples

### Adding Automations
1. Open your Home Assistant dashboard and navigate to **Settings** → **Automations & Scenes**.
2. Click **Create Automation** → **Create new automation**.
3. Click the **⋮** (three dots) menu in the top-right corner and select **Edit in YAML**.
4. Copy and paste the contents from any `.yaml` file in the [`automations/`](automations/) folder.
5. Update entity names (e.g. `media_player.office_tv`, `light.living_room`, or `media_player.jellyha_admin`) to match your setup, and save!

### Adding Dashboard Cards
1. Edit any Home Assistant dashboard and click **+ Add Card**.
2. Scroll to the bottom and select **Manual** (or click **Edit in YAML** if editing an existing card).
3. Copy and paste the configuration from [`dashboards/`](dashboards/).
4. Adjust options to fit your screen size or preferences.

---

> 💡 **Contributing your own recipes:**
> Found a creative use case or built an awesome dashboard layout? Feel free to open a Pull Request or share it in [GitHub Discussions](https://github.com/zupancicmarko/jellyha/discussions)!
