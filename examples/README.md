# JellyHA Examples & Cookbook

Welcome to the **JellyHA Examples & Recipe Library**! Here you will find copy-paste ready automations, scripts, Lovelace dashboard setups, and smart home recipes designed to get the most out of your Jellyfin media system in Home Assistant.

> **Prompting an AI assistant (ChatGPT, Claude, Cursor)?**  
> Feed the official [**`llms.txt`**](../llms.txt) into your prompt to get 100% accurate, hallucination-free Home Assistant automations tailored for JellyHA.

---

## Automations

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

## Scripts

| Script | Description | Invocation |
|:---|:---|:---|
| **[Play on Android TV (Wholphin)](scripts/card_action_play_on_wholpin.yaml)** | Plays selected movie or episode on Android TV (Wholphin client) via Android Debug Bridge (ADB) when clicking an item in the library card. | Library card click action (`call-service`) |
| **[Cast with Custom Subtitles](scripts/card_action_cast_with_subtitles.yaml)** | Casts selected movie or episode to Chromecast with custom subtitle language priority (e.g. `sl, en`) and automatic server-side transcode burn-in. | Library card click / hold / double-tap action (`call-service`) |
| **[Play on Apple TV](scripts/card_action_play_on_apple_tv.yaml)** | Routes JellyHA Library Card click actions to Apple TV (Infuse or native player) passing full media metadata. | Card click / hold / double-tap action |
| **[Play on Kodi](scripts/card_action_play_on_kodi.yaml)** | Routes JellyHA Library Card click actions to Kodi (via JellyCon add-on, direct disk/SMB/NFS file path, or stream URL) passing full media metadata. | Card click / hold / double-tap action |
| **[Play Random Top Movie](scripts/play_random_movie.yaml)** | Dynamically searches your library for high-rated unwatched movies (by year/rating) and casts one to Chromecast or media player. | Action call / voice command / button |
| **[Search and Play Specific Episode](scripts/search_and_play_episode.yaml)** | Searches for a specific TV show and episode name (or season/episode number) and starts playback on your target player. | Action call / voice command / NFC tag |

---

## Lovelace Dashboard Cards

| Layout Example | Description | Card Type |
|:---|:---|:---|
| **[System & Library Monitoring Stack](dashboards/system_monitoring_card.yaml)** | Comprehensive vertical stack with server version, WebSocket health, full library breakdown (movies/series/episodes), latest content additions, active & transcoding session gauges, modern storage percentage meter, and sync diagnostics. | `vertical-stack` (Native HA Cards) |
| **[Library Card Variations](dashboards/library_cards.yaml)** | Curated setups for `jellyha-library-card`: Hero Carousel with auto-swipe, Binge-watching "Next Up", Grid with search bar, Favorites view, and Multi-Target Custom Play Actions. | `custom:jellyha-library-card` |
| **[Now Playing Card Variations](dashboards/now_playing_cards.yaml)** | Curated setups for `jellyha-now-playing-card` (Backdrop, Minimal, Multi-Instance, Device Player). | `custom:jellyha-now-playing-card` |
| **[Latest Media Hero Backdrop Cards](dashboards/latest_media_hero_card.yaml)** | Cinematic hero banner cards for newly added movies and episodes featuring backdrop blurring, floating poster art, format pills, and overview text. | `markdown` + `card-mod` |

---

## Custom Play Actions in More Information Dialog (`modal_play_actions`)

The JellyHA Library Card supports dynamic, multi-target playback inside its **More Information** dialog:

- **Dynamic Play Button**:
  - **0 Targets**: The Play button is cleanly hidden if no targets are configured.
  - **1 Target**: Displays the target's label and icon (e.g. *"Play in Browser"*, *"Cast to Chromecast"*, or *"Play on Apple TV"*) with immediate 1-click execution.
  - **2+ Targets**: Displays `Play` with `mdi:play`. Clicking it opens a sleek, glassmorphic **Action Sheet picker** allowing the user to select where to play.
- **How to Enable**:
  - **Visual Editor**: Turn on the **Custom Play Actions** switch. This automatically pre-fills your configured browser player, Cast device, and scripts directly into `modal_play_actions` in YAML.
  - **In YAML**: Set `enable_custom_play_actions: true` and configure `modal_play_actions`:

```yaml
type: custom:jellyha-library-card
entity: sensor.jellyha_library
click_action: more-info
enable_custom_play_actions: true
modal_play_actions:
  - type: browser
    name: Play in Browser
    icon: mdi:monitor
  - type: cast
    name: Living Room Chromecast
    device: media_player.living_room_tv
    icon: mdi:cast
  - type: script
    name: Play on Apple TV
    service: script.play_on_apple_tv
    icon: mdi:apple
    show_entity_name: false
```

### Target Properties

| Property | Type | Default | Description |
|:---|:---|:---|:---|
| `type` | string | **Required** | Target type: `browser`, `cast`, or `script`.<br>• `browser`: Plays directly in dashboard using `<jellyha-browser-player>` with native Closed Captions (CC) and subtitle track selection.<br>• `cast`: Streams to Chromecast via `jellyha.play_on_chromecast`.<br>• `script`: Calls an HA script with rich media metadata. |
| `name` | string | Auto | Custom label displayed on the button or Action Sheet list. |
| `icon` | string | Auto | Custom MDI icon (defaults: `mdi:monitor` for browser, `mdi:cast` for cast, `mdi:play` for script). |
| `device` | string | `''` | Target `media_player` entity ID (required for `type: cast`). |
| `service` | string | `''` | Target script entity ID (required for `type: script`). |
| `service_data` | dict | `{}` | Optional extra arguments passed to the script payload. |
| `show_entity_name` | boolean | `true` | Set to `false` to hide the entity subtitle in the Action Sheet picker. |

---

## How to Use These Examples

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


