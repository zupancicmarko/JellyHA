# Dashboard Cards Configuration

JellyHA provides two custom Lovelace cards for Home Assistant:
- **JellyHA Library Card** (`custom:jellyha-library-card`): Browse and play your media collection with Carousel, Grid, and List layouts.
- **JellyHA Now Playing Card** (`custom:jellyha-now-playing-card`): View active playback, metadata, and control media sessions with blurred dynamic backdrops.

Both cards feature a full visual configuration editor in the Home Assistant dashboard UI (Add Card -> search for "JellyHA"). YAML configuration is optional.

---

## JellyHA Library Card

The Library Card displays media items from your Jellyfin library with rich artwork, badges, ratings, and custom interaction triggers.

### Basic YAML Configuration

```yaml
type: custom:jellyha-library-card
entity: sensor.jellyha_library
title: Jellyfin Library
layout: carousel
media_type: both
items_per_page: 3
max_pages: 5
```

### Configuration Options

| Option | Type | Default | Description |
|---|---|---|---|
| `entity` | string | **Required** | The sensor entity ID (e.g. `sensor.jellyha_library`) |
| `title` | string | `Jellyfin Library` | Card header title |
| `layout` | string | `carousel` | Layout mode: `carousel`, `grid`, or `list` |
| `media_type` | string | `both` | Media filter: `movies`, `series`, `next_up`, or `both` |
| `tv_content` | string | `series` | Content type when TV shows are active: `series` (Shows / Series) or `episodes` (Individual Episodes) |
| `columns` | number | `4` | Number of columns for grid and list layout. Changes to number of rows when Grid layout has Auto-Swipe enabled. |
| `items_per_page` | number | `3` | Items visible per page. For more than 8 rows in Grid view, set this via the YAML code editor. |
| `max_pages` | number | `5` | Maximum number of pages to display (set to `0` for infinite pagination) |
| `auto_swipe_interval` | number | `0` | Auto-scroll interval in seconds (`0` = disabled) |
| `new_badge_days` | number | `3` | Items added within X days display a "New" badge |
| `click_action` | string | `more-info` | Action on single tap: `more-info`, `play-browser`, `cast`, `jellyfin`, `trailer`, `call-service` (Run Script), or `none` |
| `click_service` | string | `''` | Target Home Assistant script entity to execute on tap (e.g. `script.card_action_play_on_wholpin`) |
| `hold_action` | string | `jellyfin` | Action on press and hold: `jellyfin`, `play-browser`, `cast`, `more-info`, `trailer`, `call-service`, or `none` |
| `hold_service` | string | `''` | Target Home Assistant script entity to execute on press and hold |
| `double_tap_action` | string | `none` | Action on double tap: `jellyfin`, `play-browser`, `cast`, `more-info`, `trailer`, `call-service`, or `none` |
| `double_tap_service` | string | `''` | Target Home Assistant script entity to execute on double tap |
| `enable_browser_player` | boolean | `true` | Enable "Play in Browser" option in card actions and More Information dialog |
| `enable_custom_play_actions` | boolean | `false` | Enable custom playback targets in the More Information dialog via `modal_play_actions` |
| `modal_play_actions` | list | `[]` | List of custom play targets (`browser`, `cast`, `script`) displayed in the More Info dialog |
| `default_cast_device` | string | `''` | Default `media_player` entity used when action is set to `cast` (filtered to Google Cast devices in visual editor) |
| `subtitle_mode` | string | `auto` | Subtitle strategy for casting and browser playback: `auto` (Jellyfin user profile with English fallback), `none` (disabled), `forced_only`, or `custom` |
| `subtitle_language` | string | `''` | Prioritized comma-separated subtitle language codes/names when `subtitle_mode` is `custom` (e.g. `sl, en` or `slv, eng`) for casting and browser playback |
| `show_now_playing` | boolean | `true` | Display active playback banner at the top of the card |
| `show_title` | boolean | `true` | Display media title text |
| `show_year` | boolean | `true` | Display release year |
| `show_ratings` | boolean | `true` | Display community rating score |
| `show_runtime` | boolean | `true` | Display runtime duration |
| `show_date_added` | boolean | `false` | Display date added in List view |
| `show_genres` | boolean | `true` | Display genre tags |
| `show_description_on_hover` | boolean | `true` | Display plot summary overview on hover or tap |
| `show_media_type_badge` | boolean | `true` | Display Movie / Series badge |
| `show_watched_status` | boolean | `true` | Display watched checkmarks on movies and unplayed episode counts on series |
| `show_search` | boolean | `false` | Display search bar for real-time filtering by title and genre |
| `metadata_position` | string | `below` | Position of metadata text relative to poster: `below` or `above` |
| `sort_option` | string | `date_added_desc` | Sort order (`date_added_desc`, `date_added_asc`, `name_asc`, `name_desc`, `rating_desc`, `year_desc`) |
| `enable_pagination` | boolean | `true` | Enable pagination controls |
| `show_pagination_dots` | boolean | `true` | Display pagination indicator dots |
| `status_filter` | string | `all` | Filter by watch status: `all`, `unwatched`, `watched` |
| `filter_favorites` | boolean | `false` | Display only favorite items |
| `filter_newly_added` | boolean | `false` | Display only items added within `new_badge_days` |
| `use_series_image` | boolean | `false` | For episodes and Next Up, display parent series cover art instead of episode thumbnail |

> **Performance Note:** When using **Auto Swipe** with a large number of items, keep `items_per_page` and `max_pages` reasonable to ensure smooth animation on low-power tablets and mobile devices.

---

### Play in Browser & Custom Play Actions (`modal_play_actions`)

JellyHA supports streaming media directly inside Home Assistant dashboards using a dedicated HTML5 browser player (`<jellyha-browser-player>`) with authenticated streaming:

- **Single Tap / Hold / Double Tap**: Set `click_action: play-browser` to immediately play any tapped movie or episode in your browser.
- **More Information Dialog & Target Picker**:
  By default, the More Information modal provides 1-tap playback or an Action Sheet target picker for configured Cast devices, Browser playback, and scripts.
- **Subtitles & Closed Captions**:
  The browser player automatically extracts text-based subtitle streams (SRT, ASS, VTT) and serves them via an authenticated WebVTT proxy endpoint (`/api/jellyha/subtitles/...`). You can switch tracks anytime via the player's native Closed Captions (**CC**) menu. Initial track auto-selection respects the card's `subtitle_mode` and `subtitle_language` preferences (prioritizing clean dialogue tracks over SDH/hearing impaired).
- **Custom Play Actions (`modal_play_actions`)**:
  When `enable_custom_play_actions: true` is enabled, you can define exactly which play options appear in the More Info dialog:

```yaml
type: custom:jellyha-library-card
entity: sensor.jellyha_library
enable_custom_play_actions: true
modal_play_actions:
  - type: browser
    name: Play in Browser
    icon: mdi:monitor
  - type: cast
    name: Living Room TV
    device: media_player.living_room_chromecast
    icon: mdi:cast
  - type: script
    name: Play on Apple TV
    service: script.play_on_apple_tv
    icon: mdi:apple
    show_entity_name: false
```

Target Options:
- `type`: Target type (`browser`, `cast`, or `script`).
- `name` (optional): Custom display label in button and Action Sheet picker.
- `icon` (optional): Custom MDI icon (defaults: `mdi:monitor` for browser, `mdi:cast` for cast, `mdi:play` for script).
- `device`: Required for `type: cast`, target `media_player` entity ID.
- `service`: Required for `type: script`, target script entity ID.
- `service_data` (optional): Extra payload dictionary passed to script.
- `show_entity_name` (optional, boolean, default: `true`): Set to `false` to hide the entity subtitle in the Action Sheet picker.

---

### Custom Script Execution (`Run Script`)

When `click_action`, `hold_action`, or `double_tap_action` is set to `call-service` ("Run Script"), you can select any Home Assistant script from the UI dropdown (or define it in YAML via `click_service`).

When the card triggers the script, it automatically passes the tapped media item's complete metadata as execution variables:

| Variable | Type | Description | Example |
|---|---|---|---|
| `{{ item_id }}` | string | Jellyfin item GUID | `"d8f34a8e..."` |
| `{{ title }}` / `{{ name }}` | string | Media title or episode title | `"28 Years Later"` / `"Episode 1"` |
| `{{ media_type }}` | string | Item classification | `"Movie"`, `"Series"`, `"Episode"`, `"Audio"` |
| `{{ series_name }}` | string | Parent series name (episodes only) | `"Severance"` |
| `{{ series_id }}` | string | Parent series GUID (episodes only) | `"a7b2c1..."` |
| `{{ season }}` | number | Season number | `1` |
| `{{ episode }}` | number | Episode number | `3` |
| `{{ year }}` | number | Release year | `2026` |
| `{{ genres }}` | list | Array of genres | `["Action", "Thriller"]` |
| `{{ rating }}` | number | Community rating score | `7.5` |
| `{{ poster_url }}` | string | Authenticated poster image URL | `"http://.../Primary?..."` |
| `{{ series_poster_url }}` | string | Parent series poster URL (episodes only) | `"http://.../Primary?..."` |
| `{{ backdrop_url }}` | string | Backdrop / fanart image URL | `"http://.../Backdrop?..."` |
| `{{ date_created }}` / `{{ date_added }}` | string | ISO addition date | `"2026-09-08T11:20:00Z"` |
| `{{ last_played_date }}` | string / null | Last playback timestamp | `"2026-09-08T14:30:00Z"` |
| `{{ artist }}` / `{{ artist_name }}` | string | Track or album artist (music only) | `"Hans Zimmer"` |
| `{{ album }}` | string | Album title (music only) | `"Interstellar OST"` |
| `{{ album_artist }}` | string | Primary album artist | `"Hans Zimmer"` |
| `{{ overview }}` / `{{ description }}` | string | Plot synopsis | `"An ex-hitman comes out of retirement..."` |
| `{{ official_rating }}` | string | Age rating / certification | `"R"`, `"PG-13"`, `"TV-MA"` |
| `{{ dynamic_range }}` | string | Dynamic range classification | `"SDR"`, `"HDR10"`, `"Dolby Vision"` |
| `{{ video_range_type }}` | string | Raw Jellyfin classification | `"DOVIWithHDR10"`, `"HDR10"`, `"SDR"` |
| `{{ video_codec }}` | string | Video codec | `"hevc"`, `"av1"`, `"h264"` |
| `{{ dv_profile }}` | number / null | Dolby Vision profile number | `7`, `8`, `5` |
| `{{ is_played }}` | boolean | Watched status | `true`, `false` |
| `{{ is_favorite }}` | boolean | Favorite status | `true`, `false` |
| `{{ runtime_minutes }}` | number | Total runtime in minutes | `122` |
| `{{ jellyfin_url }}` | string | Direct web URL to the item in Jellyfin | `"https://jf.domain/..."` |
| `{{ path }}` / `{{ filepath }}` | string / null | Absolute media file path on server disk (Issue #37) | `"/media/movies/Inception (2010)/Inception.mkv"` |
| `{{ config_entry_id }}` | string | JellyHA instance GUID | `"01KM6..."` |
| `{{ action_type }}` | string | Interaction trigger | `"click"`, `"hold"`, `"double_tap"` |

#### Ready-to-Use External Player Scripts:
- **[Play on Android TV (Wholphin via ADB)](../examples/scripts/card_action_play_on_wholpin.yaml)**: Sends direct playback intent to Wholphin without user confirmation prompts.
- **[Play on Apple TV (Infuse)](../examples/scripts/card_action_play_on_apple_tv.yaml)**: Direct playback handoff to Apple TV.
- **[Play on Kodi (JellyCon & Direct Path)](../examples/scripts/card_action_play_on_kodi.yaml)**: Direct playback handoff to Kodi via JellyCon streaming or direct file path.

---

## JellyHA Now Playing Card

The Now Playing Card displays an interactive playback controller for an active user or client device.

### Basic YAML Configuration

```yaml
type: custom:jellyha-now-playing-card
entity: media_player.jellyha_admin
title: Now Playing
show_background: true
```

> **Entity Support:** Accepts per-user media players (e.g. `media_player.jellyha_admin`), per-device media players (e.g. `media_player.jellyha_living_room_tv`), or legacy Now Playing sensors.

### Configuration Options

| Option | Type | Default | Description |
|---|---|---|---|
| `entity` | string | **Required** | The target media player entity (e.g. `media_player.jellyha_admin` or `media_player.jellyha_living_room_tv`) |
| `title` | string | `Jellyfin` | Header title text |
| `show_background` | boolean | `true` | Display blurred backdrop fanart as card background |
| `show_title` | boolean | `true` | Display media title text |
| `show_subtitle` | boolean | `true` | Display subtitle (artist or series and season/episode info) |
| `show_client` | boolean | `true` | Display client device name (e.g. "Wholphin", "Chrome") |
| `show_user` | boolean | `true` | Display viewer user name |
| `show_time` | boolean | `false` | Display elapsed and remaining playback time |
| `show_media_type_badge` | boolean | `true` | Display media type badge (`MOVIE`, `SERIES`, `EPISODE`) |
| `badge_style` | string | `'poster'` | Media type badge presentation: `'poster'` (default, overlay on artwork), `'header'` (pill in header next to title, keeps poster artwork 100% uncovered), `'inline'` (prefixed to episode title for TV shows, e.g. `S01E02 • Title`), `'none'` (hidden) |
| `show_genres` | boolean | `true` | Display genre tags |
| `show_ratings` | boolean | `true` | Display community rating score |
| `show_runtime` | boolean | `true` | Display total runtime |
| `show_year` | boolean | `true` | Display release year |
| `use_series_image` | boolean | `false` | Display series poster cover instead of episode screenshot thumbnail |

### Media Type Badge Presentation (`badge_style`)

By default, media type badges (`S01E02` for episodes, `MOVIE` for films, `AUDIO` for music) appear as colored pill badges on the top-left corner of the poster image (`badge_style: poster`).

If you prefer your poster artwork or episode screenshot thumbnails to remain completely unobstructed, you can customize the badge presentation using `badge_style` (or in the card visual editor under **Badge Style**):

| `badge_style` | TV Episodes | Movies & Music | Poster Artwork |
|---|---|---|---|
| **`poster`** *(default)* | `S01E02` pill on top-left of artwork | `MOVIE` / `AUDIO` pill on top-left of artwork | Overlaid badge |
| **`header`** | `S01E02` pill in header right-aligned next to episode title | `MOVIE` / `AUDIO` pill in header right-aligned next to title | **100% Uncovered** |
| **`inline`** | Prepend `S01E02 • ` directly to episode title text (e.g. `S01E02 • Pilot`) | Clean title without prefix (no badge) | **100% Uncovered** |
| **`none`** | Hidden (no badge or prefix) | Hidden (no badge) | **100% Uncovered** |

#### Example: Uncovered Artwork with Header Badge
```yaml
type: custom:jellyha-now-playing-card
entity: media_player.jellyha_admin
title: Now Watching
badge_style: header
show_background: true
```

#### Example: Streamlined Minimal Title Prefix
```yaml
type: custom:jellyha-now-playing-card
entity: media_player.jellyha_admin
badge_style: inline
show_background: false
```

### Migrating from Legacy Now Playing Sensors (`sensor.jellyha_now_playing_*`)

Starting in **v1.3.0**, `sensor.jellyha_now_playing_<user>` is deprecated in favor of `media_player.jellyha_<user>` and scheduled for removal in **v2.0.0**.

**You do NOT need to replace `custom:jellyha-now-playing-card` or switch to third-party cards.** The card natively supports `media_player` entities with 100% visual and functional parity.

#### Card Migration Example
Simply update the `entity` field in your card YAML:

```diff
type: custom:jellyha-now-playing-card
-entity: sensor.jellyha_now_playing_marko
+entity: media_player.jellyha_marko
title: Now Playing
show_background: true
```

#### Dashboard Visibility Conditions
If you have conditional cards or badges that show/hide based on playback state:
```yaml
type: conditional
conditions:
  - entity: media_player.jellyha_marko
    state: playing
card:
  type: custom:jellyha-now-playing-card
  entity: media_player.jellyha_marko
```
Because `media_player.jellyha_<user>` outputs the exact same state strings (`playing`, `paused`, `idle`), your existing conditional visibility rules require **no logic changes**.

For curated dashboard designs, see the **[Lovelace Dashboard Examples](../examples/dashboards/)**.
