# Services Reference

JellyHA exposes custom Home Assistant actions/services under the `jellyha` domain for library management, multi-instance search, item manipulation, and media playback.

---

## Service Catalog

| Action | Description | Key Parameters |
|---|---|---|
| `jellyha.play_on_chromecast` | Cast media to Google Cast device. Passing a TV Series ID automatically resolves and casts the next unplayed episode (or Season 1 Episode 1). Supports subtitle burn-in transcoding and language priority selection. | `entity_id` (Req), `item_id` (Req), `subtitle_mode` (Opt), `subtitle_language` (Opt), `use_series_image` (Opt), `config_entry_id` (Opt) |
| `jellyha.refresh_library` | Force refresh library data directly from Jellyfin. | `entity_id` (Opt), `server_entity_id` (Opt), `config_entry_id` (Opt) |
| `jellyha.delete_item` | Permanently delete an item from library and disk. Use with caution. | `item_id` (Req), `entity_id` (Opt), `config_entry_id` (Opt) |
| `jellyha.mark_watched` | Mark an item as watched (`true`) or unwatched (`false`). | `item_id` (Req), `is_played` (Req), `config_entry_id` (Opt) |
| `jellyha.update_favorite` | Add (`true`) or remove (`false`) an item from favorites. | `item_id` (Req), `is_favorite` (Req), `config_entry_id` (Opt) |
| `jellyha.session_control` | Send transport commands to an active session (`Pause`, `Unpause`, `TogglePause`, `Stop`, `NextTrack`, `PreviousTrack`, `Shuffle`, `SetRepeatMode`). | `session_id` (Req), `command` (Req), `config_entry_id` (Opt) |
| `jellyha.session_play` | Instruct an active Jellyfin client session or device player to play a media item (Movie, Episode, Song). Auto-resolves TV shows to the next unplayed episode. | `item_id` (Req), `entity_id` / `device_name` / `session_id` / `device_id` / `client` (Opt), `play_command` (`PlayNow`/`PlayNext`/`PlayLast`, Opt), `start_position_ticks` (Opt), `config_entry_id` (Opt) |
| `jellyha.get_live_tv_channels` | Retrieve available Live TV channels, including number, display name, and normalized name with optional query search and pagination limit. Results are returned through `response_variable`. | `query` (Opt), `limit` (Opt), `config_entry_id` / `entity_id` / `server_entity_id` (Opt) |
| `jellyha.play_live_tv_channel` | Resolve a Live TV channel by exact channel number or normalized name, then play its Jellyfin channel item on an active session. | `channel_number` or `channel_name` (one Req), `entity_id` / `session_id` / `device_name` / `device_id` / `client` (Opt), `server_entity_id` / `config_entry_id` (Opt) |
| `jellyha.music_search` | High-performance search for tracks, albums, or artists with FLAC, ALAC, and Hi-Res audio specifications returned into `response_variable`. | `query`, `search_type`, `artist`, `album`, `genre`, `year`, `codec`, `is_hi_res`, `is_lossless`, `is_favorite`, `sort_by`, `sort_order`, `limit`, `offset` |
| `jellyha.play_music` | Search and play music from Jellyfin directly on any Home Assistant media player (e.g. Kitchen Speaker, Sonos, Cast, Wiim). Ideal for voice commands and 1-tap automations. | `entity_id` (Req), `query` (Opt), `artist` (Opt), `album` (Opt), `search_type` (Opt), `codec` (Opt), `is_hi_res` (Opt), `is_lossless` (Opt), `item_id` (Opt) |
| `jellyha.session_seek` | Seek an active playback session. Accepts `position_seconds` (seconds) or `position_ticks`. Use `0` to rewind. | `session_id` (Req), `position_seconds` (Opt), `position_ticks` (Opt), `config_entry_id` (Opt) |
| `jellyha.session_general_command` | Send arbitrary commands to a Jellyfin playback session (e.g. `SetSubtitleStreamIndex`, `SetAudioStreamIndex`, `Mute`, `Unmute`, `SetVolume`, `DisplayMessage`). | `session_id` (Req), `command` (Req), `arguments` (Opt), `config_entry_id` (Opt) |
| `jellyha.search` | Search and filter library media with advanced sorting and filtering, returning results into `response_variable`. | `query`, `media_type`, `sort_by`, `sort_order`, `parent_id`, `is_played`, `is_favorite`, `genre`, `year`, `min_rating`, `limit`, `config_entry_id` |
| `jellyha.get_recommendations` | Fetch similar item recommendations based on a given item ID into `response_variable`. | `item_id` (Req), `limit` (Opt), `config_entry_id` (Opt) |
| `jellyha.get_item` | Retrieve comprehensive item metadata into `response_variable`. | `item_id` (Req), `config_entry_id` (Opt) |

---

## Multi-Instance Targeting

When running multiple JellyHA servers (e.g., Primary Jellyfin and 4K Media Server), actions can target a specific server using any of the following parameters:
- `config_entry_id`: The target JellyHA integration config entry GUID.
- `server_entity_id`: Any sensor belonging to that server (e.g. `sensor.jellyha_primary_library`).
- `entity_id`: A target entity belonging to that server.

If omitted, the action automatically targets the first available JellyHA instance.

---

## Action Examples

### Search & List Live TV Channels

Search channels matching a query and return up to a specific limit into `response_variable`:

```yaml
action: jellyha.get_live_tv_channels
data:
  query: "news"
  limit: 10
response_variable: tv_channels
```

### Play a Live TV Channel by Number

```yaml
action: jellyha.play_live_tv_channel
data:
  channel_number: "3"
  entity_id: media_player.jellyha_living_room_tv
```

### Play a Live TV Channel by Name

Names are normalized by lowercasing and removing non-alphanumeric characters,
so `Comedy Central` can be passed as `comedycentral`.

```yaml
action: jellyha.play_live_tv_channel
data:
  channel_name: Comedy Central
  entity_id: media_player.jellyha_living_room_tv
```

### Home Assistant Voice / Assist Integration (Live TV Tuning)

Tuning can be triggered in a single step using Home Assistant Voice Assist conversation triggers:

```yaml
alias: "Voice: Tune Live TV Channel"
description: "Tunes TV to requested channel name or number via voice commands"
mode: single
trigger:
  - trigger: conversation
    command:
      - "Tune to {channel}"
      - "Watch {channel}"
      - "Switch to channel {channel}"
      - "Put on {channel}"
action:
  - action: jellyha.play_live_tv_channel
    data:
      channel_name: "{{ trigger.slots.channel }}"
      entity_id: media_player.jellyha_living_room_tv
  - set_conversation_response: "Tuning to {{ trigger.slots.channel }}."
```

### Play Movie or Next Up Episode on Chromecast

```yaml
action: jellyha.play_on_chromecast
data:
  entity_id: media_player.living_room_chromecast
  item_id: "a7b2c1d8e4f5..."
```

### Cast with Subtitles and Language Priority

```yaml
action: jellyha.play_on_chromecast
data:
  entity_id: media_player.office_tv
  item_id: "a7b2c1d8e4f5..."
  subtitle_mode: custom
  subtitle_language: "sl, en"
```

#### Subtitle Modes:
- `auto` *(default)*: Uses the Jellyfin user profile's subtitle preferences; falls back to English if unconfigured.
- `none`: Disables subtitles completely.
- `forced_only`: Only displays forced subtitle tracks (e.g. translation for foreign-language dialogue).
- `custom`: Evaluates `subtitle_language` as a prioritized comma-separated list of 2-letter codes, 3-letter codes, or language names (e.g. `"sl, en"` or `"slv, eng"`), selecting the first match. Graphical formats (PGS, VOBSUB, DVDSUB) are automatically burned into the video stream via server-side transcoding.

### Search Unwatched 4K / High-Rated Movies

```yaml
service: jellyha.search
data:
  media_type: Movie
  is_played: false
  min_rating: 7.5
  sort_by: Random
  limit: 1
response_variable: top_pick
```

### Mark Item as Watched

```yaml
service: jellyha.mark_watched
data:
  item_id: "d8f34a8e..."
  is_played: true
```

### Control Active Session

```yaml
service: jellyha.session_control
data:
  session_id: "3e5c9b7..."
  command: TogglePause
```

### Play Item on Client Session or Device Player

```yaml
service: jellyha.session_play
data:
  entity_id: media_player.jellyha_android_tv
  item_id: "d8f34a8e..."
  play_command: PlayNow
```

### Send General Command (e.g. Set Subtitle Track)

```yaml
service: jellyha.session_general_command
data:
  session_id: "3e5c9b7..."
  command: SetSubtitleStreamIndex
  arguments:
    Index: 1
```

### Retrieve Item Details & Filepath

Retrieve comprehensive metadata and disk file path for an item (e.g. to launch in an external player or script):

```yaml
action: jellyha.get_item
data:
  item_id: "a7b2c1d8e4f5..."
response_variable: movie_info

# Downstream script access:
# {{ movie_info.item.path }} or {{ movie_info.item.filepath }}
```

### Search Music (with FLAC / Hi-Res Specifications)

Query the music library with indexed fast search and audio stream inspection:

```yaml
action: jellyha.music_search
data:
  query: "Beautiful Day"
  artist: "U2"
  codec: "flac"
  is_hi_res: true
  limit: 5
response_variable: music_results

# Returned item attributes:
# {{ music_results.items[0].name }} -> "Beautiful Day"
# {{ music_results.items[0].artist_name }} -> "U2"
# {{ music_results.items[0].album }} -> "All That You Can't Leave Behind"
# {{ music_results.items[0].audio_codec }} -> "flac"
# {{ music_results.items[0].audio_bit_depth }} -> 24
# {{ music_results.items[0].audio_sample_rate }} -> 96000
# {{ music_results.items[0].audio_quality_label }} -> "24-bit / 96 kHz FLAC (Hi-Res Lossless)"
# {{ music_results.items[0].stream_url }} -> Direct bit-perfect stream URL
# {{ music_results.items[0].path }} -> Physical disk path on server
```

### Play Music on Any Media Player (Voice & Automation One-Shot)

Play a song or album from Jellyfin directly on a speaker (`media_player.kitchen_speaker`, Sonos, Google Nest / Cast, Wiim, HomePod, etc.):

```yaml
action: jellyha.play_music
data:
  entity_id: media_player.kitchen_speaker
  query: "It's a Beautiful Day"
  artist: "U2"
```

### Home Assistant Voice / Assist Music Playback

Easily trigger music playback on any room speaker with Home Assistant Voice Assist:

```yaml
alias: "Voice: Play Music on Speaker"
description: "Plays requested track or artist on a speaker via voice command"
mode: single
trigger:
  - trigger: conversation
    command:
      - "Play {track} by {artist} on {speaker}"
      - "Play {track} on {speaker}"
action:
  - action: jellyha.play_music
    data:
      entity_id: "media_player.{{ speaker | lower | replace(' ', '_') }}"
      query: "{{ trigger.slots.track }}"
      artist: "{{ trigger.slots.artist | default('') }}"
  - set_conversation_response: "Playing {{ trigger.slots.track }} on {{ trigger.slots.speaker }}."
```

### Play Playlist on Any Speaker or Device

Play a music or video playlist from Jellyfin on any Home Assistant speaker (Google Cast, Sonos, Wiim, HomePod) or directly on a Jellyfin client session, with optional track shuffling:

```yaml
action: jellyha.play_playlist
data:
  entity_id: media_player.kitchen_speaker
  playlist: "Morning Coffee"
  shuffle: true
```

*When targeting a Jellyfin client (e.g. `media_player.jellyha_living_room_tv`), the entire playlist is queued and managed natively by Jellyfin.*

### Retrieve User Playlists

Query all playlists in the user's library with track count, duration, and thumbnail into `response_variable` (ideal for dynamic dashboard buttons or voice dropdowns):

```yaml
action: jellyha.get_playlists
data:
  limit: 20
response_variable: user_playlists

# Downstream script access:
# {{ user_playlists.playlists[0].name }} -> "Morning Coffee"
# {{ user_playlists.playlists[0].item_count }} -> 42
# {{ user_playlists.playlists[0].image_url }} -> Jellyfin cover art URL
```

### Retrieve BoxSets & Movie Collections

Query all Movie Collections / BoxSets from Jellyfin, including their contained films and technical metadata:

```yaml
action: jellyha.get_collections
data:
  include_items: true
response_variable: movie_collections

# Downstream script access:
# {{ movie_collections.collections[0].name }} -> "The Lord of the Rings Collection"
# {{ movie_collections.collections[0].item_count }} -> 3
# {{ movie_collections.collections[0].items[0].name }} -> "The Fellowship of the Ring"
# {{ movie_collections.collections[0].items[0].path }} -> Server disk path
```


