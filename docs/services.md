# Services Reference

JellyHA exposes custom Home Assistant actions/services under the `jellyha` domain for library management, multi-instance search, item manipulation, and media playback.

---

## Service Catalog

| Action | Description | Key Parameters |
|---|---|---|
| `jellyha.play_on_chromecast` | Cast media to Google Cast device. Passing a TV Series ID automatically resolves and casts the next unplayed episode (or Season 1 Episode 1). | `entity_id` (Req), `item_id` (Req), `use_series_image` (Opt), `config_entry_id` (Opt) |
| `jellyha.refresh_library` | Force refresh library data directly from Jellyfin. | `entity_id` (Opt), `server_entity_id` (Opt), `config_entry_id` (Opt) |
| `jellyha.delete_item` | Permanently delete an item from library and disk. Use with caution. | `item_id` (Req), `entity_id` (Opt), `config_entry_id` (Opt) |
| `jellyha.mark_watched` | Mark an item as watched (`true`) or unwatched (`false`). | `item_id` (Req), `is_played` (Req), `config_entry_id` (Opt) |
| `jellyha.update_favorite` | Add (`true`) or remove (`false`) an item from favorites. | `item_id` (Req), `is_favorite` (Req), `config_entry_id` (Opt) |
| `jellyha.session_control` | Send transport commands to an active session (`Pause`, `Unpause`, `TogglePause`, `Stop`, `NextTrack`, `PreviousTrack`, `Shuffle`, `SetRepeatMode`). | `session_id` (Req), `command` (Req), `config_entry_id` (Opt) |
| `jellyha.session_play` | Instruct an active Jellyfin client session or device player to play a media item (Movie, Episode, Song). Auto-resolves TV shows to the next unplayed episode. | `item_id` (Req), `entity_id` / `device_name` / `session_id` / `device_id` / `client` (Opt), `play_command` (`PlayNow`/`PlayNext`/`PlayLast`, Opt), `start_position_ticks` (Opt), `config_entry_id` (Opt) |
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

### Play Movie or Next Up Episode on Chromecast

```yaml
service: jellyha.play_on_chromecast
data:
  entity_id: media_player.living_room_chromecast
  item_id: "a7b2c1d8e4f5..."
```

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
