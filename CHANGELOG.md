# Changelog

All notable changes to JellyHA will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] - 2026-09-07

### Added
- **Client/Device-Based Media Players (Resolves #12)**: Added support for dedicated media player entities per physical client device (e.g. Smart TVs, Android TV boxes, Fire TV sticks) selected in Integration Options Flow (Settings → Devices & Services → JellyHA → Configure). Device media players maintain 100% attribute, chapter, segment, and transport control parity with per-user media players while tracking playback on the specific device regardless of which user account is logged in, enabling room-specific automations (e.g., living room cinema lighting) that don't trigger when the user watches in another room.
- **Multi-Session Command Routing**: Media player transport controls (`async_media_play`, `async_media_pause`, `async_media_stop`, `async_media_seek`, volume, mute, repeat, shuffle) broadcast commands across all matching sessions for a target device (both controller and playback sessions), ensuring commands reach devices with split session architectures.
- **Full Media Player Migration & Enhancement**: `media_player.jellyha_<user>` is now the primary, recommended entity for playback tracking and control in JellyHA. Added standard Home Assistant properties (`media_artist`, `media_album_name`, `media_content_id`, `shuffle`, `repeat`) and transport controls for shuffle (`async_set_shuffle`) and repeat (`async_set_repeat`), backed by full attribute parity in `extra_state_attributes` (including `title`, `user_name`, `series_image_url`, `backdrop_url`, `is_favorite`, ratings, `runtime_minutes`, and `progress_percent`).
- **Community Media Card Compatibility**: Out-of-the-box support for popular community Lovelace cards including **Mini Media Player**, **Mushroom Media Card**, and **Universal Media Player** using standard Home Assistant `media_player` controls and properties.
- **Card & Editor Media Player Support**: `jellyha-now-playing-card` and its graphical editor now natively prioritize `media_player.jellyha_<user>` entities while seamlessly retaining fallback support for legacy sensor entities.
- **Live Media Segment Detection**: Real-time detection of `Intro`, `Outro`, `Recap`, `Preview`, and `Commercial` segments from Jellyfin's MediaSegments API (e.g., Intro Skipper plugin) as well as fallback regex classification from chapter titles.
- **Segment Attributes & Accurate Timing**: Added `media_segment_type` and live `segment_end_seconds` attributes to `media_player` entities, enabling precise auto-skip and ambient automation triggers.
- **Chapter Awareness & Attributes**: Added `media_chapter_name`, `media_chapter_index`, `media_chapter_count`, and `is_last_chapter` attributes to `media_player` entities.
- **Synthetic Chapters**: Automatic generation of synthetic chapter boundaries for media files without embedded MKV chapter markers when segment providers (like Intro Skipper) detect scenes.
- **Segment & Chapter Change Events**: Fired `media_chapter_change` and `media_segment_change` events on the Home Assistant event bus with entry/exit signals (`in_segment=True/False`), current chapter context, and exact `segment_end_seconds`.
- **Device Triggers**: Added device triggers for chapter and segment changes for easy automation building in the HA UI.
- **Now Playing Card Updates**: Added visual badges for current chapter name/index and active segment type (Intro, Outro, Recap).
- **Examples Knowledge Base**: Structured repository examples into a dedicated `examples/` directory with `automations/` (cinema lighting, auto-skip intro, doorbell pause, new movie notifications) and `dashboards/` (now playing cards, library cards, system monitoring).
- **TV Content (Shows / Series vs. Episodes)**: Added a `tv_content` sub-option under **TV Shows Only** and **Movies & TV Shows** in the JellyHA Library Card. Users can now choose between showing full series or newly added individual episodes (`Shows / Series` vs `Episodes`).
- **Use Series Cover Image in Library Cards**: Made the `use_series_image` option available for episode cards (under TV Shows and combined Movies & TV Shows), allowing episode items to optionally display their parent show's portrait cover poster rather than 16:9 episode screenshots for a clean, uniform grid/carousel layout.
- **WebSocket On-Demand Media Endpoint**: Added `jellyha/get_latest_items` WebSocket command to query newly added episodes or combined media with multi-library deduplication and chronological ordering.
- **Custom Script Calling (`call-service` / `Run Script`) in Library Card**:
  - Added `call-service` ("Run Script") option to `click_action`, `hold_action`, and `double_tap_action` (Resolves #10).
  - Built dedicated native `<ha-selector>` entity dropdown pickers filtered strictly to `domain: 'script'` (`click_service`, `hold_service`, `double_tap_service`), presenting friendly names, icons, and live search.
  - When tapped, the card executes the user's selected Home Assistant script (e.g. `script.play_on_apple_tv`) and automatically injects an extensive metadata payload into Jinja template variables:
    - **Core**: `item_id`, `title`, `name`, `media_type`, `year`, `runtime_minutes`, `genres`, `rating`, `jellyfin_url`, `action_type`, `is_played`, `is_favorite`
    - **TV Shows & Episodes**: `series_name`, `series_id`, `season`, `episode`, `series_poster_url`
    - **Music Tracks & Albums**: `artist`, `artist_name`, `album`, `album_artist`
    - **Dates**: `date_created`, `date_added`, `last_played_date`
    - **Artwork & Content**: `poster_url`, `backdrop_url`, `overview`, `description`, `official_rating`
  - Dispatches `jellyha_item_clicked` DOM event with the identical payload, allowing event-based automation triggers. Unlocks hybrid setups for Apple TV, Plex, Infuse, Kodi, ambient cinema lighting, and custom media routers.
- **Search Service Supercharging (`jellyha.search`)**:
  - Added sorting parameters `sort_by` (`DateCreated`, `SortName`, `PremiereDate`, `CommunityRating`, `IndexNumber`, `DatePlayed`, `PlayCount`, `Random`) and `sort_order` (`Ascending`, `Descending`).
  - Added granular media filtering: `parent_id` (or `series_id`) to search inside specific shows/albums, `official_rating` (age/content certification), `studio` (studio/network), `person` (actor/director), and `offset` (pagination).
- **TV Series Auto-Resolve & Fallback in `jellyha.play_on_chromecast`**: When passing a Series ID to `play_on_chromecast`, the service now automatically resolves to the next unplayed episode via Next Up, with a seamless fallback to the first unplayed episode or Episode 1 if the series has not yet been started in Jellyfin. This delivers plug-and-play support for physical NFC cartridge players (like Stock Pots) and TV series automations.
- **Modernized Card Editors**: Replaced legacy MWC elements with Home Assistant's native `<ha-selector>` across dropdowns, number inputs, text inputs, and sliders, fixing invisible form fields (`title`, `columns`, `items_per_page`, `max_pages`, `auto_swipe_interval`, `new_badge_days`) and dropdown selection issues.
- **Consolidated MediaType Imports**: Updated media player, browse media, and media source components to import `MediaType` and `MediaClass` directly from `homeassistant.components.media_player`.
- **Jellyfin 12 WebSocket Authentication**: Authenticate WebSocket connections via the `Authorization: MediaBrowser ...` header in addition to the query string parameter, fixing persistent 403 handshake failures on Jellyfin 12+ while maintaining full backward compatibility with Jellyfin 10.x (Fixes #23, PR #24 by @odtgit).

### Deprecated
- **`sensor.jellyha_now_playing_<user>` Deprecation**: The legacy Now Playing sensor entity is formally deprecated as of v1.3.0 and will be removed in v2.0.0. All playback state, rich metadata, transport controls, and segment information are fully available on `media_player.jellyha_<user>`. Existing automations and dashboards will continue to function normally during the deprecation period.

### Changed
- **Documentation Restructuring**: Streamlined `README.md` by replacing long inline YAML code blocks with references to the new `examples/` directory.
- **Cinematic Item Details ("More information") Modal**: Completely redesigned the item details modal dialog into a modern, cinematic hero presentation:
  - Hidden default detached Home Assistant dialog header in favor of an integrated top-right circular close button (`✕`).
  - Subtle fanart backdrop hero overlay with a smooth gradient fade behind the modal header.
  - Placed a primary **Play on Cast** pill action button directly beneath the media poster, along with a secondary circular icon toolbar (View Episodes, Watch Trailer, Mark Watched, Favorite, Open in Jellyfin, Delete).
  - Replaced the "Open in Jellyfin" icon with `mdi:open-in-new` for clear distinction from delete.
  - Modernized the "Next Up" card for TV series with a 16:9 thumbnail, hover play overlay, `NEXT UP` badge, episode code, runtime, rating, and quick-cast button.
  - Formatted technical media specs into modern chip badges (4K UHD / 1080p / 720p, Video Codec, Audio Codec, Audio Channels).

### Fixed
- **Consistent Poster Border Radius Across Custom Themes**: Decoupled `--jf-poster-radius` from `--ha-card-border-radius` (which custom themes like *Frosted Glass* set to `18px` or higher for entire card containers). Individual poster thumbnails now consistently use the clean `12px` radius across all themes, while still allowing optional `--jellyha-poster-border-radius` overrides.
- **Unrated Episodes Rendering Crash in "View All Episodes"**: Fixed an issue where series with unrated episodes (such as *Cape Fear* Episode 8 having `rating: null`) crashed the template rendering due to calling `.toFixed(1)` on null, causing the episodes list to appear completely empty. Added safe truthy rating validation, season filter tabs for multi-season shows, `S{season}:E{episode}` prefix formatting, and optional season querying support in `websocket_get_episodes`.
- **Episode Thumbnails in "View All Episodes"**: Fixed an issue where all episode rows showed the parent series backdrop by prioritizing each episode's individual preview screenshot (`ep.poster_url`).
- **YouTube Watch Trailer Navigation**: Fixed an issue where clicking "Watch Trailer" redirected YouTube URLs to the local Jellyfin server address by opening YouTube trailers directly in a new tab/app and guarding `_openExternalUrl` against rewriting 3rd-party domains.
- **Favorite & Watched Service Payload Validation**: Fixed `Failed to perform the action jellyha/update_favorite: not a valid option, did you mean 'entity_id'? at 'server_entity_id'` (and `mark_watched`, `delete_item`) by allowing both `entity_id` and `server_entity_id` in backend Voluptuous service schemas and aligning frontend service calls to pass `entity_id`.
- **Item Details Modal Backdrop Image**: Fixed missing fanart backdrop image in the modal header by properly returning `backdrop_url` and `media_streams` from `_async_transform_item`, fetching backdrop image tags in API library and episode queries, and rendering an `<img class="backdrop-img">` hero with smooth gradient fade and episode fallback.
- **Segment-Chapter Decoupling**: Fixed an issue where Intro and Outro segments were missed because Intro Skipper's audio-detected boundaries did not align with coarse embedded chapter start markers. Segments are now evaluated independently based on real-time playback position.
- **`SnullEnull` Badge in Item Details Modal**: Fixed an issue where movies and series incorrectly rendered an `SnullEnull` badge because `null !== undefined` evaluated to true for non-episode media types. Strictly constrained season/episode badges to `item.type === 'Episode'`.

## [1.2.0] - 2026-03-22

### Added
- **Multi-Instance Support**: You can now run multiple JellyHA instances concurrently, perfect for multi-server setups (e.g., separate Movies and Music servers).
- **Smart Instance Naming**: Automatically prefixes instance names with `JellyHA` and handles de-duplication to prevent nested names (e.g., `JellyHA Movies`).
- **Immediate Library Refresh**: Added an option to "Refresh fetched data immediately" in the integration config/options flow to force an immediate synchronization after changes.
- **Options Flow User Switching**: You can now switch the connected Jellyfin user profile directly from the integration Options menu without needing to delete and re-add the integration.
- **Dynamic Options Library Selection**: You can now modify the list of synchronized libraries natively via the Options menu, dynamically updating your dashboard content.
- **Configuration Localization**: Deployed fully native UI strings for the new configuration and options flows across German, Spanish, French, Italian, and Russian languages (joining English and Slovenian).
- **Media Browser Support**: Full multi-instance support in the Home Assistant Media Browser. You can now browse and stream from multiple Jellyfin servers concurrently with accurate root-level categorization.
- **Improved Streaming Compatibility**: Enhanced MIME type detection for Audio and Video content, improving playback reliability across various Home Assistant media players (like Chromecast).
- **Home Videos & Music Video Support**: Added support for Home Videos and Music Video library types in background sync.
- **Music & Photos Setup Support**: Expanded config flow to allow Music, Photos, and Home Videos libraries during setup to prevent crashes.
- **Direct Search API**: New `jellyha/search_media` WebSocket endpoint for direct server-side search (perfect for massive music libraries).
- **Expanded Search Service**: The `jellyha.search` service now supports `Audio`, `MusicAlbum`, `MusicArtist`, `MusicVideo`, and `Video` media types.
- **Library Sensor Update**: Added `videos` attribute showing the count of Home Videos.
- **External URL Support**: Added an optional configuration setting for users running Jellyfin in clusters to override the UI base link, ensuring "Open in Jellyfin" actions remain working across public endpoints.
- **Russian Translation**: Extensive frontend and backend translation coverage provided for the Russian language.
- **Refresh Interval Dropdown**: Upgraded the Library Refresh Interval setting from a raw seconds slider to a human-readable dropdown format (e.g. `5 minutes`, `1 hour`).
- **Now Playing Card Updates**:
  - Added elapsed/remaining time display.
  - Added user name information and client details formatting.
  - Added specific Artist and Series name support for Music and TV shows.
  - Added interactive scrubbable progress bar: Drag to seek with real-time visual tracking before committing the jump.
  - Added Favorites and Repeat buttons for music playback directly in the UI.
  - Added visual `-10s` rewind and `+30s` fast-forward controls for video media.
  - Added stop-pulse animation and comprehensive haptic vibration feedback for mobile.

### Changed
- **Now Playing Card**: Improved Now Playing card visuals with dot separators, dynamic colors extracted from posters, glassmorphic progress bar, badges, and refined spacing.
- **Stream View Routing**: Improved internal proxy routing to correctly handle multiple active servers simultaneously without URL collisions.
- **Explicit Frontend Targeting**: Enhanced all card components (Library, Now Playing, Details Modal) to explicitly target their respective integration instances.

### Fixed
- **Empty Setup Dropout**: Fixed an issue where initial setup or reconfiguration would crash if the user did not have standard `movies` or `tvshows` library types (added fallback to `mixed`, `musicvideos` and `homevideos`, protected against completely empty dropdowns).
- **Setup API Headers**: Fixed a double keyword argument error crashing the setup flow logout cleanup routine.
- **Item Details Modal**: Fixed a bug where favorited status was not correctly displayed in the "More Information" card when opened from lists.
- **Progress Bar**: Fixed the immediate snap-back effect when manually jumping or scrubbing the progress bar by optimistically holding the new position for 3 seconds while awaiting the server update.
- **Stop Pulse**: Fixed a bug where the long-press stop shadow-pulse effect rendered as a square instead of a circle.
- **Loading Spinner**: Fixed the loading spinner shrinking during rewind/seek actions, now properly maintaining the 44px play/pause button size.
- **Show All Episodes**: Fixed a bug where the "View All Episodes" button was hidden for series that hadn't been started yet. Restored visibility of the episode list in the "More Information" modal, even when "Next Up" data is not yet available (defaults to Season 1).


## [1.1.0] - 2026-02-15

### Added
- **Per-User Media Player Entities**: Each Jellyfin user now gets their own `media_player` entity (e.g., `media_player.jellyha_username`)
  - Full transport controls: Play, Pause, Stop, Seek, Next Track, Previous Track
  - Volume controls: Set volume level and Mute/Unmute
  - Rich media metadata: Title, series/season/episode info, poster images, duration, position
  - Real-time state updates via WebSocket or polling
  - Automatic session priority (prefers playing over paused sessions)
- **Series Cover Image Option**: Added option to display series posters instead of episode thumbnails
  - Available for **Now Playing card** (all episodes)
  - Available for **Library Card** (Next Up view)
- Enhanced session control API with `session_general_command` for volume and other general commands

### Changed
- Existing user sensors (`sensor.jellyha_now_playing_*`) remain unchanged for backwards compatibility
- Library Browser media_player remains separate and unchanged

## [1.0.5] - 2026-02-15

### Fixed
- Fixed `400 Bad Request` during setup when selecting multiple libraries (ParentId now fetched per library).
- Improved API error reporting by logging response bodies for 4xx responses.
- Optimized API request logic by stopping retries for non-transient 4xx client errors.

### Added
- Enhanced setup diagnostics by logging server name and version at INFO level.

## [1.0.4] - 2026-02-14

### Fixed
- Fixed signed image URL cache expiration bug.

## [1.0.3] - 2026-02-05

### Added
- **Smart Server URL Validation**: Automatically probes `http` and `https` schemes to detect the correct server address, even if the scheme is missing or incorrect.
- **Secure Image Proxy**: All image URLs are now signed with 24-hour expiration for security.
- **Image URL Caching**: Signed URLs are cached by `(item_id, image_type, tag)` to enable proper browser caching.

### Changed
- Changed default minimum rows for Library Card from 5 to 4 for better compactness.
- **Optimized Image Widths**: Reduced bandwidth usage with appropriate sizing
- Image format defaults to WebP with 80% quality in the backend.

## [1.0.2] - 2026-02-01

### Fixed
- Fixed `400 Bad Request` error by removing unused heavy fields from API requests.

## [1.0.1] - 2026-01-31

### Added
- Added `info.md` for HACS repository display.
- Added official branding assets (`logo.png`, `icon.png`).

### Changed
- Improved HACS compatibility and validation.

## [1.0.0] - 2026-01-31

### Added
- **Initial release of JellyHA**
- **JellyHA Library Card**
  - Three layouts: Carousel, Grid, List
  - Pagination with swipe gesture support
  - **Next Up Integration**: Dedicated support for "Next Up" episodes
  - **Auto Swipe & Infinite Scroll**: True infinite scroll (marquee) for unpaginated views
  - **Swipe to Close**: Mobile-friendly swipe-down gesture for "More Info" modal
  - **Double Tap Action**: Configurable double-tap action on items
  - **Pagination Dots**: Option to show/hide dots
  - **Search Bar**: Built-in search bar with Title and Genre filtering
  - Configurable items per page, rows/columns, and alignment
- **JellyHA Now Playing Card**
  - Now Playing banner with media controls
  - Configurable actions for play, pause, stop, seek, rewind
- **JellyHA Sensor**: Sensors for library items
- **Playback Services**: Play, pause, stop, seek, rewind
- **More Info Modal**: Enhanced with swipe to close gesture
- **Cast Support**: Chromecast Gen 1 support
- **Authentication**: Username/Password and API Key support
- **Configuration Flow**: Easy setup via HACS or manual installation
- **Entity Naming**: Managed by Home Assistant
- **Device Naming**: "JellyHA" device naming
- **Automation Examples**: Doorbell pause, Lights control, New Content notification
- **Troubleshooting Guide**: Basic troubleshooting steps
- **Localization**: English, German, Spanish, French, Italian, Slovenian
- **Documentation**: Comprehensive documentation
