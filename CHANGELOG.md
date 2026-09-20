# Changelog

All notable changes to JellyHA will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Home Assistant 2026.8+ Media Source Search & Modernization**:
  - Implemented `async_search_media` on `JellyHAMediaSource` supporting query dataclasses and keyword filters across Jellyfin libraries.
  - Dynamically enabled `can_search=True` on `BrowseMediaSource` for Home Assistant 2026.8+ environments.
  - Enhanced `async_resolve_media` on `JellyHAMediaSource` to automatically resolve complex containers (BoxSets/collections to their first movie, and series/seasons to their first unplayed episode).
- **Native Media Browsing on Individual Players (Follow-up to [#11](https://github.com/zupancicmarko/JellyHA/issues/11))**:
  - Added `MediaPlayerEntityFeature.BROWSE_MEDIA` and `async_browse_media` to `JellyHABasePlaybackMediaPlayer`, enabling direct Jellyfin media library browsing on all user (`media_player.jellyha_<user>`) and device (`media_player.jellyha_<device>`) media players in Home Assistant.
  - Enhanced `async_play_media` across all player entities to parse `jellyha://` URIs and automatically resolve complex media containers upon selection (albums & playlists to first audio track, BoxSets/collections to first video, and TV shows/seasons to Next Up episode).
- **Playlist Playback & Management Actions**:
  - Added `jellyha.play_playlist`: Play Jellyfin playlists on any Home Assistant media player (with live stream URL resolution, cover art, track metadata, and optional `shuffle`) or directly on active Jellyfin client sessions (via server-side queueing).
  - Added `jellyha.get_playlists`: Fetch all user playlists with track counts, durations, and thumbnails to `response_variable`.
- **BoxSet / Movie Collections Support**:
  - Added `jellyha.get_collections`: Fetch all BoxSets and movie collections with item counts and contained movies to `response_variable`.
  - Added 1-tap playback for BoxSets / Collections in the Home Assistant Media Browser: selecting Play on a BoxSet automatically resolves and plays its first movie.
  - Added multi-instance smart routing and localized translations across all 7 supported languages (`en`, `sl`, `de`, `es`, `fr`, `it`, `ru`).

### Fixed
- **Stream URL Item ID Resolution (Fixes [#43](https://github.com/zupancicmarko/JellyHA/issues/43))**:
  - Resolved `jellyha.play_music` and `media_player.play_media` extracting the literal string `"stream"` as the `item_id` when supplied with direct stream URLs (e.g. `/Audio/<GUID>/stream?static=true`).
  - Implemented a robust item ID extraction utility (`extract_item_id`) supporting 32-hex GUIDs, UUIDs, stream URLs (`/Audio/.../stream`, `/Videos/.../master.m3u8`), proxy stream URLs, downloads, query parameters (`?itemId=`), and Web UI fragments.
  - Fixed resulting HTTP 400 Bad Request errors (`The value 'stream' is not valid`) and prevented WebSocket client message loop crashes (`IndexError: list index out of range` in `jellyfin-mpv-shim`, Android TV, and Web clients).
- **Home Assistant Voice Assist Search Compatibility (`async_search_media`) (Fixes [#43](https://github.com/zupancicmarko/JellyHA/issues/43))**:
  - Updated `async_search_media` across media player entities to accept modern Home Assistant core's `SearchMediaQuery` dataclass and return `SearchMedia(result=...)`, resolving `TypeError: ...got an unexpected keyword argument 'query'` when Voice Assist (`HassMediaSearchAndPlay`) searches against JellyHA media players.
  - Added `MediaPlayerEntityFeature.SEARCH_MEDIA` and `async_search_media` to all session-backed user and device media players, enabling direct voice searches on individual players.
- **Idle User Media Player Playback (`JellyHAUserMediaPlayer`)**:
  - Fixed an issue where targeting an idle user media player (`media_player.jellyha_<user>`) with `play_media` or `play_music` failed with `"No active Jellyfin session found"` when the user had their Jellyfin client open but was not yet playing media.
  - Updated user session resolution to prioritize active playback while retaining idle sessions, allowing remote playback to start immediately.
- **HTTP Byte-Range Requests & Seeking in Stream Proxy (`JellyHAStreamView`)**:
  - Forwarded incoming `Range` headers to the Jellyfin server, added support for `206 Partial Content` upstream responses, and forwarded `Content-Range`, `Accept-Ranges`, and `Content-Length` headers back to the client.
  - Resolved media scrubbing/seeking failures and fixed stream playback issues on Safari, iOS devices, and Google Cast endpoints.
- **Direct Session Routing for Music Playback**:
  - Enhanced `jellyha.play_music` to detect when `target_player` is an active Jellyfin session and route playback directly via `api.session_play`, eliminating unnecessary stream URL indirection while continuing to deliver direct HTTP stream URLs to external speakers (Sonos, Google Cast, Chromecast).
- **Series / Season Playback Fallback**:
  - Added automatic fallback to the first unplayed episode (or first episode) when Next-Up episode resolution returns empty for a series or season.

## [1.4.0] - 2026-09-15

### Added
- **Dedicated Music Search & Playback Services (Fixes [#26](https://github.com/zupancicmarko/JellyHA/issues/26))**:
  - Added `jellyha.music_search`: An indexed, sub-50ms music search action querying tracks, albums, or artists with FLAC, ALAC, and Hi-Res audio specifications returned to `response_variable`.
  - Added `jellyha.play_music`: A 1-step action to search and play a song or album from Jellyfin directly on any Home Assistant media player (e.g. Kitchen Speaker, Sonos, Google Cast, Wiim, HomePod). Designed for voice assistants (Home Assistant Assist / LLMs) and automations.
  - Added full **FLAC, ALAC & Hi-Res Audio** stream extraction via `MediaStrategy.extract_audio_stream_attributes`: exposes `audio_codec`, `audio_container`, `bit_depth` (16, 24, 32-bit), `sample_rate` (44.1 to 192 kHz), `channels`, `channel_layout`, `bit_rate`, `is_lossless`, `is_hi_res`, and human-readable badges (`audio_quality_label`, e.g. `"24-bit / 96 kHz FLAC (Hi-Res Lossless)"`).
  - Added direct bit-perfect audio stream URLs (`stream_url`) and disk paths (`path`, `filepath`).
  - Added clean display format (`Artist - Song Title`) for music playback in Media Browser, stripping file extensions (`.flac`, `.mp3`) and track number prefixes across `media_player` titles, Media Browser track lists, signed stream URLs, and `Content-Disposition` headers.
  - Full **Multi-Instance Smart Routing**: When running separate instances (e.g. "JellyHA Movies" and "JellyHA Music"), voice commands and automations without explicit instance parameters automatically route to the Music instance.
  - Added `songs`, `albums`, and `artists` count attributes to `sensor.jellyha_library`.
- **Expose Media File Path in Actions & Cards (Fixes [#37](https://github.com/zupancicmarko/JellyHA/issues/37))**:
  - Exposed `path` and `filepath` in the `jellyha.get_item` response, `jellyha.search`, and `jellyha.get_recommendations`, providing the absolute server file path on disk.
  - Injected `path` and `filepath` into the execution variables of the Lovelace Library Card "Run Script" action (`call-service`) and `jellyha_item_clicked` events, making it easy to route local paths to external media players (Kodi, MPV, VLC).
  - Updated the Kodi external player script example ([`card_action_play_on_kodi.yaml`](examples/scripts/card_action_play_on_kodi.yaml)) with direct file path playback mode (`playback_mode: "direct_path"`), enabling direct playback without streaming add-ons when Kodi has access to local or network SMB/NFS storage.
- **Standardized Watched Percentage Sensors (PR [#35](https://github.com/zupancicmarko/JellyHA/pull/35))**:
  - Added `sensor.jellyha_library_movies_watched_percentage`, `sensor.jellyha_library_series_watched_percentage`, and `sensor.jellyha_library_episodes_watched_percentage`.
  - Configured with `SensorStateClass.MEASUREMENT` for Home Assistant Long-Term Statistics (LTS) tracking and historical graphs.
- **Per-Library Storage Size Sensors (PR [#36](https://github.com/zupancicmarko/JellyHA/pull/36))**:
  - Added dedicated per-library storage size sensors (`sensor.jellyha_library_<name>_storage_size`) with `SensorDeviceClass.DATA_SIZE` and `SensorStateClass.MEASUREMENT` in GB with raw byte breakdown.
- **Live TV Support (PR [#38](https://github.com/zupancicmarko/JellyHA/pull/38), Fixes [#11](https://github.com/zupancicmarko/JellyHA/issues/11))**:
  - Added visual Live TV channel browsing with 1-tap playback in the Media Browser under a dedicated **📡 Live TV** category with authenticated channel logos and channel numbers.
  - Added `enable_live_tv` toggle in Integration Options Flow (defaults to `false`) to eliminate unnecessary API polling for setups without TV tuners or IPTV.
  - Added lightweight `sensor.jellyha_live_tv_channels` reporting total channel count with recorder database protection against SQLite attribute size limits.
  - Added dedicated Live TV services: `jellyha.play_live_tv_channel` (direct tuning by channel number or name in a single step, compatible with Home Assistant Voice Assist) and `jellyha.get_live_tv_channels` (searchable channel list with query and limit parameters, plus coordinator RAM fallback).
  - Full multi-instance support and localization across 7 languages (`en`, `sl`, `de`, `fr`, `es`, `it`, `ru`).

### Changed
- **Now Playing Card Migration Documentation (Fixes [#34](https://github.com/zupancicmarko/JellyHA/issues/34))**:
  - Documented the seamless 1-line migration path from deprecated `sensor.jellyha_now_playing_<user>` to `media_player.jellyha_<user>` in `README.md`, `docs/cards.md`, and `docs/entities.md`.
  - Clarified that `custom:jellyha-now-playing-card` retains 100% visual and functional parity (fanart, ratings, season/episode badges, live scrub bar, transport controls) and requires no third-party cards or dashboard rewrites.
  - Enhanced `jellyha.update_favorite` and `jellyha.mark_watched` actions to resolve target `user_id` from entity attributes when called with `media_player.jellyha_<user>`, ensuring correct per-user state in multi-user households.
- **Device Custom Names in Options Flow (PR [#39](https://github.com/zupancicmarko/JellyHA/pull/39))**: Prioritized `CustomName` when generating the device player list in Integration Options Flow, displaying user-assigned nicknames from the Jellyfin Dashboard (e.g., "Living Room OLED") instead of generic hardware labels.

### Fixed
- **Library Card Editor Rendering in Grid and List Layouts**: Fixed card editor fields disappearing or failing to render when selecting Grid or List layouts due to an unhandled `ReferenceError: columnsLabel is not defined`.
- **Music Library Sync & Audio Search Infinite Hang (Fixes [#26](https://github.com/zupancicmarko/JellyHA/issues/26))**:
  - Resolved `media_type: Audio` search hanging indefinitely by enforcing indexed `SortBy=SortName` on audio queries instead of unindexed `DateCreated`, preventing server-side SQLite full table scans across large song libraries.
  - Resolved music-only library instances showing `0` items on `sensor.jellyha_library` and watched sensors by fetching instant item counts from Jellyfin's `GET /Items/Counts?userId={user_id}` without downloading tens of thousands of track objects into Home Assistant memory.
- **Device Session Collisions on webOS & Browsers (Fixes [#39](https://github.com/zupancicmarko/JellyHA/pull/39))**: Enforced exact `DeviceId` matching across device media players, companion session checks, and playback services. This eliminates cross-device session collisions caused by fuzzy 8-character and 16-character prefix slicing, which previously caused LG webOS TVs, Samsung Tizen TVs, and web browser clients to match each other due to shared base64 User-Agent prefixes (`Mozilla/5.0...`).

## [1.3.1] - 2026-09-14

### Added
- **Friendly Stream Filenames & Clean Display Titles**: Generated clean, human-readable display filenames (`Artist - Track Name`, `Series - S01E02 - Episode Name`, `Movie (Year)`) in stream URLs and added `Content-Disposition: inline` headers, ensuring Google Cast devices and external players display proper titles and artist metadata instead of raw Jellyfin GUIDs.
- **Universal Favorites Support**: Added direct API fetching for user favorites across all media types (audio tracks, albums, artists, series, episodes, and movies) with automatic fallback to local cached items.
- **Music & Audio Support in Media Browser**: Added full MIME type classification for audio streams (`audio/flac`, `audio/mp4`, `audio/ogg`, `audio/wav`, `audio/mpeg`) and proper MediaClass hierarchy (`TRACK`, `ALBUM`, `ARTIST`) in the media browser.
- **Album & Playlist Playback Resolution**: Playing a music album or playlist now automatically resolves and plays its first playable track in both the media player and media source integration.
- **Cinematic Latest Media Hero Card Examples**: Added ready-to-use Lovelace dashboard recipes (`latest_media_hero_card.yaml`) for latest movies and episodes featuring backdrop blurring, floating poster art, format pills, and synopsis text.

### Changed
- **Library-Scoped Favorites & Recently Added Browsing**: Scoped favorites and recently added media views to the specific authorized libraries configured for each integration instance via `ParentId` filtering.
- **Active Jellyfin Session Remote Control**: Media player `play_media` requests now automatically route playback to active Jellyfin client sessions for the user, filtering out background clients (Home Assistant and Seerr).
- **Brand Assets Location**: Relocated brand icons and logos into `custom_components/jellyha/brand/` in accordance with Home Assistant integration standards.

### Fixed
- **Album Playback & Invalid Media ID Error (Fixes [#25](https://github.com/zupancicmarko/JellyHA/issues/25))**: Resolved `Cannot play: invalid media_id format: jellyha://album/...` errors when initiating playback on albums and playlists by accepting container media categories and resolving their first playable track. Also fixed silent playback failures for individual music tracks by routing requests to active Jellyfin sessions and streaming proxies.
- **Cast Audio Playback & Streaming Proxies**: Added dedicated proxy endpoints (`/api/jellyha/stream/{entry_id}/{media_type}/{item_id}/{filename}`) with `Accept-Ranges` headers for seamless seeking and streaming on Chromecast devices without exposing API keys.
- **On-Demand API Fallback for Uncached Media**: Resolved missing metadata or playback failures when browsing deeply nested tracks or uncached items by fetching details on-demand via the Jellyfin API.


## [1.3.0] - 2026-09-11

### Added
- **Jellyfin 12.0 Ready**: Full compatibility with Jellyfin 12.0+ WebSocket authentication and modern universal API endpoints (Fixes #23, PR #24 by @odtgit, and #29 with help from @dlip9663).
- **Device-Based Media Players (Resolves [#12](https://github.com/zupancicmarko/JellyHA/issues/12), thanks to @barrelltitor)**: Added dedicated media player entities for physical client devices (e.g., Smart TVs, Apple TV, Fire TV) in Options Flow. These enable room-specific automations (like cinema lighting) regardless of which user is watching.
- **Enhanced Media Players**: `media_player.jellyha_<user>` is now the primary entity for playback and automations, featuring full transport controls (play, pause, stop, seek, shuffle, repeat, volume) and rich state attributes.
- **Community Card Compatibility**: Out-of-the-box compatibility with popular Lovelace cards including **Mini Media Player**, **Mushroom Media Card**, and **Universal Media Player**.
- **Intro & Segment Detection**: Live detection of Intro, Outro, Recap, and Commercial segments (via Intro Skipper or chapters), complete with auto-skip timing attributes and change events.
- **Chapter Awareness**: Media players now expose chapter names, index numbers, counts, and fire chapter transition events.
- **HDR & Dynamic Range Detection (Resolves [#18](https://github.com/zupancicmarko/JellyHA/issues/18))**: Real-time detection of SDR, HDR10, HDR10+, Dolby Vision, and HLG formats to trigger TV picture modes and ambient lighting automations.
- **Run Script Action in Library Card (Resolves [#10](https://github.com/zupancicmarko/JellyHA/issues/10), thanks to @garpernaut)**: Tap, hold, or double-tap any media poster to trigger a Home Assistant script with full media details passed directly into template variables.
- **Shows vs. Episodes in Library Card**: Added an option to display newly added individual episodes instead of full series, with optional series poster art for uniform layouts.
- **Supercharged Search Service (Resolves [#13](https://github.com/zupancicmarko/JellyHA/issues/13), thanks to @deergitseason)**: Added sorting, granular filtering (by studio, person, parent show), and enriched TV episode search results with parent series metadata.
- **Smart Chromecast TV Playback**: Playing a series on Chromecast now automatically resolves to the next unplayed episode.
- **Subtitle Selection for Chromecast (Resolves [#15](https://github.com/zupancicmarko/JellyHA/issues/15), thanks to @danezu-create)**: Added full subtitle controls to `jellyha.play_on_chromecast` and the Library Card editor (`subtitle_mode`: `auto`, `none`, `forced_only`, `custom`, and prioritized language list `subtitle_language`, e.g. `sl, en`). Subtitles are automatically burned into the stream via server-side video transcoding for bitmap formats (PGS, VOBSUB, DVDSUB) and delivered externally for text formats (WebVTT/SubRip), with automatic fallback to user profile preferences or English.
- **Card Editor Polish & Scoped Labels**: Scoped card editor cast fields to **Cast Subtitles** and **Cast Subtitle Priority**, filtered the Default Cast Device picker strictly to Google Cast endpoints, and aligned Double Tap spacing with the cast device selector.
- **New Jellyfin Sensors**: Added dedicated sensors for **Movies Count**, **Series Count**, **Episodes Count**, **Active Transcoding Streams**, and **Media Storage Free Space** (GB & Percentage with breakdown and capacity attributes).
- **Latest Media Sensors**: Added **Latest Movie** and **Latest Episode** sensors featuring rich attributes: runtime, overview, ratings, series and episode info, dynamic range (HDR/DV), resolution, and codecs.
- **Automation & Dashboard Examples**: Added ready-to-use YAML examples in the new `examples/` directory for lighting, auto-skip, notifications, and dashboards.
- **Connected Clients Sensor (Resolves [#30](https://github.com/zupancicmarko/JellyHA/issues/30), thanks to @Grizzelbee)**: Added `sensor.jellyha_connected_clients` — counts all Jellyfin clients that are currently connected, regardless of play state. Unlike Active Sessions, this sensor updates the moment a client opens the app (via WebSocket push) making it ideal for Wake-on-LAN automations. Includes per-client attributes: `user`, `device`, `client`, `last_activity_date`, `is_playing`. See `examples/automations/wol_on_client_connect.yaml`.

### Deprecated
- **Legacy Now Playing Sensors**: `sensor.jellyha_now_playing_<user>` is deprecated in favor of `media_player.jellyha_<user>`, `media_player.jellyha_<device_name>`and will be removed in v2.0.0.

### Changed
- **Cinematic Item Details Modal**: Redesigned the "More Information" dialog with hero backdrop artwork, quick action buttons (Cast, Episodes, Trailer), and technical format badges.
- **Streamlined Documentation**: Replaced inline YAML configurations in `README.md` with organized references to `examples/`.
- **Modernized Card Editors**: All card settings and form inputs now use native Home Assistant selectors.

### Fixed
- **Stack-in-Card & Vertical Stack Layouts (Fixes [#21](https://github.com/zupancicmarko/JellyHA/issues/21), thanks to @bbqbob)**: Resolved layout collapse, clipping, and floating controls when Now Playing cards are placed inside vertical stacks, `stack-in-card`, or clamped Section views.
- **Jellyfin 12.0 Compatibility & Stability (Fixes [#29](https://github.com/zupancicmarko/JellyHA/issues/29), thanks to @dlip9663)**: Fixed API key deletion on reload, updated deprecated user endpoints, and hardened WebSocket keepalives against silent dropouts.
- **Chromecast Playback on Jellyfin 12.0**: Added case-sensitive `ApiKey` parameter to HLS stream manifests (`master.m3u8`), resolving `401 Unauthorized` playback failures when casting to Chromecast devices.
- **Chromecast HLS Stream Manifest Caching & Session Reuse**: Prevented Chromecast from replaying cached segments when switching subtitle streams by injecting unique `PlaySessionId` tokens per transcode job and issuing an automatic device reset before `play_media`.
- **Item Details Dialog Subtitle Pass-through**: Fixed `Play`, `Cast`, and `Play Next Up` actions inside the "More Information" dialog not respecting the card's configured cast subtitle strategy.
- **Large Libraries & Collections (Fixes [#22](https://github.com/zupancicmarko/JellyHA/issues/22), thanks to @Matthieu-Em)**: Fixed movies inside box sets being hidden and added automatic batching so libraries with thousands of items sync completely.
- **Episode & Library Statistics (Fixes [#22](https://github.com/zupancicmarko/JellyHA/issues/22), thanks to @Matthieu-Em)**: Corrected watched episode counts and library sensor aggregation.
- **Service Action Validation (Fixes [#28](https://github.com/zupancicmarko/JellyHA/issues/28), thanks to @slm020)*: Fixed `extra keys not allowed` errors across JellyHA service calls.
- **Episode List Crash**: Fixed a template crash in "View All Episodes" when series contain unrated episodes.
- **Episode Screenshots**: Corrected episode list rows to show individual episode thumbnails instead of series backdrops.
- **Trailer Playback**: YouTube trailer links now open directly in YouTube rather than redirecting to Jellyfin.
- **Theme Border Radius**: Fixed poster corner rounding when using custom themes with large border radii.
- **Date Added & "New" Badges**: Fixed "Show Date Added" and newly-added badges not appearing on library cards.
- **Next Up Filtering**: Fixed favorite and watch status filters not applying to the Next Up view.
- **Episode Favorites**: TV episodes now inherit parent series favorite status so favorite filters and badges work seamlessly.
- **Card Editor Defaults**: Fixed visual editor toggles (playback controls, runtime, genres, background) showing out of sync on newly created cards.
- **Carousel Alignment**: Added a horizontal alignment option (center / left) in the Library Card editor.


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
