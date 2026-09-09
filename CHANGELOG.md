# Changelog

All notable changes to JellyHA will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] - 2026-09-10

### Added
- **Device-Based Media Players (Resolves #12)**: Added dedicated media player entities for physical client devices (e.g., Smart TVs, Apple TV, Fire TV) in Options Flow. These enable room-specific automations (like cinema lighting) regardless of which user is watching.
- **Enhanced Media Players**: `media_player.jellyha_<user>` is now the primary entity for playback and automations, featuring full transport controls (play, pause, stop, seek, shuffle, repeat, volume) and rich state attributes.
- **Community Card Compatibility**: Out-of-the-box compatibility with popular Lovelace cards including **Mini Media Player**, **Mushroom Media Card**, and **Universal Media Player**.
- **Intro & Segment Detection**: Live detection of Intro, Outro, Recap, and Commercial segments (via Intro Skipper or chapters), complete with auto-skip timing attributes and change events.
- **Chapter Awareness**: Media players now expose chapter names, index numbers, counts, and fire chapter transition events.
- **HDR & Dynamic Range Detection (Resolves #18)**: Real-time detection of SDR, HDR10, HDR10+, Dolby Vision, and HLG formats to trigger TV picture modes and ambient lighting automations.
- **Run Script Action in Library Card (Resolves #10)**: Tap, hold, or double-tap any media poster to trigger a Home Assistant script with full media details passed directly into template variables.
- **Shows vs. Episodes in Library Card**: Added an option to display newly added individual episodes instead of full series, with optional series poster art for uniform layouts.
- **Supercharged Search Service (Resolves #13)**: Added sorting, granular filtering (by studio, person, parent show), and enriched TV episode search results with parent series metadata.
- **Smart Chromecast TV Playback**: Playing a series on Chromecast now automatically resolves to the next unplayed episode.
- **New Jellyfin Sensors**: Added dedicated sensors for **Movies Count**, **Series Count**, **Episodes Count**, **Active Transcoding Streams**, and **Media Storage Free Space** (GB & Percentage with breakdown and capacity attributes).
- **Latest Media Sensors**: Added **Latest Movie** and **Latest Episode** sensors featuring rich attributes: runtime, overview, ratings, series and episode info, dynamic range (HDR/DV), resolution, and codecs.
- **Automation & Dashboard Examples**: Added ready-to-use YAML examples in the new `examples/` directory for lighting, auto-skip, notifications, and dashboards.
- **Jellyfin 12.0 Ready**: Full compatibility with Jellyfin 12.0+ WebSocket authentication and modern universal API endpoints (Fixes #23, PR #24 by @odtgit, and #29 with help from @dlip9663).

### Deprecated
- **Legacy Now Playing Sensors**: `sensor.jellyha_now_playing_<user>` is deprecated in favor of `media_player.jellyha_<user>` and will be removed in v2.0.0.

### Changed
- **Cinematic Item Details Modal**: Redesigned the "More Information" dialog with hero backdrop artwork, quick action buttons (Cast, Episodes, Trailer), and technical format badges.
- **Streamlined Documentation**: Replaced inline YAML configurations in `README.md` with organized references to `examples/`.
- **Modernized Card Editors**: All card settings and form inputs now use native Home Assistant selectors.

### Fixed
- **Stack-in-Card & Vertical Stack Layouts (Fixes #21, thanks to @bbqbob)**: Resolved layout collapse, clipping, and floating controls when Now Playing cards are placed inside vertical stacks, `stack-in-card`, or clamped Section views.
- **Jellyfin 12.0 Compatibility & Stability (Fixes #29, thanks to @dlip9663)**: Fixed API key deletion on reload, updated deprecated user endpoints, and hardened WebSocket keepalives against silent dropouts.
- **Chromecast Playback on Jellyfin 12.0**: Added case-sensitive `ApiKey` parameter to HLS stream manifests (`master.m3u8`), resolving `401 Unauthorized` playback failures when casting to Chromecast devices.
- **Large Libraries & Collections (Fixes #22)**: Fixed movies inside box sets being hidden and added automatic batching so libraries with thousands of items sync completely.
- **Episode & Library Statistics (Fixes #22)**: Corrected watched episode counts and library sensor aggregation.
- **Service Action Validation (Fixes #28)**: Fixed `extra keys not allowed` errors across JellyHA service calls.
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
