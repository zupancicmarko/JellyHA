# Changelog

All notable changes to JellyHA will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.1] - 2026-03-08

### Added
- **Options Flow User Switching**: You can now switch the connected Jellyfin user profile directly from the integration Options menu without needing to delete and re-add the integration.
- **Dynamic Options Library Selection**: You can now modify the list of synchronized libraries natively via the Options menu, dynamically updating your dashboard content.
- **Configuration Localization**: Deployed fully native UI strings for the new configuration and options flows across German, Spanish, French, Italian, and Russian languages (joining English and Slovenian).
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
- Improved Now Playing card visuals with dot separators, dynamic colors extracted from posters, glassmorphic progress bar, badges, and refined spacing.

### Fixed
- **Empty Setup Dropout**: Fixed an issue where initial setup or reconfiguration would crash if the user did not have standard `movies` or `tvshows` library types (added fallback to `mixed`, `musicvideos` and `homevideos`, protected against completely empty dropdowns).
- **Setup API Headers**: Fixed a double keyword argument error crashing the setup flow logout cleanup routine.
- **Item Details Modal**: Fixed a bug where favorited status was not correctly displayed in the "More Information" card when opened from lists.
- **Progress Bar**: Fixed the immediate snap-back effect when manually jumping or scrubbing the progress bar by optimistically holding the new position for 3 seconds while awaiting the server update.
- **Stop Pulse**: Fixed a bug where the long-press stop shadow-pulse effect rendered as a square instead of a circle.
- **Loading Spinner**: Fixed the loading spinner shrinking during rewind/seek actions, now properly maintaining the 44px play/pause button size.



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
