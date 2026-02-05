# Changelog

All notable changes to JellyHA will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
