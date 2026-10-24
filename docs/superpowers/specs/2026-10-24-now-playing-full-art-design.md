# Design Specification: Full Artwork (Fanart / Poster) Mode for Now Playing Card

- **Date:** 2026-10-24
- **Feature:** Full Artwork Mode during Active Playback
- **Component:** `jellyha-now-playing-card`, `jellyha-now-playing-editor`
- **Target Release:** JellyHA 1.8.0

---

## 1. Overview & Motivation
Currently, the JellyHA Now Playing card provides two presentation styles for the idle screensaver (`idle_display_mode`):
- `backdrop`: Full Fanart Backdrop Screensaver (full-bleed artwork with title/metadata/overview overlaid).
- `card`: Card Layout (side-by-side vertical poster and details).

However, during active media playback, the card has only supported the traditional 2-column layout (vertical poster on the left, info and controls on the right, with an optional blurred backdrop background).

This feature introduces a dedicated **Full Artwork (Cinematic Hero)** mode for active playback (`playing_display_mode: 'full_art'`). In this mode, the media's artwork fills the card full-bleed, with the full suite of playback controls, seeking progress bar, title, subtitle, badges, metadata pills, and volume controls anchored over a dark gradient scrim at the bottom. Additionally, users can choose their preferred artwork source: either the wide **Fanart Backdrop** (`'backdrop'`) or the vertical **Poster** (`'poster'`).

---

## 2. Configuration Schema & Types

In `src/shared/types.ts`:
```typescript
export interface JellyHANowPlayingCardConfig extends LovelaceCardConfig {
    // Existing configuration properties ...
    playing_display_mode?: 'card' | 'full_art';
    playing_artwork_source?: 'backdrop' | 'poster';
}
```

### Configuration Options
| Key | Type | Default | Description |
|---|---|---|---|
| `playing_display_mode` | string | `'card'` | Active playback layout presentation: `'card'` (standard side-by-side poster + details) or `'full_art'` (cinematic full-bleed hero artwork). |
| `playing_artwork_source` | string | `'backdrop'` | Sourced artwork for full-art layout: `'backdrop'` (fanart landscape backdrop) or `'poster'` (movie/series portrait poster). |

### Backward Compatibility
If omitted, `playing_display_mode` defaults to `'card'`, preserving the exact existing behavior for all existing dashboards.

---

## 3. Card Visual Architecture & DOM Hierarchy

When media is active and `playing_display_mode === 'full_art'`, the card renders `_renderFullArtPlayingMode(...)`:

```
+-------------------------------------------------------------------------+
| [Card Title]                                  [Badge (opt)]   [Power ⏻] |  <-- .full-art-top-bar
|                                                                         |
|                                                                         |
|                       FULL-BLEED HERO ARTWORK                           |
|                  (Backdrop Fanart OR Full Poster)                       |
|                                                                         |
|============================ GRADIENT SCRIM =============================|  <-- .full-art-scrim
| Dune: Part Two                                                          |  <-- .title
| Paul Atreides unites with Chani and the Fremen                          |  <-- .subtitle
| [MOVIE]  2024 · 2h 46m · ★ 8.5 · Sci-Fi, Adventure · Living Room · user |  <-- _renderMetaRow
|                                                                         |
|                  [ ⏪ 10s ]   [  ▶ / ⏸  ]   [ ⏩ 30s ]                  |  <-- .playback-controls
|                             (Hold to Stop)                              |
|               [ ── Volume Slider / Step Buttons ── ]                    |  <-- _renderVolumeControls
| 01:14:22 ━━━━━━━━━━━━━━━━━━━━●─────────────────────────────── -01:31:38 |  <-- .progress-container & timestamps
+-------------------------------------------------------------------------+
```

### Artwork & Focal Alignment
1. **Fanart Backdrop (`playing_artwork_source: 'backdrop'`):**
   - Source: `attributes.backdrop_url || cachedItem?.backdrop_url || imageUrl`
   - Image parameters: `addImageParams(url, 960)`
   - CSS: `object-fit: cover; object-position: center center;`
2. **Poster (`playing_artwork_source: 'poster'`):**
   - Source: `(use_series_image && seriesImageUrl) ? seriesImageUrl : (imageUrl || backdropUrl)`
   - Image parameters: `addImageParams(url, 640)`
   - CSS: `object-fit: cover; object-position: center 15%;` (focal top-center alignment to keep titles and faces framed nicely).
3. **Automatic Fallback:**
   - If preferred source is missing, the card automatically falls back to whichever artwork is available (backdrop $\leftrightarrow$ poster).

### Scrim & Readability
- `.full-art-scrim`: Positioned absolutely from bottom to top with a multi-stop gradient:
  ```css
  background: linear-gradient(
      180deg,
      rgba(0, 0, 0, 0) 0%,
      rgba(0, 0, 0, 0.35) 30%,
      rgba(0, 0, 0, 0.7) 65%,
      rgba(0, 0, 0, 0.92) 100%
  );
  ```
- Ensures high contrast and accessible text/control visibility across all brightness levels.

### Card Controls & Interactivity
- Reuses all existing interaction handlers:
  - Play / Pause with hold-to-stop long-press radial progress ring (`_startLongPress`, `_endLongPress`).
  - Seek -10s / +30s (`_handleSeekRelative`).
  - Next / Prev / Heart / Repeat for audio playback.
  - Interactive pointer scrubbing for progress bar with dominant-color accent styling (`--card-dominant-color`).
  - Volume slider and step buttons (`_renderVolumeControls`).
  - Power button (`_renderPowerButton`).

---

## 4. Card Editor UI (`jellyha-now-playing-editor.ts`)

Under the **Card Display** section:
1. **Playback Display Style Dropdown (`playing_display_mode`):**
   - `card`: "Card Layout (Poster + Details)"
   - `full_art`: "Full Artwork (Cinematic Hero)"
2. **Playback Artwork Image Dropdown (`playing_artwork_source`):**
   - Visible only when `playing_display_mode === 'full_art'`.
   - `backdrop`: "Fanart Backdrop"
   - `poster`: "Poster"
3. Uses Home Assistant's native `<ha-selector>` elements with reactive value-change handlers.

---

## 5. Localization (`src/shared/localize.ts`)

The following translation keys are added across all 8 supported languages (`en`, `de`, `fr`, `es`, `it`, `nl`, `sl`, `ru`):
- `editor.playing_display_mode`: "Playback Display Style"
- `editor.playing_display_mode_card`: "Card Layout (Poster + Details)"
- `editor.playing_display_mode_full_art`: "Full Artwork (Cinematic Hero)"
- `editor.playing_artwork_source`: "Playback Artwork Image"
- `editor.playing_artwork_source_backdrop`: "Fanart Backdrop"
- `editor.playing_artwork_source_poster`: "Poster"

---

## 6. Testing Strategy

1. **Unit & Integration Tests (`tests/now-playing-full-art.test.ts`):**
   - Verify card renders standard 2-column layout when `playing_display_mode: 'card'` (default).
   - Verify card renders full-art layout when `playing_display_mode: 'full_art'`.
   - Verify backdrop image is selected when `playing_artwork_source: 'backdrop'`.
   - Verify poster image is selected with `center 15%` focal alignment when `playing_artwork_source: 'poster'`.
   - Verify image fallback when requested source is absent.
   - Verify complete controls tree is present in full-art mode (play/pause, seek, volume, progress, timestamps).
   - Verify audio/music playback layout in full-art mode.
2. **Editor Tests (`tests/editor.test.ts`):**
   - Verify editor renders `playing_display_mode` selector.
   - Verify editor displays `playing_artwork_source` conditionally when `playing_display_mode === 'full_art'`.
   - Verify config updates correctly emit `config-changed` events.
