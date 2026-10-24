# Now Playing Card Full Artwork Playback Mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a cinematic "Full Artwork" (Hero Fanart or Poster) display mode to the JellyHA Now Playing card during active media playback, configurable via card editor and YAML.

**Architecture:** Extend `JellyHANowPlayingCardConfig` with `playing_display_mode` (`'card' | 'full_art'`) and `playing_artwork_source` (`'backdrop' | 'poster'`). In `jellyha-now-playing-card.ts`, branch rendering during active playback to `_renderFullArtPlayingMode(...)` when `playing_display_mode === 'full_art'`. The full art layout layers full-bleed artwork, a dark gradient scrim, and bottom-anchored controls (title, subtitle, metadata pills, playback controls with long-press stop, volume, and interactive seek progress bar). Update editor with reactive selectors and add full translations and test coverage.

**Tech Stack:** TypeScript, Lit, Home Assistant Lovelace Card API, Vitest.

**Spec:** `docs/superpowers/specs/2026-10-24-now-playing-full-art-design.md`

## Global Constraints
- `playing_display_mode` defaults to `'card'` to preserve 100% backward compatibility.
- `playing_artwork_source` defaults to `'backdrop'`.
- Poster focal alignment must use `object-position: center 15%` when `playing_artwork_source: 'poster'` to prevent cropping actor heads or movie titles.
- Automatic fallback: If requested artwork (`backdrop` or `poster`) is missing for an item, the card must fall back to whichever artwork image is available.
- All translations must be added for all 8 supported languages (`en`, `de`, `fr`, `es`, `it`, `nl`, `sl`, `ru`).

## Review Focus
1. An item has no backdrop image while `playing_artwork_source: 'backdrop'` is set -> card must automatically fall back to poster image without broken `<img>` src.
2. An audio track (music) is playing with square album art in full art mode -> card must render cleanly with ambient edge fill.
3. Media player entity does not support remote playback services -> card must hide or disable playback controls gracefully.
4. Card rendered in a narrow column (< 380px) -> metadata pills and controls must not overflow or clip.
5. Long-press hold-to-stop interaction -> the SVG radial stop ring must position correctly over the play/pause button in full art mode.

---

### Task 1: Config Types & Localization

**Files:**
- Modify: `src/shared/types.ts:237-274`
- Modify: `src/shared/localize.ts`
- Test: `tests/types.test.ts`

**Interfaces:**
- Produces:
  - `JellyHANowPlayingCardConfig.playing_display_mode?: 'card' | 'full_art'`
  - `JellyHANowPlayingCardConfig.playing_artwork_source?: 'backdrop' | 'poster'`
  - Localization keys: `editor.playing_display_mode`, `editor.playing_display_mode_card`, `editor.playing_display_mode_full_art`, `editor.playing_artwork_source`, `editor.playing_artwork_source_backdrop`, `editor.playing_artwork_source_poster`

- [ ] **Step 1: Write the failing type & localization test**

In `tests/types.test.ts`, add test verifying the new config fields and localization strings:
```typescript
it('defines playing_display_mode and playing_artwork_source in now playing config', () => {
    const config: JellyHANowPlayingCardConfig = {
        type: 'custom:jellyha-now-playing-card',
        entity: 'media_player.jellyfin',
        playing_display_mode: 'full_art',
        playing_artwork_source: 'poster',
    };
    expect(config.playing_display_mode).toBe('full_art');
    expect(config.playing_artwork_source).toBe('poster');
});

it('translates playing display mode keys across languages', () => {
    expect(localize('en', 'editor.playing_display_mode')).toBe('Playback Display Style');
    expect(localize('de', 'editor.playing_display_mode')).toBeDefined();
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node ./node_modules/vitest/vitest.mjs run tests/types.test.ts`
Expected: FAIL with TypeScript/assertion errors for missing fields or localization keys.

- [ ] **Step 3: Implement config types and localization keys**

In `src/shared/types.ts`:
Add `playing_display_mode?: 'card' | 'full_art';` and `playing_artwork_source?: 'backdrop' | 'poster';` to `JellyHANowPlayingCardConfig`.

In `src/shared/localize.ts`:
Add translations for all 8 languages:
- `en`: "Playback Display Style", "Card Layout (Poster + Details)", "Full Artwork (Cinematic Hero)", "Playback Artwork Image", "Fanart Backdrop", "Poster"
- `de`: "Wiedergabe-Anzeigestil", "Karten-Layout (Poster + Details)", "Vollbild-Grafik (Kino-Held)", "Wiedergabe-Grafikbild", "Fanart-Hintergrund", "Poster"
- `fr`: "Style d'affichage en lecture", "Disposition carte (Affiche + Détails)", "Plein écran artistique (Héros cinématographique)", "Image artistique de lecture", "Arrière-plan Fanart", "Affiche"
- `es`: "Estilo de visualización de reproducción", "Diseño de tarjeta (Póster + Detalles)", "Ilustración completa (Héroe cinematográfico)", "Imagen de la ilustración", "Fondo Fanart", "Póster"
- `it`: "Stile visualizzazione riproduzione", "Layout scheda (Locandina + Dettagli)", "Opera d'arte completa (Eroe cinematografico)", "Immagine opera d'arte", "Sfondo Fanart", "Locandina"
- `nl`: "Afspeelweergavestijl", "Kaartindeling (Poster + Details)", "Volledige illustratie (Cinematische held)", "Afspeelillustratie", "Fanart-achtergrond", "Poster"
- `sl`: "Slog prikaza predvajanja", "Postavitev kartice (Plakat + Podrobnosti)", "Celotna umetnost (Kinematografski junak)", "Slika umetnosti predvajanja", "Fanart ozadje", "Plakat"
- `ru`: "Стиль отображения воспроизведения", "Вид карточки (Постер + Детали)", "Полноэкранный арт (Кинематографичный герой)", "Изображение арта воспроизведения", "Фон фанарта", "Постер"

- [ ] **Step 4: Run test to verify it passes**

Run: `node ./node_modules/vitest/vitest.mjs run tests/types.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/shared/types.ts src/shared/localize.ts tests/types.test.ts
git commit -m "feat(types): add playing_display_mode and playing_artwork_source config options and localization"
```

---

### Task 2: Card Editor UI

**Files:**
- Modify: `src/editors/jellyha-now-playing-editor.ts:470-520`
- Modify: `tests/editor.test.ts`

**Interfaces:**
- Consumes: `JellyHANowPlayingCardConfig.playing_display_mode`, `JellyHANowPlayingCardConfig.playing_artwork_source`, localization keys from Task 1.
- Produces: Reactive dropdowns in editor triggering `_updateConfig('playing_display_mode', ...)` and `_updateConfig('playing_artwork_source', ...)`.

- [ ] **Step 1: Write the failing editor test**

In `tests/editor.test.ts`, add tests:
```typescript
it('renders playing_display_mode selector with card and full_art options', async () => {
    const editor = new JellyHANowPlayingEditor();
    editor.setConfig({ entity: 'media_player.jellyfin' } as any);
    await (editor as any).updateComplete;
    const template = (editor as any).render();
    const str = JSON.stringify(template);
    expect(str).toContain('editor.playing_display_mode');
});

it('conditionally renders playing_artwork_source when playing_display_mode is full_art', async () => {
    const editor = new JellyHANowPlayingEditor();
    editor.setConfig({ entity: 'media_player.jellyfin', playing_display_mode: 'full_art' } as any);
    await (editor as any).updateComplete;
    const template = (editor as any).render();
    const str = JSON.stringify(template);
    expect(str).toContain('editor.playing_artwork_source');
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node ./node_modules/vitest/vitest.mjs run tests/editor.test.ts`
Expected: FAIL

- [ ] **Step 3: Implement editor selectors and handlers**

In `src/editors/jellyha-now-playing-editor.ts`:
1. Add `_playingDisplayModeChanged(ev: CustomEvent)`:
   ```typescript
   private _playingDisplayModeChanged(ev: CustomEvent): void {
       const value = ev.detail.value;
       this._updateConfig('playing_display_mode', value);
   }
   ```
2. Add `_playingArtworkSourceChanged(ev: CustomEvent)`:
   ```typescript
   private _playingArtworkSourceChanged(ev: CustomEvent): void {
       const value = ev.detail.value;
       this._updateConfig('playing_artwork_source', value);
   }
   ```
3. In `render()` under the Display/Layout options, render the `<ha-selector>` for `playing_display_mode` (`'card'` and `'full_art'`).
4. If `this._config.playing_display_mode === 'full_art'`, render the `<ha-selector>` for `playing_artwork_source` (`'backdrop'` and `'poster'`).

- [ ] **Step 4: Run test to verify it passes**

Run: `node ./node_modules/vitest/vitest.mjs run tests/editor.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/editors/jellyha-now-playing-editor.ts tests/editor.test.ts
git commit -m "feat(editor): add playing display style and artwork source selectors"
```

---

### Task 3: Full Art Playback Mode Template & Artwork Sourcing

**Files:**
- Modify: `src/cards/jellyha-now-playing-card.ts:340-500`
- Create: `tests/now-playing-full-art.test.ts`

**Interfaces:**
- Consumes: `JellyHANowPlayingCardConfig.playing_display_mode`, `playing_artwork_source`
- Produces: `_renderFullArtPlayingMode(...)` returning Lit `TemplateResult` with full-bleed hero artwork, scrim, top bar, and bottom overlay.

- [ ] **Step 1: Write the failing tests for Full Art Playback Mode**

Create `tests/now-playing-full-art.test.ts`:
```typescript
import { describe, it, expect } from 'vitest';
import { JellyHANowPlayingCard } from '../src/cards/jellyha-now-playing-card';
import { HomeAssistant, JellyHANowPlayingCardConfig } from '../src/shared/types';

describe('Now Playing Card - Full Art Playback Mode', () => {
    const createMockHass = (state: string, attributes: Record<string, any>): HomeAssistant => ({
        states: {
            'media_player.jellyfin': {
                entity_id: 'media_player.jellyfin',
                state,
                attributes: {
                    friendly_name: 'Jellyfin Web',
                    ...attributes,
                },
            },
        },
        callService: async () => {},
        locale: { language: 'en' },
        language: 'en',
    } as unknown as HomeAssistant);

    it('renders classic card mode by default or when playing_display_mode is card', () => {
        const card = new JellyHANowPlayingCard();
        card.setConfig({
            type: 'custom:jellyha-now-playing-card',
            entity: 'media_player.jellyfin',
            playing_display_mode: 'card',
        } as JellyHANowPlayingCardConfig);

        card.hass = createMockHass('playing', {
            media_title: 'Dune: Part Two',
            media_content_type: 'movie',
            entity_picture: '/api/poster.jpg',
            backdrop_url: '/api/fanart.jpg',
        });

        const template = (card as any).render();
        const str = JSON.stringify(template);
        expect(str).toContain('poster-container');
        expect(str).not.toContain('full-art-playing-card');
    });

    it('renders full art layout when playing_display_mode is full_art with backdrop', () => {
        const card = new JellyHANowPlayingCard();
        card.setConfig({
            type: 'custom:jellyha-now-playing-card',
            entity: 'media_player.jellyfin',
            playing_display_mode: 'full_art',
            playing_artwork_source: 'backdrop',
        } as JellyHANowPlayingCardConfig);

        card.hass = createMockHass('playing', {
            media_title: 'Dune: Part Two',
            media_content_type: 'movie',
            entity_picture: '/api/poster.jpg',
            backdrop_url: '/api/fanart.jpg',
        });

        const template = (card as any).render();
        const str = JSON.stringify(template);
        expect(str).toContain('full-art-playing-card');
        expect(str).toContain('full-art-hero-img');
        expect(str).toContain('/api/fanart.jpg');
    });

    it('uses poster artwork and top-center positioning when playing_artwork_source is poster', () => {
        const card = new JellyHANowPlayingCard();
        card.setConfig({
            type: 'custom:jellyha-now-playing-card',
            entity: 'media_player.jellyfin',
            playing_display_mode: 'full_art',
            playing_artwork_source: 'poster',
        } as JellyHANowPlayingCardConfig);

        card.hass = createMockHass('playing', {
            media_title: 'Dune: Part Two',
            media_content_type: 'movie',
            entity_picture: '/api/poster.jpg',
            backdrop_url: '/api/fanart.jpg',
        });

        const template = (card as any).render();
        const str = JSON.stringify(template);
        expect(str).toContain('full-art-playing-card');
        expect(str).toContain('poster-source');
        expect(str).toContain('/api/poster.jpg');
    });

    it('falls back to poster when backdrop is missing in backdrop mode', () => {
        const card = new JellyHANowPlayingCard();
        card.setConfig({
            type: 'custom:jellyha-now-playing-card',
            entity: 'media_player.jellyfin',
            playing_display_mode: 'full_art',
            playing_artwork_source: 'backdrop',
        } as JellyHANowPlayingCardConfig);

        card.hass = createMockHass('playing', {
            media_title: 'Dune: Part Two',
            media_content_type: 'movie',
            entity_picture: '/api/poster.jpg',
        });

        const template = (card as any).render();
        const str = JSON.stringify(template);
        expect(str).toContain('/api/poster.jpg');
    });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node ./node_modules/vitest/vitest.mjs run tests/now-playing-full-art.test.ts`
Expected: FAIL (full_art layout not implemented yet).

- [ ] **Step 3: Implement `_renderFullArtPlayingMode` in `jellyha-now-playing-card.ts`**

1. In `render()` in `src/cards/jellyha-now-playing-card.ts`:
   When `stateObj` is active, check:
   ```typescript
   if (this._config.playing_display_mode === 'full_art') {
       return this._renderFullArtPlayingMode(stateObj, cachedItem, durationSeconds, displayPositionSeconds, isMediaPlayer);
   }
   ```
2. Implement `_renderFullArtPlayingMode`:
   - Determine hero image URL:
     - If `playing_artwork_source === 'poster'`, use poster (`imageUrl`), fallback to `backdropUrl`. Add CSS class `poster-source`.
     - If `playing_artwork_source === 'backdrop'` (default), use `backdropUrl`, fallback to `imageUrl`. Add CSS class `backdrop-source`.
   - Render:
     - `<div class="full-art-backdrop-container">` with `<img class="full-art-hero-img ${sourceClass}" src="..." />` and `<div class="full-art-scrim"></div>`.
     - Top bar `<div class="full-art-top-bar">` with title, header badge, and `this._renderPowerButton()`.
     - Bottom overlay `<div class="full-art-bottom-overlay">`:
       - Title row with displayTitle and subtitle.
       - Metadata row via `this._renderMetaRow(...)`.
       - Playback controls (prev/rewind 10s, play/pause with hold-to-stop radial ring, next/fwd 30s, music favorite/repeat).
       - Volume controls via `this._renderVolumeControls()`.
       - Progress bar and timestamps.

- [ ] **Step 4: Run test to verify it passes**

Run: `node ./node_modules/vitest/vitest.mjs run tests/now-playing-full-art.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/cards/jellyha-now-playing-card.ts tests/now-playing-full-art.test.ts
git commit -m "feat(cards): implement full art active playback mode and image sourcing"
```

---

### Task 4: Full Art CSS Styles & Responsive Breakpoints

**Files:**
- Modify: `src/cards/jellyha-now-playing-card.ts:4050-4310`
- Test: `tests/now-playing-full-art.test.ts`

**Interfaces:**
- Produces: CSS rules for `.full-art-playing-card`, `.full-art-hero-img`, `.full-art-scrim`, `.full-art-top-bar`, `.full-art-bottom-overlay`, `.poster-source`, and responsive media query adjustments.

- [ ] **Step 1: Write tests for full art controls & interactive elements**

In `tests/now-playing-full-art.test.ts`, add:
```typescript
it('renders full playback controls and interactive progress bar in full art mode', () => {
    const card = new JellyHANowPlayingCard();
    card.setConfig({
        type: 'custom:jellyha-now-playing-card',
        entity: 'media_player.jellyfin',
        playing_display_mode: 'full_art',
        show_controls: true,
        show_time: true,
    } as JellyHANowPlayingCardConfig);

    card.hass = createMockHass('playing', {
        media_title: 'Dune: Part Two',
        media_content_type: 'movie',
        entity_picture: '/api/poster.jpg',
        backdrop_url: '/api/fanart.jpg',
        media_duration: 3600,
        media_position: 1200,
        supports_remote_control: true,
    });

    const template = (card as any).render();
    const str = JSON.stringify(template);
    expect(str).toContain('playback-controls');
    expect(str).toContain('play-pause-btn');
    expect(str).toContain('progress-container');
    expect(str).toContain('timestamps');
});
```

- [ ] **Step 2: Run test to verify it passes or check style coverage**

Run: `node ./node_modules/vitest/vitest.mjs run tests/now-playing-full-art.test.ts`

- [ ] **Step 3: Implement CSS styling for Full Art mode in `jellyha-now-playing-card.ts`**

Add CSS rules in static styles:
```css
/* Full Art Playback Mode Styles */
.full-art-playing-card {
    position: relative;
    min-height: 270px;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    overflow: hidden;
    border-radius: var(--ha-card-border-radius, 12px);
    background: #111;
}

.full-art-playing-card .full-art-backdrop-container {
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    overflow: hidden;
    pointer-events: none;
    z-index: 0;
}

.full-art-playing-card .full-art-hero-img {
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    object-fit: cover;
    object-position: center center;
}

.full-art-playing-card .full-art-hero-img.poster-source {
    object-position: center 15%;
}

.full-art-playing-card .full-art-scrim {
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: linear-gradient(
        180deg,
        rgba(0, 0, 0, 0.4) 0%,
        rgba(0, 0, 0, 0) 25%,
        rgba(0, 0, 0, 0.25) 50%,
        rgba(0, 0, 0, 0.72) 75%,
        rgba(0, 0, 0, 0.92) 100%
    );
    pointer-events: none;
    z-index: 1;
}

.full-art-playing-card .full-art-top-bar {
    position: relative;
    z-index: 2;
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 12px 16px 0 16px;
}

.full-art-playing-card .full-art-bottom-overlay {
    position: relative;
    z-index: 2;
    padding: 12px 18px 16px 18px;
    display: flex;
    flex-direction: column;
    gap: 8px;
    margin-top: auto;
}

.full-art-playing-card .full-art-bottom-overlay .title {
    font-size: 1.35rem;
    font-weight: 700;
    color: #fff;
    text-shadow: 0 1px 3px rgba(0, 0, 0, 0.8);
    margin: 0;
    line-height: 1.25;
}

.full-art-playing-card .full-art-bottom-overlay .subtitle {
    font-size: 0.9rem;
    color: rgba(255, 255, 255, 0.85);
    text-shadow: 0 1px 2px rgba(0, 0, 0, 0.8);
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node ./node_modules/vitest/vitest.mjs run tests/now-playing-full-art.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/cards/jellyha-now-playing-card.ts tests/now-playing-full-art.test.ts
git commit -m "feat(styles): add full art card styles, gradient scrim, and layout rules"
```

---

### Task 5: Documentation & Integration Verification

**Files:**
- Modify: `docs/cards.md`
- Modify: `llms.txt`
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Update documentation**

In `docs/cards.md`:
Document `playing_display_mode` (`'card'` or `'full_art'`) and `playing_artwork_source` (`'backdrop'` or `'poster'`). Provide YAML examples.

In `llms.txt`:
Add `playing_display_mode` and `playing_artwork_source` to the configuration reference.

In `CHANGELOG.md`:
Add entry under Upcoming / Unreleased for Full Artwork playback mode support.

- [ ] **Step 2: Build project bundle**

Run: `npm run build`
Expected: Build succeeds and outputs to `custom_components/jellyha/www/jellyha-cards.js`.

- [ ] **Step 3: Run full test suite**

Run: `node ./node_modules/vitest/vitest.mjs run tests/now-playing-full-art.test.ts tests/types.test.ts`
Expected: All tests PASS.

- [ ] **Step 4: Commit**

```bash
git add docs/cards.md llms.txt CHANGELOG.md custom_components/jellyha/www/jellyha-cards.js custom_components/jellyha/www/jellyha-cards.js.map
git commit -m "docs: document playing_display_mode and playing_artwork_source and update bundle"
```
