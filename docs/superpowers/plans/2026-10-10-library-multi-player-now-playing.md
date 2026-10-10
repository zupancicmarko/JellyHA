# Library Card Multi-Device "Now Playing" Overlay Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable the Library Card's on-poster "Now Playing" overlay to detect and control playback across multiple devices simultaneously (e.g. Chromecast, Jellyfin TV client, mobile clients, and JellyHA session players).

**Architecture:** Refactor `_isItemPlaying` and `_renderNowPlayingOverlay` in `jellyha-media-item.ts` to resolve the matching active player (`default_cast_device`, `default_client_device`, or any active `media_player.jellyha_*`) on a per-poster basis. Update `jellyha-library-card.ts`'s update cycle to observe state transitions on all candidate media players so both posters update in real-time.

**Tech Stack:** TypeScript, Lit, Home Assistant Frontend Custom Cards, Vitest

**Spec:** User request: Support multiple posters simultaneously displaying active playback overlays (e.g. one on Chromecast and another on Jellyfin TV client), routing playback controls (play/pause, stop, rewind) to the specific device playing that item.

## Global Constraints

- Preserve backwards compatibility: `default_cast_device` continues working as before.
- Support simultaneous multi-device playback: Poster A and Poster B independently match and control their respective media players.
- Target the correct device: Clicking play/pause/stop/rewind on Poster A affects Device A only; clicking Poster B affects Device B only.
- Responsive real-time updates: Card re-renders when any monitored media player's state or position updates.
- All existing Vitest and Python unit tests must pass.

## Review Focus

- Matching collisions: If the same title is played on both devices, the one with active playback (`playing`) takes precedence.
- Entity resolution fallback: Handle cases where `default_client_device` or `default_cast_device` is not set or not in `hass.states`.
- Event propagation: Control clicks must continue calling `e.stopPropagation()` so the card does not trigger single-tap/double-tap actions.
- Player states: Match `playing`, `paused`, and `buffering` states.

---

### Task 1: Add Unit Tests for Multi-Player Poster Matching & Controls

**Files:**
- Create: `tests/library-now-playing.test.ts`
- Test: `tests/library-now-playing.test.ts`

**Interfaces:**
- Consumes: `MediaItem`, `JellyHALibraryCardConfig`, `HomeAssistant`
- Produces: Test suite validating `findActiveMediaItemPlayer(item, hass, config)` logic

- [ ] **Step 1: Write the failing unit tests for player matching**

```typescript
import { describe, it, expect } from 'vitest';
import { findActiveMediaItemPlayer } from '../src/shared/power-volume-helpers';
import { MediaItem, HomeAssistant, JellyHALibraryCardConfig } from '../src/shared/types';

describe('Library Card Multi-Device Now Playing Detection', () => {
    it('matches item playing on default_cast_device', () => { ... });
    it('matches item playing on default_client_device', () => { ... });
    it('supports two different items playing simultaneously on different devices', () => { ... });
    it('routes controls to the respective player entity for each item', () => { ... });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- --run tests/library-now-playing.test.ts`
Expected: FAIL with missing helper or function

- [ ] **Step 3: Implement helper `findActiveMediaItemPlayer` in `src/shared/power-volume-helpers.ts`**

Implement candidate collection (`default_cast_device`, `default_client_device`, and active `media_player.jellyha_*` players), title matching (`media_title` or `media_series_title`), state checking (`playing`, `paused`, `buffering`), and player info return (`{ entityId, state, friendlyName }`).

- [ ] **Step 4: Run test to verify it passes**

Run: `npm test -- --run tests/library-now-playing.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tests/library-now-playing.test.ts src/shared/power-volume-helpers.ts
git commit -m "test: add tests for library card multi-device now playing matching"
```

---

### Task 2: Update `jellyha-media-item.ts` to Use Multi-Player Resolver

**Files:**
- Modify: `src/components/jellyha-media-item.ts:306-365` and `538-590`

**Interfaces:**
- Consumes: `findActiveMediaItemPlayer(item, hass, config)`
- Produces: Dynamically targeted `now-playing-overlay` per poster

- [ ] **Step 1: Update `_renderNowPlayingOverlay` and `_isItemPlaying` in `src/components/jellyha-media-item.ts`**

Replace the hardcoded `default_cast_device` lookups with `findActiveMediaItemPlayer(item, this.hass, this.config)`. Pass the resolved `activePlayer.entityId` into `_handlePlayPause`, `_handleStop`, and `_handleRewind`.

- [ ] **Step 2: Run Vitest tests**

Run: `npm test -- --run`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add src/components/jellyha-media-item.ts
git commit -m "feat: enable per-poster active player detection and controls in jellyha-media-item"
```

---

### Task 3: Update `jellyha-library-card.ts` State Observation & Re-rendering

**Files:**
- Modify: `src/cards/jellyha-library-card.ts:865-885`

**Interfaces:**
- Consumes: `this._config.default_cast_device`, `this._config.default_client_device`, and `hass.states`
- Produces: Proactive re-render on state changes for any candidate player

- [ ] **Step 1: Expand `shouldUpdate` in `src/cards/jellyha-library-card.ts`**

Watch `default_cast_device`, `default_client_device`, and any active `media_player.jellyha_*` entities that are playing or paused for state or position changes between `oldHass` and `this.hass`.

- [ ] **Step 2: Build bundle and run all tests**

Run: `npm test -- --run`
Run: `npm run build`
Run: `python -m unittest discover tests`
Expected: All PASS

- [ ] **Step 3: Deploy to test server and verify**

Deploy to test server:
`scp -o Ciphers=aes256-gcm@openssh.com -i ~/.ssh/id_ed25519 -r custom_components/jellyha root@10.10.10.136:/config/custom_components/`

- [ ] **Step 4: Commit and push**

```bash
git add src/cards/jellyha-library-card.ts custom_components/jellyha/www/
git commit -m "feat: support simultaneous multi-device now playing overlays on library card"
git push origin october-2026-6
```
