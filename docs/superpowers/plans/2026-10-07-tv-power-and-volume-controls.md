# TV Power & Volume Controls Implementation Plan (Option 1 Design)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the locked-in **Option 1** TV Power Button (`power_entity`, `power_state_entity`, `show_power_button`) and Capsule Volume Slider (`show_volume`, `volume_entity`, `show_volume_step_buttons`, `volume_step`) for `custom:jellyha-now-playing-card`, along with automatic Lovelace resource cache-busting (`/jellyha/jellyha-cards.js?v=1.5.7`), rich haptic feedback on buttons and scrub dragging, consistent power button sizing across active/idle modes, white/dimmed color scheme (matching pause button), and auto-stopping Jellyfin content when powering off.

**Architecture:** 
1. **Python Backend**: Automatically register and update `/jellyha/jellyha-cards.js?v={version}` in Home Assistant's Lovelace resource storage on startup (matching HACS's `hacstag` behavior).
2. **Frontend Helpers**: Pure TypeScript helper module (`src/shared/power-volume-helpers.ts`) for entity resolution, service dispatching (handling `script`, `switch`, `media_player`, `button`, `scene`), volume calculations, and mute toggles with unit tests.
3. **Card Component**: Lit 3 rendering of the Option 1 top-right power button (consistent 36px circular glass, white when ON matching pause button, dimmed when OFF) across active playback and idle showcase modes; Option 1 capsule-shaped translucent glass volume row positioned above the seek bar; haptic feedback (`_haptic`) on button clicks and scrub dragging; auto-stopping Jellyfin playback on power off.
4. **Editor**: Card GUI editor entity pickers and toggle controls.

**Tech Stack:** TypeScript, Lit 3, Python (Home Assistant Component), Vite, Vitest.

**Spec & Reference:** 
- [Issue #60](https://github.com/zupancicmarko/JellyHA/issues/60)
- Reference Layout: Option 1 (pill capsule volume row below transport controls, circular glass power button at top right).

---

## Configuration Naming Conventions Analysis

| Proposed Option Name | Type | Default | Community Benchmark / Consistency Rationale |
| :--- | :--- | :--- | :--- |
| `power_entity` | string | `undefined` | **De facto standard**: Matches `universal-remote-card` (Nerwyn) and `YAMP`. Clearly distinguishes power target from media stream player. |
| `power_state_entity` | string | `undefined` | **Advanced pairing**: Standard in custom HA setups where power action is an IR blaster/script, but state feedback is a smart plug, ping binary sensor, or TV state entity. |
| `show_power_button` | boolean | `true` (if `power_entity` set) | Matches JellyHA's internal naming convention (`show_controls`, `show_media_type_badge`, `show_title`). Also accepts `show_power` as alias. |
| `stop_on_power_off` | boolean | `true` | When powering off the TV/display, automatically stops the active Jellyfin session/media player so streaming/transcoding halts. |
| `volume_entity` | string | `entity` | **De facto standard**: Matches `universal-remote-card` (Nerwyn) and `YAMP`. Allows routing volume to soundbar / AVR while playing via Chromecast / Jellyfin. |
| `show_volume` | boolean | `false` (or `true` if `volume_entity` set) | Matches JellyHA's `show_*` convention (`show_controls`, `show_runtime`). |
| `show_volume_step_buttons`| boolean | `true` | Controls visibility of discrete `−` and `+` quick-step buttons inside the capsule. |
| `volume_step` | number | `5` | Matches `mini-media-player`'s standard step parameter (percentage step delta, e.g. `5` for 5%). |

---

## Global Constraints

- **Power Button Sizing & Consistency**: The power button must be strictly identical in dimensions (`36px` diameter, `20px` icon size) in both **Active Playback** and **Idle Showcase** (card and backdrop modes).
- **Power Button Colors**:
  - **ON** (or active / stateless script ready): **Crisp white** (`#ffffff` / matching the pause button icon).
  - **OFF** (standby / idle): **Dimmed gray-white** (`rgba(255, 255, 255, 0.45)` / matching the `−` volume button).
  - **NO cyan glow**: Clean, frosted translucent glass background circle with natural anti-aliased edge.
- **Haptic & Visual Feedback**:
  - Button presses (power, volume step `−`/`+`, mute) trigger `_haptic('light')` and visual press depression (`:active { transform: scale(0.92); }`).
  - Volume slider dragging triggers `_haptic('selection')` on grab and as the volume value crosses discrete percentage intervals (every 5%), giving tactile notch feedback while scrubbing.
- **Stopping Playback on Power Off**: Powering off the TV/display while media is active must trigger `_handleControl('Stop')` on the Jellyfin media player entity, halting streaming and saving progress.
- **Stateless Scripts**: When `power_entity` is a `script.*` (or `button.*`), it renders in white ready action mode, executes `script.turn_on`, and displays momentary active pulse animation without getting stuck in an incorrect off state.
- **Resource Versioning**: Lovelace resource URL in Home Assistant must automatically append `?v={integration.version}` (e.g. `/jellyha/jellyha-cards.js?v=1.5.7`) and auto-update across releases without requiring manual user edits.

---

## Review Focus

1. **Lovelace Resource Version Cache-Buster:** Verify that Home Assistant startup automatically creates or updates the Lovelace resource entry to `/jellyha/jellyha-cards.js?v={version}`, eliminating stale browser caches.
2. **Stopping Playback on Power Off:** Verify that clicking the power button to turn off the TV while content is playing dispatches `media_stop` to the Jellyfin player in addition to powering off the TV entity.
3. **Power Button Sizing Uniformity:** Verify that the power button maintains identical `36px` dimensions, spacing, and icon alignment between active playback and idle showcase modes.
4. **Power Button Color Accuracy:** Verify that the power icon is pure white when ON (identical to the pause icon) and dimmed when OFF (identical to the `−` volume button), with zero cyan glow.
5. **Haptic & Visual Feedback:** Verify that `_haptic('light')` fires on power/volume button clicks, `:active` scales visually, and `_haptic('selection')` fires on volume slider scrubbing notches.
6. **External Audio Routing (`volume_entity`):** Verify that when `volume_entity` is set to an external receiver or soundbar, volume sliders, `−`/`+` step buttons, and mute toggles route commands specifically to that device.

---

### Task 1: Python Backend — Automatic Lovelace Resource Cache-Busting

**Files:**
- Modify: `custom_components/jellyha/__init__.py:100-120`

**Interfaces:**
- Produces: `async_register_lovelace_resource(hass: HomeAssistant, version: str) -> None`

- [x] **Step 1: Implement `async_register_lovelace_resource` in `custom_components/jellyha/__init__.py`**

```python
async def async_register_lovelace_resource(hass: HomeAssistant, version: str) -> None:
    """Register or update JellyHA cards in Lovelace resources with cache-busting version query."""
    try:
        if "lovelace" in hass.data and hasattr(hass.data["lovelace"], "resources"):
            resources = hass.data["lovelace"].resources
            if not resources.loaded:
                await resources.async_load()
            target_url = f"/jellyha/jellyha-cards.js?v={version}"
            
            for item in resources.async_items():
                url = item.get("url", "")
                if url.startswith("/jellyha/jellyha-cards.js"):
                    if url != target_url:
                        _LOGGER.debug("Updating JellyHA Lovelace resource to %s", target_url)
                        await resources.async_update_item(item["id"], {"res_type": "module", "url": target_url})
                    return
            
            _LOGGER.info("Registering JellyHA Lovelace resource: %s", target_url)
            await resources.async_create_item({"res_type": "module", "url": target_url})
    except Exception as err:
        _LOGGER.warning("Could not automatically register Lovelace resource: %s", err)
```

- [x] **Step 2: Invoke registration during integration setup**

In `async_setup_entry` around line 117:
```python
add_extra_js_url(hass, f"/jellyha/jellyha-cards.js?v={integration.version}")
await async_register_lovelace_resource(hass, str(integration.version))
```

- [x] **Step 3: Verify Python syntax and compilation**

Run: `python -m py_compile custom_components/jellyha/__init__.py`
Expected: Exits with code 0 (clean compilation).

- [ ] **Step 4: Commit (Pending user approval)**

```bash
git add custom_components/jellyha/__init__.py
git commit -m "feat(backend): add automatic Lovelace resource registration with cache-busting version query"
```

---

### Task 2: Configuration Types & Schema Definition

**Files:**
- Modify: `src/shared/types.ts:218-246`
- Test: `tests/types.test.ts`

**Interfaces:**
- Produces: Updated `JellyHANowPlayingCardConfig` with:
  ```typescript
  power_entity?: string;
  power_state_entity?: string;
  show_power_button?: boolean;
  show_power?: boolean;
  stop_on_power_off?: boolean;
  show_volume?: boolean;
  volume_entity?: string;
  show_volume_step_buttons?: boolean;
  volume_step?: number;
  ```

- [x] **Step 1: Write type verification test in `tests/types.test.ts`**

```typescript
import { describe, it, expect } from 'vitest';
import { JellyHANowPlayingCardConfig } from '../src/shared/types';

describe('JellyHANowPlayingCardConfig types', () => {
    it('accepts power and volume configuration properties including stop_on_power_off', () => {
        const config: JellyHANowPlayingCardConfig = {
            type: 'custom:jellyha-now-playing-card',
            entity: 'media_player.jellyfin',
            power_entity: 'script.tv_power',
            power_state_entity: 'binary_sensor.tv_ping',
            show_power_button: true,
            stop_on_power_off: true,
            show_volume: true,
            volume_entity: 'media_player.soundbar',
            show_volume_step_buttons: true,
            volume_step: 5,
        };
        expect(config.power_entity).toBe('script.tv_power');
        expect(config.stop_on_power_off).toBe(true);
        expect(config.volume_entity).toBe('media_player.soundbar');
        expect(config.volume_step).toBe(5);
    });
});
```

- [x] **Step 2: Run test to verify failure**

Run: `npx vitest run tests/types.test.ts`
Expected: FAIL due to missing type properties.

- [x] **Step 3: Update `src/shared/types.ts`**

Add the new properties to `JellyHANowPlayingCardConfig`.

- [x] **Step 4: Run test to verify pass**

Run: `npx vitest run tests/types.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit (Pending user approval)**

```bash
git add src/shared/types.ts tests/types.test.ts
git commit -m "feat(types): add power, volume, and stop_on_power_off properties to card config type definition"
```

---

### Task 3: Power & Volume Service Helpers

**Files:**
- Create: `src/shared/power-volume-helpers.ts`
- Test: `tests/power-volume-helpers.test.ts`

**Interfaces:**
- Produces:
  - `resolvePowerState(hass: HomeAssistant, powerEntity?: string, stateEntity?: string): PowerStateInfo`
  - `callPowerAction(hass: HomeAssistant, powerEntity: string): Promise<void>`
  - `resolveVolumeState(hass: HomeAssistant, volumeEntity?: string, defaultEntity?: string): VolumeStateInfo`
  - `setVolumeLevel(hass: HomeAssistant, entityId: string, level: number): Promise<void>`
  - `stepVolume(hass: HomeAssistant, entityId: string, step: number): Promise<void>`
  - `toggleMute(hass: HomeAssistant, entityId: string): Promise<void>`

- [x] **Step 1: Write unit tests in `tests/power-volume-helpers.test.ts`**

Cover:
1. Stateless detection (`script.*`, `button.*`, `scene.*`).
2. Stateful detection (`switch.*`, `media_player.*`, `light.*`, `input_boolean.*`).
3. Dual-entity pairing (`power_entity` + `power_state_entity`).
4. Service dispatching (`script.turn_on`, `button.press`, `scene.turn_on`, `homeassistant.toggle`).
5. Volume reading, level clamping (0..1), step math, and mute toggling.

- [x] **Step 2: Run test to verify failure**

Run: `npx vitest run tests/power-volume-helpers.test.ts`
Expected: FAIL with module not found.

- [x] **Step 3: Implement `src/shared/power-volume-helpers.ts`**

Implement helper functions with clean error handling and domain-specific service dispatches.

- [x] **Step 4: Run test to verify pass**

Run: `npx vitest run tests/power-volume-helpers.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit (Pending user approval)**

```bash
git add src/shared/power-volume-helpers.ts tests/power-volume-helpers.test.ts
git commit -m "feat: add domain-aware power and volume service helpers with unit tests"
```

---

### Task 4: Power Button Component (Uniform Size, White/Dimmed Colors & Stop-on-Power-Off)

**Files:**
- Modify: `src/cards/jellyha-now-playing-card.ts`
- Test: `tests/power-button.test.ts`

**Interfaces:**
- Consumes: `power-volume-helpers.ts`
- Produces:
  - `_renderPowerButton(): TemplateResult | typeof nothing`
  - State: `@state() private _powerActivating: boolean = false;`
  - Handler: `_handlePowerClick(e: Event): Promise<void>`

- [x] **Step 1: Write component unit tests in `tests/power-button.test.ts`**

Verify:
1. Returns `nothing` when `show_power_button === false` or no `power_entity`.
2. Emits `.power-btn` with unified dimensions (36px).
3. Applies `.is-on` (pure white icon) or `.is-off` (dimmed icon).
4. On click: triggers `_haptic('light')`, triggers momentary `_powerActivating = true` pulse, dispatches `callPowerAction`.
5. If TV is currently ON or content is actively playing, dispatches `_handleControl('Stop')` to halt Jellyfin streaming when powering off.

- [x] **Step 2: Run test to verify failure**

Run: `npx vitest run tests/power-button.test.ts`

- [x] **Step 3: Implement Power Button in `src/cards/jellyha-now-playing-card.ts`**

- In `setConfig`: default `show_power_button: true`, `stop_on_power_off: true`.
- Implement `_handlePowerClick`:
  ```typescript
  private async _handlePowerClick(e: Event): Promise<void> {
      e.stopPropagation();
      this._haptic('light');
      const powerEntity = this._config.power_entity;
      if (!powerEntity || !this.hass) return;

      const stateInfo = resolvePowerState(this.hass, powerEntity, this._config.power_state_entity);
      
      // If currently ON or if media is playing and stop_on_power_off is enabled, stop Jellyfin session
      if ((stateInfo.isOn || !stateInfo.isStateless) && this._config.stop_on_power_off !== false) {
          const entityId = this._config.entity;
          const stateObj = this.hass.states[entityId];
          if (stateObj && (stateObj.state === 'playing' || stateObj.state === 'paused')) {
              await this._handleControl('Stop');
          }
      }

      this._powerActivating = true;
      setTimeout(() => { this._powerActivating = false; }, 800);
      await callPowerAction(this.hass, powerEntity);
  }
  ```
- Implement `_renderPowerButton()`:
  - Render identical HTML structure `<ha-icon-button class="power-btn ${stateClass} ${this._powerActivating ? 'activating' : ''}" @click=${this._handlePowerClick}><ha-icon icon="mdi:power"></ha-icon></ha-icon-button>`.
  - Insert in `title-row` beside `header-badge` in Active Playback mode.
  - Insert in header beside badge in `_renderIdleCardMode` and `_renderIdleBackdropMode`.

- [x] **Step 4: Run test to verify pass**

Run: `npx vitest run tests/power-button.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit (Pending user approval)**

```bash
git add src/cards/jellyha-now-playing-card.ts tests/power-button.test.ts
git commit -m "feat: implement unified power button with white/dimmed states and playback stop on power off"
```

---

### Task 5: Option 1 Capsule Volume Slider Component with Scrubbing Haptics

**Files:**
- Modify: `src/cards/jellyha-now-playing-card.ts`
- Test: `tests/volume-controls.test.ts`

**Interfaces:**
- Consumes: `power-volume-helpers.ts`
- Produces:
  - `_renderVolumeControls(): TemplateResult | typeof nothing`
  - Drag state:
    - `@state() private _isVolumeDragging: boolean = false;`
    - `@state() private _dragVolumePercent: number = 0;`
    - `private _lastHapticVolumeTick: number = 0;`
  - Handlers:
    - `_handleVolumeStep(delta: number): Promise<void>`
    - `_handleToggleMute(): Promise<void>`
    - `_startVolumeDrag(e: PointerEvent): void`
    - `_handleVolumeDrag(e: PointerEvent): void`
    - `_endVolumeDrag(e: PointerEvent): Promise<void>`

- [x] **Step 1: Write component unit tests in `tests/volume-controls.test.ts`**

Verify:
1. Renders capsule container `.volume-capsule` when `show_volume` is true.
2. Formats volume percentage correctly (e.g. `45%`).
3. Mute icon button toggles `mdi:volume-high` / `mdi:volume-mute` and fires `_haptic('light')`.
4. Step buttons fire `_haptic('light')` and step by `volume_step` (default 5%).
5. Slider drag fires `_haptic('selection')` on grab and on discrete 5% tick changes while scrubbing.

- [x] **Step 2: Run test to verify failure**

Run: `npx vitest run tests/volume-controls.test.ts`

- [x] **Step 3: Implement Option 1 Capsule Volume Row in `src/cards/jellyha-now-playing-card.ts`**

- Render directly below `.playback-controls` and above `.progress-container`.
- Implement scrub tick haptics:
  ```typescript
  private _handleVolumeDrag(e: PointerEvent): void {
      if (!this._isVolumeDragging) return;
      const track = this.shadowRoot?.querySelector('.volume-slider-track') as HTMLElement;
      if (!track) return;
      const rect = track.getBoundingClientRect();
      const pct = Math.min(100, Math.max(0, ((e.clientX - rect.left) / rect.width) * 100));
      this._dragVolumePercent = Math.round(pct);

      // Trigger selection haptic on 5% notches
      const notch = Math.floor(this._dragVolumePercent / 5);
      if (notch !== this._lastHapticVolumeTick) {
          this._lastHapticVolumeTick = notch;
          this._haptic('selection');
      }
  }
  ```
- Render translucent pillow capsule with mute button, continuous slider track with dominant fill and circle thumb, percentage readout, and discrete `−` / `+` step buttons.

- [x] **Step 4: Run test to verify pass**

Run: `npx vitest run tests/volume-controls.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit (Pending user approval)**

```bash
git add src/cards/jellyha-now-playing-card.ts tests/volume-controls.test.ts
git commit -m "feat: implement Option 1 capsule volume slider with continuous scrubbing haptics and step buttons"
```

---

### Task 6: CSS Styling — Glassmorphism, Uniform Sizing, White/Dimmed Colors & Visual Feedback

**Files:**
- Modify: `src/cards/jellyha-now-playing-card.ts` (static styles block)

**Interfaces:**
- Produces: CSS rules for:
  - `.power-btn`: Strict `36px` circular dark glass button (`border-radius: 50%`, `background: rgba(255, 255, 255, 0.12)`, `border: 1px solid rgba(255, 255, 255, 0.16)`, `backdrop-filter: blur(8px)`).
  - `.power-btn ha-icon`: Strict `--mdc-icon-size: 20px`.
  - `.power-btn.is-on`, `.power-btn.stateless-ready`: White icon (`color: #ffffff;`). Exact match to pause button icon. Zero cyan glow.
  - `.power-btn.is-off`: Dimmed icon (`color: rgba(255, 255, 255, 0.45);`). Exact match to `−` volume button.
  - `.power-btn:active`, `.volume-step-btn:active`, `.mute-btn:active`: Press depression animation (`transform: scale(0.92); transition: transform 0.1s ease;`).
  - `.power-btn.activating`: Momentary pulse animation (`animation: powerPulse 0.8s ease-out;`).
  - `.volume-capsule`: Option 1 translucent pillow capsule (`background: rgba(0, 0, 0, 0.25)`, `border-radius: 20px`, `backdrop-filter: blur(8px)`, padding, flex layout).
  - `.volume-slider-track`, `.volume-slider-fill`, `.volume-thumb`, `.volume-pct`, `.volume-step-btn`.

- [x] **Step 1: Add CSS rules into static styles**
- [x] **Step 2: Verify production bundle compilation**

Run: `npm run build`
Expected: Successful Vite build.

- [ ] **Step 3: Commit (Pending user approval)**

```bash
git add src/cards/jellyha-now-playing-card.ts
git commit -m "style: add glassmorphic styling, uniform 36px power button, white/dimmed colors, and active animations"
```

---

### Task 7: Card Editor GUI Pickers

**Files:**
- Modify: `src/editors/jellyha-now-playing-editor.ts`
- Test: `tests/editor.test.ts`

**Interfaces:**
- Produces:
  - Entity picker for `power_entity` (domains: `media_player`, `switch`, `script`, `button`, `scene`, `input_boolean`).
  - Optional entity picker for `power_state_entity`.
  - Switch for `show_power_button`.
  - Switch for `stop_on_power_off`.
  - Switch for `show_volume`.
  - Entity picker for `volume_entity` (domain: `media_player`).
  - Switch for `show_volume_step_buttons`.
  - Number slider/input for `volume_step` (1 to 20, default 5).

- [x] **Step 1: Write test in `tests/editor.test.ts`**
- [x] **Step 2: Implement UI controls in `jellyha-now-playing-editor.ts`**
- [x] **Step 3: Run full test suite and build**

Run: `npx vitest run` and `npm run build`
Expected: PASS with 0 errors.

- [ ] **Step 4: Commit (Pending user approval)**

```bash
git add src/editors/jellyha-now-playing-editor.ts tests/editor.test.ts
git commit -m "feat(editor): add power, volume, and stop_on_power_off controls to configuration editor"
```

---

### Task 8: Documentation, Changelog & Final Verification

**Files:**
- Modify: `CHANGELOG.md`, `README.md`, `docs/cards.md`

- [x] **Step 1: Update documentation**

Document `power_entity`, `power_state_entity`, `show_power_button`, `stop_on_power_off`, `show_volume`, `volume_entity`, `show_volume_step_buttons`, and `volume_step` with YAML configuration examples.
Document automatic Lovelace resource cache-busting with `?v={version}`.

- [x] **Step 2: Run all linters and tests**

Run: `python -m py_compile`, `npx vitest run`, `npm run build`
Expected: All pass without errors.

- [ ] **Step 3: Commit (Pending user approval)**

```bash
git add CHANGELOG.md README.md docs/cards.md
git commit -m "docs: document power controls, volume slider, and Lovelace resource versioning"
```
