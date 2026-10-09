# Media Player User & Device Naming Differentiation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Differentiate per-user and per-device media player entities in the Home Assistant UI and entity naming with `User` and `Device` prefixes while preserving zero breakage for existing installations.

**Architecture:** Update `_attr_name` in `JellyHAUserMediaPlayer` to `f"User {username}"` and `JellyHADeviceMediaPlayer` to `f"Device {custom_device_name}"`, causing Home Assistant (`has_entity_name = True`) to render display names as `JellyHA User <name>` and `JellyHA Device <name>`, and generate new entity IDs as `media_player.jellyha_user_<name>` and `media_player.jellyha_device_<name>`. Maintain stable `_attr_unique_id` values so existing Home Assistant installations preserve their existing entity IDs and automations without breaking changes. Update frontend card prefix parsing and add unit test coverage.

**Tech Stack:** Python (Home Assistant Core integration), TypeScript / Lit (Lovelace cards), Vitest, Pytest.

**Spec:** In-chat approved design (Approach 1: Display name differentiation + suggested entity ID prefixes for new entities with existing entity preservation).

## Global Constraints

- Never change `_attr_unique_id` for existing entities (`{entry.entry_id}_media_player_{user_id}` and `{entry.entry_id}_device_player_{device_id}`).
- Preserve backwards compatibility for existing installations: existing entity IDs (`media_player.jellyha_<user>` and `media_player.jellyha_<device>`) remain functional without breaking existing YAML dashboards or automations.
- Support both legacy (`media_player.jellyha_*`) and new (`media_player.jellyha_user_*` / `media_player.jellyha_device_*`) formats across card selectors, editor dropdowns, and sensor prefix resolution.

## Review Focus

1. **Existing entity stability**: Ensure existing entity unique IDs are untouched so Home Assistant never duplicates or orphans registered entities.
2. **Card unwatched sensor scoping**: Ensure `media_player.jellyha_user_<user>` correctly maps to `sensor.jellyha_unwatched` without looking for non-existent `sensor.jellyha_user_unwatched`.
3. **Editor entity filter**: Ensure the visual card editor continues to offer both user and device media players regardless of whether the system is on legacy or new entity IDs.
4. **Card build integrity**: Ensure `npm run build` rebuilds `jellyha-cards.js` cleanly.
5. **Test coverage**: Unit tests verifying name attributes, entity prefix parsing, and editor selectors pass 100%.

---

### Task 1: Update Media Player Entity Naming in Backend Integration

**Files:**
- Modify: `custom_components/jellyha/media_player.py:1078-1175`
- Test: `tests/test_media_player_naming.py` (or verify via Python compile/test)

**Interfaces:**
- Consumes: `username: str`, `custom_device_name: str`
- Produces: `_attr_name = f"User {username}"` for `JellyHAUserMediaPlayer`, `_attr_name = f"Device {custom_device_name}"` for `JellyHADeviceMediaPlayer`

- [x] **Step 1: Write backend naming verification**

Write a Python test or verification script verifying that `JellyHAUserMediaPlayer` sets `_attr_name = f"User {username}"` and `JellyHADeviceMediaPlayer` sets `_attr_name = f"Device {custom_device_name}"`, while preserving `_attr_unique_id`.

- [x] **Step 2: Update `JellyHAUserMediaPlayer` in `custom_components/jellyha/media_player.py`**

In `JellyHAUserMediaPlayer.__init__`:
Change `self._attr_name = f"{username}"` to `self._attr_name = f"User {username}"`.

- [x] **Step 3: Update `JellyHADeviceMediaPlayer` in `custom_components/jellyha/media_player.py`**

In `JellyHADeviceMediaPlayer.__init__`:
Change `self._attr_name = f"{custom_device_name}"` to `self._attr_name = f"Device {custom_device_name}"`.

- [x] **Step 4: Verify Python syntax and execution**

Run: `python -m py_compile custom_components/jellyha/media_player.py`
Expected: Exit code 0 (no syntax errors).

---

### Task 2: Update Frontend Now Playing Card Entity Prefix Parsing

**Files:**
- Modify: `src/cards/jellyha-now-playing-card.ts:508-525`
- Test: `tests/editor.test.ts` or `tests/power-button.test.ts`

**Interfaces:**
- Consumes: `configEntity` (e.g. `media_player.jellyha_user_admin`, `media_player.jellyha_device_tv`, or legacy `media_player.jellyha_admin`)
- Produces: `entityBase` correctly resolving to `sensor.<instance_prefix>` (e.g. `sensor.jellyha`)

- [x] **Step 1: Write test for entity prefix resolution**

Add unit test verifying that `media_player.jellyha_user_admin` and `media_player.jellyha_device_tv` correctly map to base instance `sensor.jellyha`.

- [x] **Step 2: Update entityBase resolution in `src/cards/jellyha-now-playing-card.ts`**

Update lines 513-518 to handle `_user_` and `_device_`:

```typescript
} else if (configEntity.startsWith('media_player.')) {
    const nameWithoutDomain = configEntity.replace(/^media_player\./, '');
    let prefix = nameWithoutDomain;
    if (nameWithoutDomain.includes('_user_')) {
        prefix = nameWithoutDomain.substring(0, nameWithoutDomain.indexOf('_user_'));
    } else if (nameWithoutDomain.includes('_device_')) {
        prefix = nameWithoutDomain.substring(0, nameWithoutDomain.indexOf('_device_'));
    } else if (nameWithoutDomain.includes('_')) {
        prefix = nameWithoutDomain.substring(0, nameWithoutDomain.lastIndexOf('_'));
    }
    entityBase = `sensor.${prefix}`;
}
```

- [x] **Step 3: Run Vitest test suite**

Run: `npx vitest run`
Expected: 33+ tests pass with 0 failures.

- [x] **Step 4: Build cards bundle**

Run: `npm run build`
Expected: `custom_components/jellyha/www/jellyha-cards.js` built cleanly with exit code 0.

---

### Task 3: Update Documentation & Release Notes

**Files:**
- Modify: `CHANGELOG.md`
- Modify: `info.md`
- Modify: `docs/cards.md`
- Modify: `README.md`
- Modify: `llms.txt`

**Interfaces:**
- Consumes: Naming conventions specification
- Produces: Updated user documentation explaining the `JellyHA User <name>` and `JellyHA Device <name>` convention and backwards compatibility.

- [x] **Step 1: Update CHANGELOG.md**
Document the updated media player display naming conventions and entity ID suggestions.

- [x] **Step 2: Update documentation files**
Update references in `docs/` and `README.md` noting the `media_player.jellyha_user_<user>` and `media_player.jellyha_device_<device>` naming format.

---

### Task 4: Verification and Deployment

**Files:**
- Check: `git status`, `git diff`

- [x] **Step 1: Run complete test suite**
Run: `npx vitest run`
Expected: All tests pass.

- [x] **Step 2: Run production build**
Run: `npm run build`
Expected: Exit code 0.

- [x] **Step 3: Deploy to test instance**
Deploy updated integration files and bundle to test Home Assistant instance.
