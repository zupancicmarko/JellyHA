# Security Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate vulnerabilities identified in the security audit: enforce admin-only access on destructive services, strictly validate all item/entity/stream inputs against path traversal, lock HLS capability tokens to their specific item and maximum lifetime, sanitize error responses, and ensure safe frontend external URL navigation.

**Architecture:** Introduce a dedicated `custom_components/jellyha/security.py` validation module establishing centralized validation rules (UUID/hex item IDs, allowed image types, safe URL protocols). Integrate validation and admin context permission checks across `services.py`, `views.py`, and `hls_manager.py`. Complement backend protections with a frontend `safe-url` helper enforcing strict URL scheme validation (`http`/`https`) and `noopener,noreferrer` tab isolation.

**Tech Stack:** Python 3.12+, Home Assistant Core (ServiceCall, HomeAssistantView, auth permissions), TypeScript, Lit, Vitest, Python unittest.

**Spec:** Security audit findings detailed in conversation on 2026-10-15 (High: unauthorized `delete_item` and path traversal; Medium: unvalidated proxy view parameters and over-scoped HLS capability tokens; Low: unsanitized 500 error disclosure and unchecked `window.open` navigation).

## Global Constraints

- Never break backward compatibility for legitimate Jellyfin item IDs (both 32-char hex `11d6bf041f2b4cfbbae8d4f17fa2ab2e` and 36-char hyphenated UUIDs `11d6bf04-1f2b-4cfb-bae8-d4f17fa2ab2e`).
- All existing 127 frontend tests (`npx vitest run`) and 37 backend tests (`python -m unittest discover tests`) must continue to pass without regression.
- External URLs for trailer playback must strictly permit only `https:`, `http:`, or explicit `vnd.youtube:<id>` for mobile YouTube app links.
- Error responses returned to client browsers must not leak internal backend stack traces, private server IPs, or API credentials.

## Review Focus

1. **Path Traversal in Item Deletion:** Passing `../Users/<user_id>` or `../System/Configuration` to `delete_item` service must raise validation error and never hit the network.
2. **Non-Admin Media Deletion:** Service call to `delete_item` with non-admin `user_id` context must be rejected with an unauthorized error before issuing any delete API request.
3. **HTTP Proxy Injection:** Requesting an image or stream with an invalid or traversal ID (e.g. `../../api/users`) must be immediately blocked with HTTP 400 Bad Request.
4. **HLS Token Cross-Item Streaming:** An HLS token issued for Item A attempting to stream segments or playlists of Item B must return HTTP 403 Forbidden.
5. **Frontend `javascript:` URL Execution:** Item with a malicious `javascript:alert(1)` trailer or external link must be rejected by the safe URL validator and not opened.

---

### Task 1: Centralized Security Validation Module

**Files:**
- Create: `custom_components/jellyha/security.py`
- Create: `tests/test_security.py`

**Interfaces:**
- Produces:
  - `is_valid_item_id(val: str | None) -> bool`
  - `validate_item_id(val: str | None) -> str` (returns normalized lowercase 32-hex string or raises `ValueError`)
  - `is_valid_entry_id(val: str | None) -> bool`
  - `validate_entry_id(val: str | None) -> str`
  - `ALLOWED_IMAGE_TYPES: frozenset[str]`
  - `ALLOWED_MEDIA_TYPES: frozenset[str]`
  - `is_valid_stream_index(val: str | int | None) -> bool`

- [ ] **Step 1: Write the failing unit tests for security validation**

Create `tests/test_security.py` verifying:
- Valid 32-hex ID (`"11d6bf041f2b4cfbbae8d4f17fa2ab2e"`) passes and normalizes.
- Valid hyphenated UUID (`"11d6bf04-1f2b-4cfb-bae8-d4f17fa2ab2e"`) passes and normalizes to 32-hex without dashes.
- Traversal payloads (`"../Users/123"`, `"..%2F..%2FSystem"`, `"id/../../"`) return False / raise `ValueError`.
- Empty strings, None, or special character injections return False / raise `ValueError`.
- Entry ID validation allows standard ULIDs and alphanumeric entry IDs, rejecting traversals.
- `ALLOWED_IMAGE_TYPES` contains standard Jellyfin image types (`Primary`, `Backdrop`, `Banner`, `Thumb`, `Logo`, `Art`, `Disc`, `Box`, `Screenshot`).
- `is_valid_stream_index` accepts non-negative integers `"0"`, `"1"`, `5`, but rejects `"-1"`, `"1/../"`, `"abc"`.

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests/test_security.py`
Expected: FAIL with "ModuleNotFoundError: No module named 'custom_components.jellyha.security'"

- [ ] **Step 3: Implement `custom_components/jellyha/security.py`**

Implement strict regex matchers:
```python
import re

UUID_HEX_RE = re.compile(
    r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
ENTRY_ID_RE = re.compile(r"^[0-9a-zA-Z]{16,36}$")
STREAM_INDEX_RE = re.compile(r"^\d{1,5}$")

ALLOWED_IMAGE_TYPES = frozenset({
    "Primary", "Backdrop", "Banner", "Thumb", "Logo", "Art", "Disc", "Box", "Screenshot"
})

ALLOWED_MEDIA_TYPES = frozenset({"Audio", "Videos"})
```
Implement `is_valid_item_id`, `validate_item_id`, `is_valid_entry_id`, `validate_entry_id`, and `is_valid_stream_index`.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m unittest tests/test_security.py`
Expected: PASS (all tests pass).

- [ ] **Step 5: Commit**

```bash
git add custom_components/jellyha/security.py tests/test_security.py
git commit -m "feat(security): add centralized input validation module"
```

---

### Task 2: Service Hardening & Admin-Only Deletion

**Files:**
- Modify: `custom_components/jellyha/services.py:35-45, 1615-1644, 400-440`
- Create: `tests/test_services_security.py`

**Interfaces:**
- Consumes:
  - `validate_item_id` from `custom_components.jellyha.security`
- Produces:
  - Admin permission verification in `async_delete_item`
  - Schema-level & handler-level `item_id` validation on `delete_item`, `update_favorite`, `mark_watched`

- [ ] **Step 1: Write the failing unit test for delete permissions and item_id validation**

Create `tests/test_services_security.py` testing:
- Calling `async_delete_item` with non-admin `user_id` context raises `HomeAssistantError` ("Unauthorized").
- Calling `async_delete_item` with admin `user_id` context proceeds with deletion.
- Calling `async_delete_item` with system context (`user_id=None`) proceeds with deletion.
- Calling `async_delete_item` with traversal `item_id="../Users/admin"` raises `HomeAssistantError` ("Invalid item ID").
- Calling `async_update_favorite` or `async_mark_watched` with traversal `item_id` raises `HomeAssistantError`.

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests/test_services_security.py`
Expected: FAIL (unauthorized user call does not raise error).

- [ ] **Step 3: Implement admin check and input validation in `services.py`**

In `custom_components/jellyha/services.py`:
1. In `async_delete_item`:
   ```python
   # Enforce administrator permissions
   if call.context.user_id:
       user = await hass.auth.async_get_user(call.context.user_id)
       if user and not user.is_admin:
           _LOGGER.warning("Unauthorized delete_item attempt by non-admin user %s", call.context.user_id)
           raise HomeAssistantError("Unauthorized: Only administrators can delete items from Jellyfin")

   # Validate item_id to prevent path traversal
   try:
       item_id = validate_item_id(call.data["item_id"])
   except ValueError as err:
       raise HomeAssistantError(f"Invalid item ID: {err}") from err
   ```
2. In `async_update_favorite` and `async_mark_watched`:
   Validate `item_id = validate_item_id(call.data["item_id"])` before issuing API requests.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m unittest tests/test_services_security.py`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add custom_components/jellyha/services.py tests/test_services_security.py
git commit -m "fix(security): restrict item deletion to administrators and validate item IDs"
```

---

### Task 3: HTTP Views Hardening & Error Sanitization

**Files:**
- Modify: `custom_components/jellyha/views.py:65-140, 205-245, 365-410`
- Create: `tests/test_views_security.py`

**Interfaces:**
- Consumes:
  - `is_valid_item_id`, `validate_item_id`, `ALLOWED_IMAGE_TYPES`, `ALLOWED_MEDIA_TYPES`, `is_valid_stream_index`, `is_valid_entry_id` from `custom_components.jellyha.security`
- Produces:
  - Strict input validation (HTTP 400 on malformed input)
  - Generic client error responses (no raw stack traces / private URLs returned to clients)

- [ ] **Step 1: Write the failing unit tests for HTTP views input validation**

Create `tests/test_views_security.py` testing:
- `JellyHAImageView`:
  - Returns 400 Bad Request when `item_id` contains path traversal (`"../../System/Info"`).
  - Returns 400 Bad Request when `image_type` is not in `ALLOWED_IMAGE_TYPES` (e.g. `"../../secret"`).
  - Returns 400 Bad Request when `width` or `height` is non-numeric (`"100;DROP"`).
  - Catches internal exceptions and returns HTTP 500 with sanitized message `"Image proxy error"` rather than raw exception text.
- `JellyHAStreamView`:
  - Returns 400 Bad Request when `media_type` is not `"Audio"` or `"Videos"`.
  - Returns 400 Bad Request when `item_id` contains path traversal.
  - Sanitizes 500 error response to `"Stream proxy error"`.
- `JellyHASubtitleView`:
  - Returns 400 Bad Request when `stream_index` contains non-digit characters (`"0/../"`).
  - Returns 400 Bad Request when `media_source_id` is an invalid format.
  - Sanitizes 500 error response to `"Subtitle proxy error"`.

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests/test_views_security.py`
Expected: FAIL (invalid item_id or image_type does not return 400).

- [ ] **Step 3: Implement validation and error sanitization in `views.py`**

1. In `JellyHAImageView.get`:
   - Validate `is_valid_entry_id(entry_id)` -> 400 if invalid.
   - Validate `is_valid_item_id(item_id)` -> 400 if invalid.
   - Validate `image_type in ALLOWED_IMAGE_TYPES` -> 400 if invalid.
   - Validate query params `width`, `height`, `quality` are strictly numeric digits if provided.
   - Sanitize 500 error: `web.Response(status=500, text="Image proxy error")`.
2. In `JellyHAStreamView._handle_stream`:
   - Validate `is_valid_entry_id(entry_id)` and `is_valid_item_id(item_id)`.
   - Validate `media_type in ALLOWED_MEDIA_TYPES`.
   - Sanitize 500 error: `web.Response(status=500, text="Stream proxy error")`.
3. In `JellyHASubtitleView.get`:
   - Validate `is_valid_entry_id(entry_id)` and `is_valid_item_id(item_id)`.
   - Validate `is_valid_stream_index(stream_index)`.
   - If `media_source_id` is provided, validate with `is_valid_item_id(media_source_id)`.
   - Sanitize 500 error: `web.Response(status=500, text="Subtitle proxy error")`.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m unittest tests/test_views_security.py`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add custom_components/jellyha/views.py tests/test_views_security.py
git commit -m "fix(security): sanitize proxy view inputs and error responses"
```

---

### Task 4: HLS Capability Token Scoping & Hard Lifetime

**Files:**
- Modify: `custom_components/jellyha/hls_manager.py:15-45, 80-95`
- Modify: `custom_components/jellyha/views.py:480-530`
- Create: `tests/test_hls_security.py`

**Interfaces:**
- Consumes:
  - `HlsSession` from `custom_components.jellyha.hls_manager`
- Produces:
  - Absolute session expiration limit (`MAX_LIFETIME_SECONDS = 14400`)
  - Strict path restriction in `JellyHAHlsView`: path must strictly pertain to the session's `item_id` and have an approved HLS extension (`.m3u8`, `.ts`, `.m4s`, `.mp4`, `.key`)

- [ ] **Step 1: Write the failing unit tests for HLS scoping and expiration**

Create `tests/test_hls_security.py` testing:
- Session expires if elapsed time exceeds 14400 seconds (4 hours) even if `touch()` was repeatedly called.
- Request to `JellyHAHlsView` with a path referencing another item (e.g. `Videos/other_item_id/stream.ts`) returns 403 Forbidden.
- Request with path traversal (e.g. `../` or `..%2f`) returns 400 Bad Request.
- Request with unauthorized file extension (e.g. `master.json` or `config.xml`) returns 400 Bad Request.
- Legitimate playlist and segment requests for `session.item_id` succeed.

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests/test_hls_security.py`
Expected: FAIL.

- [ ] **Step 3: Implement HLS hard lifetime and path scoping**

1. In `hls_manager.py`:
   - Add `MAX_SESSION_LIFETIME_SECONDS = 14400` (4 hours).
   - In `HlsSession`: add `max_expires_at: float`. In `create_session`: initialize `max_expires_at = now + MAX_SESSION_LIFETIME_SECONDS`.
   - Update `is_expired(now)` to check `ts > self.max_expires_at or (ts - self.last_accessed) > SESSION_TTL_SECONDS`.
2. In `views.py` (`JellyHAHlsView.get`):
   - Reject path if `".." in path` or `"/" in path and path.startswith("/")` (400 Bad Request).
   - Verify path file extension is in `{".m3u8", ".ts", ".m4s", ".mp4", ".key"}` (400 Bad Request).
   - If path starts with `"Videos/"`: extract target item ID. If it does not match `session.item_id`, return 403 Forbidden.
   - Always route to `f"{session.server_url}/Videos/{session.item_id}/{sanitized_filename}"`.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m unittest tests/test_hls_security.py`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add custom_components/jellyha/hls_manager.py custom_components/jellyha/views.py tests/test_hls_security.py
git commit -m "fix(security): scope HLS capability tokens to target item with hard maximum lifetime"
```

---

### Task 5: Frontend Safe URL Navigation & Tab Security

**Files:**
- Create: `src/shared/safe-url.ts`
- Create: `tests/safe-url.test.ts`
- Modify: `src/components/jellyha-item-details-modal.ts:2215-2235, 2305-2325`
- Modify: `src/cards/jellyha-library-card.ts:1600-1605, 1845-1855`

**Interfaces:**
- Produces:
  - `isSafeExternalUrl(url: string | null | undefined): boolean`
  - `safeOpenWindow(url: string | null | undefined, target?: string): Window | null`

- [ ] **Step 1: Write the failing unit tests for safe URL opening**

Create `tests/safe-url.test.ts` verifying:
- `isSafeExternalUrl` accepts `"https://youtube.com/watch?v=123"`, `"http://jellyfin.local:8096"`, `"vnd.youtube:123"`.
- `isSafeExternalUrl` rejects `"javascript:alert(1)"`, `"data:text/html,... "`, `"vbscript:..."`, `"file:///etc/passwd"`, `""`, `null`.
- `safeOpenWindow` calls `window.open` with `'noopener,noreferrer'` features.
- `safeOpenWindow` refuses to open unsafe URLs and returns `null`.

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/safe-url.test.ts`
Expected: FAIL (module not found).

- [ ] **Step 3: Implement `safe-url.ts` and integrate in modal and library cards**

1. Create `src/shared/safe-url.ts`:
   ```typescript
   export function isSafeExternalUrl(url: string | null | undefined): boolean {
     if (!url || typeof url !== 'string') return false;
     const trimmed = url.trim();
     if (/^vnd\.youtube:[a-zA-Z0-9_-]{5,20}$/i.test(trimmed)) {
       return true;
     }
     try {
       const parsed = new URL(trimmed);
       return parsed.protocol === 'https:' || parsed.protocol === 'http:';
     } catch {
       return false;
     }
   }

   export function safeOpenWindow(url: string | null | undefined, target = '_blank'): Window | null {
     if (!isSafeExternalUrl(url)) {
       console.warn('Blocked opening unsafe URL:', url);
       return null;
     }
     return window.open(url!.trim(), target, 'noopener,noreferrer');
   }
   ```
2. In `src/components/jellyha-item-details-modal.ts` and `src/cards/jellyha-library-card.ts`:
   Replace raw `window.open(url, '_blank')` calls with `safeOpenWindow(url, '_blank')`.

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/safe-url.test.ts`
Expected: PASS.

- [ ] **Step 5: Run full frontend test suite**

Run: `npx vitest run`
Expected: PASS (all 127+ tests pass).

- [ ] **Step 6: Commit**

```bash
git add src/shared/safe-url.ts tests/safe-url.test.ts src/components/jellyha-item-details-modal.ts src/cards/jellyha-library-card.ts
git commit -m "fix(security): sanitize external trailer and web URLs and isolate opened tabs"
```

---

### Task 6: Full Verification, Bundle Build & Deployment

**Files:**
- Modify: `CHANGELOG.md`
- Compile: `custom_components/jellyha/www/jellyha-cards.js`

- [ ] **Step 1: Run all Python backend test suites**

Run: `python -m unittest discover tests`
Expected: PASS with 0 failures or errors.

- [ ] **Step 2: Run all Vitest frontend test suites**

Run: `npx vitest run`
Expected: PASS with all tests passing.

- [ ] **Step 3: Build production frontend bundle**

Run: `npm run build`
Expected: Bundle created with 0 errors.

- [ ] **Step 4: Deploy bundle and backend updates to Home Assistant**

Deploy updated `custom_components/jellyha/` files to `10.10.10.136`.
Run `ha core check` over SSH to confirm valid configuration.

- [ ] **Step 5: Update CHANGELOG.md**

Record security hardening improvements under version 1.7.0 in simple, clear terms.

- [ ] **Step 6: Final Commit**

```bash
git add CHANGELOG.md custom_components/jellyha/www/jellyha-cards.js*
git commit -m "chore(release): security hardening verification and frontend bundle build"
```
