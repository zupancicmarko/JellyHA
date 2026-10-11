# Browser Player HLS Transcoding (Option A) & Security Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement Jellyfin PlaybackInfo-driven HLS transcoding fallback for the in-dashboard browser player (resolving Issue [#61](https://github.com/zupancicmarko/JellyHA/issues/61)) with an in-memory tokenized HLS proxy, playlist API key redaction, and active ffmpeg session cleanup, while patching the `authSig` security bypass in media streaming and subtitle proxy views for release v1.6.0.

**Architecture:** 
- **Security Hotfix**: Restrict media stream and subtitle endpoints in `views.py` exclusively to authenticated HA user sessions (`request["hass_user"]`) or cryptographically verified signatures (`request["hass_refresh_token_id"]`), eliminating unauthenticated query parameter and header bypasses.
- **Playback Decision (Option A)**: Leverage Jellyfin's `POST /Items/{id}/PlaybackInfo` endpoint with a standardized HTML5 browser device profile. If `SupportsDirectPlay` is true, stream directly via the existing signed static stream URL. If false (e.g. AVI/Xvid container, AC3/DTS/TrueHD audio), initiate an HLS transcoding session.
- **Capability-Token HLS Proxy**: Generate short-lived random in-memory tokens (`HlsSession`) to serve master playlists, variant playlists, and video segments under `/api/jellyha/hls/{token}/{path}` without exposing Jellyfin API keys. Dynamically rewrite `.m3u8` playlists to strip API keys and maintain relative segment paths.
- **Transcode Lifecycle & Cleanup**: Register active `PlaySessionId` values in an `HlsSessionManager` with automatic TTL expiration. Send `DELETE /Videos/ActiveEncodings?PlaySessionId={play_session_id}` and `POST /Sessions/Playing/Stopped` when the player dialog closes or when sessions expire, preventing orphaned ffmpeg processes on the Jellyfin server.
- **Frontend Player**: Integrate `hls.js` for Chromium/Firefox/Edge while utilizing native HLS decoding on Apple Safari / iOS, with automated cleanup on dialog close.

**Tech Stack:** Python 3.11+ (Home Assistant Core, aiohttp), TypeScript, Lit 3.x, Vite, Vitest, hls.js.

**Spec:** Issue [#61](https://github.com/zupancicmarko/JellyHA/issues/61) and Claude's Option A architectural review (incorporating PlaybackInfo API, tokenized HLS proxy, playlist rewriting, transcode termination, and security auth hardening).

---

## Global Constraints

- Must be completely incorporated into the upcoming **v1.6.0** release (no deferral to v1.7.0).
- Never leak the Jellyfin API key (`api_key` or `ApiKey`) to the browser client in `.m3u8` playlists or URLs.
- Maintain full zero-regression compatibility for direct-play media (H.264/AAC in MP4/WebM) — zero unnecessary transcoding or server CPU load.
- Ensure all media streaming endpoints require valid Home Assistant authentication or valid HMAC signatures (`hass_refresh_token_id`).
- All active ffmpeg transcoding jobs must be terminated when the user closes the player modal or after session idle timeout.

---

## Review Focus

1. **Security Auth Validation**: Requests with `?authSig=anything` or forged `Referer` headers must be strictly rejected with HTTP 401 Unauthorized unless verified by Home Assistant's authentication middleware.
2. **Playlist API Key Leakage**: Master and variant `.m3u8` playlists rewritten by the proxy must have all query parameters containing `api_key` and `ApiKey` stripped, and segment URLs must resolve through the session token route.
3. **Orphaned ffmpeg Transcodes**: Closing the player dialog, navigating away, or experiencing a client crash must reliably trigger `DELETE /Videos/ActiveEncodings` (via explicit websocket command or backend TTL sweep), preventing server CPU starvation.
4. **Platform Compatibility (Safari vs Chromium)**: Safari/iOS must leverage native HLS playback (`canPlayType('application/vnd.apple.mpegurl')`) without requiring MSE, while Chrome/Edge/Firefox must load `hls.js` without bundle bloat.
5. **Seeking & Subtitles**: Seeking within transcoded HLS streams must work smoothly via `hls.js` timeline navigation, and external WebVTT subtitles must remain properly signed and synchronized.

---

### Task 1: Security Hotfix — Close Auth Bypass in Media Stream and Subtitle Views

**Files:**
- Modify: `custom_components/jellyha/views.py:204-211, 371-385`
- Test: `tests/test_views_auth.py`

**Interfaces:**
- Consumes: `request.get("hass_user")`, `request.get("hass_refresh_token_id")`
- Produces: Strict 401 Unauthorized on unauthenticated requests without a verified signature, discarding raw query parameters and spoofable referer checks.

- [x] **Step 1: Write failing authentication security test**

Create `tests/test_views_auth.py` verifying that:
1. `JellyHAStreamView` rejects requests where `request.query.get("authSig")` is set but `request.get("hass_refresh_token_id")` is None (HTTP 401).
2. `JellyHASubtitleView` rejects requests with arbitrary `Referer` headers and unverified `authSig` query parameters (HTTP 401).
3. Authenticated requests with `hass_user` or valid `hass_refresh_token_id` proceed past the authentication check.

- [x] **Step 2: Run test to verify it fails on existing code**

Run: `python tests/test_views_auth.py`
Expected: FAIL (existing code returns 200/proceeds because `has_auth_sig = bool(request.query.get("authSig"))` evaluates to True).

- [x] **Step 3: Implement strict authentication checks in `custom_components/jellyha/views.py`**

In `JellyHAStreamView._handle_stream`:
Remove `has_auth_sig = bool(request.query.get("authSig"))`.
Update check:
```python
is_authenticated = request.get("hass_user") is not None
has_valid_signature = request.get("hass_refresh_token_id") is not None

if not is_authenticated and not has_valid_signature:
    _LOGGER.warning("Unauthorized stream request for item %s", item_id)
    return web.Response(status=401, text="Unauthorized")
```

In `JellyHASubtitleView.get`:
Remove `has_auth_sig = bool(request.query.get("authSig"))` and remove `is_ha_referer` bypass.
Update check:
```python
is_authenticated = request.get("hass_user") is not None
has_valid_signature = request.get("hass_refresh_token_id") is not None

if not is_authenticated and not has_valid_signature:
    _LOGGER.warning("Unauthorized subtitle request for item %s, stream %s", item_id, stream_index)
    return web.Response(status=401, text="Unauthorized")
```

- [x] **Step 4: Run test to verify it passes**

Run: `python tests/test_views_auth.py`
Expected: PASS (all mock unauthenticated requests return 401).

- [x] **Step 5: Verify Python syntax**

Run: `python -m py_compile custom_components/jellyha/views.py`
Expected: Exit code 0.

---

### Task 2: Jellyfin API Client — Browser Device Profile & Transcode Lifecycle Controls

**Files:**
- Modify: `custom_components/jellyha/api.py:579-660`
- Test: `tests/test_api_playback_info.py`

**Interfaces:**
- Consumes: `user_id: str`, `item_id: str`, `play_session_id: str`
- Produces: `get_browser_device_profile() -> dict`, `stop_active_encoding(play_session_id: str) -> bool`, `stop_playback_session(play_session_id: str, item_id: str) -> bool`

- [x] **Step 1: Write failing unit test for browser device profile and active encoding stop**

Create `tests/test_api_playback_info.py` testing:
1. `get_browser_device_profile()` returns a valid Jellyfin DeviceProfile structure with DirectPlay for MP4 (H.264/AAC/MP3) and Transcoding for HLS (`ts`/`h264`/`aac`).
2. `stop_active_encoding(play_session_id)` issues `DELETE /Videos/ActiveEncodings?PlaySessionId={play_session_id}`.
3. `stop_playback_session(play_session_id, item_id)` issues `POST /Sessions/Playing/Stopped`.

- [x] **Step 2: Run test to verify it fails**

Run: `python tests/test_api_playback_info.py`
Expected: FAIL with `AttributeError: 'JellyfinApiClient' object has no attribute 'stop_active_encoding'`.

- [x] **Step 3: Implement device profile and stop methods in `custom_components/jellyha/api.py`**

Define `BROWSER_DEVICE_PROFILE`:
```python
BROWSER_DEVICE_PROFILE: dict[str, Any] = {
    "Name": "JellyHA Browser Player",
    "Id": "jellyha-browser-player",
    "DirectPlayProfiles": [
        {
            "Container": "mp4,m4v,webm",
            "Type": "Video",
            "VideoCodec": "h264,vp8,vp9,av1",
            "AudioCodec": "aac,mp3,opus,flac,vorbis",
        },
        {
            "Container": "mp3,m4a,aac,flac,ogg,wav",
            "Type": "Audio",
            "AudioCodec": "mp3,aac,flac,opus,vorbis",
        },
    ],
    "TranscodingProfiles": [
        {
            "Container": "ts",
            "Type": "Video",
            "VideoCodec": "h264",
            "AudioCodec": "aac",
            "Protocol": "hls",
            "Context": "Streaming",
            "BreakOnNonKeyFrames": False,
            "MinSegments": 2,
        },
        {
            "Container": "mp3",
            "Type": "Audio",
            "AudioCodec": "mp3",
            "Protocol": "http",
            "Context": "Streaming",
        },
    ],
    "SubtitleProfiles": [
        {"Format": "vtt", "Method": "External"},
    ],
}
```

Add methods to `JellyfinApiClient`:
```python
async def stop_active_encoding(self, play_session_id: str) -> bool:
    """Stop active transcode encoding in Jellyfin to kill ffmpeg process."""
    try:
        await self._request("DELETE", "/Videos/ActiveEncodings", params={"PlaySessionId": play_session_id})
        return True
    except Exception as err:
        _LOGGER.debug("Failed to stop active encoding for %s: %s", play_session_id, err)
        return False

async def stop_playback_session(self, play_session_id: str, item_id: str) -> bool:
    """Report playback stopped to Jellyfin."""
    try:
        await self._request("POST", "/Sessions/Playing/Stopped", json={"PlaySessionId": play_session_id, "ItemId": item_id})
        return True
    except Exception as err:
        _LOGGER.debug("Failed to report playback stopped: %s", err)
        return False
```

- [x] **Step 4: Run test to verify it passes**

Run: `python tests/test_api_playback_info.py`
Expected: PASS.

- [x] **Step 5: Verify Python syntax**

Run: `python -m py_compile custom_components/jellyha/api.py`
Expected: Exit code 0.

---

### Task 3: In-Memory HLS Session Manager & Capability Token Registry

**Files:**
- Create: `custom_components/jellyha/hls_manager.py`
- Modify: `custom_components/jellyha/__init__.py`
- Test: `tests/test_hls_manager.py`

**Interfaces:**
- Consumes: `entry_id: str`, `item_id: str`, `play_session_id: str`, `server_url: str`, `api_key: str`, `api: JellyfinApiClient`
- Produces: `HlsSessionManager` managing short-lived capability tokens, TTL sliding windows, and background session cleanup.

- [x] **Step 1: Write failing unit test for `HlsSessionManager`**

Create `tests/test_hls_manager.py` testing:
1. `create_session` returns a token and stores an `HlsSession` instance.
2. `get_session(token)` returns the session and extends its `last_accessed` timestamp.
3. Expired sessions are not returned by `get_session`.
4. `terminate_session(token)` removes the session and invokes `api.stop_active_encoding(play_session_id)`.
5. `async_cleanup_expired()` reaps old sessions and calls `stop_active_encoding`.

- [x] **Step 2: Run test to verify it fails**

Run: `python tests/test_hls_manager.py`
Expected: FAIL with `ModuleNotFoundError: No module named 'custom_components.jellyha.hls_manager'`.

- [x] **Step 3: Implement `custom_components/jellyha/hls_manager.py`**

Implement `HlsSession` dataclass and `HlsSessionManager` class:
- `create_session(entry_id, item_id, play_session_id, media_source_id, server_url, api_key, api)`: Generates `token = secrets.token_urlsafe(24)`, registers in `_sessions[token]`.
- `get_session(token)`: Validates TTL, calls `touch()`, returns session.
- `terminate_session(token_or_play_session_id)`: Removes from dict, triggers `api.stop_active_encoding(play_session_id)` and `api.stop_playback_session(play_session_id, item_id)`.
- `_periodic_cleanup()`: Background task waking up every 60s, terminating any sessions with idle duration > 900s.

- [x] **Step 4: Register `HlsSessionManager` in `custom_components/jellyha/__init__.py`**

In `async_setup`:
Initialize `hass.data.setdefault(DOMAIN, {})["hls_manager"] = HlsSessionManager(hass)`.

- [x] **Step 5: Run test to verify it passes**

Run: `python tests/test_hls_manager.py`
Expected: PASS.

---

### Task 4: HLS Proxy View & Playlist Rewriter

**Files:**
- Modify: `custom_components/jellyha/views.py`
- Test: `tests/test_hls_proxy_view.py`

**Interfaces:**
- Consumes: Capability token from `/api/jellyha/hls/{token}/{path:.*}`
- Produces: Sanitized `.m3u8` playlists (with API keys stripped and segment paths routed relative to token) and proxied video segments (`.ts`, `.m4s`).

- [x] **Step 1: Write failing unit test for `JellyHAHlsView` and playlist rewriting**

Create `tests/test_hls_proxy_view.py` verifying:
1. Unknown token returns HTTP 404.
2. Valid token fetching `master.m3u8`:
   - Strips `api_key=...` and `ApiKey=...` query parameters from all child playlist lines.
   - Converts absolute Jellyfin segment paths (`/Videos/...`) to relative paths under the session token.
3. Segment requests (`.ts`) are streamed back chunk-by-chunk with correct `video/mp2t` headers and Range support.

- [x] **Step 2: Run test to verify it fails**

Run: `python tests/test_hls_proxy_view.py`
Expected: FAIL with `ImportError: cannot import name 'JellyHAHlsView' from 'custom_components.jellyha.views'`.

- [x] **Step 3: Implement `JellyHAHlsView` in `custom_components/jellyha/views.py`**

Add `JellyHAHlsView(HomeAssistantView)`:
- `url = "/api/jellyha/hls/{token}/{path:.*}"`
- `name = "api:jellyha:hls"`
- `requires_auth = False` (authenticated via capability token).
- Fetches session from `hass.data[DOMAIN]["hls_manager"].get_session(token)`.
- If path ends with `.m3u8`:
  - Request playlist from Jellyfin.
  - Regex sanitize: strip `api_key` and `ApiKey` parameters.
  - Return `text/vnd.apple.mpegurl` or `application/x-mpegURL`.
- If path is media segment:
  - Stream chunks via `web.StreamResponse` with `Content-Type: video/mp2t` and Range support.

Register view in `views.py` initialization.

- [x] **Step 4: Run test to verify it passes**

Run: `python tests/test_hls_proxy_view.py`
Expected: PASS.

- [x] **Step 5: Verify Python syntax**

Run: `python -m py_compile custom_components/jellyha/views.py`
Expected: Exit code 0.

---

### Task 5: WebSocket API Endpoints for Stream Resolution and Transcode Stop

**Files:**
- Modify: `custom_components/jellyha/websocket.py`
- Test: `tests/test_websocket_playback.py`

**Interfaces:**
- Consumes: WebSocket calls `jellyha/resolve_playback` and `jellyha/stop_playback`
- Produces: JSON responses containing playback URLs (`DirectPlay` signed static URL or `Transcode` HLS token URL) and graceful teardown of active transcode sessions.

- [x] **Step 1: Write failing unit test for WebSocket playback handlers**

Create `tests/test_websocket_playback.py` testing:
1. `jellyha/resolve_playback` with a direct-playable item returns `{ "play_method": "DirectPlay", "url": "/api/jellyha/stream/...", "mime_type": "video/mp4" }`.
2. `jellyha/resolve_playback` with an item requiring transcode (e.g. `SupportsDirectPlay: False`) creates an HLS session and returns `{ "play_method": "Transcode", "url": "/api/jellyha/hls/{token}/master.m3u8?...", "mime_type": "application/x-mpegURL", "play_session_id": "...", "token": "..." }`.
3. `jellyha/stop_playback` calls `hls_manager.terminate_session` with the supplied token/session id.

- [x] **Step 2: Run test to verify it fails**

Run: `python tests/test_websocket_playback.py`
Expected: FAIL with `KeyError: 'jellyha/resolve_playback'`.

- [x] **Step 3: Implement WebSocket commands in `custom_components/jellyha/websocket.py`**

In `async_register_websocket`:
Register `websocket_resolve_playback` and `websocket_stop_playback`.

Implement `websocket_resolve_playback`:
1. Find coordinator and API client.
2. Fetch `item` and call `api.get_playback_info(user_id, item_id, profile=BROWSER_DEVICE_PROFILE)`.
3. Check `SupportsDirectPlay`:
   - If True: build signed stream URL via `api.get_stream_path()` and `async_sign_path()`. Send result with `play_method="DirectPlay"`.
   - If False: obtain `media_source_id` and `play_session_id = str(uuid.uuid4().hex)`.
     Create session via `hls_manager.create_session(...)`.
     Construct master URL: `/api/jellyha/hls/{token}/master.m3u8?MediaSourceId={media_source_id}&PlaySessionId={play_session_id}`.
     Send result with `play_method="Transcode"`, `url`, `mime_type="application/x-mpegURL"`, `play_session_id`, `token`.

Implement `websocket_stop_playback`:
Accepts `token` or `play_session_id` and calls `hls_manager.terminate_session(target)`.

- [x] **Step 4: Run test to verify it passes**

Run: `python tests/test_websocket_playback.py`
Expected: PASS.

- [x] **Step 5: Verify Python syntax**

Run: `python -m py_compile custom_components/jellyha/websocket.py`
Expected: Exit code 0.

---

### Task 6: Frontend Player HLS Integration & Lifecycle Management

**Files:**
- Modify: `package.json` (add `hls.js`)
- Modify: `src/components/jellyha-browser-player.ts`
- Test: `tests/browser-player.test.ts`

**Interfaces:**
- Consumes: WebSocket `jellyha/resolve_playback` and `jellyha/stop_playback`
- Produces: Native HLS playback on Safari/iOS, dynamic `hls.js` initialization on Chromium/Firefox, seamless video seeking, and immediate transcode cleanup on player dialog close.

- [x] **Step 1: Install `hls.js`**

Run: `npm install hls.js`
Expected: `hls.js` added to `dependencies` in `package.json`.

- [x] **Step 2: Write frontend unit tests for stream resolution and HLS handling**

Create `tests/browser-player.test.ts` testing:
1. `_resolveStream` calls `jellyha/resolve_playback` via WebSocket.
2. Sets `_playMethod` to `'Transcode'` or `'DirectPlay'`.
3. On modal close, if `_hlsToken` or `_playSessionId` exists, fires `jellyha/stop_playback` and destroys `hls.js` instance.

- [x] **Step 3: Run Vitest to verify tests fail initially**

Run: `npm test -- --run tests/browser-player.test.ts`
Expected: FAIL.

- [x] **Step 4: Update `src/components/jellyha-browser-player.ts`**

1. Track state:
   - `_playMethod: 'DirectPlay' | 'Transcode' = 'DirectPlay'`
   - `_playSessionId?: string`
   - `_hlsToken?: string`
   - `_hls?: any`
2. Update `_resolveStream` to invoke `jellyha/resolve_playback`.
3. Update player media mounting:
   - Check if MIME is `application/x-mpegURL` or URL contains `.m3u8`:
     - If `video.canPlayType('application/vnd.apple.mpegurl')`: Native HLS playback.
     - Else: Dynamic import of `hls.js`, attach to video element.
4. Update `close()` and `disconnectedCallback()`:
   - Destroy HLS instance.
   - Fire `jellyha/stop_playback` with `token` and `play_session_id`.

- [x] **Step 5: Run Vitest test suite**

Run: `npm test -- --run`
Expected: All tests pass.

- [x] **Step 6: Build card bundle with Vite**

Run: `npm run build`
Expected: `custom_components/jellyha/www/jellyha-cards.js` compiled cleanly.

---

### Task 7: Documentation & CHANGELOG Updates for Release v1.6.0

**Files:**
- Modify: `CHANGELOG.md`
- Modify: `docs/cards.md`
- Modify: `llms.txt`

- [x] **Step 1: Update `CHANGELOG.md` under [1.6.0]**

Add security fix and HLS browser transcode fallback feature details to `CHANGELOG.md`.

- [x] **Step 2: Update `docs/cards.md` and `llms.txt`**

Document browser player capability, highlighting transparent HLS transcoding fallback for AVI/Xvid/AC3/DTS formats.

- [x] **Step 3: Verification**

Run Vitest and python compile checks:
```bash
npm test -- --run
python -m py_compile custom_components/jellyha/*.py
```
Expected: PASS with 0 errors.
