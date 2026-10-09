# Troubleshooting & FAQ

Common troubleshooting steps and solutions for JellyHA integration and dashboard cards.

---

## Dashboard Card Issues

### Error: "Custom element doesn't exist: jellyha-library-card"

This error indicates that the frontend JavaScript card bundle was not yet loaded or cached by your browser.

1. **Restart Home Assistant:**
   - The integration automatically registers the frontend card bundle globally on startup. Restart Home Assistant to ensure the backend registers the frontend path.
2. **Clear Browser Cache:**
   - Force reload your browser using `Ctrl + F5` (Windows/Linux) or `Cmd + Shift + R` (macOS).
   - Test in a Private / Incognito window or the Home Assistant mobile companion app.
3. **Re-download Integration:**
   - If installed via HACS: Go to HACS -> JellyHA -> three dots -> **Redownload**.
   - Restart Home Assistant after redownloading.

---

### Duplicate Cards Shown in "Add to dashboard" Picker

If you see duplicate entries for **JellyHA Library** or **JellyHA Now Playing** when adding a card:

1. JellyHA automatically registers cards globally via Home Assistant's backend.
2. Navigate to **Settings → Dashboards → Resources** (click the three-dot menu in the upper right).
3. If `/jellyha/jellyha-cards.js` is listed there from a previous manual configuration, **delete** it.
4. Hard-refresh your browser (`Ctrl + F5` or `Cmd + Shift + R`).

---

### Card is Empty ("No recent media found")

If the card renders but displays no items:

1. **Check Active Card Filters:**
   - In the card editor, check if **Filter Favorites** or **Filter Unwatched** are enabled when all items in your library are already watched or not marked as favorites.
2. **Verify Library Sensor:**
   - Go to **Developer Tools -> States** and inspect `sensor.jellyha_library`.
   - Ensure the sensor state is greater than 0 and attributes (such as `entry_id` and item counts) are populated.
3. **Check Browser Console:**
   - Press `F12` in your browser and check the **Console** tab for any authentication or network errors.

---

## Integration and Playback Issues

### Remote Control Not Responding on Android Mobile

- The official Jellyfin for Android app defaults to the native ExoPlayer ("Integrated player"), which only sends playback reports to the server and does not listen for remote commands.
- Open the Jellyfin app on your device, navigate to **Settings -> Client Settings -> Video player type**, and switch it to **Web player**.
- Web player mode connects over WebSocket and enables full play, pause, rewind, and seek transport control from Home Assistant.

---

### Android TV & Wholphin Playback (ADB Requirement)

When using the library card's click action to trigger direct playback on an Android TV device running **Wholphin**:

1. **Install Android Debug Bridge (ADB):**
   - Install the official **Android Debug Bridge** integration (`androidtv`) in Home Assistant.
   - Connect it to your Android TV's local IP address (e.g. `10.10.10.135:5555`).
2. **Why ADB is Required instead of Android TV Remote:**
   - The standard **Android TV Remote** (`androidtv_remote`) integration only supports standard `VIEW` intents (`android.intent.action.VIEW`). When Wholphin receives a `VIEW` intent, it only opens the item details page on screen rather than starting playback.
   - Android Debug Bridge allows dispatching the native playback intent directly via ADB shell:
     ```text
     am start -a com.github.damontecres.wholphin.PLAYBACK -d "wholphin://play?itemId={{ item_id }}" -f 0x10000000
     ```
   - This starts video playback immediately on the TV without requiring manual confirmation or clicking "Play" with the remote.
3. **Recipe Reference:**
   - See the ready-to-use script in **[examples/scripts/card_action_play_on_wholpin.yaml](../examples/scripts/card_action_play_on_wholpin.yaml)**.

---

### Media Browser Entry Not Visible in Sidebar

If the **Media** entry does not appear in the Home Assistant sidebar:

1. **Unhide from User Profile:**
   - Click your profile icon at the bottom of the sidebar.
   - Scroll down to the **Sidebar** section and click **Change the order and hide items from the sidebar** -> **Edit**.
   - Ensure **Media** is checked and visible.
2. **Sidebar Edit Mode Shortcut:**
   - Click and hold the "Home Assistant" header text at the very top of the sidebar to enter sidebar edit mode directly, then unhide **Media**.
3. **Verify `media_source:` Integration:**
   - In `configuration.yaml`, ensure `media_source:` is not disabled or commented out. Home Assistant includes this by default via `default_config:`, but minimal configurations may need `media_source:` declared explicitly.

---

### Live TV Channels Not Showing in Media Browser or Entities

If Live TV channels do not appear in the Media Browser or under `sensor.jellyha_live_tv_channels`:

1. **Enable Live TV in Integration Options:**
   - Go to **Settings -> Devices & Services -> Jellyfin (JellyHA)**.
   - Click **Configure** / **Options**.
   - Check **Enable Live TV** and submit.
   - Live TV is disabled by default to prevent unnecessary API polling for setups without live TV tuners or M3U/IPTV sources.
2. **Verify Server Live TV Access:**
   - Ensure your Jellyfin user account has permissions enabled to view Live TV in Jellyfin Dashboard -> Users -> Permissions -> *Enable access to Live TV*.

---

### "Unknown entity: sensor.jellyha_now_playing_<user>"

If your existing dashboard cards show an error for the legacy now playing sensor:

- Legacy `sensor.jellyha_now_playing_<user>` entities have been deprecated in favor of native `media_player.jellyha_<user>` entities.
- In your `custom:jellyha-now-playing-card` or dashboard configuration, simply update:
  ```yaml
  # Old:
  entity: sensor.jellyha_now_playing_admin
  # New:
  entity: media_player.jellyha_admin
  ```
- All visual badges, artwork, ratings, scrub bars, and transport controls are 100% identical and fully supported.

---

### "Connection lost" on Startup

- Usually caused by conflicting older integration versions or duplicate WebSocket subscriptions.
- Ensure you are running the latest JellyHA release and restart Home Assistant.

---

### Non-Administrator Accounts vs API Key Authentication

- **Non-Admin Accounts**: Non-administrator user accounts can log in with their username and password directly. Because Jellyfin restricts full server user enumeration (`GET /Users`) strictly to administrators, JellyHA automatically detects non-admin credentials, binds to the authenticated user account, and loads their accessible libraries without prompting for a user selection dropdown.
- **Admin Accounts & API Keys**: When logging in with an administrator account or generating an API key in the Jellyfin Dashboard (**Administration → Dashboard → Advanced → API Keys**), JellyHA is granted server-wide access and allows selecting any managed user on the server to monitor.

---

### Chromecast / Google Cast: "Shows title and cover, but no video/sound"

If casting media to a Chromecast (or Chromecast Ultra) displays the media title and poster/backdrop on the TV screen but video or audio never starts:

1. **Audio Codec & Channels (5.1 AAC vs Stereo)**:
   - Google Cast hardware decoders natively support AAC in **stereo (2.0 channels)**. Multi-channel AAC (5.1 or 7.1) causes the Chromecast media player to fail initialization. JellyHA automatically transcodes multi-channel streams down to stereo AAC when targeting Cast devices.
2. **Local Network Reachability**:
   - The Chromecast device must have direct network reachability to your Jellyfin server's IP and port (e.g. `http://192.168.1.50:8096`).
   - If Home Assistant, Jellyfin, and the Chromecast reside on different VLANs or subnets, verify that mDNS reflection and cross-subnet routing permit the Chromecast to communicate directly with the Jellyfin host.
3. **Reverse Proxy & CORS Headers**:
   - If casting through an external URL or reverse proxy (e.g. Nginx, Caddy, Cloudflare), verify that your proxy allows Cross-Origin Resource Sharing (CORS) requests originating from `https://www.gstatic.com` (the Google Cast Default Media Receiver web app).

---

## Diagnostic Logs

To enable verbose debug logging for JellyHA, add the following to your `configuration.yaml`:

```yaml
logger:
  default: info
  logs:
    custom_components.jellyha: debug
```

Restart Home Assistant, reproduce the issue, and inspect the logs under **Settings -> System -> Logs**.
