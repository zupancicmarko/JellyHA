# Troubleshooting & FAQ

Common troubleshooting steps and solutions for JellyHA integration and dashboard cards.

---

## Dashboard Card Issues

### Error: "Custom element doesn't exist: jellyha-library-card"

This error indicates that the frontend JavaScript card bundle was not loaded by Home Assistant.

1. **Verify Dashboard Resource URL:**
   - Navigate to **Settings -> Dashboards -> Resources** (three-dot menu in the upper right corner).
   - Confirm that `/jellyha/jellyha-cards.js` exists and is set to **JavaScript Module**.
   - If the Resources menu is missing, enable **Advanced Mode** in your Home Assistant user profile.
2. **Clear Browser Cache:**
   - Force reload your browser using `Ctrl + F5` (Windows/Linux) or `Cmd + Shift + R` (macOS).
   - Test in a Private / Incognito window or the Home Assistant mobile companion app.
3. **Re-download Card Resource:**
   - If installed via HACS: Go to HACS -> JellyHA -> three dots -> **Redownload**.
   - Restart Home Assistant after redownloading.

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

### "Connection lost" on Startup

- Usually caused by conflicting older integration versions or duplicate WebSocket subscriptions.
- Ensure you are running the latest JellyHA release and restart Home Assistant.

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
