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
