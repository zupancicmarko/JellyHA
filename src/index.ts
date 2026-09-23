/**
 * JellyHA Cards - Main Entry Point
 * 
 * This file exports all JellyHA cards for Home Assistant.
 * Add new card imports here as they are created.
 */

// Safe Custom Elements registration guard (prevents duplicate define() errors on SPA reload)
import './shared/safe-custom-elements';

// Library Card - Display media from Jellyfin
import './cards/jellyha-library-card';

// Now Playing Card - Display active playback
import './cards/jellyha-now-playing-card';

// Browser media player seek polyfill (fixes HA 2026.9 disabled slider bug)
import './components/jellyha-seek-polyfill';

// Future cards:
// import './cards/jellyha-remote-card';
// import './cards/jellyha-statistics-card';

