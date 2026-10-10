import { describe, it, expect } from 'vitest';
import { findActiveMediaItemPlayer } from '../src/shared/power-volume-helpers';
import { MediaItem, HomeAssistant, JellyHALibraryCardConfig } from '../src/shared/types';

describe('Library Card Multi-Device Now Playing Detection', () => {
    const movieItem: MediaItem = {
        id: 'movie-1',
        name: 'Inception',
        type: 'Movie',
        year: 2010,
    };

    const episodeItem: MediaItem = {
        id: 'episode-1',
        name: 'Bad Optics',
        series_name: 'Lanterns',
        type: 'Episode',
        year: 2026,
    };

    const seriesItem: MediaItem = {
        id: 'series-1',
        name: 'Lanterns',
        type: 'Series',
        year: 2026,
    };

    it('returns null if hass or config is missing', () => {
        expect(findActiveMediaItemPlayer(movieItem, undefined, undefined)).toBeNull();
    });

    it('matches item playing on default_cast_device', () => {
        const mockHass = {
            states: {
                'media_player.chromecast_living_room': {
                    entity_id: 'media_player.chromecast_living_room',
                    state: 'playing',
                    attributes: {
                        media_title: 'Inception',
                        friendly_name: 'Living Room TV',
                    },
                },
            },
        } as unknown as HomeAssistant;

        const config: JellyHALibraryCardConfig = {
            type: 'custom:jellyha-library-card',
            entity: 'sensor.jellyha_library',
            default_cast_device: 'media_player.chromecast_living_room',
        };

        const result = findActiveMediaItemPlayer(movieItem, mockHass, config);
        expect(result).not.toBeNull();
        expect(result?.entityId).toBe('media_player.chromecast_living_room');
        expect(result?.state).toBe('playing');
        expect(result?.friendlyName).toBe('Living Room TV');
    });

    it('matches item playing on default_client_device', () => {
        const mockHass = {
            states: {
                'media_player.jellyha_device_bedroom_tv': {
                    entity_id: 'media_player.jellyha_device_bedroom_tv',
                    state: 'playing',
                    attributes: {
                        media_title: 'Bad Optics',
                        media_series_title: 'Lanterns',
                        friendly_name: 'Bedroom TV (Android TV)',
                    },
                },
            },
        } as unknown as HomeAssistant;

        const config: JellyHALibraryCardConfig = {
            type: 'custom:jellyha-library-card',
            entity: 'sensor.jellyha_library',
            default_client_device: 'media_player.jellyha_device_bedroom_tv',
        };

        const result = findActiveMediaItemPlayer(episodeItem, mockHass, config);
        expect(result).not.toBeNull();
        expect(result?.entityId).toBe('media_player.jellyha_device_bedroom_tv');
        expect(result?.state).toBe('playing');
    });

    it('matches series item when playing episode under series title', () => {
        const mockHass = {
            states: {
                'media_player.jellyha_device_moonfin': {
                    entity_id: 'media_player.jellyha_device_moonfin',
                    state: 'paused',
                    attributes: {
                        media_title: 'Bad Optics',
                        media_series_title: 'Lanterns',
                        friendly_name: 'Moonfin',
                    },
                },
            },
        } as unknown as HomeAssistant;

        const config: JellyHALibraryCardConfig = {
            type: 'custom:jellyha-library-card',
            entity: 'sensor.jellyha_library',
            default_client_device: 'media_player.jellyha_device_moonfin',
        };

        const result = findActiveMediaItemPlayer(seriesItem, mockHass, config);
        expect(result).not.toBeNull();
        expect(result?.entityId).toBe('media_player.jellyha_device_moonfin');
        expect(result?.state).toBe('paused');
    });

    it('supports two different items playing simultaneously on different devices', () => {
        const mockHass = {
            states: {
                'media_player.chromecast_living_room': {
                    entity_id: 'media_player.chromecast_living_room',
                    state: 'playing',
                    attributes: {
                        media_title: 'Inception',
                        friendly_name: 'Living Room TV',
                    },
                },
                'media_player.jellyha_device_bedroom_tv': {
                    entity_id: 'media_player.jellyha_device_bedroom_tv',
                    state: 'playing',
                    attributes: {
                        media_title: 'Bad Optics',
                        media_series_title: 'Lanterns',
                        friendly_name: 'Bedroom TV',
                    },
                },
            },
        } as unknown as HomeAssistant;

        const config: JellyHALibraryCardConfig = {
            type: 'custom:jellyha-library-card',
            entity: 'sensor.jellyha_library',
            default_cast_device: 'media_player.chromecast_living_room',
            default_client_device: 'media_player.jellyha_device_bedroom_tv',
        };

        // Poster 1 (Movie: Inception) matches Chromecast
        const movieResult = findActiveMediaItemPlayer(movieItem, mockHass, config);
        expect(movieResult).not.toBeNull();
        expect(movieResult?.entityId).toBe('media_player.chromecast_living_room');

        // Poster 2 (Episode: Lanterns) matches Jellyfin client
        const episodeResult = findActiveMediaItemPlayer(episodeItem, mockHass, config);
        expect(episodeResult).not.toBeNull();
        expect(episodeResult?.entityId).toBe('media_player.jellyha_device_bedroom_tv');
    });

    it('discovers active jellyha media players if no explicit devices matched', () => {
        const mockHass = {
            states: {
                'media_player.jellyha_device_wholphin': {
                    entity_id: 'media_player.jellyha_device_wholphin',
                    state: 'playing',
                    attributes: {
                        media_title: 'Inception',
                        friendly_name: 'Wholphin Fire TV',
                    },
                },
            },
        } as unknown as HomeAssistant;

        const config: JellyHALibraryCardConfig = {
            type: 'custom:jellyha-library-card',
            entity: 'sensor.jellyha_library',
        };

        const result = findActiveMediaItemPlayer(movieItem, mockHass, config);
        expect(result).not.toBeNull();
        expect(result?.entityId).toBe('media_player.jellyha_device_wholphin');
    });

    it('prefers active playing state over paused when multiple candidates match', () => {
        const mockHass = {
            states: {
                'media_player.cast_device': {
                    entity_id: 'media_player.cast_device',
                    state: 'paused',
                    attributes: {
                        media_title: 'Inception',
                    },
                },
                'media_player.client_device': {
                    entity_id: 'media_player.client_device',
                    state: 'playing',
                    attributes: {
                        media_title: 'Inception',
                    },
                },
            },
        } as unknown as HomeAssistant;

        const config: JellyHALibraryCardConfig = {
            type: 'custom:jellyha-library-card',
            entity: 'sensor.jellyha_library',
            default_cast_device: 'media_player.cast_device',
            default_client_device: 'media_player.client_device',
        };

        const result = findActiveMediaItemPlayer(movieItem, mockHass, config);
        expect(result?.entityId).toBe('media_player.client_device');
        expect(result?.state).toBe('playing');
    });

    it('returns null if player state is idle or off', () => {
        const mockHass = {
            states: {
                'media_player.cast_device': {
                    entity_id: 'media_player.cast_device',
                    state: 'off',
                    attributes: {
                        media_title: 'Inception',
                    },
                },
            },
        } as unknown as HomeAssistant;

        const config: JellyHALibraryCardConfig = {
            type: 'custom:jellyha-library-card',
            entity: 'sensor.jellyha_library',
            default_cast_device: 'media_player.cast_device',
        };

        expect(findActiveMediaItemPlayer(movieItem, mockHass, config)).toBeNull();
    });
});
