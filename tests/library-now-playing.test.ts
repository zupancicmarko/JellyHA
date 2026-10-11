import { describe, it, expect, vi } from 'vitest';
import { findActiveMediaItemPlayer, stopMediaPlayback } from '../src/shared/power-volume-helpers';
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
        season: 1,
        episode: 6,
    };

    const episode2Item: MediaItem = {
        id: 'episode-2',
        name: "The Jordan Boys' Legacy",
        series_name: 'Lanterns',
        type: 'Episode',
        year: 2026,
        season: 1,
        episode: 5,
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

    it('matches only the playing episode and does not match other episodes of the same series', () => {
        const mockHass = {
            states: {
                'media_player.jellyha_device_moonfin': {
                    entity_id: 'media_player.jellyha_device_moonfin',
                    state: 'playing',
                    attributes: {
                        media_title: 'Bad Optics',
                        media_series_title: 'Lanterns',
                        media_season: 1,
                        media_episode: 6,
                        item_id: 'episode-1',
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

        // Playing episode (Bad Optics) matches
        const result1 = findActiveMediaItemPlayer(episodeItem, mockHass, config);
        expect(result1).not.toBeNull();
        expect(result1?.entityId).toBe('media_player.jellyha_device_moonfin');
        expect(result1?.state).toBe('playing');

        // Other episode of same series (The Jordan Boys' Legacy) must NOT match
        const result2 = findActiveMediaItemPlayer(episode2Item, mockHass, config);
        expect(result2).toBeNull();
    });

    it('does not match another episode of the same series even without item_id on player', () => {
        const mockHass = {
            states: {
                'media_player.jellyha_device_moonfin': {
                    entity_id: 'media_player.jellyha_device_moonfin',
                    state: 'playing',
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

        // Only Bad Optics matches by title
        expect(findActiveMediaItemPlayer(episodeItem, mockHass, config)).not.toBeNull();
        // The Jordan Boys' Legacy must return null
        expect(findActiveMediaItemPlayer(episode2Item, mockHass, config)).toBeNull();
    });

    it('matches episode by season and episode number when player reports numbers', () => {
        const epWithoutTitle: MediaItem = {
            id: 'episode-anon-6',
            name: 'Episode 6',
            series_name: 'Lanterns',
            type: 'Episode',
            season: 1,
            episode: 6,
        };

        const mockHass = {
            states: {
                'media_player.tv': {
                    entity_id: 'media_player.tv',
                    state: 'playing',
                    attributes: {
                        media_title: 'Bad Optics',
                        media_series_title: 'Lanterns',
                        media_season: 1,
                        media_episode: 6,
                    },
                },
            },
        } as unknown as HomeAssistant;

        const config: JellyHALibraryCardConfig = {
            type: 'custom:jellyha-library-card',
            entity: 'sensor.jellyha_library',
            default_client_device: 'media_player.tv',
        };

        expect(findActiveMediaItemPlayer(epWithoutTitle, mockHass, config)).not.toBeNull();
        expect(findActiveMediaItemPlayer(episode2Item, mockHass, config)).toBeNull();
    });
});

describe('stopMediaPlayback service selection', () => {
    it('calls media_player.media_stop for jellyha device client', async () => {
        const mockCallService = vi.fn().mockResolvedValue(undefined);
        const mockHass = {
            states: {
                'media_player.jellyha_device_samsung_sm_s911b': {
                    entity_id: 'media_player.jellyha_device_samsung_sm_s911b',
                    state: 'playing',
                    attributes: {
                        supported_features: 4096, // STOP only, no TURN_OFF
                    },
                },
            },
            callService: mockCallService,
        } as unknown as HomeAssistant;

        await stopMediaPlayback(mockHass, 'media_player.jellyha_device_samsung_sm_s911b');

        expect(mockCallService).toHaveBeenCalledWith('media_player', 'media_stop', {
            entity_id: 'media_player.jellyha_device_samsung_sm_s911b',
        });
    });

    it('calls media_player.media_stop for default_client_device', async () => {
        const mockCallService = vi.fn().mockResolvedValue(undefined);
        const mockHass = {
            states: {
                'media_player.moonfin_app': {
                    entity_id: 'media_player.moonfin_app',
                    state: 'playing',
                    attributes: {
                        supported_features: 4096 | 256,
                    },
                },
            },
            callService: mockCallService,
        } as unknown as HomeAssistant;

        const config: JellyHALibraryCardConfig = {
            type: 'custom:jellyha-library-card',
            entity: 'sensor.jellyha_library',
            default_client_device: 'media_player.moonfin_app',
        };

        await stopMediaPlayback(mockHass, 'media_player.moonfin_app', config);

        expect(mockCallService).toHaveBeenCalledWith('media_player', 'media_stop', {
            entity_id: 'media_player.moonfin_app',
        });
    });

    it('calls media_player.turn_off for default_cast_device supporting turn_off', async () => {
        const mockCallService = vi.fn().mockResolvedValue(undefined);
        const mockHass = {
            states: {
                'media_player.chromecast': {
                    entity_id: 'media_player.chromecast',
                    state: 'playing',
                    attributes: {
                        supported_features: 4096 | 256,
                    },
                },
            },
            callService: mockCallService,
        } as unknown as HomeAssistant;

        const config: JellyHALibraryCardConfig = {
            type: 'custom:jellyha-library-card',
            entity: 'sensor.jellyha_library',
            default_cast_device: 'media_player.chromecast',
        };

        await stopMediaPlayback(mockHass, 'media_player.chromecast', config);

        expect(mockCallService).toHaveBeenCalledWith('media_player', 'turn_off', {
            entity_id: 'media_player.chromecast',
        });
    });

    it('falls back to media_stop when entity does not support turn_off', async () => {
        const mockCallService = vi.fn().mockResolvedValue(undefined);
        const mockHass = {
            states: {
                'media_player.browser': {
                    entity_id: 'media_player.browser',
                    state: 'playing',
                    attributes: {
                        supported_features: 4096, // STOP only
                    },
                },
            },
            callService: mockCallService,
        } as unknown as HomeAssistant;

        await stopMediaPlayback(mockHass, 'media_player.browser');

        expect(mockCallService).toHaveBeenCalledWith('media_player', 'media_stop', {
            entity_id: 'media_player.browser',
        });
    });
});
