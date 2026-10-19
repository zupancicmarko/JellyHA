import { describe, it, expect } from 'vitest';
import { JellyHANowPlayingCardConfig } from '../src/shared/types';

describe('Editor Config Mapping for Power & Volume', () => {
    it('correctly maps power and volume configuration fields', () => {
        let currentConfig: JellyHANowPlayingCardConfig = {
            type: 'custom:jellyha-now-playing-card',
            entity: 'media_player.jellyfin',
        };

        const updateConfig = (key: keyof JellyHANowPlayingCardConfig, value: unknown) => {
            currentConfig = { ...currentConfig, [key]: value };
        };

        updateConfig('power_entity', 'switch.tv_power');
        updateConfig('power_state_entity', 'binary_sensor.tv_ping');
        updateConfig('show_power_button', true);
        updateConfig('stop_on_power_off', true);
        updateConfig('show_volume', true);
        updateConfig('volume_entity', 'media_player.soundbar');
        updateConfig('show_volume_step_buttons', true);
        updateConfig('volume_step', 5);

        expect(currentConfig.power_entity).toBe('switch.tv_power');
        expect(currentConfig.power_state_entity).toBe('binary_sensor.tv_ping');
        expect(currentConfig.show_power_button).toBe(true);
        expect(currentConfig.stop_on_power_off).toBe(true);
        expect(currentConfig.show_volume).toBe(true);
        expect(currentConfig.volume_entity).toBe('media_player.soundbar');
        expect(currentConfig.show_volume_step_buttons).toBe(true);
        expect(currentConfig.volume_step).toBe(5);
    });

    it('handles defaults when toggles are switched', () => {
        const config: JellyHANowPlayingCardConfig = {
            type: 'custom:jellyha-now-playing-card',
            entity: 'media_player.jellyfin',
        };

        const showPowerDefault = config.show_power_button !== false;
        const stopOnPowerOffDefault = config.stop_on_power_off !== false;
        const showVolumeDefault = config.show_volume === true;
        const stepButtonsDefault = config.show_volume_step_buttons !== false;
        const volumeStepDefault = config.volume_step ?? 5;

        expect(showPowerDefault).toBe(true);
        expect(stopOnPowerOffDefault).toBe(true);
        expect(showVolumeDefault).toBe(false);
        expect(stepButtonsDefault).toBe(true);
        expect(volumeStepDefault).toBe(5);
    });

    it('removes keys from config when cleared with undefined or empty string', () => {
        let config: JellyHANowPlayingCardConfig = {
            type: 'custom:jellyha-now-playing-card',
            entity: 'media_player.jellyfin',
            power_entity: 'switch.tv_power',
            power_state_entity: 'binary_sensor.tv_ping',
            volume_entity: 'media_player.soundbar'
        };

        const updateConfig = (key: keyof JellyHANowPlayingCardConfig, value: unknown) => {
            const next = { ...config };
            if (value === undefined || value === '') {
                delete next[key];
            } else {
                (next as any)[key] = value;
            }
            config = next;
        };

        updateConfig('power_entity', undefined);
        expect('power_entity' in config).toBe(false);
        expect(config.power_entity).toBeUndefined();

        updateConfig('volume_entity', '');
        expect('volume_entity' in config).toBe(false);
        expect(config.volume_entity).toBeUndefined();

        updateConfig('power_state_entity', undefined);
        expect('power_state_entity' in config).toBe(false);
    });

    it('correctly handles clear event where detail.value is undefined and target has old value', () => {
        let config: JellyHANowPlayingCardConfig = {
            type: 'custom:jellyha-now-playing-card',
            entity: 'media_player.jellyha_lg',
            power_entity: 'media_player.office_tv'
        };

        const updateConfig = (key: keyof JellyHANowPlayingCardConfig, value: unknown) => {
            const next = { ...config };
            if (value === undefined || value === '') {
                delete next[key];
            } else {
                (next as any)[key] = value;
            }
            config = next;
        };

        // Simulating the exact Home Assistant clear event
        const clearEvent = {
            detail: { value: undefined },
            target: { value: 'media_player.office_tv' }
        };

        const extractValue = (e: any) =>
            e.detail && 'value' in e.detail ? e.detail.value : e.target?.value;

        const value = extractValue(clearEvent);
        updateConfig('power_entity', value || undefined);

        expect(value).toBeUndefined();
        expect('power_entity' in config).toBe(false);
        expect(config.power_entity).toBeUndefined();
    });

    it('only shows use_series_image when episodes is selected from tv_content or media_type is next_up', () => {
        const isUseSeriesImageVisible = (mediaType?: string, tvContent?: string) => {
            if (mediaType === 'next_up') {
                return true;
            }
            if (mediaType === 'series' || mediaType === 'both' || !mediaType) {
                return tvContent === 'episodes';
            }
            return false;
        };

        // When tv_content is 'series' (Shows / Series), use_series_image should NOT be visible
        expect(isUseSeriesImageVisible('both', 'series')).toBe(false);
        expect(isUseSeriesImageVisible('series', 'series')).toBe(false);
        expect(isUseSeriesImageVisible(undefined, 'series')).toBe(false);

        // When tv_content is 'episodes', use_series_image SHOULD be visible
        expect(isUseSeriesImageVisible('both', 'episodes')).toBe(true);
        expect(isUseSeriesImageVisible('series', 'episodes')).toBe(true);
        expect(isUseSeriesImageVisible(undefined, 'episodes')).toBe(true);

        // For next_up, use_series_image is always visible
        expect(isUseSeriesImageVisible('next_up')).toBe(true);

        // For movies only, it should not be visible
        expect(isUseSeriesImageVisible('movies', 'episodes')).toBe(false);
    });

    it('hides show_runtime on library card when media_type is TV Shows Only (series) and tv_content is Shows / Series (series)', async () => {
        const { JellyHALibraryEditor } = await import('../src/editors/jellyha-library-editor');
        const editor = new JellyHALibraryEditor();

        // 1. media_type = 'series' and tv_content = 'series' -> hidden
        (editor as any)._config = { media_type: 'series', tv_content: 'series' };
        expect((editor as any)._isRuntimeOptionVisible()).toBe(false);

        // 2. media_type = 'series' and tv_content undefined (default is 'series') -> hidden
        (editor as any)._config = { media_type: 'series' };
        expect((editor as any)._isRuntimeOptionVisible()).toBe(false);

        // 3. media_type = 'series' and tv_content = 'episodes' -> visible
        (editor as any)._config = { media_type: 'series', tv_content: 'episodes' };
        expect((editor as any)._isRuntimeOptionVisible()).toBe(true);

        // 4. media_type = 'movies' -> visible
        (editor as any)._config = { media_type: 'movies', tv_content: 'series' };
        expect((editor as any)._isRuntimeOptionVisible()).toBe(true);

        // 5. media_type = 'both' -> visible
        (editor as any)._config = { media_type: 'both', tv_content: 'series' };
        expect((editor as any)._isRuntimeOptionVisible()).toBe(true);

        // 6. media_type = 'next_up' -> visible
        (editor as any)._config = { media_type: 'next_up' };
        expect((editor as any)._isRuntimeOptionVisible()).toBe(true);
    });
});

describe('Library Card Editor - Jellyfin Client Device Filtering', () => {
    it('only allows configured JellyHA client devices and strictly excludes library browsers and user players', async () => {
        const { JellyHALibraryEditor } = await import('../src/editors/jellyha-library-editor');
        const editor = new JellyHALibraryEditor();

        editor.hass = {
            states: {
                'media_player.jellyha_device_marko_s_s23': {
                    entity_id: 'media_player.jellyha_device_marko_s_s23',
                    attributes: { friendly_name: "Device Marko's S23 (Findroid)", device_id: 'dev-123' },
                },
                'media_player.jellyha_hk1rbox_x50': {
                    entity_id: 'media_player.jellyha_hk1rbox_x50',
                    attributes: { friendly_name: 'Device HK1RBOX-X50 (Wholphin)', device_id: 'dev-456' },
                },
                'media_player.jellyha_library_browser': {
                    entity_id: 'media_player.jellyha_library_browser',
                    attributes: { friendly_name: 'Library Browser' },
                },
                'media_player.jellyha_music_cartoons_library_browser': {
                    entity_id: 'media_player.jellyha_music_cartoons_library_browser',
                    attributes: { friendly_name: 'Library Browser' },
                },
                'media_player.jellyha_moonfin': {
                    entity_id: 'media_player.jellyha_moonfin',
                    attributes: { friendly_name: 'Moonfin', user_id: 'user-789' },
                },
                'media_player.chromecast_living_room': {
                    entity_id: 'media_player.chromecast_living_room',
                    attributes: { friendly_name: 'Living Room TV' },
                },
            },
            entities: {
                'media_player.jellyha_device_marko_s_s23': {
                    platform: 'jellyha',
                    unique_id: 'entry1_device_player_dev-123',
                },
                'media_player.jellyha_hk1rbox_x50': {
                    platform: 'jellyha',
                    unique_id: 'entry1_device_player_dev-456',
                },
                'media_player.jellyha_library_browser': {
                    platform: 'jellyha',
                    unique_id: 'entry1_media_browser',
                },
                'media_player.jellyha_music_cartoons_library_browser': {
                    platform: 'jellyha',
                    unique_id: 'JellyHA_media_browser',
                },
                'media_player.jellyha_moonfin': {
                    platform: 'jellyha',
                    unique_id: 'entry1_media_player_user-789',
                },
                'media_player.chromecast_living_room': {
                    platform: 'cast',
                    unique_id: 'cast_123',
                },
            },
        } as any;

        const filter = (editor as any)._filterClientDevices;

        // Configured device players must pass
        expect(filter(editor.hass.states['media_player.jellyha_device_marko_s_s23'])).toBe(true);
        expect(filter(editor.hass.states['media_player.jellyha_hk1rbox_x50'])).toBe(true);

        // Library browsers must be rejected
        expect(filter(editor.hass.states['media_player.jellyha_library_browser'])).toBe(false);
        expect(filter(editor.hass.states['media_player.jellyha_music_cartoons_library_browser'])).toBe(false);

        // User player (e.g. Moonfin) must be rejected
        expect(filter(editor.hass.states['media_player.jellyha_moonfin'])).toBe(false);

        // Standard cast/unrelated device must be rejected
        expect(filter(editor.hass.states['media_player.chromecast_living_room'])).toBe(false);

        // Has configured client devices should be true
        expect((editor as any)._hasConfiguredClientDevices()).toBe(true);
    });

    it('detects when no client devices are configured in JellyHA integration', async () => {
        const { JellyHALibraryEditor } = await import('../src/editors/jellyha-library-editor');
        const editor = new JellyHALibraryEditor();

        editor.hass = {
            states: {
                'media_player.jellyha_library_browser': {
                    entity_id: 'media_player.jellyha_library_browser',
                    attributes: { friendly_name: 'Library Browser' },
                },
                'media_player.jellyha_admin': {
                    entity_id: 'media_player.jellyha_admin',
                    attributes: { friendly_name: 'User admin', user_id: 'user-admin' },
                },
            },
            entities: {
                'media_player.jellyha_library_browser': {
                    platform: 'jellyha',
                    unique_id: 'entry1_media_browser',
                },
                'media_player.jellyha_admin': {
                    platform: 'jellyha',
                    unique_id: 'entry1_media_player_user-admin',
                },
            },
        } as any;

        // Has configured client devices must be false
        expect((editor as any)._hasConfiguredClientDevices()).toBe(false);
    });

    it('rejects ghost entities that exist in entity registry but are absent from hass.states or unavailable', async () => {
        const { JellyHALibraryEditor } = await import('../src/editors/jellyha-library-editor');
        const editor = new JellyHALibraryEditor();

        editor.hass = {
            states: {
                // Active user player
                'media_player.jellyha_admin': {
                    entity_id: 'media_player.jellyha_admin',
                    state: 'idle',
                    attributes: { friendly_name: 'User admin', user_id: 'user-admin' },
                },
                // Restored / unavailable leftover device
                'media_player.jellyha_device_samsung_sm_s911b': {
                    entity_id: 'media_player.jellyha_device_samsung_sm_s911b',
                    state: 'unavailable',
                    attributes: { friendly_name: 'Moonfin', restored: true },
                },
            },
            entities: {
                // Leftover in registry from past configuration, but state is unavailable
                'media_player.jellyha_device_samsung_sm_s911b': {
                    platform: 'jellyha',
                    unique_id: 'entry1_device_player_dev-1',
                },
                // Leftover in registry from past configuration, but completely absent from states
                'media_player.jellyha_device_marko_s23_findroid': {
                    platform: 'jellyha',
                    unique_id: 'entry1_device_player_dev-2',
                },
            },
        } as any;

        const filter = (editor as any)._filterClientDevices;

        // Unavailable device entity must be rejected
        expect(filter(editor.hass.states['media_player.jellyha_device_samsung_sm_s911b'])).toBe(false);

        // Ghost entity absent from hass.states (passed as stub by ha-entity-picker) must be rejected
        expect(filter({ entity_id: 'media_player.jellyha_device_marko_s23_findroid' })).toBe(false);

        // _hasConfiguredClientDevices must be false
        expect((editor as any)._hasConfiguredClientDevices()).toBe(false);
    });

    it('populates availableEntities with JellyHA players, other media players (Chromecast), and legacy sensors', async () => {
        const { JellyHANowPlayingEditor } = await import('../src/editors/jellyha-now-playing-editor');
        const editor = new JellyHANowPlayingEditor();
        editor.setConfig({
            type: 'custom:jellyha-now-playing-card',
            entity: 'media_player.chromecast_ultra',
        });
        editor.hass = {
            states: {
                'media_player.jellyha_user': {
                    entity_id: 'media_player.jellyha_user',
                    attributes: { friendly_name: 'Marko JellyHA' },
                },
                'media_player.chromecast_ultra': {
                    entity_id: 'media_player.chromecast_ultra',
                    attributes: { friendly_name: 'Chromecast Ultra' },
                },
                'media_player.living_room_tv': {
                    entity_id: 'media_player.living_room_tv',
                    attributes: { friendly_name: 'Living Room TV' },
                },
                'media_player.jellyha_library_browser': {
                    entity_id: 'media_player.jellyha_library_browser',
                    attributes: { friendly_name: 'Browser' },
                },
                'sensor.jellyha_user_now_playing': {
                    entity_id: 'sensor.jellyha_user_now_playing',
                    attributes: { friendly_name: 'Marko Now Playing' },
                },
            },
        } as any;

        const rendered = (editor as any).render();
        expect(rendered).toBeDefined();

        // Check the selector options passed in the TemplateResult values
        const selectorValue = rendered.values.find((v: any) => v && typeof v === 'object' && v.select && v.select.options);
        expect(selectorValue).toBeDefined();
        const options = selectorValue.select.options;

        expect(options).toEqual([
            { value: 'media_player.jellyha_user', label: 'Marko JellyHA (JellyHA)' },
            { value: 'media_player.chromecast_ultra', label: 'Chromecast Ultra (Media Player)' },
            { value: 'media_player.living_room_tv', label: 'Living Room TV (Media Player)' },
            { value: 'sensor.jellyha_user_now_playing', label: 'Marko Now Playing (Legacy Sensor)' },
        ]);
    });
});


