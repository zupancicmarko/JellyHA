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
});
