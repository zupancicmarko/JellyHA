import { describe, it, expect } from 'vitest';
import { JellyHANowPlayingCardConfig } from '../src/shared/types';

describe('JellyHANowPlayingCardConfig types', () => {
    it('accepts power and volume configuration properties including stop_on_power_off', () => {
        const config: JellyHANowPlayingCardConfig = {
            type: 'custom:jellyha-now-playing-card',
            entity: 'media_player.jellyfin',
            power_entity: 'script.tv_power',
            power_state_entity: 'binary_sensor.tv_ping',
            show_power_button: true,
            show_power: true,
            stop_on_power_off: true,
            show_volume: true,
            volume_entity: 'media_player.soundbar',
            show_volume_step_buttons: true,
            volume_step: 5,
        };
        expect(config.power_entity).toBe('script.tv_power');
        expect(config.power_state_entity).toBe('binary_sensor.tv_ping');
        expect(config.show_power_button).toBe(true);
        expect(config.show_power).toBe(true);
        expect(config.stop_on_power_off).toBe(true);
        expect(config.show_volume).toBe(true);
        expect(config.volume_entity).toBe('media_player.soundbar');
        expect(config.show_volume_step_buttons).toBe(true);
        expect(config.volume_step).toBe(5);
    });

    it('supports play-client action and default_client_device on JellyHALibraryCardConfig', () => {
        const libConfig: import('../src/shared/types').JellyHALibraryCardConfig = {
            type: 'custom:jellyha-library-card',
            entity: 'sensor.jellyfin_library',
            click_action: 'play-client',
            hold_action: 'play-client',
            double_tap_action: 'play-client',
            default_client_device: 'media_player.jellyha_device_living_room_tv',
            modal_play_actions: [
                {
                    type: 'client',
                    device: 'media_player.jellyha_device_living_room_tv',
                    name: 'Play on Living Room TV',
                    icon: 'mdi:television-play',
                },
            ],
        };

        expect(libConfig.click_action).toBe('play-client');
        expect(libConfig.default_client_device).toBe('media_player.jellyha_device_living_room_tv');
        expect(libConfig.modal_play_actions?.[0].type).toBe('client');
    });
});
