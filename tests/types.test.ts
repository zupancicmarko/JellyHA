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

    it('defines playing_display_mode, playing_artwork_source, and playing_artwork_fit in now playing config', () => {
        const config: JellyHANowPlayingCardConfig = {
            type: 'custom:jellyha-now-playing-card',
            entity: 'media_player.jellyfin',
            playing_display_mode: 'full_art',
            playing_artwork_source: 'poster',
            playing_artwork_fit: 'contain',
        };
        expect(config.playing_display_mode).toBe('full_art');
        expect(config.playing_artwork_source).toBe('poster');
        expect(config.playing_artwork_fit).toBe('contain');
    });

    it('translates playing display mode and artwork fit keys across languages', async () => {
        const { localize } = await import('../src/shared/localize');
        expect(localize('en', 'editor.playing_display_mode')).toBe('Playback Display Style');
        expect(localize('en', 'editor.playing_display_mode_card')).toBe('Card Layout (Poster + Details)');
        expect(localize('en', 'editor.playing_display_mode_full_art')).toBe('Full Artwork (Cinematic Hero)');
        expect(localize('en', 'editor.playing_artwork_source')).toBe('Playback Artwork Image');
        expect(localize('en', 'editor.playing_artwork_source_backdrop')).toBe('Fanart Backdrop');
        expect(localize('en', 'editor.playing_artwork_source_poster')).toBe('Poster');
        expect(localize('en', 'editor.playing_artwork_fit')).toBe('Artwork Fit');
        expect(localize('en', 'editor.playing_artwork_fit_cover')).toBe('Cover (Fill Card)');
        expect(localize('en', 'editor.playing_artwork_fit_contain')).toBe('Contain (Fit Whole Image)');

        expect(localize('de', 'editor.playing_display_mode')).toBe('Wiedergabe-Anzeigestil');
        expect(localize('de', 'editor.playing_artwork_fit')).toBe('Grafik-Anpassung');
        expect(localize('sl', 'editor.playing_artwork_fit')).toBe('Prilagajanje slike');
    });
});
