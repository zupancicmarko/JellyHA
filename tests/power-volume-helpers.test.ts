import { describe, it, expect, vi } from 'vitest';
import {
    resolvePowerState,
    callPowerAction,
    resolveVolumeState,
    setVolumeLevel,
    stepVolume,
    toggleMute,
    resolveInstanceSensorBase
} from '../src/shared/power-volume-helpers';
import { HomeAssistant } from '../src/shared/types';

describe('power-volume-helpers', () => {
    describe('resolvePowerState', () => {
        it('detects stateless script entities and reports isStateless = true', () => {
            const mockHass = {
                states: {
                    'script.toggle_tv': { entity_id: 'script.toggle_tv', state: 'off', attributes: {} }
                }
            } as unknown as HomeAssistant;
            const result = resolvePowerState(mockHass, 'script.toggle_tv');
            expect(result.isStateless).toBe(true);
            expect(result.isOn).toBe(false);
            expect(result.isAvailable).toBe(true);
        });

        it('detects button entities as stateless', () => {
            const mockHass = {
                states: {
                    'button.tv_power': { entity_id: 'button.tv_power', state: '2026-10-07T12:00:00Z', attributes: {} }
                }
            } as unknown as HomeAssistant;
            const result = resolvePowerState(mockHass, 'button.tv_power');
            expect(result.isStateless).toBe(true);
            expect(result.isOn).toBe(false);
        });

        it('detects stateful switch and media_player entities', () => {
            const mockHass = {
                states: {
                    'switch.tv_power': { entity_id: 'switch.tv_power', state: 'on', attributes: {} },
                    'media_player.tv': { entity_id: 'media_player.tv', state: 'off', attributes: {} },
                    'media_player.chromecast_idle': { entity_id: 'media_player.chromecast_idle', state: 'idle', attributes: {} },
                    'media_player.chromecast_paused': { entity_id: 'media_player.chromecast_paused', state: 'paused', attributes: {} }
                }
            } as unknown as HomeAssistant;
            const onResult = resolvePowerState(mockHass, 'switch.tv_power');
            expect(onResult.isStateless).toBe(false);
            expect(onResult.isOn).toBe(true);

            const offResult = resolvePowerState(mockHass, 'media_player.tv');
            expect(offResult.isStateless).toBe(false);
            expect(offResult.isOn).toBe(false);

            const idleResult = resolvePowerState(mockHass, 'media_player.chromecast_idle');
            expect(idleResult.isStateless).toBe(false);
            expect(idleResult.isOn).toBe(true);

            const pausedResult = resolvePowerState(mockHass, 'media_player.chromecast_paused');
            expect(pausedResult.isStateless).toBe(false);
            expect(pausedResult.isOn).toBe(true);
        });

        it('handles dual-entity pairing with power_state_entity', () => {
            const mockHass = {
                states: {
                    'script.toggle_tv': { entity_id: 'script.toggle_tv', state: 'off', attributes: {} },
                    'binary_sensor.tv_ping': { entity_id: 'binary_sensor.tv_ping', state: 'on', attributes: {} }
                }
            } as unknown as HomeAssistant;
            const result = resolvePowerState(mockHass, 'script.toggle_tv', 'binary_sensor.tv_ping');
            expect(result.isStateless).toBe(false);
            expect(result.isOn).toBe(true);
        });

        it('returns unavailable when entity does not exist in hass.states', () => {
            const mockHass = { states: {} } as unknown as HomeAssistant;
            const result = resolvePowerState(mockHass, 'switch.non_existent');
            expect(result.isAvailable).toBe(false);
            expect(result.isOn).toBe(false);
        });
    });

    describe('callPowerAction', () => {
        it('calls script.turn_on for script entities', async () => {
            const callService = vi.fn().mockResolvedValue(undefined);
            const mockHass = { callService } as unknown as HomeAssistant;
            await callPowerAction(mockHass, 'script.toggle_tv');
            expect(callService).toHaveBeenCalledWith('script', 'turn_on', { entity_id: 'script.toggle_tv' });
        });

        it('calls button.press for button entities', async () => {
            const callService = vi.fn().mockResolvedValue(undefined);
            const mockHass = { callService } as unknown as HomeAssistant;
            await callPowerAction(mockHass, 'button.tv_power');
            expect(callService).toHaveBeenCalledWith('button', 'press', { entity_id: 'button.tv_power' });
        });

        it('calls homeassistant.toggle for switches and media players', async () => {
            const callService = vi.fn().mockResolvedValue(undefined);
            const mockHass = { callService } as unknown as HomeAssistant;
            await callPowerAction(mockHass, 'switch.tv_socket');
            expect(callService).toHaveBeenCalledWith('homeassistant', 'toggle', { entity_id: 'switch.tv_socket' });
        });
    });

    describe('volume helpers', () => {
        it('resolves volume state correctly', () => {
            const mockHass = {
                states: {
                    'media_player.soundbar': {
                        entity_id: 'media_player.soundbar',
                        state: 'on',
                        attributes: { volume_level: 0.45, is_volume_muted: false }
                    }
                }
            } as unknown as HomeAssistant;
            const result = resolveVolumeState(mockHass, 'media_player.soundbar');
            expect(result.canControl).toBe(true);
            expect(result.volumeLevel).toBe(0.45);
            expect(result.volumePercent).toBe(45);
            expect(result.isMuted).toBe(false);
        });

        it('sets volume level clamped between 0 and 1', async () => {
            const callService = vi.fn().mockResolvedValue(undefined);
            const mockHass = { callService } as unknown as HomeAssistant;
            await setVolumeLevel(mockHass, 'media_player.soundbar', 1.5);
            expect(callService).toHaveBeenCalledWith('media_player', 'volume_set', {
                entity_id: 'media_player.soundbar',
                volume_level: 1.0
            });
        });

        it('steps volume up and down correctly', async () => {
            const callService = vi.fn().mockResolvedValue(undefined);
            const mockHass = {
                states: {
                    'media_player.soundbar': {
                        entity_id: 'media_player.soundbar',
                        state: 'on',
                        attributes: { volume_level: 0.45 }
                    }
                },
                callService
            } as unknown as HomeAssistant;
            await stepVolume(mockHass, 'media_player.soundbar', 0.05);
            expect(callService).toHaveBeenCalledWith('media_player', 'volume_set', {
                entity_id: 'media_player.soundbar',
                volume_level: 0.50
            });
        });

        it('toggles mute correctly', async () => {
            const callService = vi.fn().mockResolvedValue(undefined);
            const mockHass = {
                states: {
                    'media_player.soundbar': {
                        entity_id: 'media_player.soundbar',
                        state: 'on',
                        attributes: { is_volume_muted: false }
                    }
                },
                callService
            } as unknown as HomeAssistant;
            await toggleMute(mockHass, 'media_player.soundbar');
            expect(callService).toHaveBeenCalledWith('media_player', 'volume_mute', {
                entity_id: 'media_player.soundbar',
                is_volume_muted: true
            });
        });

        it('resolves Google Cast speaker volume via mirror/paired entity when target is off and has no volume_level', () => {
            const mockHass = {
                states: {
                    'media_player.office_speaker': {
                        entity_id: 'media_player.office_speaker',
                        state: 'off',
                        attributes: { friendly_name: 'Office speaker' }
                    },
                    'media_player.office_speaker_2': {
                        entity_id: 'media_player.office_speaker_2',
                        state: 'idle',
                        attributes: { volume_level: 0.35 }
                    }
                }
            } as unknown as HomeAssistant;
            const result = resolveVolumeState(mockHass, 'media_player.office_speaker');
            expect(result.volumeLevel).toBe(0.35);
            expect(result.volumePercent).toBe(35);
        });

        it('resolves volume via optimistic override when entity attributes omit volume_level', () => {
            const mockHass = {
                states: {
                    'media_player.office_speaker': {
                        entity_id: 'media_player.office_speaker',
                        state: 'off',
                        attributes: { friendly_name: 'Office speaker' }
                    }
                }
            } as unknown as HomeAssistant;
            const result = resolveVolumeState(mockHass, 'media_player.office_speaker', undefined, 42);
            expect(result.volumeLevel).toBe(0.42);
            expect(result.volumePercent).toBe(42);
        });

        it('steps volume correctly using currentOverrideLevel when entity lacks volume_level', async () => {
            const callService = vi.fn().mockResolvedValue(undefined);
            const mockHass = {
                states: {
                    'media_player.office_speaker': {
                        entity_id: 'media_player.office_speaker',
                        state: 'off',
                        attributes: {}
                    }
                },
                callService
            } as unknown as HomeAssistant;
            const nextLevel = await stepVolume(mockHass, 'media_player.office_speaker', 0.05, 0.40);
            expect(nextLevel).toBe(0.45);
            expect(callService).toHaveBeenCalledWith('media_player', 'volume_set', {
                entity_id: 'media_player.office_speaker',
                volume_level: 0.45
            });
        });
    });

    describe('resolveInstanceSensorBase', () => {
        it('resolves legacy per-user and per-device media players', () => {
            expect(resolveInstanceSensorBase('media_player.jellyha_admin')).toBe('sensor.jellyha');
            expect(resolveInstanceSensorBase('media_player.jellyha_tv')).toBe('sensor.jellyha');
        });

        it('resolves prefixed user and device media players', () => {
            expect(resolveInstanceSensorBase('media_player.jellyha_user_admin')).toBe('sensor.jellyha');
            expect(resolveInstanceSensorBase('media_player.jellyha_user_ela')).toBe('sensor.jellyha');
            expect(resolveInstanceSensorBase('media_player.jellyha_device_lg_smart_tv')).toBe('sensor.jellyha');
            expect(resolveInstanceSensorBase('media_player.jellyha_device_marko_s_s23')).toBe('sensor.jellyha');
        });

        it('resolves multi-instance setups with user and device prefixes', () => {
            expect(resolveInstanceSensorBase('media_player.jellyha_office_user_marko')).toBe('sensor.jellyha_office');
            expect(resolveInstanceSensorBase('media_player.jellyha_office_device_shield')).toBe('sensor.jellyha_office');
        });

        it('resolves legacy now playing sensors', () => {
            expect(resolveInstanceSensorBase('sensor.jellyha_now_playing_admin')).toBe('sensor.jellyha');
            expect(resolveInstanceSensorBase('sensor.jellyha_office_now_playing_admin')).toBe('sensor.jellyha_office');
        });

        it('handles empty or unrecognized input', () => {
            expect(resolveInstanceSensorBase('')).toBe('');
            expect(resolveInstanceSensorBase('light.living_room')).toBe('');
        });
    });
});

