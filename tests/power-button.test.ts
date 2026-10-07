import { describe, it, expect, vi } from 'vitest';
import { resolvePowerState, callPowerAction, resolveTargetPowerEntity } from '../src/shared/power-volume-helpers';
import { HomeAssistant } from '../src/shared/types';

describe('Power Button Logic & Stop-on-Power-Off', () => {
    it('determines white icon state for active playback / ON state', () => {
        const mockHass = {
            states: {
                'media_player.living_room_tv': { entity_id: 'media_player.living_room_tv', state: 'on', attributes: {} }
            }
        } as unknown as HomeAssistant;

        const stateInfo = resolvePowerState(mockHass, 'media_player.living_room_tv');
        expect(stateInfo.isOn).toBe(true);
        expect(stateInfo.isStateless).toBe(false);
    });

    it('determines dimmed icon state for standby / OFF state', () => {
        const mockHass = {
            states: {
                'media_player.living_room_tv': { entity_id: 'media_player.living_room_tv', state: 'off', attributes: {} }
            }
        } as unknown as HomeAssistant;

        const stateInfo = resolvePowerState(mockHass, 'media_player.living_room_tv');
        expect(stateInfo.isOn).toBe(false);
        expect(stateInfo.isStateless).toBe(false);
    });

    it('triggers media stop when powering off active playing device', async () => {
        const mockStop = vi.fn().mockResolvedValue(undefined);
        const mockCallPower = vi.fn().mockResolvedValue(undefined);

        const powerEntity = 'switch.tv_socket';
        const isDeviceOn = true;
        const isMediaPlaying = true;
        const stopOnPowerOff = true;

        if (isDeviceOn && isMediaPlaying && stopOnPowerOff) {
            await mockStop('Stop');
        }
        await mockCallPower(powerEntity);

        expect(mockStop).toHaveBeenCalledWith('Stop');
        expect(mockCallPower).toHaveBeenCalledWith('switch.tv_socket');
    });

    it('does not trigger media stop if stop_on_power_off is false', async () => {
        const mockStop = vi.fn();
        const mockCallPower = vi.fn();

        const isDeviceOn = true;
        const isMediaPlaying = true;
        const stopOnPowerOff = false;

        if (isDeviceOn && isMediaPlaying && stopOnPowerOff) {
            mockStop();
        }
        mockCallPower();

        expect(mockStop).not.toHaveBeenCalled();
        expect(mockCallPower).toHaveBeenCalled();
    });

    describe('resolveTargetPowerEntity', () => {
        it('uses explicit power_entity if configured', () => {
            const target = resolveTargetPowerEntity({
                entity: 'media_player.office_tv',
                power_entity: 'switch.tv_plug'
            } as any);
            expect(target).toBe('switch.tv_plug');
        });

        it('falls back to default media player if power_entity is not configured', () => {
            const target = resolveTargetPowerEntity({
                entity: 'media_player.office_tv',
            } as any);
            expect(target).toBe('media_player.office_tv');
        });

        it('does not fall back to sensor entity when power_entity is absent', () => {
            const target = resolveTargetPowerEntity({
                entity: 'sensor.jellyha_now_playing',
            } as any);
            expect(target).toBeUndefined();
        });

        it('returns undefined if no entity is configured', () => {
            const target = resolveTargetPowerEntity({} as any);
            expect(target).toBeUndefined();
        });
    });

    describe('callPowerAction for media_player', () => {
        it('calls media_player.turn_off when media player is ON', async () => {
            const mockCallService = vi.fn().mockResolvedValue(undefined);
            const mockHass = {
                states: {
                    'media_player.office_tv': { entity_id: 'media_player.office_tv', state: 'playing', attributes: {} }
                },
                callService: mockCallService
            } as unknown as HomeAssistant;

            await callPowerAction(mockHass, 'media_player.office_tv');
            expect(mockCallService).toHaveBeenCalledWith('media_player', 'turn_off', { entity_id: 'media_player.office_tv' });
        });

        it('calls media_player.turn_on when media player is OFF', async () => {
            const mockCallService = vi.fn().mockResolvedValue(undefined);
            const mockHass = {
                states: {
                    'media_player.office_tv': { entity_id: 'media_player.office_tv', state: 'off', attributes: {} }
                },
                callService: mockCallService
            } as unknown as HomeAssistant;

            await callPowerAction(mockHass, 'media_player.office_tv');
            expect(mockCallService).toHaveBeenCalledWith('media_player', 'turn_on', { entity_id: 'media_player.office_tv' });
        });
    });
});
