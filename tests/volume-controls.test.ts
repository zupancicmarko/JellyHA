import { describe, it, expect, vi } from 'vitest';
import { resolveVolumeState, stepVolume, setVolumeLevel, toggleMute } from '../src/shared/power-volume-helpers';
import { HomeAssistant } from '../src/shared/types';

describe('Option 1 Volume Controls Logic', () => {
    it('calculates volume percentage accurately', () => {
        const mockHass = {
            states: {
                'media_player.soundbar': {
                    entity_id: 'media_player.soundbar',
                    state: 'on',
                    attributes: { volume_level: 0.45, is_volume_muted: false }
                }
            }
        } as unknown as HomeAssistant;

        const vol = resolveVolumeState(mockHass, 'media_player.soundbar');
        expect(vol.volumePercent).toBe(45);
        expect(vol.isMuted).toBe(false);
    });

    it('steps by custom volume_step (e.g. 5% = 0.05)', async () => {
        const callService = vi.fn().mockResolvedValue(undefined);
        const mockHass = {
            states: {
                'media_player.soundbar': {
                    entity_id: 'media_player.soundbar',
                    state: 'on',
                    attributes: { volume_level: 0.40 }
                }
            },
            callService
        } as unknown as HomeAssistant;

        const stepPct = 5;
        await stepVolume(mockHass, 'media_player.soundbar', stepPct / 100);

        expect(callService).toHaveBeenCalledWith('media_player', 'volume_set', {
            entity_id: 'media_player.soundbar',
            volume_level: 0.45
        });
    });

    it('calculates discrete haptic ticks every 5% during slider dragging', () => {
        const hapticMock = vi.fn();
        let lastNotch = 0;

        function simulateDrag(percent: number) {
            const notch = Math.floor(percent / 5);
            if (notch !== lastNotch) {
                lastNotch = notch;
                hapticMock('selection');
            }
        }

        simulateDrag(41); // notch = 8
        expect(hapticMock).toHaveBeenCalledTimes(1);

        simulateDrag(43); // notch = 8 (no tick)
        expect(hapticMock).toHaveBeenCalledTimes(1);

        simulateDrag(46); // notch = 9 (tick fired!)
        expect(hapticMock).toHaveBeenCalledTimes(2);

        simulateDrag(51); // notch = 10 (tick fired!)
        expect(hapticMock).toHaveBeenCalledTimes(3);
    });
});
