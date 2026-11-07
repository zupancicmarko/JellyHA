import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { resolveVolumeState, stepVolume, setVolumeLevel, toggleMute } from '../src/shared/power-volume-helpers';
import { HomeAssistant, JellyHANowPlayingCardConfig } from '../src/shared/types';
import { JellyHANowPlayingCard } from '../src/cards/jellyha-now-playing-card';

describe('Option 1 Volume Controls Logic', () => {
    beforeEach(() => {
        vi.useFakeTimers();
        if (typeof global.requestAnimationFrame === 'undefined') {
            global.requestAnimationFrame = vi.fn((cb) => setTimeout(cb, 0)) as any;
        }
        if (typeof global.cancelAnimationFrame === 'undefined') {
            global.cancelAnimationFrame = vi.fn((id) => clearTimeout(id)) as any;
        }
    });

    afterEach(() => {
        vi.useRealTimers();
    });

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

    it('updates volume when changed externally after stepping volume', async () => {
        const card = new JellyHANowPlayingCard();
        card.setConfig({
            type: 'custom:jellyha-now-playing-card',
            entity: 'media_player.soundbar',
            show_volume: true,
        } as JellyHANowPlayingCardConfig);

        const initialHass = {
            states: {
                'media_player.soundbar': {
                    entity_id: 'media_player.soundbar',
                    state: 'playing',
                    attributes: { volume_level: 0.20, is_volume_muted: false, item_id: '123' },
                    last_updated: '2026-11-06T20:00:00Z',
                }
            },
            callService: vi.fn().mockResolvedValue(undefined),
            locale: { language: 'en' },
            language: 'en',
        } as unknown as HomeAssistant;

        card.hass = initialHass;

        // 1. Step volume by +5% on the card
        await (card as any)._handleVolumeStep(5);
        expect((card as any)._optimisticVolume['media_player.soundbar']).toBe(25);

        // 2. An external device change occurs (e.g. TV remote changes volume to 45% = 0.45)
        const updatedHass = {
            states: {
                'media_player.soundbar': {
                    entity_id: 'media_player.soundbar',
                    state: 'playing',
                    attributes: { volume_level: 0.45, is_volume_muted: false, item_id: '123' },
                    last_updated: '2026-11-06T20:00:05Z',
                }
            },
            callService: vi.fn().mockResolvedValue(undefined),
            locale: { language: 'en' },
            language: 'en',
        } as unknown as HomeAssistant;

        // Simulate Home Assistant passing new hass to the card
        card.hass = updatedHass;
        (card as any).updated(new Map([['hass', initialHass]]));

        // The card MUST NOT be stuck on 25%! It must clear optimisticVolume and reflect 45%!
        expect((card as any)._optimisticVolume['media_player.soundbar']).toBeUndefined();
        const volTemplate = (card as any)._renderVolumeControls();
        expect(volTemplate.values).toContain(45);
    });

    it('updates volume when changed externally after dragging volume slider', async () => {
        const card = new JellyHANowPlayingCard();
        card.setConfig({
            type: 'custom:jellyha-now-playing-card',
            entity: 'media_player.soundbar',
            show_volume: true,
        } as JellyHANowPlayingCardConfig);

        const initialHass = {
            states: {
                'media_player.soundbar': {
                    entity_id: 'media_player.soundbar',
                    state: 'playing',
                    attributes: { volume_level: 0.20, is_volume_muted: false, item_id: '123' },
                    last_updated: '2026-11-06T20:00:00Z',
                }
            },
            callService: vi.fn().mockResolvedValue(undefined),
            locale: { language: 'en' },
            language: 'en',
        } as unknown as HomeAssistant;

        card.hass = initialHass;

        // Simulate dragging to 70% and ending drag
        (card as any)._isVolumeDragging = true;
        (card as any)._dragVolumePercent = 70;
        await (card as any)._endVolumeDrag({
            stopPropagation: vi.fn(),
            currentTarget: {
                closest: () => ({
                    hasPointerCapture: () => false,
                    releasePointerCapture: vi.fn()
                })
            }
        } as unknown as PointerEvent);

        expect((card as any)._optimisticVolume['media_player.soundbar']).toBe(70);

        // Remote or script sets volume to 30%
        const updatedHass = {
            states: {
                'media_player.soundbar': {
                    entity_id: 'media_player.soundbar',
                    state: 'playing',
                    attributes: { volume_level: 0.30, is_volume_muted: false, item_id: '123' },
                    last_updated: '2026-11-06T20:00:05Z',
                }
            },
            callService: vi.fn().mockResolvedValue(undefined),
            locale: { language: 'en' },
            language: 'en',
        } as unknown as HomeAssistant;

        card.hass = updatedHass;
        (card as any).updated(new Map([['hass', initialHass]]));

        expect((card as any)._optimisticVolume['media_player.soundbar']).toBeUndefined();
        const volTemplate = (card as any)._renderVolumeControls();
        expect(volTemplate.values).toContain(30);
    });

    it('clears optimistic volume after expiry timeout', async () => {
        const card = new JellyHANowPlayingCard();
        card.setConfig({
            type: 'custom:jellyha-now-playing-card',
            entity: 'media_player.soundbar',
            show_volume: true,
        } as JellyHANowPlayingCardConfig);

        const initialHass = {
            states: {
                'media_player.soundbar': {
                    entity_id: 'media_player.soundbar',
                    state: 'playing',
                    attributes: { volume_level: 0.20, is_volume_muted: false, item_id: '123' },
                    last_updated: '2026-11-06T20:00:00Z',
                }
            },
            callService: vi.fn().mockResolvedValue(undefined),
            locale: { language: 'en' },
            language: 'en',
        } as unknown as HomeAssistant;

        card.hass = initialHass;

        // Step volume
        await (card as any)._handleVolumeStep(5);
        expect((card as any)._optimisticVolume['media_player.soundbar']).toBe(25);

        // Advance timers by 2500ms
        vi.advanceTimersByTime(2500);

        // Optimistic volume should have expired
        expect((card as any)._optimisticVolume['media_player.soundbar']).toBeUndefined();
        const volTemplate = (card as any)._renderVolumeControls();
        expect(volTemplate.values).toContain(20);
    });

    it('applies fast slide transition when idle and disables it during dragging', () => {
        const card = new JellyHANowPlayingCard();
        card.setConfig({
            type: 'custom:jellyha-now-playing-card',
            entity: 'media_player.soundbar',
            show_volume: true,
        } as JellyHANowPlayingCardConfig);

        card.hass = {
            states: {
                'media_player.soundbar': {
                    entity_id: 'media_player.soundbar',
                    state: 'playing',
                    attributes: { volume_level: 0.50 },
                }
            },
            callService: vi.fn(),
            locale: { language: 'en' },
            language: 'en',
        } as unknown as HomeAssistant;

        // When not dragging, transition should be active (160ms)
        const idleTemplate = (card as any)._renderVolumeControls();
        expect(idleTemplate.values).toContain('width 200ms cubic-bezier(0.34, 1.28, 0.64, 1)');
        expect(idleTemplate.values).toContain('left 200ms cubic-bezier(0.34, 1.28, 0.64, 1), transform 0.1s ease');

        // When dragging, transition should be disabled ('none')
        (card as any)._isVolumeDragging = true;
        (card as any)._dragVolumePercent = 60;
        const dragTemplate = (card as any)._renderVolumeControls();
        expect(dragTemplate.values).toContain('none');
    });
});
