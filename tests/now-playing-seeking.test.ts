import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { JellyHANowPlayingCard } from '../src/cards/jellyha-now-playing-card';
import { HomeAssistant, JellyHANowPlayingCardConfig } from '../src/shared/types';

describe('Now Playing Card - Seeking & Buffering States', () => {
    beforeEach(() => {
        vi.useFakeTimers();
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    const createMockHass = (state: string, attributes: Record<string, any>): HomeAssistant => {
        return {
            states: {
                'media_player.chromecast_ultra': {
                    entity_id: 'media_player.chromecast_ultra',
                    state,
                    attributes: {
                        friendly_name: 'Chromecast Ultra',
                        supported_features: 4127295, // supports remote control, seek, volume, etc.
                        ...attributes,
                    },
                },
            },
            callService: vi.fn().mockResolvedValue(undefined),
            locale: { language: 'en' },
            language: 'en',
        } as unknown as HomeAssistant;
    };

    it('renders normal pause button when playing', () => {
        const card = new JellyHANowPlayingCard();
        card.setConfig({
            type: 'custom:jellyha-now-playing-card',
            entity: 'media_player.chromecast_ultra',
            idle_backdrop_cycle: true,
            show_controls: true,
        } as JellyHANowPlayingCardConfig);

        card.hass = createMockHass('playing', {
            media_title: 'Interstellar',
            media_duration: 10140,
            media_position: 1200,
            media_content_type: 'movie',
            entity_picture: '/api/image.jpg',
        });

        const template = (card as any).render();
        const templateStr = JSON.stringify(template);

        expect(templateStr).toContain('playback-controls');
        expect(templateStr).toContain('mdi:pause');
        expect(templateStr).not.toContain('mdi:loading');
        expect(templateStr).not.toContain('empty-card');
    });

    it('shows spinning loading icon and stays on now playing when seek is initiated', () => {
        const card = new JellyHANowPlayingCard();
        card.setConfig({
            type: 'custom:jellyha-now-playing-card',
            entity: 'media_player.chromecast_ultra',
            idle_backdrop_cycle: true,
            show_controls: true,
        } as JellyHANowPlayingCardConfig);

        card.hass = createMockHass('playing', {
            media_title: 'Interstellar',
            media_duration: 10140,
            media_position: 1200,
            media_content_type: 'movie',
            entity_picture: '/api/image.jpg',
        });

        // First render while playing to cache active state
        (card as any).render();

        // Trigger optimistic seek (as occurs when dragging/releasing progress bar)
        (card as any)._setOptimisticSeek(65);

        // Render immediately after seek initiated
        let template = (card as any).render();
        let templateStr = JSON.stringify(template);

        expect(templateStr).toContain('mdi:loading');
        expect(templateStr).toContain('spinning');

        // Now simulate Chromecast transitioning to 'idle' during buffering
        card.hass = createMockHass('idle', {
            // Chromecast often wipes or empties media attributes when briefly idle
        });

        template = (card as any).render();
        templateStr = JSON.stringify(template);

        // MUST NOT flip to screensaver or empty card!
        expect(templateStr).toContain('playback-controls');
        expect(templateStr).toContain('Interstellar');
        expect(templateStr).toContain('mdi:loading');
        expect(templateStr).toContain('spinning');
        expect(templateStr).not.toContain('empty-card');
        expect(templateStr).not.toContain('idle-showcase');
    });

    it('renders spinning loading icon when media_player state is buffering', () => {
        const card = new JellyHANowPlayingCard();
        card.setConfig({
            type: 'custom:jellyha-now-playing-card',
            entity: 'media_player.chromecast_ultra',
            idle_backdrop_cycle: true,
            show_controls: true,
        } as JellyHANowPlayingCardConfig);

        card.hass = createMockHass('buffering', {
            media_title: 'Interstellar',
            media_duration: 10140,
            media_position: 1200,
            media_content_type: 'movie',
            entity_picture: '/api/image.jpg',
        });

        const template = (card as any).render();
        const templateStr = JSON.stringify(template);

        expect(templateStr).toContain('playback-controls');
        expect(templateStr).toContain('mdi:loading');
        expect(templateStr).toContain('spinning');
        expect(templateStr).not.toContain('empty-card');
    });

    it('transitions to idle after seek timer expires if player remains idle', () => {
        const card = new JellyHANowPlayingCard();
        card.setConfig({
            type: 'custom:jellyha-now-playing-card',
            entity: 'media_player.chromecast_ultra',
            idle_backdrop_cycle: false, // will render empty card
            show_controls: true,
        } as JellyHANowPlayingCardConfig);

        card.hass = createMockHass('playing', {
            media_title: 'Interstellar',
            media_duration: 10140,
            media_position: 1200,
            media_content_type: 'movie',
            entity_picture: '/api/image.jpg',
        });

        (card as any).render();
        (card as any)._setOptimisticSeek(65);

        // Player stops and stays idle
        card.hass = createMockHass('idle', {});

        // Fast-forward past the 3-second seeking grace timer
        vi.advanceTimersByTime(3500);

        const template = (card as any).render();
        const templateStr = JSON.stringify(template);

        // Now it should cleanly transition to empty/idle
        expect(templateStr).toContain('empty-state');
        expect(templateStr).not.toContain('playback-controls');
    });
});
