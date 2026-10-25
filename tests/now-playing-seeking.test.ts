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

    it('extracts item ID from signed proxy image URLs and proxy stream URLs', () => {
        const card = new JellyHANowPlayingCard();

        // 1. Signed proxy image URL
        const stateWithProxyPic = {
            entity_id: 'media_player.chromecast_ultra',
            state: 'playing',
            attributes: {
                entity_picture: '/api/jellyha/image/01KM6Z3F4HPQZ6QED9SJP1RWA9/d58157ce14eb00a9ec37cac99e1db7c9/Primary?authSig=eyJhbGciOiJIUzI1NiJ9',
            },
        } as any;
        expect((card as any)._extractItemId(stateWithProxyPic)).toBe('d58157ce14eb00a9ec37cac99e1db7c9');

        // 2. Full host signed proxy image URL
        const stateWithFullProxyPic = {
            entity_id: 'media_player.chromecast_ultra',
            state: 'playing',
            attributes: {
                entity_picture: 'https://homeassistant.local:8123/api/jellyha/image/01KM6Z3F4HPQZ6QED9SJP1RWA9/e1f09f35228c5c13f2aa5d82c0ce19ea/Primary?authSig=abc',
            },
        } as any;
        expect((card as any)._extractItemId(stateWithFullProxyPic)).toBe('e1f09f35228c5c13f2aa5d82c0ce19ea');

        // 3. Proxy stream URL in media_content_id
        const stateWithProxyStream = {
            entity_id: 'media_player.chromecast_ultra',
            state: 'playing',
            attributes: {
                media_content_id: 'http://10.10.10.136:8123/api/jellyha/stream/01KM6Z3F4HPQZ6QED9SJP1RWA9/a7c3941dfa924bce813098319f379124',
            },
        } as any;
        expect((card as any)._extractItemId(stateWithProxyStream)).toBe('a7c3941dfa924bce813098319f379124');

        // 4. Direct Jellyfin URLs (backward compatibility)
        const stateWithDirectJellyfin = {
            entity_id: 'media_player.chromecast_ultra',
            state: 'playing',
            attributes: {
                media_content_id: 'http://10.10.10.112:8096/Videos/bf107293acde89201948172938471928/stream.mp4?Static=true',
                entity_picture: 'http://10.10.10.112:8096/Items/bf107293acde89201948172938471928/Images/Primary',
            },
        } as any;
        expect((card as any)._extractItemId(stateWithDirectJellyfin)).toBe('bf107293acde89201948172938471928');
    });
});

