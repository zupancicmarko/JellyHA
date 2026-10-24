import { describe, it, expect } from 'vitest';
import { JellyHANowPlayingCard } from '../src/cards/jellyha-now-playing-card';
import { HomeAssistant, JellyHANowPlayingCardConfig } from '../src/shared/types';

describe('Now Playing Card - Full Art Playback Mode', () => {
    const createMockHass = (state: string, attributes: Record<string, any>): HomeAssistant => ({
        states: {
            'media_player.jellyfin': {
                entity_id: 'media_player.jellyfin',
                state,
                attributes: {
                    friendly_name: 'Jellyfin Web',
                    ...attributes,
                },
            },
        },
        callService: async () => {},
        locale: { language: 'en' },
        language: 'en',
    } as unknown as HomeAssistant);

    it('renders classic card mode by default or when playing_display_mode is card', () => {
        const card = new JellyHANowPlayingCard();
        card.setConfig({
            type: 'custom:jellyha-now-playing-card',
            entity: 'media_player.jellyfin',
            playing_display_mode: 'card',
        } as JellyHANowPlayingCardConfig);

        card.hass = createMockHass('playing', {
            media_title: 'Dune: Part Two',
            media_content_type: 'movie',
            entity_picture: '/api/poster.jpg',
            backdrop_url: '/api/fanart.jpg',
        });

        const template = (card as any).render();
        const str = JSON.stringify(template);
        expect(str).toContain('poster-container');
        expect(str).not.toContain('full-art-playing-card');
    });

    it('renders full art layout when playing_display_mode is full_art with backdrop', () => {
        const card = new JellyHANowPlayingCard();
        card.setConfig({
            type: 'custom:jellyha-now-playing-card',
            entity: 'media_player.jellyfin',
            playing_display_mode: 'full_art',
            playing_artwork_source: 'backdrop',
        } as JellyHANowPlayingCardConfig);

        card.hass = createMockHass('playing', {
            media_title: 'Dune: Part Two',
            media_content_type: 'movie',
            entity_picture: '/api/poster.jpg',
            backdrop_url: '/api/fanart.jpg',
        });

        const template = (card as any).render();
        const str = JSON.stringify(template);
        expect(str).toContain('full-art-playing-card');
        expect(str).toContain('full-art-hero-img');
        expect(str).toContain('/api/fanart.jpg');
    });

    it('uses poster artwork and poster-source class when playing_artwork_source is poster', () => {
        const card = new JellyHANowPlayingCard();
        card.setConfig({
            type: 'custom:jellyha-now-playing-card',
            entity: 'media_player.jellyfin',
            playing_display_mode: 'full_art',
            playing_artwork_source: 'poster',
        } as JellyHANowPlayingCardConfig);

        card.hass = createMockHass('playing', {
            media_title: 'Dune: Part Two',
            media_content_type: 'movie',
            entity_picture: '/api/poster.jpg',
            backdrop_url: '/api/fanart.jpg',
        });

        const template = (card as any).render();
        const str = JSON.stringify(template);
        expect(str).toContain('full-art-playing-card');
        expect(str).toContain('poster-source');
        expect(str).toContain('/api/poster.jpg');
    });

    it('falls back to poster when backdrop is missing in backdrop mode', () => {
        const card = new JellyHANowPlayingCard();
        card.setConfig({
            type: 'custom:jellyha-now-playing-card',
            entity: 'media_player.jellyfin',
            playing_display_mode: 'full_art',
            playing_artwork_source: 'backdrop',
        } as JellyHANowPlayingCardConfig);

        card.hass = createMockHass('playing', {
            media_title: 'Dune: Part Two',
            media_content_type: 'movie',
            entity_picture: '/api/poster.jpg',
        });

        const template = (card as any).render();
        const str = JSON.stringify(template);
        expect(str).toContain('full-art-playing-card');
        expect(str).toContain('/api/poster.jpg');
    });
});
