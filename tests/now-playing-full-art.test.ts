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

    it('applies fit-cover class by default or when playing_artwork_fit is cover', () => {
        const card = new JellyHANowPlayingCard();
        card.setConfig({
            type: 'custom:jellyha-now-playing-card',
            entity: 'media_player.jellyfin',
            playing_display_mode: 'full_art',
            playing_artwork_fit: 'cover',
        } as JellyHANowPlayingCardConfig);

        card.hass = createMockHass('playing', {
            media_title: 'Dune: Part Two',
            media_content_type: 'movie',
            backdrop_url: '/api/fanart.jpg',
        });

        const template = (card as any).render();
        const str = JSON.stringify(template);
        expect(str).toContain('full-art-playing-card');
        expect(str).toContain('fit-cover');
        expect(str).not.toContain('fit-contain');
    });

    it('applies fit-contain class when playing_artwork_fit is contain', () => {
        const card = new JellyHANowPlayingCard();
        card.setConfig({
            type: 'custom:jellyha-now-playing-card',
            entity: 'media_player.jellyfin',
            playing_display_mode: 'full_art',
            playing_artwork_fit: 'contain',
        } as JellyHANowPlayingCardConfig);

        card.hass = createMockHass('playing', {
            media_title: 'Dune: Part Two',
            media_content_type: 'movie',
            backdrop_url: '/api/fanart.jpg',
        });

        const template = (card as any).render();
        const str = JSON.stringify(template);
        expect(str).toContain('full-art-playing-card');
        expect(str).toContain('fit-contain');
        expect(str).not.toContain('fit-cover');
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

    it('renders full playback controls, progress bar, volume and timestamps in full art mode', () => {
        const card = new JellyHANowPlayingCard();
        card.setConfig({
            type: 'custom:jellyha-now-playing-card',
            entity: 'media_player.jellyfin',
            playing_display_mode: 'full_art',
            show_controls: true,
            show_time: true,
            show_volume: true,
        } as JellyHANowPlayingCardConfig);

        card.hass = createMockHass('playing', {
            media_title: 'Dune: Part Two',
            media_content_type: 'movie',
            entity_picture: '/api/poster.jpg',
            backdrop_url: '/api/fanart.jpg',
            media_duration: 3600,
            media_position: 1200,
            supports_remote_control: true,
        });

        const template = (card as any).render();
        const str = JSON.stringify(template);
        expect(str).toContain('full-art-top-overlay');
        expect(str).toContain('full-art-header-row');
        expect(str).toContain('full-art-bottom-overlay');
        expect(str).toContain('playback-controls');
        expect(str).toContain('play-pause-btn');
        expect(str).toContain('progress-container');
        expect(str).toContain('timestamps');
    });

    it('renders music controls (favorite, repeat) in full art mode', () => {
        const card = new JellyHANowPlayingCard();
        card.setConfig({
            type: 'custom:jellyha-now-playing-card',
            entity: 'media_player.jellyfin',
            playing_display_mode: 'full_art',
            show_controls: true,
        } as JellyHANowPlayingCardConfig);

        card.hass = createMockHass('playing', {
            media_title: 'Starboy',
            media_content_type: 'music',
            artist_name: 'The Weeknd',
            entity_picture: '/api/starboy.jpg',
            supports_remote_control: true,
        });

        const template = (card as any).render();
        const str = JSON.stringify(template);
        expect(str).toContain('full-art-playing-card');
        expect(str).toContain('music-subtle-btn');
    });

    it('does not limit max_rows in getGridOptions', () => {
        const card = new JellyHANowPlayingCard();
        const gridOptions = card.getGridOptions();
        expect(gridOptions.rows).toBe(3);
        expect(gridOptions.min_rows).toBe(2);
        expect((gridOptions as any).max_rows).toBeUndefined();
    });
});
