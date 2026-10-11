import { describe, it, expect } from 'vitest';
import { JellyHANowPlayingCard } from '../src/cards/jellyha-now-playing-card';
import { HomeAssistant, JellyHANowPlayingCardConfig } from '../src/shared/types';

describe('Now Playing Card - Inline Badge Style & Metadata Layout', () => {
    const createMockHass = (state: string, attributes: Record<string, any>): HomeAssistant => {
        return {
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
        } as unknown as HomeAssistant;
    };

    it('renders movie badge, runtime, and rating inline when badge_style is inline', () => {
        const card = new JellyHANowPlayingCard();
        card.setConfig({
            type: 'custom:jellyha-now-playing-card',
            entity: 'media_player.jellyfin',
            badge_style: 'inline',
            show_media_type_badge: true,
            show_year: true,
            show_runtime: true,
            show_ratings: true,
            show_genres: true,
        } as JellyHANowPlayingCardConfig);

        card.hass = createMockHass('playing', {
            media_title: 'Inception',
            media_content_type: 'movie',
            media_type: 'Movie',
            year: 2010,
            runtime_minutes: 148,
            community_rating: 8.8,
            genres: ['Action', 'Sci-Fi'],
            entity_picture: '/api/image.jpg',
        });

        // Trigger render
        const template = (card as any).render();
        expect(template).toBeDefined();

        const templateStr = JSON.stringify(template);

        // Poster badges for media type, rating, and runtime should NOT be in poster
        expect(templateStr).not.toContain('poster-badge media-type-badge');
        expect(templateStr).not.toContain('poster-badge rating-badge');
        expect(templateStr).not.toContain('poster-badge runtime-badge');

        // Inline media type badge, rating, and runtime should be present in the metadata line
        expect(templateStr).toContain('media-type-badge inline-badge');
        expect(templateStr).toContain('MOVIE');
        expect(templateStr).toContain('idle-rating-pill');
        expect(templateStr).toContain('8.8');
        expect(templateStr).toContain('2h 28m');
        expect(templateStr).toContain('idle-meta-row');

        // Title should remain clean without prefix
        expect(templateStr).toContain('Inception');
        expect(templateStr).not.toContain('MOVIE • Inception');
    });

    it('renders episode badge S02E08 inline when badge_style is inline', () => {
        const card = new JellyHANowPlayingCard();
        card.setConfig({
            type: 'custom:jellyha-now-playing-card',
            entity: 'media_player.jellyfin',
            badge_style: 'inline',
            show_media_type_badge: true,
            show_year: true,
            show_runtime: true,
            show_ratings: true,
            show_genres: true,
        } as JellyHANowPlayingCardConfig);

        card.hass = createMockHass('playing', {
            media_title: 'Better Call Saul',
            media_content_type: 'episode',
            media_type: 'Episode',
            season: 2,
            episode: 8,
            year: 2009,
            runtime_minutes: 47,
            community_rating: 9.2,
            genres: ['Crime', 'Drama'],
            entity_picture: '/api/image.jpg',
        });

        const template = (card as any).render();
        const templateStr = JSON.stringify(template);

        // S02E08 badge should appear inline
        expect(templateStr).toContain('media-type-badge inline-badge');
        expect(templateStr).toContain('S02E08');

        // Title should NOT have S02E08 prepended to it
        expect(templateStr).not.toContain('S02E08 • Better Call Saul');
    });

    it('keeps runtime and rating on the poster when badge_style is poster', () => {
        const card = new JellyHANowPlayingCard();
        card.setConfig({
            type: 'custom:jellyha-now-playing-card',
            entity: 'media_player.jellyfin',
            badge_style: 'poster',
            show_media_type_badge: true,
            show_year: true,
            show_runtime: true,
            show_ratings: true,
            show_genres: true,
        } as JellyHANowPlayingCardConfig);

        card.hass = createMockHass('playing', {
            media_title: 'Inception',
            media_content_type: 'movie',
            media_type: 'Movie',
            year: 2010,
            runtime_minutes: 148,
            community_rating: 8.8,
            genres: ['Action', 'Sci-Fi'],
            entity_picture: '/api/image.jpg',
        });

        const template = (card as any).render();
        const templateStr = JSON.stringify(template);

        // Poster badges should appear
        expect(templateStr).toContain('poster-badge media-type-badge');
        expect(templateStr).toContain('poster-badge rating-badge');
        expect(templateStr).toContain('poster-badge runtime-badge');

        // Inline badges should not appear
        expect(templateStr).not.toContain('inline-badge');
        expect(templateStr).not.toContain('idle-rating-pill');
    });

    it('presents episode title as title and series name as subtitle in idle card mode matching active playback', () => {
        const card = new JellyHANowPlayingCard();
        card.setConfig({
            type: 'custom:jellyha-now-playing-card',
            entity: 'media_player.jellyfin',
            idle_backdrop_cycle: true,
            idle_display_mode: 'card',
        } as JellyHANowPlayingCardConfig);

        const idleEpisode = {
            id: 'ep_1',
            name: 'Bad Optics',
            series_name: 'Lanterns',
            type: 'Episode',
            season: 1,
            episode: 6,
            year: 2026,
            runtime_minutes: 53,
            community_rating: 7.4,
            genres: ['Action', 'Adventure', 'Crime'],
            poster_url: '/api/lanterns.jpg',
            backdrop_url: '/api/lanterns_bg.jpg',
        };

        const template = (card as any)._renderIdleCardMode(idleEpisode, null, 'en');
        expect(template).toBeDefined();

        const templateStr = JSON.stringify(template);
        // Title should be episode name "Bad Optics", subtitle should be series name "Lanterns"
        expect(templateStr).toContain('Bad Optics');
        expect(templateStr).toContain('Lanterns');
        // Subtitle should NOT contain "S01E06 · Bad Optics"
        expect(templateStr).not.toContain('S01E06 · Bad Optics');
    });
});
