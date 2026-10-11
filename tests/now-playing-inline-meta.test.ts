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

    it('renders runtime and rating inline instead of poster when badge_style is inline', () => {
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

        // Check template strings / values
        const templateStr = JSON.stringify(template);

        // Poster badges for rating and runtime should NOT appear
        // Rating and runtime should be present in the inline metadata line
        expect(templateStr).toContain('idle-rating-pill');
        expect(templateStr).toContain('8.8');
        expect(templateStr).toContain('2h 28m');
        expect(templateStr).toContain('idle-meta-row');
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

        // Poster badge should appear
        expect(templateStr).toContain('poster-badge rating-badge');
        expect(templateStr).toContain('poster-badge runtime-badge');
        // Inline rating pill should not appear
        expect(templateStr).not.toContain('idle-rating-pill');
    });
});
