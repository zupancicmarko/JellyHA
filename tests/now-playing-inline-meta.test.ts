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

    it('presents episode title as title and series name as subtitle in idle backdrop (fanart) mode matching active playback', () => {
        const card = new JellyHANowPlayingCard();
        card.setConfig({
            type: 'custom:jellyha-now-playing-card',
            entity: 'media_player.jellyfin',
            idle_backdrop_cycle: true,
            idle_display_mode: 'backdrop',
            idle_content_source: 'latest_episode',
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

        const template = (card as any)._renderIdleBackdropMode(idleEpisode, null, 'en');
        expect(template).toBeDefined();

        const templateStr = JSON.stringify(template);
        // Title should be episode name "Bad Optics", subtitle should be series name "Lanterns"
        expect(templateStr).toContain('Bad Optics');
        expect(templateStr).toContain('Lanterns');
        expect(templateStr).not.toContain('S01E06 · Bad Optics');

        // When latest, both "LATEST EPISODE" and "S01E06" badges should be rendered side-by-side
        expect(templateStr).toContain('LATEST EPISODE');
        expect(templateStr).toContain('S01E06');
    });

    it('shows SxxExx badge instead of generic EPISODE when episode is not latest', () => {
        const card = new JellyHANowPlayingCard();
        card.setConfig({
            type: 'custom:jellyha-now-playing-card',
            entity: 'media_player.jellyfin',
            idle_backdrop_cycle: true,
            idle_display_mode: 'backdrop',
            idle_content_source: 'random',
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

        const template = (card as any)._renderIdleBackdropMode(idleEpisode, null, 'en');
        const templateStr = JSON.stringify(template);

        // When not latest, should display S01E06 as the badge and NOT "LATEST EPISODE" or generic "Episode"
        expect(templateStr).toContain('S01E06');
        expect(templateStr).not.toContain('LATEST EPISODE');
    });

    it('centralized _renderMetaRow returns nothing when all metadata options are empty', () => {
        const card = new JellyHANowPlayingCard();
        const res = (card as any)._renderMetaRow({});
        expect(res).toBeDefined();
        // Lit 'nothing' symbol
        expect(typeof res).toBe('symbol');
    });

    it('centralized _renderMetaRow renders unified metadata pills, text, and dots', () => {
        const card = new JellyHANowPlayingCard();
        const res = (card as any)._renderMetaRow({
            year: 2026,
            runtime: '1h 32m',
            rating: '8.5',
            genres: ['Action', 'Comedy'],
            isInline: true,
        });

        const resStr = JSON.stringify(res);
        expect(resStr).toContain('meta-line');
        expect(resStr).toContain('idle-meta-row');
        expect(resStr).toContain('2026');
        expect(resStr).toContain('1h 32m');
        expect(resStr).toContain('rating-pill');
        expect(resStr).toContain('8.5');
        expect(resStr).toContain('Action');
        expect(resStr).toContain('Comedy');
        expect(resStr).toContain('meta-dot');
    });

    it('ensures screensaver metadata and description (both poster and fanart) font size is 12px', async () => {
        const { JellyHANowPlayingCard } = await import('../src/cards/jellyha-now-playing-card');
        const styles = (JellyHANowPlayingCard as any).styles;
        const cssText = Array.isArray(styles) ? styles.map((s: any) => s.cssText).join(' ') : (styles?.cssText || '');

        // Screensaver descriptions: both poster (.idle-card-desc) and fanart (.idle-overview) must be 12px
        expect(cssText).toMatch(/\.idle-overview\s*\{[^}]*font-size:\s*12px/);
        expect(cssText).toMatch(/\.idle-card-desc\s*\{[^}]*font-size:\s*12px/);

        // Screensaver metadata items must be 12px
        expect(cssText).toMatch(/\.idle-meta-row[^{]*\{[^}]*font-size:\s*12px/);
    });

    it('places runtime and rating on the poster in poster screensaver when badge_style is poster', () => {
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

        const idleMovie = {
            id: 'mov_1',
            name: 'Captain Hook: The Cursed Tides',
            type: 'Movie',
            year: 2025,
            runtime_minutes: 90,
            community_rating: 4.9,
            genres: ['Adventure', 'Action', 'Horror'],
            poster_url: '/api/hook.jpg',
            backdrop_url: '/api/hook_bg.jpg',
        };

        const template = (card as any)._renderIdleCardMode(idleMovie, null, 'en');
        const templateStr = JSON.stringify(template);

        // Poster badges for media type, rating, and runtime should appear on poster
        expect(templateStr).toContain('poster-badge media-type-badge');
        expect(templateStr).toContain('poster-badge rating-badge rating-pill');
        expect(templateStr).toContain('poster-badge runtime-badge genre-pill');
        expect(templateStr).toContain('4.9');
        expect(templateStr).toContain('1h 30m');

        // Runtime and rating should NOT appear inline in the metadata row next to the title
        expect(templateStr).not.toContain('idle-rating-pill rating-pill');
    });

    it('places media badge, runtime, and rating inline in poster screensaver when badge_style is inline', () => {
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

        const idleMovie = {
            id: 'mov_1',
            name: 'Captain Hook: The Cursed Tides',
            type: 'Movie',
            year: 2025,
            runtime_minutes: 90,
            community_rating: 4.9,
            genres: ['Adventure', 'Action', 'Horror'],
            poster_url: '/api/hook.jpg',
            backdrop_url: '/api/hook_bg.jpg',
        };

        const template = (card as any)._renderIdleCardMode(idleMovie, null, 'en');
        const templateStr = JSON.stringify(template);

        // Poster badges for rating and runtime should NOT appear on poster
        expect(templateStr).not.toContain('poster-badge rating-badge');
        expect(templateStr).not.toContain('poster-badge runtime-badge');

        // Media type, rating, and runtime should appear inline
        expect(templateStr).toContain('media-type-badge inline-badge');
        expect(templateStr).toContain('idle-rating-pill rating-pill');
        expect(templateStr).toContain('1h 30m');
    });

    it('ensures rating number span is lifted by 1px with translateY(-0.5px)', async () => {
        const { sharedMetaRowStyles } = await import('../src/styles/jellyha-shared-styles');
        const cssText = sharedMetaRowStyles.cssText;

        expect(cssText).toContain('.rating-pill span');
        expect(cssText).toContain('transform: translateY(-0.5px)');
    });

    describe('Progressive Overflow Hiding (Controls Collision Prevention)', () => {
        const setupCardWithState = (overflowState: number) => {
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
                show_client: true,
                show_user: true,
                show_subtitle: true,
            } as JellyHANowPlayingCardConfig);

            card.hass = createMockHass('playing', {
                media_title: 'Coyote vs. Acme',
                media_series_title: 'Looney Tunes Specials',
                media_content_type: 'movie',
                media_type: 'Movie',
                year: 2026,
                runtime_minutes: 103,
                community_rating: 7.6,
                genres: ['Comedy', 'Adventure', 'Family'],
                user_name: 'jelly',
                client: 'Default Media Receiver',
                entity_picture: '/api/coyote.jpg',
            });

            (card as any)._overflowState = overflowState;
            return card;
        };

        it('state 0 shows everything: title, subtitle, base meta, genres, and client line', () => {
            const card = setupCardWithState(0);
            const str = JSON.stringify((card as any).render());

            expect(str).toContain('Coyote vs. Acme');
            expect(str).toContain('Looney Tunes Specials');
            expect(str).toContain('media-type-badge inline-badge');
            expect(str).toContain('Comedy');
            expect(str).toContain('Adventure');
            expect(str).toContain('Family');
            expect(str).toContain('client-line');
            expect(str).toContain('Default Media Receiver');
        });

        it('state 1 hides client line but retains genres and metadata', () => {
            const card = setupCardWithState(1);
            const str = JSON.stringify((card as any).render());

            expect(str).toContain('Coyote vs. Acme');
            expect(str).toContain('Looney Tunes Specials');
            expect(str).toContain('media-type-badge inline-badge');
            expect(str).toContain('Comedy');
            expect(str).not.toContain('client-line');
            expect(str).not.toContain('Default Media Receiver');
        });

        it('state 2 hides client line AND genres to prevent multiline controls collision, keeping base meta', () => {
            const card = setupCardWithState(2);
            const str = JSON.stringify((card as any).render());

            expect(str).toContain('Coyote vs. Acme');
            expect(str).toContain('Looney Tunes Specials');
            // Base meta is still present
            expect(str).toContain('media-type-badge inline-badge');
            expect(str).toContain('2026');
            expect(str).toContain('1h 43m');
            expect(str).toContain('7.6');
            // Wrapped genres and client line are hidden
            expect(str).not.toContain('Comedy');
            expect(str).not.toContain('Adventure');
            expect(str).not.toContain('Family');
            expect(str).not.toContain('client-line');
        });

        it('state 3 hides entire meta row and client line, keeping subtitle and title', () => {
            const card = setupCardWithState(3);
            const str = JSON.stringify((card as any).render());

            expect(str).toContain('Coyote vs. Acme');
            expect(str).toContain('Looney Tunes Specials');
            expect(str).not.toContain('media-type-badge inline-badge');
            expect(str).not.toContain('Comedy');
            expect(str).not.toContain('client-line');
        });

        it('state 4 hides subtitle, meta row, and client line, retaining title only', () => {
            const card = setupCardWithState(4);
            const str = JSON.stringify((card as any).render());

            expect(str).toContain('Coyote vs. Acme');
            expect(str).not.toContain('Looney Tunes Specials');
            expect(str).not.toContain('media-type-badge inline-badge');
            expect(str).not.toContain('client-line');
        });

        it('ensures CSS styles have overflow: hidden on .info-container and .info-top, and power button & progress timestamps are top-most', () => {
            const cssText = (JellyHANowPlayingCard as any).styles.cssText;
            expect(cssText).toMatch(/\.info-container\s*\{[^}]*overflow:\s*hidden/);
            expect(cssText).toMatch(/\.info-top[^{]*\{[^}]*overflow:\s*hidden/);
            expect(cssText).toMatch(/\.title-row\s*\{[^}]*z-index:\s*10/);
            expect(cssText).toMatch(/\.power-btn-hit-area\s*\{[^}]*z-index:\s*10/);
            expect(cssText).toMatch(/\.progress-container\s*\{[^}]*z-index:\s*10/);
            expect(cssText).toMatch(/\.title-row\s*\{[^}]*align-items:\s*center/);
            expect(cssText).toContain('compact-height');
            expect(cssText).toContain('volume-capsule');
        });

        it('renders seek-handle with bounded position to prevent edge clipping at 0% and 100%', () => {
            const card = setupCardWithState(0);
            const str = JSON.stringify((card as any).render());

            expect(str).toContain('seek-handle');
            expect(str).toContain('calc(0% + (50 - 0) * 0.12px)');
        });

        const createMockLayoutEl = (rect: { top: number; bottom: number; height: number; width: number }, extra: Record<string, any> = {}) => {
            const classes = new Set<string>();
            return {
                classList: {
                    contains: (c: string) => classes.has(c),
                    toggle: (c: string, force?: boolean) => {
                        if (force === undefined ? !classes.has(c) : force) classes.add(c);
                        else classes.delete(c);
                    },
                    remove: (...cs: string[]) => cs.forEach(c => classes.delete(c)),
                },
                getBoundingClientRect: () => ({ left: 0, right: rect.width, x: 0, y: rect.top, toJSON: () => {}, ...rect }),
                ...extra,
            };
        };

        it('keeps _overflowState at 0 (showing user_name, client, and device_name) for TV episodes with year and genres in a standard 3-row card when badge_style is poster', () => {
            const card = new JellyHANowPlayingCard();
            card.setConfig({
                type: 'custom:jellyha-now-playing-card',
                entity: 'media_player.jellyfin',
                badge_style: 'poster',
                show_media_type_badge: true,
                show_year: true,
                show_genres: true,
                show_client: true,
                show_user: true,
                show_device_name: true,
                show_subtitle: true,
            } as JellyHANowPlayingCardConfig);

            card.hass = createMockHass('playing', {
                item_id: 'ep_101',
                media_title: 'Bad Optics',
                series_title: 'Lanterns',
                media_content_type: 'episode',
                media_type: 'Episode',
                season: 1,
                episode: 6,
                year: 2026,
                genres: ['Action', 'Adventure', 'Crime'],
                user_name: 'Alice',
                client: 'Jellyfin Mobile (iOS)',
                device_name: 'iPhone',
                entity_picture: '/api/lanterns.jpg',
            });

            // Mock standard 3-row Lovelace card geometry (184px height, 480px width)
            const haCardEl = createMockLayoutEl({ top: 0, bottom: 184, height: 184, width: 480 });
            const titleRowEl = createMockLayoutEl({ top: 10, bottom: 36, height: 26, width: 320 });
            const bottomEl = createMockLayoutEl({ top: 117, bottom: 176, height: 59, width: 320 });
            const infoContainerEl = createMockLayoutEl({ top: 10, bottom: 176, height: 166, width: 320 });

            (card as any).getBoundingClientRect = () => ({ top: 0, bottom: 184, height: 184, width: 480, left: 0, right: 480, x: 0, y: 0, toJSON: () => {} });
            Object.defineProperty(card, 'shadowRoot', {
                value: {
                    querySelector: (sel: string) => {
                        if (sel === 'ha-card') return haCardEl;
                        if (sel === '.title-row') return titleRowEl;
                        if (sel === '.info-bottom') return bottomEl;
                        if (sel === '.info-container') return infoContainerEl;
                        return null;
                    },
                },
                configurable: true,
            });

            (card as any)._doLayoutCheck();
            expect((card as any)._overflowState).toBe(0);

            const rendered = JSON.stringify((card as any).render());
            expect(rendered).toContain('client-line');
            expect(rendered).toContain('Alice');
            expect(rendered).toContain('iPhone · Jellyfin Mobile (iOS)');
        });

        it('does not collapse _overflowState to 4 when bottom controls sit near the bottom edge of a compact card', () => {
            const card = setupCardWithState(0);

            // bottomRect.bottom = 183 on a 184px card (within 6px of cardRect.bottom)
            const haCardEl = createMockLayoutEl({ top: 0, bottom: 184, height: 184, width: 480 });
            const titleRowEl = createMockLayoutEl({ top: 10, bottom: 34, height: 24, width: 340 });
            const bottomEl = createMockLayoutEl({ top: 126, bottom: 183, height: 57, width: 340 });
            const infoContainerEl = createMockLayoutEl({ top: 10, bottom: 183, height: 173, width: 340 });

            (card as any).getBoundingClientRect = () => ({ top: 0, bottom: 184, height: 184, width: 480, left: 0, right: 480, x: 0, y: 0, toJSON: () => {} });
            Object.defineProperty(card, 'shadowRoot', {
                value: {
                    querySelector: (sel: string) => {
                        if (sel === 'ha-card') return haCardEl;
                        if (sel === '.title-row') return titleRowEl;
                        if (sel === '.info-bottom') return bottomEl;
                        if (sel === '.info-container') return infoContainerEl;
                        return null;
                    },
                },
                configurable: true,
            });

            (card as any)._doLayoutCheck();
            expect((card as any)._overflowState).toBeLessThan(4);
        });

        it('updates cached backdrop URL when authSig changes for the same item_id after HA restart', () => {
            const card = new JellyHANowPlayingCard();
            card.setConfig({
                type: 'custom:jellyha-now-playing-card',
                entity: 'media_player.jellyfin',
                show_background: true,
            } as JellyHANowPlayingCardConfig);

            card.hass = createMockHass('playing', {
                item_id: 'mov_123',
                media_title: 'Inception',
                backdrop_url: '/api/jellyha/image/entry1/mov_123/Backdrop?tag=abc&authSig=old_sig',
                image_url: '/api/jellyha/image/entry1/mov_123/Primary?tag=def&authSig=old_sig',
            });
            (card as any).render();
            expect((card as any)._cachedBackdropUrl).toContain('authSig=old_sig');

            // Simulate HA restart updating the entity attributes with a newly signed URL for the same item
            card.hass = createMockHass('playing', {
                item_id: 'mov_123',
                media_title: 'Inception',
                backdrop_url: '/api/jellyha/image/entry1/mov_123/Backdrop?tag=abc&authSig=new_sig',
                image_url: '/api/jellyha/image/entry1/mov_123/Primary?tag=def&authSig=new_sig',
            });
            (card as any).render();
            expect((card as any)._cachedBackdropUrl).toContain('authSig=new_sig');
        });

        it('does not hide client-line in auto-height (Masonry/stack) layouts when info-middle fits without overflow', () => {
            const card = new JellyHANowPlayingCard();
            card.setConfig({
                type: 'custom:jellyha-now-playing-card',
                entity: 'media_player.jellyfin',
                badge_style: 'poster',
                show_year: true,
                show_genres: true,
                show_client: true,
                show_user: true,
                show_device_name: true,
                show_subtitle: true,
            } as JellyHANowPlayingCardConfig);

            card.hass = createMockHass('playing', {
                item_id: 'ep_102',
                media_title: 'Pilot',
                series_title: 'Severance',
                media_content_type: 'episode',
                media_type: 'Episode',
                season: 1,
                episode: 1,
                year: 2022,
                genres: ['Drama', 'Sci-Fi'],
                user_name: 'Mark',
                client: 'Jellyfin Web',
                device_name: 'Chrome',
            });

            // In auto-height layout (or when poster image fails/is loading), bottomRect.top - titleRect.bottom
            // equals the exact rendered height of .info-middle (64px) with no scroll overflow.
            const haCardEl = createMockLayoutEl({ top: 0, bottom: 165, height: 165, width: 480 });
            const titleRowEl = createMockLayoutEl({ top: 10, bottom: 34, height: 24, width: 320 });
            const infoMiddleEl = createMockLayoutEl({ top: 34, bottom: 98, height: 64, width: 320 }, { clientHeight: 64, scrollHeight: 64 });
            const bottomEl = createMockLayoutEl({ top: 98, bottom: 155, height: 57, width: 320 });
            const infoContainerEl = createMockLayoutEl({ top: 10, bottom: 155, height: 145, width: 320 });

            (card as any).getBoundingClientRect = () => ({ top: 0, bottom: 165, height: 165, width: 480, left: 0, right: 480, x: 0, y: 0, toJSON: () => {} });
            Object.defineProperty(card, 'shadowRoot', {
                value: {
                    querySelector: (sel: string) => {
                        if (sel === 'ha-card') return haCardEl;
                        if (sel === '.title-row') return titleRowEl;
                        if (sel === '.info-middle' || sel === '.info-top') return infoMiddleEl;
                        if (sel === '.info-bottom') return bottomEl;
                        if (sel === '.info-container') return infoContainerEl;
                        return null;
                    },
                },
                configurable: true,
            });

            (card as any)._doLayoutCheck();
            expect((card as any)._overflowState).toBe(0);
        });

        it('does not unconditionally hide client-line or meta-line via max-width: 320px container query', async () => {
            const { JellyHANowPlayingCard } = await import('../src/cards/jellyha-now-playing-card');
            const styles = (JellyHANowPlayingCard as any).styles;
            const cssText = Array.isArray(styles) ? styles.map((s: any) => s.cssText).join(' ') : (styles?.cssText || '');

            expect(cssText).not.toMatch(/@container\s+now-playing\s*\(max-width:\s*320px\)\s*\{[^}]*\.client-line\s*\{[^}]*display:\s*none/);
        });
    });
});
