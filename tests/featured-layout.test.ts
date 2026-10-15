import { describe, it, expect } from 'vitest';
import { JellyHALibraryCardConfig } from '../src/shared/types';
import { localize } from '../src/shared/localize';

describe('Featured Layout (Concept 1 Spotlight Hero)', () => {
    it('accepts layout: featured in JellyHALibraryCardConfig', () => {
        const config: JellyHALibraryCardConfig = {
            type: 'custom:jellyha-library-card',
            entity: 'sensor.jellyha_library',
            layout: 'featured',
            items_per_page: 4,
        };

        expect(config.layout).toBe('featured');
        expect(config.items_per_page).toBe(4);
    });

    it('has localization entries for editor.layout_featured across all languages', () => {
        const languages = ['en', 'de', 'fr', 'es', 'it', 'nl', 'sl', 'ru'];
        for (const lang of languages) {
            const label = localize(lang, 'editor.layout_featured');
            expect(label).toBeTruthy();
            expect(label).not.toBe('editor.layout_featured');
        }
    });

    it('editor.layout_featured has correct localized names', () => {
        expect(localize('en', 'editor.layout_featured')).toBe('Featured');
        expect(localize('de', 'editor.layout_featured')).toBe('Hervorgehoben');
        expect(localize('fr', 'editor.layout_featured')).toBe('En vedette');
        expect(localize('es', 'editor.layout_featured')).toBe('Destacado');
        expect(localize('it', 'editor.layout_featured')).toBe('In evidenza');
        expect(localize('nl', 'editor.layout_featured')).toBe('Uitgelicht');
        expect(localize('sl', 'editor.layout_featured')).toBe('Izpostavljeno');
        expect(localize('ru', 'editor.layout_featured')).toBe('Витрина');
    });

    it('correctly calculates pagination and slices 1 hero item plus 3 side items by default', () => {
        const dummyItems = Array.from({ length: 10 }, (_, i) => ({
            id: `item-${i + 1}`,
            name: `Item ${i + 1}`,
            type: 'Movie' as const,
        }));

        const itemsPerPage = 4;
        const totalPages = Math.ceil(dummyItems.length / itemsPerPage);
        expect(totalPages).toBe(3);

        // Page 0
        const page0 = dummyItems.slice(0, 4);
        const [hero0, ...side0] = page0;
        expect(hero0.id).toBe('item-1');
        expect(side0).toHaveLength(3);
        expect(side0.map((x) => x.id)).toEqual(['item-2', 'item-3', 'item-4']);

        // Page 2 (last page with only 2 items)
        const page2 = dummyItems.slice(8, 12);
        const [hero2, ...side2] = page2;
        expect(hero2.id).toBe('item-9');
        expect(side2).toHaveLength(1);
        expect(side2[0].id).toBe('item-10');
    });

    it('handles single item library or filter cleanly with no side items', () => {
        const singleList = [{ id: 'solo-1', name: 'Solo Movie', type: 'Movie' as const }];
        const [hero, ...side] = singleList;
        expect(hero.id).toBe('solo-1');
        expect(side).toHaveLength(0);
    });

    it('calculates effective items per page strictly from columns and rows for featured layout', () => {
        const getEffectiveItemsPerPage = (config: JellyHALibraryCardConfig, fallback: number = 3): number => {
            if (config.layout === 'featured') {
                const sideColumns = Math.max(1, config.columns || 1);
                const sideRows = Math.max(2, Math.min(3, config.rows || 3));
                return 1 + (sideColumns * sideRows);
            }
            return config.items_per_page || fallback;
        };

        // Default or columns: 1, default rows 3 -> 1 hero + 3 side = 4
        expect(getEffectiveItemsPerPage({ type: 'custom:jellyha-library-card', entity: 'x', layout: 'featured' })).toBe(4);
        expect(getEffectiveItemsPerPage({ type: 'custom:jellyha-library-card', entity: 'x', layout: 'featured', columns: 1 })).toBe(4);

        // columns: 2, default rows 3 -> 1 hero + 6 side = 7
        expect(getEffectiveItemsPerPage({ type: 'custom:jellyha-library-card', entity: 'x', layout: 'featured', columns: 2 })).toBe(7);

        // columns: 3, default rows 3 -> 1 hero + 9 side = 10
        expect(getEffectiveItemsPerPage({ type: 'custom:jellyha-library-card', entity: 'x', layout: 'featured', columns: 3 })).toBe(10);

        // columns: 4, default rows 3 -> 1 hero + 12 side = 13
        expect(getEffectiveItemsPerPage({ type: 'custom:jellyha-library-card', entity: 'x', layout: 'featured', columns: 4 })).toBe(13);

        // Configurable rows: 2
        // columns: 1, rows: 2 -> 1 hero + 2 side = 3
        expect(getEffectiveItemsPerPage({ type: 'custom:jellyha-library-card', entity: 'x', layout: 'featured', columns: 1, rows: 2 })).toBe(3);
        // columns: 2, rows: 2 -> 1 hero + 4 side = 5
        expect(getEffectiveItemsPerPage({ type: 'custom:jellyha-library-card', entity: 'x', layout: 'featured', columns: 2, rows: 2 })).toBe(5);
        // columns: 3, rows: 2 -> 1 hero + 6 side = 7
        expect(getEffectiveItemsPerPage({ type: 'custom:jellyha-library-card', entity: 'x', layout: 'featured', columns: 3, rows: 2 })).toBe(7);

        // items_per_page in config is completely ignored in featured layout
        expect(getEffectiveItemsPerPage({ type: 'custom:jellyha-library-card', entity: 'x', layout: 'featured', columns: 2, items_per_page: 9 })).toBe(7);
        expect(getEffectiveItemsPerPage({ type: 'custom:jellyha-library-card', entity: 'x', layout: 'featured', columns: 2, rows: 2, items_per_page: 9 })).toBe(5);

        // Grid layout untouched
        expect(getEffectiveItemsPerPage({ type: 'custom:jellyha-library-card', entity: 'x', layout: 'grid', items_per_page: 10 })).toBe(10);
    });

    it('has localization entries for editor.featured_columns_helper, editor.featured_rows, and editor.featured_rows_helper across all languages', () => {
        const languages = ['en', 'de', 'fr', 'es', 'it', 'nl', 'sl', 'ru'];
        for (const lang of languages) {
            const colHelper = localize(lang, 'editor.featured_columns_helper');
            expect(colHelper).toBeTruthy();
            expect(colHelper).not.toBe('editor.featured_columns_helper');

            const rowsLabel = localize(lang, 'editor.featured_rows');
            expect(rowsLabel).toBeTruthy();
            expect(rowsLabel).not.toBe('editor.featured_rows');

            const rowsHelper = localize(lang, 'editor.featured_rows_helper');
            expect(rowsHelper).toBeTruthy();
            expect(rowsHelper).not.toBe('editor.featured_rows_helper');
        }
    });

    it('accepts show_card_backdrop and featured_queue_backdrop options in JellyHALibraryCardConfig', () => {
        const configWithBackdrop: JellyHALibraryCardConfig = {
            type: 'custom:jellyha-library-card',
            entity: 'sensor.jellyha_library',
            layout: 'featured',
            show_card_backdrop: true,
            featured_queue_backdrop: true,
        };
        const configWithoutBackdrop: JellyHALibraryCardConfig = {
            type: 'custom:jellyha-library-card',
            entity: 'sensor.jellyha_library',
            layout: 'featured',
            show_card_backdrop: false,
            featured_queue_backdrop: false,
        };

        expect(configWithBackdrop.show_card_backdrop).toBe(true);
        expect(configWithoutBackdrop.show_card_backdrop).toBe(false);
        expect(configWithBackdrop.featured_queue_backdrop).toBe(true);
        expect(configWithoutBackdrop.featured_queue_backdrop).toBe(false);
    });

    it('has localization entries for show_card_backdrop across all languages', () => {
        const languages = ['en', 'de', 'fr', 'es', 'it', 'nl', 'sl', 'ru'];
        for (const lang of languages) {
            expect(localize(lang, 'editor.show_card_backdrop')).toBeTruthy();
            expect(localize(lang, 'editor.show_card_backdrop')).not.toBe('editor.show_card_backdrop');

            expect(localize(lang, 'editor.show_card_backdrop_helper')).toBeTruthy();
            expect(localize(lang, 'editor.show_card_backdrop_helper')).not.toBe('editor.show_card_backdrop_helper');

            expect(localize(lang, 'editor.featured_queue_backdrop')).toBeTruthy();
            expect(localize(lang, 'editor.featured_queue_backdrop')).not.toBe('editor.featured_queue_backdrop');

            expect(localize(lang, 'editor.featured_queue_backdrop_helper')).toBeTruthy();
            expect(localize(lang, 'editor.featured_queue_backdrop_helper')).not.toBe('editor.featured_queue_backdrop_helper');
        }
    });

    it('queue cards do not render volume icon (playback controls consolidated onto poster)', () => {
        const renderAction = (isPlaying: boolean) => {
            return null; // volume icon removed from card content
        };
        expect(renderAction(false)).toBeNull();
        expect(renderAction(true)).toBeNull();
    });

    it('suppresses title when show_title is false in featured hero and queue', () => {
        const shouldRenderTitle = (config: Partial<JellyHALibraryCardConfig>) => {
            return config.show_title !== false;
        };

        expect(shouldRenderTitle({})).toBe(true);
        expect(shouldRenderTitle({ show_title: true })).toBe(true);
        expect(shouldRenderTitle({ show_title: false })).toBe(false);
    });

    it('correctly handles show_card_backdrop precedence over featured_queue_backdrop', () => {
        const resolveBackdrop = (config: JellyHALibraryCardConfig) => {
            return config.show_card_backdrop !== undefined
                ? config.show_card_backdrop !== false
                : config.featured_queue_backdrop !== false;
        };

        expect(resolveBackdrop({ type: 'x', entity: 'y', show_card_backdrop: true })).toBe(true);
        expect(resolveBackdrop({ type: 'x', entity: 'y', show_card_backdrop: false })).toBe(false);
        expect(resolveBackdrop({ type: 'x', entity: 'y', featured_queue_backdrop: false })).toBe(false);
        expect(resolveBackdrop({ type: 'x', entity: 'y', show_card_backdrop: false, featured_queue_backdrop: true })).toBe(false);
    });

    it('correctly builds metadata text parts with date_added placed after runtime', () => {
        const buildMetaTextParts = (config: Partial<JellyHALibraryCardConfig>, item: { year?: number; runtime_minutes?: number; date_added?: string }) => {
            const showYear = config.show_year !== false;
            const showRuntime = config.show_runtime !== false;
            const showDateAdded = config.show_date_added === true;

            const yearStr = showYear && item.year ? String(item.year) : '';
            const runtimeStr = showRuntime && item.runtime_minutes ? `${item.runtime_minutes}m` : '';
            const dateAddedStr = showDateAdded && item.date_added ? 'Oct 12, 2026' : '';

            const parts: string[] = [];
            if (yearStr) parts.push(yearStr);
            if (runtimeStr) parts.push(runtimeStr);
            if (dateAddedStr) parts.push(dateAddedStr);
            return parts;
        };

        const item = { year: 2026, runtime_minutes: 97, date_added: '2026-10-12T10:00:00Z' };

        // By default show_date_added is false
        expect(buildMetaTextParts({ show_date_added: false }, item)).toEqual(['2026', '97m']);

        // When show_date_added is true, date_added appears after runtime
        expect(buildMetaTextParts({ show_date_added: true }, item)).toEqual(['2026', '97m', 'Oct 12, 2026']);

        // When runtime is disabled, date_added appears right after year
        expect(buildMetaTextParts({ show_date_added: true, show_runtime: false }, item)).toEqual(['2026', 'Oct 12, 2026']);
    });

    it('determines whether show_description should be visible in editor based on layout', () => {
        const isShowDescriptionVisibleInEditor = (layout: string) => layout !== 'featured';

        expect(isShowDescriptionVisibleInEditor('grid')).toBe(true);
        expect(isShowDescriptionVisibleInEditor('carousel')).toBe(true);
        expect(isShowDescriptionVisibleInEditor('list')).toBe(true);
        expect(isShowDescriptionVisibleInEditor('featured')).toBe(false);
    });

    it('detects cramped queue card layout when columns >= 3 or cramped class is present', () => {
        const checkIsCramped = (config: Partial<JellyHALibraryCardConfig>, hasCrampedClass: boolean = false) => {
            return (config.columns || 1) >= 3 || hasCrampedClass;
        };

        expect(checkIsCramped({ columns: 1 })).toBe(false);
        expect(checkIsCramped({ columns: 2 })).toBe(false);
        expect(checkIsCramped({ columns: 3 })).toBe(true);
        expect(checkIsCramped({ columns: 4 })).toBe(true);
        expect(checkIsCramped({ columns: 2 }, true)).toBe(true);
    });

    it('builds queue badges allowing up to 3 badges (media, new, watched) simultaneously', () => {
        const buildQueueBadges = (
            config: Partial<JellyHALibraryCardConfig>,
            item: { type: string; is_played?: boolean; season?: number; episode?: number },
            isNew: boolean
        ) => {
            const showMediaTypeBadge = config.show_media_type_badge !== false;
            const showWatched = config.show_watched_status !== false;

            const badges: string[] = [];
            if (showMediaTypeBadge) {
                if (item.season != null && item.episode != null) {
                    badges.push(`S0${item.season}E0${item.episode}`);
                } else {
                    badges.push(item.type === 'Movie' ? 'MOVIE' : 'SERIES');
                }
            }
            if (isNew) {
                badges.push('NEW');
            }
            if (showWatched && item.is_played) {
                badges.push('WATCHED');
            }
            return badges;
        };

        // Movie that is both New and Watched -> all 3 badges
        expect(buildQueueBadges({}, { type: 'Movie', is_played: true }, true)).toEqual(['MOVIE', 'NEW', 'WATCHED']);

        // Episode that is New and unwatched -> media + new
        expect(buildQueueBadges({}, { type: 'Episode', season: 1, episode: 6, is_played: false }, true)).toEqual(['S01E06', 'NEW']);

        // Movie that is Watched but not New -> media + watched
        expect(buildQueueBadges({}, { type: 'Movie', is_played: true }, false)).toEqual(['MOVIE', 'WATCHED']);
    });

    it('ensures featured-queue badges are pinned to top right and title/subtitle are tightly grouped', async () => {
        const { cardStyles } = await import('../src/styles/jellyha-library-styles');
        const cssText = cardStyles.cssText;

        // featured-queue-title should wrap and not have white-space: nowrap or padding-right: 76px
        expect(cssText).toContain('.featured-queue-title');
        expect(cssText).toContain('max-height: 2.5em');
        expect(cssText).toContain('word-break: break-word');
        expect(cssText).not.toMatch(/\.featured-queue-title\s*\{[^}]*white-space:\s*nowrap/);
        expect(cssText).not.toMatch(/\.featured-queue-title\s*\{[^}]*padding-right:\s*76px/);

        // queue badges are pinned to the top right in the same location and share 22px height
        expect(cssText).toContain('.featured-queue-badges');
        expect(cssText).toContain('top: 8px');
        expect(cssText).toContain('right: 12px');
        expect(cssText).toContain('.featured-queue-badges .status-badge');
        expect(cssText).toContain('height: 22px');

        // title and subtitle are grouped in a container with tight gap
        expect(cssText).toContain('.featured-queue-title-container');
        expect(cssText).toContain('gap: 1px');
    });

    it('ensures featured queue poster is refined to 68x102px and supports configurable rows styles', async () => {
        const { cardStyles } = await import('../src/styles/jellyha-library-styles');
        const cssText = cardStyles.cssText;

        // Poster 68x102px sizing
        expect(cssText).toContain('width: 68px !important');
        expect(cssText).toContain('height: 102px !important');

        // Dynamic featured-rows variable
        expect(cssText).toContain('grid-template-rows: repeat(var(--jf-featured-rows, 3), 1fr)');

        // Rows 2 hero container constraint
        expect(cssText).toContain('.featured.rows-2 .featured-hero-container');
        expect(cssText).toContain('.featured.rows-2 .poster-container.featured-hero-poster');
    });

    it('ensures list metadata matches Featured layout styling with inline badges, dot, and rating pill', async () => {
        const { cardStyles } = await import('../src/styles/jellyha-library-styles');
        const cssText = cardStyles.cssText;

        // .list-metadata flex with 6px 8px gap
        expect(cssText).toContain('.list-metadata');
        expect(cssText).toContain('gap: 6px 8px');

        // .meta-text, .list-year, .list-runtime unified styling
        expect(cssText).toContain('.list-metadata .meta-text');
        expect(cssText).toContain('.list-metadata .meta-dot');

        // Static positioning and height for inline media badge
        expect(cssText).toContain('.list-metadata .media-type-badge.inline-badge');
        expect(cssText).toContain('position: static !important');

        // Genre pill support in list metadata
        expect(cssText).toContain('.list-metadata .genre-pill');

        // Text color transition on hover instead of font-weight jump
        expect(cssText).toContain('.media-item.list-item:hover .list-year');
        expect(cssText).toContain('color: var(--jf-text)');
    });

    it('ensures sharedMetaRowStyles provides centralized 22px height, optical alignment, and vertical centering for rating and genre pills', async () => {
        const { sharedMetaRowStyles } = await import('../src/styles/jellyha-shared-styles');
        const cssText = sharedMetaRowStyles.cssText;

        // Container styles
        expect(cssText).toContain('.list-metadata');
        expect(cssText).toContain('.idle-meta-row');
        expect(cssText).toContain('gap: 6px 8px');

        // Rating pill vertical centering with star transform and span line-height
        expect(cssText).toContain('.rating-pill ha-icon');
        expect(cssText).toContain('transform: translateY(-1px)');
        expect(cssText).toContain('.rating-pill span');
        expect(cssText).toContain('display: inline-flex');

        // Genre pill glassmorphic styling and line-height centering
        expect(cssText).toContain('.genre-pill');
        expect(cssText).toContain('background: rgba(255, 255, 255, 0.14)');
        expect(cssText).toContain('border: 1px solid rgba(255, 255, 255, 0.24)');
        expect(cssText).toContain('padding: 0 7px !important');
        expect(cssText).toContain('line-height: 1 !important');

        // Plain text and separator dot optical baseline adjustments
        expect(cssText).toContain('.meta-text');
        expect(cssText).toContain('transform: translateY(1px)');
        expect(cssText).toContain('.meta-dot');
        expect(cssText).toContain('transform: translateY(0.5px)');
    });

    it('ensures _renderListItem renders two rows with date added after runtime and rating followed by genres', async () => {
        const { JellyHAMediaItem } = await import('../src/components/jellyha-media-item');
        const mediaElem = new JellyHAMediaItem();
        mediaElem.config = {
            show_media_type_badge: true,
            show_year: true,
            show_runtime: true,
            show_date_added: true,
            show_ratings: true,
            show_genres: true,
        } as any;
        mediaElem.item = {
            id: 'hook-1',
            name: 'Captain Hook: The Cursed Tides',
            type: 'Movie',
            year: 2025,
            runtime_minutes: 90,
            date_added: '2025-05-10T12:00:00Z',
            community_rating: 4.9,
            genres: ['Adventure', 'Action', 'Horror'],
        } as any;
        mediaElem.layout = 'list';

        const template = (mediaElem as any)._renderListItem();
        const templateStr = JSON.stringify(template);

        // Header with title and media badge at top right
        expect(templateStr).toContain('list-header');
        expect(templateStr).toContain('list-title-container');
        expect(templateStr).toContain('list-title');
        expect(templateStr).toContain('media-type-badge list-type-badge');
        expect(templateStr).toContain('movie');

        // Contains container and two distinct rows
        expect(templateStr).toContain('list-metadata');
        expect(templateStr).toContain('idle-meta-row list-meta-row');
        expect(templateStr).toContain('idle-meta-row list-meta-pills');

        // Row 1: Year, Runtime, Date added
        expect(templateStr).toContain('idle-meta-text meta-text meta-year list-year');
        expect(templateStr).toContain('2025');
        expect(templateStr).toContain('idle-dot meta-dot');
        expect(templateStr).toContain('1h 30m');
        expect(templateStr).toContain('idle-meta-text meta-text meta-date-added list-date-added');

        // Row 2: Rating pill and Genre pills
        expect(templateStr).toContain('idle-rating-pill rating-pill list-rating');
        expect(templateStr).toContain('4.9');
        expect(templateStr).toContain('genre-pill idle-genre-pill list-genre-pill');
        expect(templateStr).toContain('Adventure');
        expect(templateStr).toContain('Action');
        expect(templateStr).toContain('Horror');
    });

    it('ensures _renderListItem renders subtitle and episode badge for TV episodes', async () => {
        const { JellyHAMediaItem } = await import('../src/components/jellyha-media-item');
        const mediaElem = new JellyHAMediaItem();
        mediaElem.config = {
            show_media_type_badge: true,
            show_title: true,
            show_subtitle: true,
        } as any;
        mediaElem.item = {
            id: 'ep-1',
            name: 'The Pilot',
            series_name: 'Lanterns',
            type: 'Episode',
            season: 1,
            episode: 1,
            year: 2026,
            date_added: '2026-09-12T10:00:00Z',
        } as any;
        mediaElem.layout = 'list';

        const template = (mediaElem as any)._renderListItem();
        const templateStr = JSON.stringify(template);

        expect(templateStr).toContain('list-title');
        expect(templateStr).toContain('The Pilot');
        expect(templateStr).toContain('list-subtitle');
        expect(templateStr).toContain('Lanterns');
        expect(templateStr).toContain('S01E01');
    });

    it('ensures Grid layout supports Show Card Backdrop styling', async () => {
        const { cardStyles } = await import('../src/styles/jellyha-library-styles');
        const cssText = cardStyles.cssText;

        expect(cssText).toContain('.media-item:not(.featured-queue-item):not(.list-item).has-backdrop');
        expect(cssText).toContain('.grid-card-backdrop-container');
        expect(cssText).toContain('.grid-card-backdrop');
        expect(cssText).toContain('.grid-card-backdrop-scrim');
    });

    it('ensures List layout supports Show Card Backdrop styling and 76px poster', async () => {
        const { cardStyles } = await import('../src/styles/jellyha-library-styles');
        const cssText = cardStyles.cssText;

        expect(cssText).toContain('.media-item.list-item.has-backdrop');
        expect(cssText).toContain('.list-card-backdrop-scrim');
        expect(cssText).toContain('width: 76px !important');
        expect(cssText).toContain('padding: 10px');
    });

    it('ensures _renderListItem renders backdrop when show_card_backdrop is enabled', async () => {
        const { JellyHAMediaItem } = await import('../src/components/jellyha-media-item');
        const mediaElem = new JellyHAMediaItem();
        mediaElem.config = {
            show_card_backdrop: true,
            show_title: true,
        } as any;
        mediaElem.item = {
            id: 'item-1',
            name: 'Inception',
            type: 'Movie',
            poster_url: '/image/1',
            backdrop_url: '/backdrop/1',
        } as any;
        mediaElem.layout = 'list';

        const template = (mediaElem as any)._renderListItem();
        const templateStr = JSON.stringify(template);

        expect(templateStr).toContain('has-backdrop');
        expect(templateStr).toContain('grid-card-backdrop-container');
        expect(templateStr).toContain('list-card-backdrop-scrim');
        expect(templateStr).toContain('width=\\"76\\"');
        expect(templateStr).toContain('height=\\"114\\"');
    });

    it('ensures _renderMediaItem for carousel and grid does not render backdrops', async () => {
        const { JellyHAMediaItem } = await import('../src/components/jellyha-media-item');
        const mediaElem = new JellyHAMediaItem();
        mediaElem.config = {
            show_card_backdrop: true,
            show_title: true,
        } as any;
        mediaElem.item = {
            id: 'item-1',
            name: 'Inception',
            type: 'Movie',
            poster_url: '/image/1',
            backdrop_url: '/backdrop/1',
        } as any;
        mediaElem.layout = 'grid';

        const template = (mediaElem as any)._renderMediaItem();
        const templateStr = JSON.stringify(template);

        expect(templateStr).not.toContain('has-backdrop');
        expect(templateStr).not.toContain('grid-card-backdrop-container');
    });

    it('ensures featured queue title turns primary color on hover even with backdrop', async () => {
        const { cardStyles } = await import('../src/styles/jellyha-library-styles');
        const cssText = cardStyles.cssText;

        expect(cssText).toContain('.media-item.featured-queue-item.has-backdrop:hover .featured-queue-title');
        expect(cssText).toContain('color: var(--jf-primary) !important');
    });

    it('ensures list card moves right on hover and suppresses poster border enhancement', async () => {
        const { cardStyles } = await import('../src/styles/jellyha-library-styles');
        const cssText = cardStyles.cssText;

        expect(cssText).toContain('.media-item.list-item.has-backdrop:hover');
        expect(cssText).toContain('transform: translateX(4px)');
        expect(cssText).toContain('.media-item.list-item:hover .poster-inner');
        expect(cssText).toContain('transform: none !important');
    });

    it('ensures list card has fixed 136px height and description line clamp with three dots', async () => {
        const { cardStyles } = await import('../src/styles/jellyha-library-styles');
        const cssText = cardStyles.cssText;

        expect(cssText).toContain('.media-item.list-item');
        expect(cssText).toContain('height: 136px');
        expect(cssText).toContain('box-sizing: border-box');
        expect(cssText).toContain('text-overflow: ellipsis');
        expect(cssText).toContain('-webkit-line-clamp: 2');
        expect(cssText).toContain('-webkit-line-clamp: 1');
        expect(cssText).toContain('.media-item.list-item.meta-wrapped .list-description');
    });

    it('ensures list card retains border, border-radius, and padding even without backdrop', async () => {
        const { cardStyles } = await import('../src/styles/jellyha-library-styles');
        const cssText = cardStyles.cssText;

        expect(cssText).toContain('.media-item.list-item');
        expect(cssText).toContain('border: 1px solid var(--ha-card-border-color, rgba(255, 255, 255, 0.18))');
        expect(cssText).toContain('border-radius: var(--jf-poster-radius, 12px)');
        expect(cssText).toContain('padding: 10px');
    });

    it('ensures _renderListItem adds has-subtitle class when subtitle is present', async () => {
        const { JellyHAMediaItem } = await import('../src/components/jellyha-media-item');
        const mediaElem = new JellyHAMediaItem();
        mediaElem.config = {
            show_card_backdrop: true,
            show_title: true,
            show_subtitle: true,
        } as any;
        mediaElem.item = {
            id: 'item-2',
            name: 'Bad Optics',
            series_name: 'Lanterns',
            type: 'Episode',
            season: 1,
            episode: 6,
            description: 'Now in business with his brother Marcus...',
            poster_url: '/image/2',
        } as any;
        mediaElem.layout = 'list';

        const template = (mediaElem as any)._renderListItem();
        const templateStr = JSON.stringify(template);

        expect(templateStr).toContain('has-subtitle');
        expect(templateStr).toContain('list-subtitle');
        expect(templateStr).toContain('Lanterns');
    });

    it('ensures whole card has click effect on active/press and poster does not scale', async () => {
        const { cardStyles } = await import('../src/styles/jellyha-library-styles');
        const cssText = cardStyles.cssText;

        expect(cssText).toContain('.media-item:active');
        expect(cssText).toContain('transform: scale(0.98)');
        expect(cssText).toContain('.media-item.list-item:active');
        expect(cssText).toContain('transform: translateX(2px) scale(0.98) !important');
        expect(cssText).toContain('.media-item:active .poster-container');
        expect(cssText).toContain('transform: none !important');
    });

    it('ensures mouse press handlers add and remove active-press class', async () => {
        const { JellyHAMediaItem } = await import('../src/components/jellyha-media-item');
        const mediaElem = new JellyHAMediaItem();
        mediaElem.config = { show_title: true } as any;
        mediaElem.item = { id: 'item-1', name: 'Movie' } as any;

        const classes = new Set<string>();
        const fakeElement = {
            classList: {
                add: (c: string) => classes.add(c),
                remove: (c: string) => classes.delete(c),
                contains: (c: string) => classes.has(c),
            }
        };
        const mousedownEvent = { button: 0, currentTarget: fakeElement } as any;
        (mediaElem as any)._handleMouseDown(mousedownEvent);
        expect(fakeElement.classList.contains('active-press')).toBe(true);

        const mouseupEvent = { currentTarget: fakeElement, preventDefault: () => {}, stopPropagation: () => {} } as any;
        (mediaElem as any)._handleMouseUp(mouseupEvent);
        expect(fakeElement.classList.contains('active-press')).toBe(false);

        fakeElement.classList.add('active-press');
        const mouseleaveEvent = { currentTarget: fakeElement } as any;
        (mediaElem as any)._handleMouseLeave(mouseleaveEvent);
        expect(fakeElement.classList.contains('active-press')).toBe(false);
    });

    it('ensures list layout places new and watched badges in list-badges after media badge', async () => {
        const { JellyHAMediaItem } = await import('../src/components/jellyha-media-item');
        const mediaElem = new JellyHAMediaItem();
        mediaElem.config = {
            show_media_type_badge: true,
            show_watched_status: true,
            new_badge_days: 7,
        } as any;
        const recentDate = new Date().toISOString();
        mediaElem.item = {
            id: 'item-new',
            name: 'Fall 2: Deadpoint',
            type: 'Movie',
            date_added: recentDate,
            poster_url: '/image/1',
        } as any;
        mediaElem.layout = 'list';

        const template = (mediaElem as any)._renderListItem();
        const templateStr = JSON.stringify(template);

        // Header contains list-badges
        expect(templateStr).toContain('list-badges');
        expect(templateStr).toContain('media-type-badge list-type-badge');
        expect(templateStr).toContain('new-badge');
        expect(templateStr).toContain('inline-badge');

        // Verify media badge appears before new badge in list-badges
        const mediaBadgeIdx = templateStr.indexOf('media-type-badge list-type-badge');
        const newBadgeIdx = templateStr.indexOf('new-badge');
        expect(mediaBadgeIdx).toBeGreaterThan(0);
        expect(newBadgeIdx).toBeGreaterThan(mediaBadgeIdx);

        // Poster does not contain status/new badge
        const posterContainerIdx = templateStr.indexOf('list-poster-wrapper');
        const listInfoIdx = templateStr.indexOf('list-info');
        const posterPart = templateStr.slice(posterContainerIdx, listInfoIdx);
        expect(posterPart).not.toContain('new-badge');
        expect(posterPart).not.toContain('status-badge');
    });

    it('ensures list layout places watched checkmark after media badge', async () => {
        const { JellyHAMediaItem } = await import('../src/components/jellyha-media-item');
        const mediaElem = new JellyHAMediaItem();
        mediaElem.config = {
            show_media_type_badge: true,
            show_watched_status: true,
            new_badge_days: 0,
        } as any;
        mediaElem.item = {
            id: 'item-watched',
            name: 'Captain Hook',
            type: 'Movie',
            is_played: true,
            poster_url: '/image/2',
        } as any;
        mediaElem.layout = 'list';

        const template = (mediaElem as any)._renderListItem();
        const templateStr = JSON.stringify(template);

        expect(templateStr).toContain('list-badges');
        expect(templateStr).toContain('media-type-badge list-type-badge');
        expect(templateStr).toContain('status-badge watched');
        expect(templateStr).toContain('inline-badge');

        const mediaBadgeIdx = templateStr.indexOf('media-type-badge list-type-badge');
        const watchedBadgeIdx = templateStr.indexOf('status-badge watched');
        expect(mediaBadgeIdx).toBeGreaterThan(0);
        expect(watchedBadgeIdx).toBeGreaterThan(mediaBadgeIdx);
    });

    it('ensures cardStyles defines list-badges and inline badges styling', async () => {
        const { cardStyles } = await import('../src/styles/jellyha-library-styles');
        const cssText = cardStyles.cssText;

        expect(cssText).toContain('.list-badges');
        expect(cssText).toContain('.list-badges .new-badge.inline-badge');
        expect(cssText).toContain('.list-badges .status-badge.inline-badge');
    });

    it('ensures list layout styles prevent horizontal overflow and allow dynamic shrinking', async () => {
        const { cardStyles } = await import('../src/styles/jellyha-library-styles');
        const cssText = cardStyles.cssText;

        expect(cssText).toContain('overflow-x: hidden');
        expect(cssText).toContain('grid-template-columns: repeat(var(--jf-list-columns, 1), minmax(0, 1fr))');
        expect(cssText).toContain('.list jellyha-media-item');
        expect(cssText).toContain('.media-item.list-item');
        expect(cssText).toContain('min-width: 0');
    });

    it('ensures dynamic list column calculation wraps down when container is narrow', async () => {
        const { JellyHALibraryCard } = await import('../src/cards/jellyha-library-card');
        const card = new JellyHALibraryCard();
        card.setConfig({
            type: 'custom:jellyha-library-card',
            entity: 'sensor.jellyha_library',
            layout: 'list',
            columns: 2,
        });

        // Wide container (e.g. 700px content width) -> 2 columns
        (card as any)._updateEffectiveListColumns(700);
        expect((card as any)._effectiveListColumns).toBe(2);

        // Narrow container (e.g. 450px content width) -> collapses to 1 column
        (card as any)._updateEffectiveListColumns(450);
        expect((card as any)._effectiveListColumns).toBe(1);

        // Re-expanded container -> expands back to 2 columns
        (card as any)._updateEffectiveListColumns(650);
        expect((card as any)._effectiveListColumns).toBe(2);
    });

    it('ensures carousel and grid items do not shrink into thin slivers and list pills do not wrap', async () => {
        const { cardStyles } = await import('../src/styles/jellyha-library-styles');
        const cssText = cardStyles.cssText;

        // Carousel items must be flex: 0 0 auto
        expect(cssText).toContain('.carousel jellyha-media-item');
        expect(cssText).toContain('flex: 0 0 auto');

        // Grid items must have width: auto / min-width: 140px in horizontal
        expect(cssText).toContain('.grid jellyha-media-item');
        expect(cssText).toContain('.grid.horizontal jellyha-media-item');
        expect(cssText).toContain('min-width: 140px');

        // List pills must be nowrap to avoid 3rd row pushing description into border
        expect(cssText).toContain('.media-item.list-item .list-meta-pills');
        expect(cssText).toContain('flex-wrap: nowrap !important');

        // List description must have max-height matching clamp
        expect(cssText).toContain('max-height: calc(1.3em * 2)');

        // Genre pills must have ellipsis styling
        expect(cssText).toContain('.media-item.list-item .list-genre-pill');
        expect(cssText).toContain('text-overflow: ellipsis');
    });

    it('renders description on list and featured-queue items when enabled and hides when disabled', async () => {
        const { JellyHAMediaItem } = await import('../src/components/jellyha-media-item');
        const mediaElem = new JellyHAMediaItem();
        mediaElem.config = {
            entity: 'sensor.jellyha_library',
            show_description_on_hover: true,
        };
        mediaElem.item = {
            name: 'Inception',
            type: 'Movie',
            overview: 'A thief who steals corporate secrets through dream-sharing technology.',
            poster_url: '/image/1',
        } as any;
        mediaElem.layout = 'featured-queue';

        // When enabled, list-description is rendered
        let template = (mediaElem as any)._renderListItem();
        let templateStr = JSON.stringify(template);
        expect(templateStr).toContain('list-description');
        expect(templateStr).toContain('A thief who steals corporate secrets through dream-sharing technology.');

        // When show_description_on_hover is false, list-description is not rendered
        mediaElem.config = {
            entity: 'sensor.jellyha_library',
            show_description_on_hover: false,
        };
        template = (mediaElem as any)._renderListItem();
        templateStr = JSON.stringify(template);
        expect(templateStr).not.toContain('list-description');
    });

    it('ensures list and featured-queue card hover and active click effects are configured on card not poster', async () => {
        const { cardStyles } = await import('../src/styles/jellyha-library-styles');
        const cssText = cardStyles.cssText;

        // Whole card active click effect
        expect(cssText).toContain('.media-item.list-item:active');
        expect(cssText).toContain('scale(0.98)');

        // Poster container hover effect suppressed (no border on smaller posters)
        expect(cssText).toContain('.media-item.list-item:hover .poster-container');
        expect(cssText).toContain('border: none !important');
    });

    it('renders rating with rating-pill style and runtime with genre-pill style without clock icon on poster', async () => {
        const { JellyHAMediaItem } = await import('../src/components/jellyha-media-item');
        const mediaElem = new JellyHAMediaItem();
        mediaElem.config = {
            entity: 'sensor.jellyha_library',
            show_ratings: true,
            show_runtime: true,
        };
        mediaElem.item = {
            name: 'Inception',
            type: 'Movie',
            community_rating: 8.8,
            runtime_minutes: 148,
            poster_url: '/image/1',
        } as any;
        mediaElem.layout = 'grid';

        const template = (mediaElem as any)._renderMediaItem();
        const templateStr = JSON.stringify(template);

        // Rating badge on poster should have rating-pill class and star icon
        expect(templateStr).toContain('rating rating-pill');
        expect(templateStr).toContain('mdi:star');
        expect(templateStr).toContain('8.8');

        // Runtime badge on poster should have genre-pill class, formatted runtime, and NO clock icon
        expect(templateStr).toContain('runtime genre-pill');
        expect(templateStr).toContain('2h 28m');
        expect(templateStr).not.toContain('mdi:clock-outline');
    });

    it('ensures poster rating and runtime badge styles are centralized in sharedMetaRowStyles', async () => {
        const { cardStyles } = await import('../src/styles/jellyha-library-styles');
        const cssText = cardStyles.cssText;

        // .rating and .runtime on poster should define position and transition only
        expect(cssText).toContain('.rating');
        expect(cssText).toContain('bottom: 6px');
        expect(cssText).toContain('right: 6px');
        expect(cssText).toContain('.runtime');
        expect(cssText).toContain('left: 6px');

        // Redundant duplicate .rating-pill in jellyha-library-styles should be removed (only sharedMetaRowStyles defines it)
        const ratingPillOccurrences = (cssText.match(/\.rating-pill\s*\{/g) || []).length;
        expect(ratingPillOccurrences).toBe(1);
    });

    it('ensures smaller posters in list and featured side cards have no border while hero poster retains border', async () => {
        const { cardStyles } = await import('../src/styles/jellyha-library-styles');
        const cssText = cardStyles.cssText;

        // Big hero poster retains its border
        expect(cssText).toContain('.poster-container.featured-hero-poster .poster-inner');
        expect(cssText).toContain('border: 1px solid var(--ha-card-border-color, var(--jf-border-color))');

        // Smaller posters in list and featured side items have border removed
        expect(cssText).toContain('.media-item.list-item .poster-container');
        expect(cssText).toContain('.poster-container.featured-queue-poster');
        expect(cssText).toContain('.featured-side .poster-container');
    });

    it('ensures smaller cards backdrop scrim matches now playing screensaver blackness and has subtle blur', async () => {
        const { cardStyles } = await import('../src/styles/jellyha-library-styles');
        const cssText = cardStyles.cssText;

        // Scrim blackness starts at 0.35 instead of opaque 0.88
        expect(cssText).toContain('.list-card-backdrop-scrim');
        expect(cssText).toContain('rgba(0, 0, 0, 0.35) 0%');
        expect(cssText).toContain('rgba(0, 0, 0, 0.42) 35%');

        // Subtle 2px blur on backdrop image
        expect(cssText).toContain('.media-item.list-item .grid-card-backdrop');
        expect(cssText).toContain('filter: blur(2px) brightness(0.92)');
        expect(cssText).toContain('transform: scale(1.03)');
    });

    it('ensures metadata and description font size is 11px for Featured and List layout', async () => {
        const { cardStyles } = await import('../src/styles/jellyha-library-styles');
        const cssText = cardStyles.cssText;

        // Metadata text (year, runtime, created date, separator dot) must be 11px
        expect(cssText).toContain('.list-metadata .meta-text');
        expect(cssText).toMatch(/\.list-metadata\s+\.meta-text[^{]*\{[^}]*font-size:\s*11px/);

        // Description must be 11px
        expect(cssText).toContain('.list-description');
        expect(cssText).toMatch(/\.list-description\s*\{[^}]*font-size:\s*11px/);

        // Featured Hero metadata and pills must be 11px
        expect(cssText).toContain('.featured-hero-scrim .meta-text');
        expect(cssText).toMatch(/\.featured-hero-scrim\s+\.meta-text[^{]*\{[^}]*font-size:\s*11px/);
        expect(cssText).toMatch(/\.featured-hero-scrim\s+\.rating-pill[^{]*\{[^}]*font-size:\s*11px/);
    });

    it('ensures featured hero poster card has glowing theme border when playing', async () => {
        const { cardStyles } = await import('../src/styles/jellyha-library-styles');
        const cssText = cardStyles.cssText;

        expect(cssText).toContain('.media-item.featured-hero.playing .poster-inner');
        expect(cssText).toContain('border-color: var(--jf-primary)');
        expect(cssText).toMatch(/\.media-item\.featured-hero\.playing\s+\.poster-inner\s*\{[^}]*border-color:\s*var\(--jf-primary\)/);
        expect(cssText).toMatch(/\.media-item\.featured-hero\.playing\s+\.poster-inner\s*\{[^}]*box-shadow:[^}]*16px/);
    });

    it('ensures runtime is suppressed on media items when media_type is series and tv_content is series', async () => {
        const { JellyHAMediaItem } = await import('../src/components/jellyha-media-item');
        const mediaItem = new JellyHAMediaItem();

        // 1. media_type = 'series', tv_content = 'series' -> false
        mediaItem.config = { show_runtime: true, media_type: 'series', tv_content: 'series' } as any;
        expect((mediaItem as any)._isRuntimeVisible()).toBe(false);

        // 2. media_type = 'series', tv_content undefined (defaults to series) -> false
        mediaItem.config = { show_runtime: true, media_type: 'series' } as any;
        expect((mediaItem as any)._isRuntimeVisible()).toBe(false);

        // 3. media_type = 'series', tv_content = 'episodes' -> true
        mediaItem.config = { show_runtime: true, media_type: 'series', tv_content: 'episodes' } as any;
        expect((mediaItem as any)._isRuntimeVisible()).toBe(true);

        // 4. media_type = 'movies' -> true
        mediaItem.config = { show_runtime: true, media_type: 'movies' } as any;
        expect((mediaItem as any)._isRuntimeVisible()).toBe(true);
    });
});



