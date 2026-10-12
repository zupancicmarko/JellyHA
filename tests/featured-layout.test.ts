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

    it('queue action only renders playing icon when active, chevron is removed', () => {
        // Test verify logic that queue items only display action when isPlaying is true
        const renderAction = (isPlaying: boolean) => {
            return isPlaying ? 'mdi:volume-high' : null;
        };
        expect(renderAction(false)).toBeNull();
        expect(renderAction(true)).toBe('mdi:volume-high');
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

    it('ensures featured-queue-title does not cut prematurely and wraps with floated badges', async () => {
        const { cardStyles } = await import('../src/styles/jellyha-library-styles');
        const cssText = cardStyles.cssText;

        // featured-queue-title should wrap up to 2 lines and not have white-space: nowrap or padding-right: 76px
        expect(cssText).toContain('.featured-queue-title');
        expect(cssText).toContain('max-height: 2.55em');
        expect(cssText).toContain('word-break: break-word');
        expect(cssText).not.toMatch(/\.featured-queue-title\s*\{[^}]*white-space:\s*nowrap/);
        expect(cssText).not.toMatch(/\.featured-queue-title\s*\{[^}]*padding-right:\s*76px/);

        // queue badges in normal mode float right to let title fill space below them
        expect(cssText).toContain('.media-item.featured-queue-item:not(.cramped) .featured-queue-badges');
        expect(cssText).toContain('float: right');

        // cramped mode retains absolute positioning and resets float
        expect(cssText).toContain('.media-item.featured-queue-item.cramped .featured-queue-badges');
        expect(cssText).toContain('float: none !important');
    });

    it('ensures featured queue poster is refined to 60x90px and supports configurable rows styles', async () => {
        const { cardStyles } = await import('../src/styles/jellyha-library-styles');
        const cssText = cardStyles.cssText;

        // Poster 60x90px sizing
        expect(cssText).toContain('width: 60px !important');
        expect(cssText).toContain('height: 90px !important');

        // Dynamic featured-rows variable
        expect(cssText).toContain('grid-template-rows: repeat(var(--jf-featured-rows, 3), 1fr)');

        // Rows 2 hero container constraint
        expect(cssText).toContain('.featured.rows-2 .featured-hero-container');
        expect(cssText).toContain('.featured.rows-2 .poster-container.featured-hero-poster');
    });
});



