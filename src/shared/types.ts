/**
 * Type definitions for JellyHA Library Card
 */

// Home Assistant types
export interface HomeAssistant {
    states: Record<string, HassEntity>;
    language: string;
    callService: (domain: string, service: string, data?: Record<string, unknown>) => Promise<void>;
}

export interface HassEntity {
    entity_id: string;
    state: string;
    attributes: Record<string, unknown>;
    last_changed: string;
    last_updated: string;
}

export interface LovelaceCard extends HTMLElement {
    hass?: HomeAssistant;
    setConfig(config: LovelaceCardConfig): void;
    getCardSize?(): number;
}

export interface LovelaceCardConfig {
    type: string;
    [key: string]: unknown;
}

export interface MediaItem {
    id: string;
    name: string;
    type: 'Movie' | 'Series';
    year?: number;
    runtime_minutes?: number;
    genres: string[];
    rating?: number;
    rating_imdb?: string;
    rating_tmdb?: string;
    description?: string;
    poster_url: string;
    backdrop_url: string;
    date_added: string;
    jellyfin_url: string;
}

export interface JellyHALibraryCardConfig extends LovelaceCardConfig {
    entity: string;
    title?: string;
    layout?: 'carousel' | 'grid' | 'list';
    media_type?: 'movies' | 'series' | 'both';
    items_per_page?: number;
    max_pages?: number;
    auto_swipe_interval?: number; // seconds, 0 = disabled
    columns?: number;
    show_title?: boolean;
    show_year?: boolean;
    show_runtime?: boolean;
    show_ratings?: boolean;
    show_media_type_badge?: boolean;
    show_description_on_hover?: boolean;
    show_genres?: boolean;
    show_date_added?: boolean;
    show_pagination?: boolean;
    metadata_position?: 'above' | 'below';
    rating_source?: 'auto' | 'imdb' | 'tmdb';
    new_badge_days?: number;
    horizontal_alignment?: 'left' | 'center';
    click_action?: 'jellyfin' | 'more-info' | 'none';
    image_quality?: number;
    image_height?: number;
    theme?: 'auto' | 'light' | 'dark';
}

export interface SensorData {
    items: MediaItem[];
    count: number;
    server_name: string;
    last_updated: string;
}

// Card registration info
export interface CustomCardInfo {
    type: string;
    name: string;
    description: string;
    preview: boolean;
}

// Declare custom elements
declare global {
    interface HTMLElementTagNameMap {
        'ha-card': HTMLElement;
        'ha-icon': HTMLElement;
        'ha-entity-picker': HTMLElement;
        'ha-textfield': HTMLInputElement;
        'ha-select': HTMLSelectElement;
        'ha-switch': HTMLInputElement;
        'ha-slider': HTMLInputElement;
        'mwc-list-item': HTMLElement;
    }
}
