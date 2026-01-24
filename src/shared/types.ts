/**
 * Type definitions for JellyHA Library Card
 */

// Home Assistant types
export interface HomeAssistant {
    states: Record<string, HassEntity>;
    language: string;
    themes?: {
        darkMode: boolean;
        selectedTheme?: string;
    };
    callService: (domain: string, service: string, data?: Record<string, unknown>) => Promise<void>;
    callWS: <T>(msg: Record<string, unknown>) => Promise<T>;
    locale?: {
        language: string;
        number_format?: string;
        time_format?: string;
    };
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
    is_played?: boolean;
    unplayed_count?: number;
    is_favorite?: boolean;
    media_streams?: Record<string, any>[];
    official_rating?: string;
    season?: number;
    episode?: number;
    trailer_url?: string;
    last_played_date?: string;
    series_name?: string;
}

export interface JellyHALibraryCardConfig extends LovelaceCardConfig {
    entity: string;
    title?: string;
    layout?: 'carousel' | 'grid' | 'list';
    media_type?: 'movies' | 'series' | 'next_up' | 'both';
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
    show_watched_status?: boolean;
    enable_pagination?: boolean;
    show_pagination_dots?: boolean;
    metadata_position?: 'above' | 'below';
    rating_source?: 'auto' | 'imdb' | 'tmdb';
    new_badge_days?: number;
    horizontal_alignment?: 'left' | 'center';
    click_action?: 'jellyfin' | 'more-info' | 'cast' | 'trailer' | 'none';
    hold_action?: 'jellyfin' | 'more-info' | 'cast' | 'trailer' | 'none';
    default_cast_device?: string;
    show_now_playing?: boolean;
    image_quality?: number;
    image_height?: number;
    theme?: 'auto' | 'light' | 'dark';
    filter_favorites?: boolean;
    status_filter?: 'all' | 'watched' | 'unwatched';
    filter_newly_added?: boolean;
    sort_option?: 'date_added_asc' | 'date_added_desc' | 'title_asc' | 'title_desc' | 'year_asc' | 'year_desc' | 'last_played_asc' | 'last_played_desc';
}

export interface SensorData {
    // items: MediaItem[]; // Removed in favor of WebSocket
    entry_id: string;
    count: number;
    server_name: string;
    last_updated: string;
}

export interface NowPlayingSensorData {
    user_id: string;
    session_id?: string;
    device_name?: string;
    client?: string;
    item_id?: string;
    title?: string;
    series_title?: string;
    season?: number;
    episode?: number;
    year?: number;
    progress_percent?: number;
    position_ticks?: number;
    image_url?: string;
    media_type?: string;
    icon?: string;
    is_paused?: boolean;
    official_rating?: string;
    runtime_minutes?: number;
    genres?: string[];
    backdrop_url?: string;
    community_rating?: number;
    critic_rating?: number;
}

export interface JellyHANowPlayingCardConfig extends LovelaceCardConfig {
    entity: string;
    title?: string;
    show_title?: boolean;
    show_media_type_badge?: boolean;
    show_ratings?: boolean;
    show_runtime?: boolean;
    show_genres?: boolean;
    show_year?: boolean;
    show_client?: boolean;
    show_background?: boolean;
    show_description?: boolean;
    theme?: 'auto' | 'light' | 'dark';
}

// Card registration info
export interface CustomCardInfo {
    type: string;
    name: string;
    description: string;
    preview: boolean;
}

declare global {
    interface Window {
        customCards: CustomCardInfo[];
    }
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
