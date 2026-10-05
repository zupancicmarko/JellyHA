import { LitElement, html, TemplateResult, css, PropertyValues, nothing } from 'lit';
import { customElement, property, state } from 'lit/decorators.js';
import {
    HomeAssistant,
    HassEntity,
    JellyHANowPlayingCardConfig,
    NowPlayingSensorData,
    MediaItem
} from '../shared/types';
import { localize } from '../shared/localize';
import { formatRuntime, addImageParams } from '../shared/utils';

// Import editor for side effects
import '../editors/jellyha-now-playing-editor';

// Register card in the custom cards array
window.customCards = window.customCards || [];
if (!window.customCards.some(card => card.type === 'jellyha-now-playing-card')) {
    window.customCards.push({
        type: 'jellyha-now-playing-card',
        name: 'JellyHA Now Playing',
        description: 'Display currently playing media from Jellyfin',
        preview: true,
    });
}

@customElement('jellyha-now-playing-card')
export class JellyHANowPlayingCard extends LitElement {
    @property({ attribute: false }) public hass!: HomeAssistant;
    @state() private _config!: JellyHANowPlayingCardConfig;
    @state() private _rewindActive: boolean = false;
    @state() private _overflowState: number = 0; // 0=All, 1=Hide line3/4, 2=Hide all text
    @state() private _dominantColor: string = 'var(--primary-color)';
    @state() private _longPressProgress: number = 0;
    @state() private _stopPulse: boolean = false;
    @state() private _isDragging: boolean = false;
    @state() private _dragPercentage: number = 0;
    @state() private _optimisticSeekPercent: number | null = null;
    @state() private _idleItems: MediaItem[] = [];
    @state() private _currentIdleIndex: number = 0;
    @state() private _prevIdleIndex: number | null = null;
    @state() private _idleFadeOut: boolean = false;
    private _idleTimer?: number;
    private _fetchingIdleItems: boolean = false;
    private _visibilityHandler?: () => void;
    private _optimisticSeekTimer?: number;
    private _longPressRaf: number | null = null;
    private _longPressConsumed: boolean = false;
    private _resizeObserver?: ResizeObserver;
    private _layoutCheckRaf: number | null = null;
    private _progressTimer?: number;

    private _cachedBackdropUrl: string | undefined;
    private _cachedItemId: string | undefined;
    private _cachedColorItemId: string | undefined;
    private _optimisticFavorites: Record<string, boolean> = {};
    private _resolvedImages: Record<string, { seriesImageUrl?: string; episodeImageUrl?: string }> = {};
    private _fetchingImageKey: string | null = null;
    private _resolvedMetadata: Record<string, any> = {};
    private _fetchingMetadataId: string | null = null;

    public setConfig(config: JellyHANowPlayingCardConfig): void {
        this._config = {
            show_title: true,
            show_subtitle: true,
            show_media_type_badge: true,
            badge_style: 'poster',
            show_year: true,
            show_client: true,
            show_device_name: false,
            show_user: true,
            show_time: false,
            show_background: true,
            show_genres: true,
            show_ratings: true,
            show_runtime: true,
            use_series_image: false,
            show_controls: true,
            idle_backdrop_cycle: false,
            idle_cycle_interval: 20,
            idle_display_mode: 'backdrop',
            idle_media_type: 'both',
            ...config,
        };
    }

    public static getConfigElement(): HTMLElement {
        return document.createElement('jellyha-now-playing-editor');
    }

    public static getStubConfig(hass: HomeAssistant): Partial<JellyHANowPlayingCardConfig> {
        const entities = Object.keys(hass.states);
        const entity = entities.find((e) => e.startsWith('media_player.jellyha_') && !e.includes('_library_browser') && !e.endsWith('_browser'))
            || entities.find((e) => e.startsWith('sensor.jellyha_now_playing_'))
            || '';
        return {
            entity,
            show_title: true,
            show_subtitle: true,
            show_media_type_badge: true,
            badge_style: 'poster',
            show_year: true,
            show_client: true,
            show_device_name: false,
            show_user: true,
            show_time: false,
            show_background: true,
            show_genres: true,
            show_ratings: true,
            show_runtime: true,
            use_series_image: false,
            show_controls: true,
            idle_backdrop_cycle: false,
            idle_cycle_interval: 20,
            idle_display_mode: 'backdrop',
            idle_media_type: 'both',
        };
    }

    public getCardSize(): number {
        return 3;
    }

    public getLayoutOptions() {
        return {
            grid_rows: 3,
            grid_columns: 12,
        };
    }

    public getGridOptions() {
        return {
            columns: 12,
            rows: 3,
            min_columns: 6,
            min_rows: 2,
            max_rows: 5
        };
    }

    protected render(): TemplateResult {
        if (!this.hass || !this._config) {
            return html``;
        }

        const entityId = this._config.entity;
        if (!entityId) {
            return this._renderError('Please configure a JellyHA Now Playing entity');
        }

        const stateObj = this.hass.states[entityId];
        if (!stateObj) {
            return this._renderError(localize(this.hass.locale?.language || this.hass.language, 'entity_not_found') || 'Entity not found');
        }

        const attributes = stateObj.attributes as unknown as NowPlayingSensorData;
        const isMediaPlayer = entityId.startsWith('media_player.');
        const isPlaying = isMediaPlayer
            ? (stateObj.state === 'playing' || stateObj.state === 'paused' || !!attributes.item_id)
            : !!attributes.item_id;

        if (!isPlaying) {
            if (this._config.idle_backdrop_cycle) {
                return this._renderIdleShowcase();
            }
            this._stopIdleTimer();
            return this._renderEmpty();
        }

        // Active playback: stop idle timer if it was running
        this._stopIdleTimer();

        // Extract Jellyfin item ID and enrich missing metadata for generic media players (like Chromecast)
        const itemId = this._extractItemId(stateObj);
        if (itemId && !this._resolvedMetadata[itemId] && (!attributes.community_rating || !attributes.year || !attributes.genres || !attributes.media_type)) {
            this._fetchMissingMetadata(itemId);
        }
        const cachedItem = itemId ? this._resolvedMetadata[itemId] : null;

        const durationSeconds = this._getDurationSeconds(stateObj);
        const currentPositionSeconds = this._getCurrentPositionSeconds(stateObj);

        let progressPercent = 0;
        if (this._optimisticSeekPercent !== null) {
            progressPercent = this._optimisticSeekPercent;
        } else if (durationSeconds > 0) {
            progressPercent = Math.min(100, Math.max(0, (currentPositionSeconds / durationSeconds) * 100));
        } else if (typeof attributes.progress_percent === 'number') {
            progressPercent = attributes.progress_percent;
        }

        const displayPositionSeconds = this._isDragging && durationSeconds > 0
            ? (this._dragPercentage / 100) * durationSeconds
            : (this._optimisticSeekPercent !== null && durationSeconds > 0)
                ? (this._optimisticSeekPercent / 100) * durationSeconds
                : currentPositionSeconds;

        // Resolve images (handling both Jellyfin entities and generic media players like Chromecast)
        const { seriesImageUrl, episodeImageUrl } = this._resolveImages(stateObj, cachedItem);

        // Use series image if configured and available, otherwise use episode/movie image
        const rawImageUrl = this._config.use_series_image && seriesImageUrl
            ? seriesImageUrl
            : (episodeImageUrl || attributes.image_url || (stateObj.attributes as any).entity_picture || cachedItem?.poster_url);
        const imageUrl = rawImageUrl;

        // Cache backdrop URL to prevent flicker - update when item or series image toggle changes
        const currentItemId = itemId || attributes.item_id || (stateObj.attributes as any).media_content_id;
        const backdropCacheKey = `${currentItemId}_${this._config.use_series_image ? 'series' : 'item'}`;
        if (backdropCacheKey !== this._cachedItemId) {
            this._cachedItemId = backdropCacheKey;
            const rawBackdropUrl = attributes.backdrop_url || cachedItem?.backdrop_url || rawImageUrl;
            this._cachedBackdropUrl = rawBackdropUrl ? addImageParams(rawBackdropUrl, 640) : undefined;
        }

        // Extract dominant color when item or series image toggle changes
        if (backdropCacheKey !== this._cachedColorItemId && imageUrl) {
            this._cachedColorItemId = backdropCacheKey;
            this._extractDominantColor(addImageParams(imageUrl, 80));
        }

        const backdropUrl = this._cachedBackdropUrl;
        const showBackground = this._config.show_background !== false && backdropUrl;
        const isPaused = isMediaPlayer ? stateObj.state === 'paused' : attributes.is_paused;

        const rawMediaType = attributes.media_type || (cachedItem?.type ? cachedItem.type : null) || (stateObj.attributes as any).media_content_type || '';
        const mediaType = rawMediaType.toLowerCase();
        const isMusic = mediaType === 'audio' || mediaType === 'music';

        let displayTitle = attributes.title || (stateObj.attributes as any).media_title || cachedItem?.name || '';
        const showSubtitle = this._config.show_subtitle !== false;
        const seriesTitle = attributes.series_title || (stateObj.attributes as any).media_series_title || cachedItem?.series_name || '';
        const subtitle = showSubtitle ? (attributes.artist_name || (stateObj.attributes as any).media_artist || seriesTitle || cachedItem?.artist_name || '') : '';

        const effectiveYear = attributes.year ?? cachedItem?.year;
        const yearStr = (this._config.show_year !== false && effectiveYear) ? String(effectiveYear) : '';

        const effectiveGenres = (attributes.genres && attributes.genres.length > 0) ? attributes.genres : (cachedItem?.genres || []);
        const genres = (this._config.show_genres !== false && effectiveGenres?.length) ? effectiveGenres.slice(0, 3) : [];
        const hasMetaLine = !!(yearStr || genres.length > 0);

        const effectiveUser = attributes.user_name || this.hass.user?.name || '';
        const userName = (this._config.show_user !== false) ? effectiveUser : '';

        const effectiveClient = attributes.client || (stateObj.attributes as any).app_name || (stateObj.attributes as any).friendly_name || '';
        const clientInfo = (this._config.show_client !== false) ? effectiveClient : '';
        const deviceInfo = (this._config.show_device_name === true) ? (attributes.device_name || '') : '';
        const sourceInfo = [...new Set([deviceInfo, clientInfo].filter(Boolean))].join(' · ');

        // Media type badge text
        const rawSeason = attributes.season !== undefined && attributes.season !== null ? attributes.season : ((stateObj.attributes as any).media_season !== undefined && (stateObj.attributes as any).media_season !== null ? (stateObj.attributes as any).media_season : cachedItem?.season);
        const rawEpisode = attributes.episode !== undefined && attributes.episode !== null ? attributes.episode : ((stateObj.attributes as any).media_episode !== undefined && (stateObj.attributes as any).media_episode !== null ? (stateObj.attributes as any).media_episode : cachedItem?.episode);
        const numSeason = Number(rawSeason);
        const numEpisode = Number(rawEpisode);
        const hasValidEp = rawSeason != null && rawEpisode != null && !isNaN(numSeason) && !isNaN(numEpisode) && numSeason >= 0 && numEpisode >= 0;
        const isEpisodeItem = (mediaType === 'episode' || mediaType === 'tvshow') && hasValidEp;
        const badgeText = isEpisodeItem
            ? `S${String(numSeason).padStart(2, '0')}E${String(numEpisode).padStart(2, '0')}`
            : (mediaType === 'movie' ? 'MOVIE' : (mediaType === 'episode' ? 'EPISODE' : (mediaType === 'tvshow' ? 'SERIES' : (attributes.media_type || cachedItem?.type || ''))));

        // Badge placement style (applies to both Movies and TV Shows; inline applies to TV Shows)
        const badgeStyle = this._config.badge_style || this._config.media_type_badge_style || 'poster';
        const showBadge = this._config.show_media_type_badge !== false && !!badgeText;

        let showPosterBadge = false;
        let showHeaderBadge = false;

        if (showBadge && badgeStyle !== 'none') {
            if (badgeStyle === 'poster') {
                showPosterBadge = true;
            } else if (badgeStyle === 'header') {
                showHeaderBadge = true;
            } else if (badgeStyle === 'inline') {
                if (isEpisodeItem) {
                    const epPrefix = `S${String(numSeason).padStart(2, '0')}E${String(numEpisode).padStart(2, '0')}`;
                    if (displayTitle && !displayTitle.toLowerCase().startsWith(epPrefix.toLowerCase())) {
                        displayTitle = `${epPrefix} • ${displayTitle}`;
                    } else if (!displayTitle) {
                        displayTitle = epPrefix;
                    }
                }
                // Movies and other media keep clean displayTitle without any prefix
            }
        }

        // Rating
        const communityRating = attributes.community_rating ?? cachedItem?.community_rating ?? cachedItem?.rating;

        // Determine effective favorite status using optimistic override if available
        const isFavorite = currentItemId && this._optimisticFavorites[currentItemId] !== undefined
            ? this._optimisticFavorites[currentItemId]
            : (attributes.is_favorite || cachedItem?.is_favorite || false);

        // SVG ring circumference for stop animation (r=20 => C=2*PI*20 ≈ 125.66)
        const ringCircumference = 125.66;
        const ringOffset = ringCircumference * (1 - this._longPressProgress);

        const supportsRemote = this._supportsRemote(stateObj);

        return html`
            <ha-card class="jellyha-now-playing ${showBackground ? 'has-background' : ''} ${this._config.title ? 'has-title' : ''}" style="--card-dominant-color: ${this._dominantColor};">
                ${showBackground ? html`
                    <div class="card-background" style="background-image: url('${backdropUrl}')"></div>
                    <div class="card-overlay"></div>
                ` : nothing}
                
                <div class="card-content">
                    ${this._config.title ? html`
                        <div class="card-header">${this._config.title}</div>
                    ` : nothing}
                    
                    <div class="main-container">
                        ${imageUrl ? html`
                            <div class="poster-container ${supportsRemote ? '' : 'no-rewind'}" @click=${supportsRemote ? this._handlePosterRewind : undefined}>
                                <img src="${addImageParams(imageUrl, 160)}" alt="${displayTitle}" loading="eager" fetchpriority="high" />
                                
                                ${showPosterBadge ? html`
                                    <span class="poster-badge media-type-badge ${mediaType}">${badgeText}</span>
                                ` : nothing}
                                ${this._config.show_ratings !== false && communityRating ? html`
                                    <span class="poster-badge rating-badge">
                                        <ha-icon icon="mdi:star"></ha-icon>
                                        ${Number(communityRating).toFixed(1)}
                                    </span>
                                ` : nothing}
                                ${this._config.show_runtime !== false && (attributes.runtime_minutes || durationSeconds > 0) ? html`
                                    <span class="poster-badge runtime-badge">
                                        <ha-icon icon="mdi:clock-outline"></ha-icon>
                                        ${mediaType === 'audio' && durationSeconds > 0
                        ? `${Math.floor(durationSeconds / 60)}m ${Math.floor(durationSeconds % 60)}s`
                        : formatRuntime(attributes.runtime_minutes || Math.round(durationSeconds / 60))}
                                    </span>
                                ` : nothing}

                                ${this._rewindActive ? html`
                                    <div class="rewind-overlay">
                                        <span>${localize(this.hass.locale?.language || this.hass.language, 'rewinding')}</span>
                                    </div>
                                ` : nothing}
                            </div>
                        ` : nothing}
                        
                        <div class="info-container">
                            <div class="info-top">
                                <div class="header">
                                    <div class="title-row">
                                        ${this._config.show_title !== false ? html`<div class="title">${displayTitle}</div>` : nothing}
                                        ${showHeaderBadge ? html`
                                            <span class="media-type-badge header-badge ${mediaType}">${badgeText}</span>
                                        ` : nothing}
                                    </div>
                                    ${this._overflowState < 3 && subtitle ? html`<div class="subtitle">${subtitle}</div>` : nothing}
                                    ${this._overflowState < 2 && hasMetaLine ? html`
                                        <div class="meta-line">
                                            ${yearStr ? html`<span class="meta-year">${yearStr}</span>` : nothing}
                                            ${yearStr && genres.length > 0 ? html`<span class="meta-dot">•</span>` : nothing}
                                            ${genres.map(g => html`<span class="genre-pill">${g}</span>`)}
                                        </div>
                                    ` : nothing}
                                    ${this._overflowState < 1 && (userName || sourceInfo) ? html`<div class="client-line">${userName ? html`<strong>${userName}</strong>` : nothing}${userName && sourceInfo ? ' · ' : ''}${sourceInfo || nothing}</div>` : nothing}
                                </div>
                            </div>

                            <div class="info-bottom">
                                ${supportsRemote && this._config.show_controls !== false ? html`
                                    <div class="playback-controls">
                                        ${isMusic ? html`
                                            <ha-icon-button class="music-subtle-btn ${isFavorite ? 'active' : ''}" .label=${'Favorite'} @click=${() => this._handleFavoriteToggle(attributes.item_id!, isFavorite)}>
                                                <ha-icon icon="${isFavorite ? 'mdi:heart' : 'mdi:heart-outline'}"></ha-icon>
                                            </ha-icon-button>
                                            <ha-icon-button .label=${localize(this.hass.locale?.language || this.hass.language, 'previous') || 'Previous'} @click=${() => this._handleControl('PreviousTrack')}>
                                                <ha-icon icon="mdi:skip-previous"></ha-icon>
                                            </ha-icon-button>
                                        ` : html`
                                            <ha-icon-button class="seek-btn" .label=${'Rewind 10s'} @click=${() => this._handleSeekRelative(-10)}>
                                                <ha-icon icon="mdi:rewind-10"></ha-icon>
                                            </ha-icon-button>
                                        `}

                                        <div class="play-pause-wrapper ${this._stopPulse ? 'stop-pulse' : ''}"
                                            @pointerdown=${this._startLongPress}
                                            @pointerup=${this._endLongPress}
                                            @pointerleave=${this._endLongPress}
                                            @contextmenu=${(e: Event) => e.preventDefault()}
                                        >
                                            ${this._rewindActive ? html`
                                                <ha-icon-button class="play-pause-btn spinning" .label=${localize(this.hass.locale?.language || this.hass.language, 'loading')}>
                                                    <ha-icon icon="mdi:loading"></ha-icon>
                                                </ha-icon-button>
                                            ` : isPaused ? html`
                                                <ha-icon-button class="play-pause-btn" .label=${localize(this.hass.locale?.language || this.hass.language, 'play')} @click=${() => { if (this._longPressConsumed) { this._longPressConsumed = false; return; } this._handleControl(isMusic ? 'PlayPause' : 'Unpause'); }}>
                                                    <ha-icon icon="mdi:play"></ha-icon>
                                                </ha-icon-button>
                                            ` : html`
                                                <ha-icon-button class="play-pause-btn" .label=${localize(this.hass.locale?.language || this.hass.language, 'pause')} @click=${() => { if (this._longPressConsumed) { this._longPressConsumed = false; return; } this._handleControl('Pause'); }}>
                                                    <ha-icon icon="mdi:pause"></ha-icon>
                                                </ha-icon-button>
                                            `}
                                            ${this._longPressProgress > 0 ? html`
                                                <svg class="stop-ring" viewBox="0 0 44 44">
                                                    <circle cx="22" cy="22" r="20"
                                                        stroke="#ef4444" stroke-width="3" fill="none"
                                                        stroke-dasharray="${ringCircumference}"
                                                        stroke-dashoffset="${ringOffset}"
                                                        stroke-linecap="round"
                                                        transform="rotate(-90 22 22)" />
                                                </svg>
                                            ` : nothing}
                                        </div>

                                        ${isMusic ? html`
                                            <ha-icon-button .label=${localize(this.hass.locale?.language || this.hass.language, 'next') || 'Next'} @click=${() => this._handleControl('NextTrack')}>
                                                <ha-icon icon="mdi:skip-next"></ha-icon>
                                            </ha-icon-button>
                                            <ha-icon-button class="music-subtle-btn ${(attributes.repeat_mode && attributes.repeat_mode !== 'RepeatNone') ? 'active' : ''}" .label=${'Repeat'} @click=${() => this._handleRepeatMode(attributes.session_id!, attributes.repeat_mode || 'RepeatNone')}>
                                                <ha-icon icon="${attributes.repeat_mode === 'RepeatOne' ? 'mdi:repeat-once' : 'mdi:repeat'}"></ha-icon>
                                            </ha-icon-button>
                                        ` : html`
                                            <ha-icon-button class="seek-btn" .label=${'Forward 30s'} @click=${() => this._handleSeekRelative(30)}>
                                                <ha-icon icon="mdi:fast-forward-30"></ha-icon>
                                            </ha-icon-button>
                                        `}
                                    </div>
                                ` : nothing}

                                <div class="progress-container ${supportsRemote ? '' : 'readonly'}"
                                    @pointerdown=${supportsRemote ? this._startDrag : undefined}
                                    @pointermove=${supportsRemote ? this._handleDrag : undefined}
                                    @pointerup=${supportsRemote ? this._endDrag : undefined}
                                    @pointercancel=${supportsRemote ? this._cancelDrag : undefined}
                                >
                                    <div class="progress-bar">
                                        <div class="progress-fill" style="width: ${this._isDragging ? this._dragPercentage : progressPercent}%; transition: ${this._isDragging ? 'none' : 'width 1s linear'}; background: ${this._dominantColor}"></div>
                                        <div class="seek-handle" style="left: ${this._isDragging ? this._dragPercentage : progressPercent}%; transition: ${this._isDragging ? 'none' : 'left 1s linear'}; transform: translate(-50%, -50%) ${this._isDragging ? 'scale(1.3)' : 'scale(1)'}; background: ${this._dominantColor}"></div>
                                    </div>
                                </div>

                                ${this._config.show_time && durationSeconds > 0 ? html`
                                    <div class="timestamps">
                                        <span class="time-elapsed">${this._formatSeconds(displayPositionSeconds)}</span>
                                        <span class="time-remaining">${this._formatSeconds(-(durationSeconds - displayPositionSeconds))}</span>
                                    </div>
                                ` : nothing}
                            </div>
                        </div>
                    </div>
                </div>
            </ha-card>
        `;
    }

    private _phrases: string[] = [];

    private async _fetchPhrases(): Promise<void> {
        if (this._phrases.length > 0) return;
        try {
            const response = await fetch('/jellyha_static/phrases.json');
            if (response.ok) {
                this._phrases = await response.json();
            }
        } catch (e) {
            console.warn('JellyHA: Could not fetch phrases.json', e);
        }
    }

    private _renderEmpty(): TemplateResult {
        this._fetchPhrases(); // Trigger async fetch

        const isDarkMode = this.hass.themes?.darkMode;
        const logoUrl = isDarkMode
            ? 'https://raw.githubusercontent.com/home-assistant/brands/master/custom_integrations/jellyha/dark_logo.png'
            : 'https://raw.githubusercontent.com/home-assistant/brands/master/custom_integrations/jellyha/logo.png';
        const iconUrl = 'https://raw.githubusercontent.com/home-assistant/brands/master/custom_integrations/jellyha/icon.png';

        let phrase = localize(this.hass.locale?.language || this.hass.language, 'nothing_playing');

        if (this._phrases.length > 0) {
            const daySeed = Math.floor(Date.now() / (1000 * 60 * 60 * 24));
            const phraseIndex = daySeed % this._phrases.length;
            phrase = this._phrases[phraseIndex];

            // Get unwatched number - scope to the same instance as this card's entity
            const configEntity = this._config?.entity || '';
            let entityBase = '';
            if (configEntity.startsWith('sensor.')) {
                entityBase = configEntity.replace(/_now_playing.*$/, '');
            } else if (configEntity.startsWith('media_player.')) {
                // e.g. media_player.jellyha_admin -> sensor.jellyha
                const nameWithoutDomain = configEntity.replace(/^media_player\./, '');
                const prefix = nameWithoutDomain.includes('_') ? nameWithoutDomain.substring(0, nameWithoutDomain.lastIndexOf('_')) : nameWithoutDomain;
                entityBase = `sensor.${prefix}`;
            }
            const scopedSensor = entityBase ? `${entityBase}_unwatched` : '';
            // Try scoped sensor first, fall back to global search for single-instance setups
            let unwatchedSensor = scopedSensor && this.hass.states[scopedSensor] ? scopedSensor : '';
            if (!unwatchedSensor) {
                unwatchedSensor = Object.keys(this.hass.states).find(e => e.startsWith('sensor.') && e.endsWith('_unwatched')) || '';
            }
            const count = unwatchedSensor ? this.hass.states[unwatchedSensor].state : "0";

            phrase = phrase.replace(/\[number\]/g, count);
        }

        return html`
            <ha-card class="jellyha-now-playing empty-state">
                <div class="card-content">
                    <div class="logo-container full-logo">
                        <img src="${logoUrl}" alt="JellyHA Logo" />
                    </div>
                    <div class="logo-container mini-icon">
                        <img src="${iconUrl}" alt="JellyHA Icon" />
                    </div>
                    <p>${phrase}</p>
                </div>
            </ha-card>
        `;
    }

    private _renderIdleShowcase(): TemplateResult {
        if (this._idleItems.length === 0) {
            if (!this._fetchingIdleItems) {
                this._fetchIdleLibraryItems();
            }
            return this._renderEmpty();
        }

        const currentItem = this._idleItems[this._currentIdleIndex];
        if (!currentItem) {
            return this._renderEmpty();
        }

        if (!this._idleTimer) {
            this._startIdleTimer();
        }

        const prevItem = this._prevIdleIndex !== null ? this._idleItems[this._prevIdleIndex] : null;
        const lang = this.hass.locale?.language || this.hass.language;

        if (this._config.idle_display_mode === 'card') {
            return this._renderIdleCardMode(currentItem, prevItem, lang);
        }

        return this._renderIdleBackdropMode(currentItem, prevItem, lang);
    }

    private _getItemFromLatestSensor(type: 'movie' | 'episode'): MediaItem | null {
        if (!this.hass?.states) return null;

        const configEntity = this._config?.entity || '';
        let prefix = 'jellyha';
        if (configEntity.startsWith('media_player.')) {
            const raw = configEntity.replace(/^media_player\./, '');
            prefix = raw.includes('_') ? raw.substring(0, raw.lastIndexOf('_')) : raw;
        }

        const sensorEntityId = type === 'movie'
            ? `sensor.${prefix}_latest_movie`
            : `sensor.${prefix}_latest_episode`;

        const stateObj = this.hass.states[sensorEntityId] || this.hass.states[`sensor.jellyha_latest_${type}`];
        if (!stateObj || !stateObj.attributes || stateObj.state === 'unavailable' || stateObj.state === 'unknown') {
            return null;
        }

        const attrs = stateObj.attributes;
        return {
            id: attrs.item_id || stateObj.state,
            name: attrs.title || attrs.name || stateObj.state,
            type: type === 'movie' ? 'Movie' : 'Episode',
            year: attrs.year,
            description: attrs.overview || attrs.description,
            genres: attrs.genres || [],
            rating: attrs.rating,
            community_rating: attrs.community_rating,
            official_rating: attrs.official_rating,
            critic_rating: attrs.critic_rating,
            runtime_minutes: attrs.runtime_minutes,
            poster_url: attrs.poster_url,
            series_poster_url: attrs.series_poster_url as string | undefined,
            backdrop_url: attrs.backdrop_url,
            series_name: attrs.series_name,
            season: attrs.season,
            episode: attrs.episode,
            date_added: attrs.date_added,
            dynamic_range: attrs.dynamic_range,
            resolution: attrs.resolution,
            jellyfin_url: (attrs.jellyfin_url as string) || '',
        } as unknown as MediaItem;
    }

    private _renderIdleBackdropMode(currentItem: MediaItem, prevItem: MediaItem | null, lang: string): TemplateResult {
        const currentBackdrop = addImageParams(currentItem.backdrop_url || currentItem.poster_url, 960);
        const prevBackdrop = prevItem ? addImageParams(prevItem.backdrop_url || prevItem.poster_url, 960) : '';

        const rawRating = currentItem.community_rating ?? currentItem.rating;
        const communityRating = (typeof rawRating === 'number' && !isNaN(rawRating) && rawRating > 0) ? rawRating.toFixed(1) : (rawRating ? String(rawRating) : '');
        const runtime = currentItem.runtime_minutes ? formatRuntime(currentItem.runtime_minutes) : '';
        const rawGenres = currentItem.genres && currentItem.genres.length > 0 ? currentItem.genres.slice(0, 3) : [];
        const genres = this._config.show_genres !== false ? rawGenres : [];

        // Media Type Badge & Option B Latest Spotlight Badge
        const showBadge = this._config.show_media_type_badge !== false && this._config.badge_style !== 'none';
        const badgeStyle = this._config.badge_style || this._config.media_type_badge_style || 'poster';
        const isInlineBadge = showBadge && badgeStyle === 'inline';
        const isTopBadge = showBadge && !isInlineBadge;

        const isMovie = currentItem.type === 'Movie';
        const isEpisode = currentItem.type === 'Episode';
        const isSeries = currentItem.type === 'Series' || (!isMovie && !isEpisode);
        const rawSeason = currentItem.season;
        const rawEpisode = currentItem.episode;
        const numSeason = Number(rawSeason);
        const numEpisode = Number(rawEpisode);
        const hasValidEp = rawSeason != null && rawEpisode != null && !isNaN(numSeason) && !isNaN(numEpisode) && numSeason >= 0 && numEpisode >= 0;
        const isEpisodeItem = isEpisode && hasValidEp;
        const epPrefix = isEpisodeItem
            ? `S${String(numSeason).padStart(2, '0')}E${String(numEpisode).padStart(2, '0')}`
            : '';

        let displayTitle = '';
        let subtitle = '';

        if (isEpisode) {
            if (currentItem.series_name) {
                displayTitle = currentItem.series_name;
                const epName = currentItem.name && currentItem.name !== currentItem.series_name ? currentItem.name : '';
                if (epPrefix && epName) {
                    subtitle = `${epPrefix} · ${epName}`;
                } else if (epPrefix) {
                    subtitle = epPrefix;
                } else {
                    subtitle = epName || currentItem.tagline || '';
                }
            } else {
                displayTitle = currentItem.name || '';
                subtitle = epPrefix ? (currentItem.tagline ? `${epPrefix} · ${currentItem.tagline}` : epPrefix) : (currentItem.tagline || '');
            }
        } else {
            displayTitle = currentItem.name || '';
            subtitle = currentItem.tagline || '';
        }

        // Show subtitle setting check
        if (this._config.show_subtitle === false) {
            subtitle = '';
            if (showBadge && isInlineBadge && isEpisodeItem && epPrefix) {
                if (!displayTitle.toLowerCase().startsWith(epPrefix.toLowerCase())) {
                    displayTitle = `${epPrefix} · ${displayTitle}`;
                }
            }
        }

        const isFirstOfItsType = this._idleItems.findIndex(it => {
            if (isMovie) return it.type === 'Movie';
            if (isEpisode) return it.type === 'Episode';
            return it.type === 'Series' || (it.type !== 'Movie' && it.type !== 'Episode');
        }) === this._currentIdleIndex;

        const isLatest = this._config.idle_content_source === 'latest_movie' ||
                         this._config.idle_content_source === 'latest_episode' ||
                         this._config.idle_content_source === 'latest_both' ||
                         (this._config.idle_content_source === 'recent' && isFirstOfItsType);

        const badgeTypeClass = isMovie ? 'movie' : (isEpisode ? 'episode' : 'series');
        const badgeText = isLatest
            ? (isMovie ? localize(lang, 'card.latest_movie_badge') || 'LATEST MOVIE' : (isEpisode ? localize(lang, 'card.latest_episode_badge') || 'LATEST EPISODE' : localize(lang, 'card.latest_series_badge') || 'LATEST SERIES'))
            : (isMovie ? localize(lang, 'movie') || 'Movie' : (isEpisode ? localize(lang, 'episode') || 'Episode' : localize(lang, 'series') || 'Series'));

        return html`
            <ha-card class="jellyha-now-playing idle-showcase-card">
                <div class="idle-backdrop-container">
                    <img class="idle-backdrop-img" src="${currentBackdrop}" alt="${currentItem.name}" />
                    ${prevBackdrop ? html`
                        <img class="idle-backdrop-img prev-backdrop ${this._idleFadeOut ? 'fade-out' : ''}" src="${prevBackdrop}" alt="" />
                    ` : nothing}
                    <div class="idle-backdrop-scrim"></div>
                </div>

                ${isTopBadge ? html`
                    <span class="media-type-badge idle-backdrop-top-badge ${isLatest ? 'latest-badge' : ''} ${badgeTypeClass}">${badgeText}</span>
                ` : nothing}

                <div class="idle-bottom-content">
                    <div class="title-row">
                        ${this._config.show_title !== false ? html`
                            <h2 class="idle-title">${displayTitle}</h2>
                        ` : nothing}
                    </div>
                    ${subtitle ? html`
                        <div class="subtitle-row">
                            <span class="subtitle">${subtitle}</span>
                        </div>
                    ` : nothing}
                    <div class="idle-meta-row">
                        ${isInlineBadge ? html`
                            <span class="media-type-badge inline-badge ${isLatest ? 'latest-badge' : ''} ${badgeTypeClass}">${badgeText}</span>
                            <span class="idle-dot">•</span>
                        ` : nothing}
                        ${this._config.show_year !== false && currentItem.year ? html`<span class="idle-meta-text">${currentItem.year}</span>` : nothing}
                        ${this._config.show_year !== false && currentItem.year && ((this._config.show_runtime !== false && runtime) || (this._config.show_ratings !== false && communityRating) || genres.length > 0) ? html`<span class="idle-dot">•</span>` : nothing}
                        ${this._config.show_runtime !== false && runtime ? html`<span class="idle-meta-text">${runtime}</span>` : nothing}
                        ${this._config.show_runtime !== false && runtime && ((this._config.show_ratings !== false && communityRating) || genres.length > 0) ? html`<span class="idle-dot">•</span>` : nothing}
                        ${this._config.show_ratings !== false && communityRating ? html`
                            <span class="idle-rating-pill">
                                <ha-icon icon="mdi:star"></ha-icon>
                                <span>${communityRating}</span>
                            </span>
                        ` : nothing}
                        ${genres.map(g => html`<span class="idle-genre-pill">${g}</span>`)}
                    </div>
                    ${this._config.show_description !== false && currentItem.description ? html`
                        <p class="idle-overview">${currentItem.description}</p>
                    ` : nothing}
                </div>
            </ha-card>
        `;
    }

    private _renderIdleCardMode(item: MediaItem, prevItem: MediaItem | null, lang: string): TemplateResult {
        const backdropUrl = addImageParams(item.backdrop_url || item.poster_url, 960);
        const prevBackdrop = prevItem ? addImageParams(prevItem.backdrop_url || prevItem.poster_url, 960) : '';

        const posterSrc = (this._config.use_series_image && item.series_poster_url) ? item.series_poster_url : (item.poster_url || item.backdrop_url);
        const posterUrl = addImageParams(posterSrc, 320);

        const prevPosterSrc = (prevItem && this._config.use_series_image && prevItem.series_poster_url) ? prevItem.series_poster_url : (prevItem?.poster_url || prevItem?.backdrop_url);
        const prevPoster = prevPosterSrc ? addImageParams(prevPosterSrc, 320) : '';

        const rawRating = item.community_rating ?? item.rating;
        const communityRating = (typeof rawRating === 'number' && !isNaN(rawRating) && rawRating > 0) ? rawRating.toFixed(1) : (rawRating ? String(rawRating) : '');
        const runtime = item.runtime_minutes ? formatRuntime(item.runtime_minutes) : '';
        const rawGenres = item.genres && item.genres.length > 0 ? item.genres.slice(0, 3) : [];
        const genres = this._config.show_genres !== false ? rawGenres : [];

        // Badge placement style
        const badgeStyle = this._config.badge_style || this._config.media_type_badge_style || 'poster';
        const showBadge = this._config.show_media_type_badge !== false && badgeStyle !== 'none';
        const isInlineBadge = showBadge && badgeStyle === 'inline';

        const isMovie = item.type === 'Movie';
        const isEpisode = item.type === 'Episode';
        const isSeries = item.type === 'Series' || (!isMovie && !isEpisode);
        const rawSeason = item.season;
        const rawEpisode = item.episode;
        const numSeason = Number(rawSeason);
        const numEpisode = Number(rawEpisode);
        const hasValidEp = rawSeason != null && rawEpisode != null && !isNaN(numSeason) && !isNaN(numEpisode) && numSeason >= 0 && numEpisode >= 0;
        const isEpisodeItem = isEpisode && hasValidEp;
        const epPrefix = isEpisodeItem
            ? `S${String(numSeason).padStart(2, '0')}E${String(numEpisode).padStart(2, '0')}`
            : '';

        let displayTitle = '';
        let subtitle = '';

        if (isEpisode) {
            if (item.series_name) {
                displayTitle = item.series_name;
                const epName = item.name && item.name !== item.series_name ? item.name : '';
                if (epPrefix && epName) {
                    subtitle = `${epPrefix} · ${epName}`;
                } else if (epPrefix) {
                    subtitle = epPrefix;
                } else {
                    subtitle = epName || item.tagline || '';
                }
            } else {
                displayTitle = item.name || '';
                subtitle = epPrefix ? (item.tagline ? `${epPrefix} · ${item.tagline}` : epPrefix) : (item.tagline || '');
            }
        } else {
            displayTitle = item.name || '';
            subtitle = item.tagline || '';
        }

        // Show subtitle setting check
        if (this._config.show_subtitle === false) {
            subtitle = '';
            if (showBadge && isInlineBadge && isEpisodeItem && epPrefix) {
                if (!displayTitle.toLowerCase().startsWith(epPrefix.toLowerCase())) {
                    displayTitle = `${epPrefix} · ${displayTitle}`;
                }
            }
        }

        const isFirstOfItsType = this._idleItems.findIndex(it => {
            if (isMovie) return it.type === 'Movie';
            if (isEpisode) return it.type === 'Episode';
            return it.type === 'Series' || (it.type !== 'Movie' && it.type !== 'Episode');
        }) === this._currentIdleIndex;

        const isLatest = this._config.idle_content_source === 'latest_movie' ||
                         this._config.idle_content_source === 'latest_episode' ||
                         this._config.idle_content_source === 'latest_both' ||
                         (this._config.idle_content_source === 'recent' && isFirstOfItsType);

        const badgeTypeClass = isMovie ? 'movie' : (isEpisode ? 'episode' : 'series');
        const badgeText = isLatest
            ? (isMovie ? localize(lang, 'card.latest_movie_badge') || 'LATEST MOVIE' : (isEpisode ? localize(lang, 'card.latest_episode_badge') || 'LATEST EPISODE' : localize(lang, 'card.latest_series_badge') || 'LATEST SERIES'))
            : (isMovie ? localize(lang, 'movie') || 'Movie' : (isEpisode ? localize(lang, 'episode') || 'Episode' : localize(lang, 'series') || 'Series'));

        return html`
            <ha-card class="jellyha-now-playing has-background idle-card-mode">
                <div class="idle-card-bg-container">
                    ${backdropUrl ? html`
                        <img class="idle-card-bg-img" src="${backdropUrl}" alt="" />
                    ` : nothing}
                    ${prevBackdrop ? html`
                        <img class="idle-card-bg-img prev-bg ${this._idleFadeOut ? 'fade-out' : ''}" src="${prevBackdrop}" alt="" />
                    ` : nothing}
                    <div class="card-overlay"></div>
                </div>

                <div class="card-content">
                    <div class="main-container">
                        <div class="poster-container no-rewind">
                            <img class="idle-poster-img" src="${posterUrl}" alt="${item.name}" loading="eager" />
                            ${prevPoster ? html`
                                <img class="idle-poster-img prev-poster ${this._idleFadeOut ? 'fade-out' : ''}" src="${prevPoster}" alt="" />
                            ` : nothing}
                            ${showBadge && badgeStyle === 'poster' ? html`
                                <span class="poster-badge media-type-badge ${isLatest ? 'latest-badge' : ''} ${badgeTypeClass}">${badgeText}</span>
                            ` : nothing}
                        </div>

                        <div class="info-container">
                            <div class="info-top">
                                <div class="title-row">
                                    ${this._config.show_title !== false ? html`
                                        <span class="title" title="${item.series_name ? `${item.series_name} - ${item.name}` : displayTitle}">${displayTitle}</span>
                                    ` : nothing}
                                    ${showBadge && badgeStyle === 'header' ? html`
                                        <span class="media-type-badge header-badge ${isLatest ? 'latest-badge' : ''} ${badgeTypeClass}">${badgeText}</span>
                                    ` : nothing}
                                </div>
                                ${subtitle ? html`
                                    <div class="subtitle-row">
                                        <span class="subtitle">${subtitle}</span>
                                    </div>
                                ` : nothing}
                                <div class="meta-line idle-meta-row">
                                    ${showBadge && badgeStyle === 'inline' ? html`
                                        <span class="media-type-badge inline-badge ${isLatest ? 'latest-badge' : ''} ${badgeTypeClass}">${badgeText}</span>
                                        <span class="idle-dot">•</span>
                                    ` : nothing}
                                    ${this._config.show_year !== false && item.year ? html`<span class="idle-meta-text">${item.year}</span>` : nothing}
                                    ${this._config.show_year !== false && item.year && ((this._config.show_runtime !== false && runtime) || (this._config.show_ratings !== false && communityRating) || genres.length > 0) ? html`<span class="idle-dot">•</span>` : nothing}
                                    ${this._config.show_runtime !== false && runtime ? html`<span class="idle-meta-text">${runtime}</span>` : nothing}
                                    ${this._config.show_runtime !== false && runtime && ((this._config.show_ratings !== false && communityRating) || genres.length > 0) ? html`<span class="idle-dot">•</span>` : nothing}
                                    ${this._config.show_ratings !== false && communityRating ? html`
                                        <span class="idle-rating-pill">
                                            <ha-icon icon="mdi:star"></ha-icon>
                                            <span>${communityRating}</span>
                                        </span>
                                    ` : nothing}
                                    ${genres.map(g => html`<span class="idle-genre-pill">${g}</span>`)}
                                </div>
                                ${this._config.show_description !== false && item.description ? html`
                                    <div class="idle-card-desc">${item.description}</div>
                                ` : nothing}
                            </div>
                        </div>
                    </div>
                </div>
            </ha-card>
        `;
    }

    private _startIdleTimer(): void {
        this._stopIdleTimer();
        if (!this._config?.idle_backdrop_cycle || this._idleItems.length <= 1) return;
        const rawInterval = Number(this._config.idle_cycle_interval);
        const intervalSec = Math.max(5, !isNaN(rawInterval) && rawInterval > 0 ? rawInterval : 20);
        this._idleTimer = window.setInterval(() => {
            this._advanceIdleSlide();
        }, intervalSec * 1000);
    }

    private _stopIdleTimer(): void {
        if (this._idleTimer) {
            clearInterval(this._idleTimer);
            this._idleTimer = undefined;
        }
    }

    private _advanceIdleSlide(): void {
        if (!this.isConnected || !this._config?.idle_backdrop_cycle || this._idleItems.length <= 1) return;
        this._prevIdleIndex = this._currentIdleIndex;
        this._currentIdleIndex = (this._currentIdleIndex + 1) % this._idleItems.length;
        this._idleFadeOut = true;
        this.requestUpdate();

        // Preload upcoming slide
        const nextNextIdx = (this._currentIdleIndex + 1) % this._idleItems.length;
        const nextItem = this._idleItems[nextNextIdx];
        if (nextItem) {
            const isCard = this._config?.idle_display_mode === 'card';
            if (isCard && nextItem.poster_url) {
                const posterImg = new Image();
                posterImg.src = addImageParams(nextItem.poster_url, 320);
            }
            const backdropSrc = nextItem.backdrop_url || nextItem.poster_url;
            if (backdropSrc) {
                const bgImg = new Image();
                bgImg.src = addImageParams(backdropSrc, 960);
            }
        }

        setTimeout(() => {
            this._prevIdleIndex = null;
            this._idleFadeOut = false;
            this.requestUpdate();
        }, 850);
    }

    private async _fetchIdleLibraryItems(): Promise<void> {
        if (!this.hass || this._fetchingIdleItems) return;
        this._fetchingIdleItems = true;

        try {
            const source = this._config?.idle_content_source || 'random';

            // 1. Direct sensor extraction for static latest spotlights
            if (source === 'latest_movie' || source === 'latest_episode' || source === 'latest_both') {
                const items: MediaItem[] = [];
                if (source === 'latest_movie' || source === 'latest_both') {
                    const movie = this._getItemFromLatestSensor('movie');
                    if (movie) items.push(movie);
                }
                if (source === 'latest_episode' || source === 'latest_both') {
                    const ep = this._getItemFromLatestSensor('episode');
                    if (ep) items.push(ep);
                }

                if (items.length > 0) {
                    this._idleItems = items;
                    this._currentIdleIndex = 0;
                    this._prevIdleIndex = null;
                    this._idleFadeOut = false;
                    this._startIdleTimer();
                    this.requestUpdate();
                    return;
                }
                // Fallback to WebSocket get_items if sensor not present
            }

            const configEntity = this._config?.entity || '';
            let libraryEntity = Object.keys(this.hass?.states || {}).find(
                e => e.startsWith('sensor.jellyha') && e.endsWith('_library')
            );
            if (configEntity.startsWith('media_player.')) {
                const nameWithoutDomain = configEntity.replace(/^media_player\./, '');
                const prefix = nameWithoutDomain.includes('_') ? nameWithoutDomain.substring(0, nameWithoutDomain.lastIndexOf('_')) : nameWithoutDomain;
                const scoped = `sensor.${prefix}_library`;
                if (this.hass?.states[scoped]) libraryEntity = scoped;
            }

            const mediaTypeFilter = (source === 'movies' || source === 'series')
                ? source
                : (this._config.idle_media_type || 'both');
            const isCardMode = this._config.idle_display_mode === 'card';
            const limit = Math.max(1, this._config.idle_recent_limit || 15);

            let res: { items: MediaItem[] } | null = null;
            if (source === 'recent') {
                let itemTypes = ['Movie', 'Series'];
                if (mediaTypeFilter === 'movies') itemTypes = ['Movie'];
                else if (mediaTypeFilter === 'series') itemTypes = ['Series'];
                else if (mediaTypeFilter === 'movies_episodes') itemTypes = ['Movie', 'Episode'];
                else if (mediaTypeFilter === 'episodes') itemTypes = ['Episode'];

                try {
                    const latestMsg: any = {
                        type: 'jellyha/get_latest_items',
                        item_types: itemTypes,
                        limit: Math.max(limit * 3, 100),
                    };
                    if (libraryEntity) latestMsg.server_entity_id = libraryEntity;
                    if (configEntity) latestMsg.entity_id = configEntity;
                    res = await this.hass.callWS<{ items: MediaItem[] }>(latestMsg);
                } catch (e) {
                    console.warn('[JellyHA] get_latest_items failed, falling back to get_items:', e);
                }
            }

            if (!res || !Array.isArray(res.items) || res.items.length === 0) {
                const wsMsg: any = {
                    type: 'jellyha/get_items',
                };
                if (libraryEntity) wsMsg.server_entity_id = libraryEntity;
                if (configEntity) wsMsg.entity_id = configEntity;

                res = await this.hass.callWS<{ items: MediaItem[] }>(wsMsg);
            }

            if (res && Array.isArray(res.items) && res.items.length > 0) {
                let filtered = res.items.filter(it => {
                    if (isCardMode) {
                        return !!it.poster_url || !!it.backdrop_url;
                    }
                    return !!it.backdrop_url;
                });

                if (mediaTypeFilter === 'movies') {
                    filtered = filtered.filter(it => it.type === 'Movie');
                } else if (mediaTypeFilter === 'series') {
                    filtered = filtered.filter(it => it.type === 'Series' || it.type === 'Episode');
                } else if (mediaTypeFilter === 'movies_episodes') {
                    filtered = filtered.filter(it => it.type === 'Movie' || it.type === 'Episode');
                } else if (mediaTypeFilter === 'episodes') {
                    filtered = filtered.filter(it => it.type === 'Episode');
                }

                if (filtered.length > 0) {
                    if (source === 'recent') {
                        filtered.sort((a, b) => {
                            const timeA = a.date_added ? new Date(a.date_added).getTime() : 0;
                            const timeB = b.date_added ? new Date(b.date_added).getTime() : 0;
                            return timeB - timeA;
                        });
                        const limit = Math.max(1, this._config.idle_recent_limit || 15);
                        let sliced = filtered.slice(0, limit);

                        if (mediaTypeFilter === 'movies_episodes') {
                            const hasMovie = sliced.some(it => it.type === 'Movie');
                            const hasEp = sliced.some(it => it.type === 'Episode');
                            if (!hasMovie) {
                                const latestMovie = filtered.find(it => it.type === 'Movie');
                                if (latestMovie) sliced.push(latestMovie);
                            }
                            if (!hasEp) {
                                const latestEp = filtered.find(it => it.type === 'Episode');
                                if (latestEp) sliced.push(latestEp);
                            }
                        } else if (mediaTypeFilter === 'both') {
                            const hasMovie = sliced.some(it => it.type === 'Movie');
                            const hasSeries = sliced.some(it => it.type === 'Series');
                            if (!hasMovie) {
                                const latestMovie = filtered.find(it => it.type === 'Movie');
                                if (latestMovie) sliced.push(latestMovie);
                            }
                            if (!hasSeries) {
                                const latestSeries = filtered.find(it => it.type === 'Series');
                                if (latestSeries) sliced.push(latestSeries);
                            }
                        }
                        this._idleItems = sliced;
                    } else if (source === 'latest_movie') {
                        const movie = filtered.find(it => it.type === 'Movie');
                        this._idleItems = movie ? [movie] : filtered.slice(0, 1);
                    } else if (source === 'latest_episode') {
                        const ep = filtered.find(it => it.type === 'Episode' || it.type === 'Series');
                        this._idleItems = ep ? [ep] : filtered.slice(0, 1);
                    } else {
                        this._idleItems = this._shuffleArray(filtered);
                    }

                    this._currentIdleIndex = 0;
                    this._prevIdleIndex = null;
                    this._idleFadeOut = false;
                    this._startIdleTimer();
                    this.requestUpdate();
                }
            }
        } catch (err) {
            console.warn('[JellyHA] Failed to fetch library items for idle showcase:', err);
        } finally {
            this._fetchingIdleItems = false;
        }
    }

    private _shuffleArray<T>(array: T[]): T[] {
        const shuffled = [...array];
        for (let i = shuffled.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
        }
        return shuffled;
    }

    private _renderError(error: string): TemplateResult {
        return html`
            <ha-card class="error-state">
                <div class="card-content">
                    <p>${error}</p>
                </div>
            </ha-card>
        `;
    }

    private _extractItemId(stateObj: HassEntity): string | null {
        const attributes = stateObj.attributes as unknown as NowPlayingSensorData;
        if (attributes.item_id) return String(attributes.item_id);

        const contentId = (stateObj.attributes as any).media_content_id || '';
        const entityPic = (stateObj.attributes as any).entity_picture || '';

        // Match /Videos/<id>/... or /Items/<id>/... or /Audio/<id>/...
        const vidMatch = contentId.match(/(?:Videos|Items|Audio)\/([a-zA-Z0-9_-]+)/i);
        if (vidMatch && vidMatch[1]) return vidMatch[1];

        const picMatch = entityPic.match(/Items\/([a-zA-Z0-9_-]+)/i);
        if (picMatch && picMatch[1]) return picMatch[1];

        return null;
    }

    private async _fetchMissingMetadata(itemId: string): Promise<void> {
        if (!itemId || this._resolvedMetadata[itemId] || this._fetchingMetadataId === itemId) return;
        this._fetchingMetadataId = itemId;
        try {
            const libraryEntity = Object.keys(this.hass?.states || {}).find(
                e => e.startsWith('sensor.jellyha') && e.endsWith('_library')
            );
            const wsMsg: any = {
                type: 'jellyha/get_item',
                item_id: itemId,
            };
            if (libraryEntity) {
                wsMsg.server_entity_id = libraryEntity;
            }
            const res: any = await this.hass.callWS(wsMsg);
            if (res && res.item) {
                this._resolvedMetadata[itemId] = res.item;
            } else {
                this._resolvedMetadata[itemId] = {};
            }
            this.requestUpdate();
        } catch (e) {
            // WS call failed, ignore
        } finally {
            this._fetchingMetadataId = null;
        }
    }

    private _resolveImages(stateObj: HassEntity, cachedItem?: any): { seriesImageUrl?: string; episodeImageUrl?: string } {
        const attributes = stateObj.attributes as unknown as NowPlayingSensorData;
        let seriesImageUrl = attributes.series_image_url || cachedItem?.series_poster_url;
        let episodeImageUrl = attributes.image_url || cachedItem?.poster_url || cachedItem?.image_url;

        // Determine if this is an episode / TV series item
        const mediaType = ((attributes.media_type || cachedItem?.type || (stateObj.attributes as any).media_content_type) || '').toLowerCase();
        const seriesTitle = attributes.series_title || (stateObj.attributes as any).media_series_title || cachedItem?.series_name;
        const episodeTitle = attributes.title || (stateObj.attributes as any).media_title || cachedItem?.name;
        const isEpisode = mediaType === 'episode' || mediaType === 'tvshow' || !!seriesTitle || (stateObj.attributes as any).media_season !== undefined || cachedItem?.season !== undefined;

        const contentId = (stateObj.attributes as any).media_content_id || '';
        const entityPic = (stateObj.attributes as any).entity_picture || '';
        const cacheKey = attributes.item_id || cachedItem?.id || contentId || seriesTitle || stateObj.entity_id;

        // Check if previously resolved in memory
        if (cacheKey && this._resolvedImages[cacheKey]) {
            if (!seriesImageUrl) seriesImageUrl = this._resolvedImages[cacheKey].seriesImageUrl;
            if (!episodeImageUrl) episodeImageUrl = this._resolvedImages[cacheKey].episodeImageUrl;
        }

        // If not an episode, or both already resolved, return
        if (!isEpisode || (seriesImageUrl && episodeImageUrl)) {
            return { seriesImageUrl, episodeImageUrl };
        }

        // If cachedItem has series_poster_url or poster_url, use them directly
        if (cachedItem) {
            if (cachedItem.series_poster_url && !seriesImageUrl) seriesImageUrl = cachedItem.series_poster_url;
            if ((cachedItem.poster_url || cachedItem.image_url) && !episodeImageUrl) episodeImageUrl = cachedItem.poster_url || cachedItem.image_url;
        }

        // Try to parse Jellyfin URL from media_content_id or entity_picture
        const vidMatch = contentId.match(/^(https?:\/\/[^\/]+)\/(?:Videos|Items)\/([a-zA-Z0-9_-]+)/i);
        const picMatch = entityPic.match(/^(https?:\/\/[^\/]+)\/Items\/([a-zA-Z0-9_-]+)\/Images\/Primary/i);

        const serverBase = vidMatch ? vidMatch[1] : (picMatch ? picMatch[1] : '');
        const epId = vidMatch ? vidMatch[2] : (attributes.item_id || null);
        const picId = picMatch ? picMatch[2] : null;

        // Find API key from contentId or entityPic
        const keyMatch = contentId.match(/[?&](?:api_key|ApiKey)=([a-zA-Z0-9]+)/i) ||
                         entityPic.match(/[?&](?:api_key|ApiKey)=([a-zA-Z0-9]+)/i);
        const apiKeyParam = keyMatch ? `&api_key=${keyMatch[1]}` : '';

        if (serverBase && epId) {
            // We know the episode ID!
            const epDirectUrl = `${serverBase}/Items/${epId}/Images/Primary?maxHeight=300&quality=90${apiKeyParam}`;
            if (!episodeImageUrl) {
                if (picId === epId) {
                    episodeImageUrl = entityPic;
                } else {
                    episodeImageUrl = epDirectUrl;
                }
            }

            if (picId && picId !== epId && !seriesImageUrl) {
                // picId differs from episode ID -> entity_picture is the Series poster!
                seriesImageUrl = entityPic;
            }
        } else if (picMatch && !episodeImageUrl && !seriesImageUrl) {
            // Default entity_picture as fallback for episode
            episodeImageUrl = entityPic;
        }

        // Save what we have in cache
        if (cacheKey && (seriesImageUrl || episodeImageUrl)) {
            this._resolvedImages[cacheKey] = {
                ...this._resolvedImages[cacheKey],
                ...(seriesImageUrl ? { seriesImageUrl } : {}),
                ...(episodeImageUrl ? { episodeImageUrl } : {}),
            };
        }

        // If either seriesImageUrl or episodeImageUrl is still missing for an episode, query Jellyfin via WebSocket
        if (isEpisode && (!seriesImageUrl || !episodeImageUrl) && this._fetchingImageKey !== cacheKey) {
            this._fetchMissingImages(seriesTitle, episodeTitle, cacheKey);
        }

        return { seriesImageUrl, episodeImageUrl };
    }

    private async _fetchMissingImages(seriesTitle?: string, episodeTitle?: string, cacheKey?: string): Promise<void> {
        if (!cacheKey) return;
        this._fetchingImageKey = cacheKey;
        try {
            // 1. Try querying episode title first (returns both episode still and series poster!)
            if (episodeTitle) {
                const res: any = await this.hass.callWS({
                    type: 'jellyha/search_media',
                    query: episodeTitle,
                    media_type: 'Episode',
                    limit: 1,
                });
                const items = res?.items;
                if (items && items.length > 0) {
                    const item = items[0];
                    const epImg = item.poster_url || item.image_url;
                    const seriesImg = item.series_poster_url;
                    if (epImg || seriesImg) {
                        this._resolvedImages[cacheKey] = {
                            ...this._resolvedImages[cacheKey],
                            ...(epImg ? { episodeImageUrl: epImg } : {}),
                            ...(seriesImg ? { seriesImageUrl: seriesImg } : {}),
                        };
                        this.requestUpdate();
                        return;
                    }
                }
            }

            // 2. If series image is still missing, query series title
            if (seriesTitle && !this._resolvedImages[cacheKey]?.seriesImageUrl) {
                const res: any = await this.hass.callWS({
                    type: 'jellyha/search_media',
                    query: seriesTitle,
                    media_type: 'Series',
                    limit: 1,
                });
                const items = res?.items;
                if (items && items.length > 0) {
                    const seriesImg = items[0].poster_url || items[0].series_poster_url || items[0].image_url;
                    if (seriesImg) {
                        this._resolvedImages[cacheKey] = {
                            ...this._resolvedImages[cacheKey],
                            seriesImageUrl: seriesImg,
                        };
                        this.requestUpdate();
                    }
                }
            }
        } catch (e) {
            // Silently ignore if WS search fails
        } finally {
            this._fetchingImageKey = null;
        }
    }

    private _supportsRemote(stateObj?: HassEntity | null): boolean {
        if (!stateObj) return false;
        if (this._config.show_controls === false) return false;
        const attrs = stateObj.attributes as any;
        if (attrs.supports_remote_control === false) return false;
        const isMediaPlayer = stateObj.entity_id.startsWith('media_player.');
        if (isMediaPlayer && attrs.supported_features !== undefined && attrs.supported_features === 0) {
            return false;
        }
        return true;
    }

    private async _handleControl(command: string): Promise<void> {
        this._haptic('light');
        const entityId = this._config.entity;
        const stateObj = this.hass.states[entityId];
        if (!stateObj || !this._supportsRemote(stateObj)) return;
        const isMediaPlayer = entityId.startsWith('media_player.');

        if (isMediaPlayer) {
            let service = '';
            if (command === 'Pause') service = 'media_pause';
            else if (command === 'Unpause' || command === 'Play') service = 'media_play';
            else if (command === 'PlayPause') service = 'media_play_pause';
            else if (command === 'Stop') service = 'media_stop';
            else if (command === 'NextTrack') service = 'media_next_track';
            else if (command === 'PreviousTrack') service = 'media_previous_track';

            if (service) {
                await this.hass.callService('media_player', service, {
                    entity_id: entityId
                });
                return;
            }
        }

        const sessionId = stateObj?.attributes.session_id;
        if (!sessionId) return;

        await this.hass.callService('jellyha', 'session_control', {
            entity_id: entityId,
            session_id: sessionId,
            command: command
        });
    }

    private async _handleRepeatMode(sessionId: string, currentMode: string): Promise<void> {
        let nextMode = 'RepeatAll';
        let nextHaMode = 'all';
        if (currentMode === 'RepeatAll' || currentMode === 'all') {
            nextMode = 'RepeatOne';
            nextHaMode = 'one';
        } else if (currentMode === 'RepeatOne' || currentMode === 'one') {
            nextMode = 'RepeatNone';
            nextHaMode = 'off';
        }

        const entityId = this._config.entity;
        if (entityId.startsWith('media_player.')) {
            await this.hass.callService('media_player', 'repeat_set', {
                entity_id: entityId,
                repeat: nextHaMode
            });
            return;
        }

        await this.hass.callService('jellyha', 'session_general_command', {
            entity_id: entityId,
            session_id: sessionId,
            command: 'SetRepeatMode',
            arguments: { RepeatMode: nextMode }
        });
    }

    private _haptic(type: 'selection' | 'light' | 'medium' | 'heavy' | 'success' | 'warning' | 'failure' = 'selection') {
        const event = new CustomEvent('haptic', {
            detail: type,
            bubbles: true,
            composed: true
        });
        this.dispatchEvent(event);
    }

    private async _handleFavoriteToggle(itemId: string, currentStatus: boolean): Promise<void> {
        this._haptic();
        const newStatus = !currentStatus;

        // Apply optimistic update immediately
        this._optimisticFavorites[itemId] = newStatus;
        this.requestUpdate();

        await this.hass.callService('jellyha', 'update_favorite', {
            entity_id: this._config.entity,
            item_id: itemId,
            is_favorite: newStatus
        });
    }

    private _getDragPercent(e: PointerEvent): number {
        const container = e.currentTarget as HTMLElement;
        const rect = container.getBoundingClientRect();
        // Give 10px buffer on each side for easier edge grabbing
        let x = e.clientX - rect.left;
        if (x < 10) x = 0;
        if (x > rect.width - 10) x = rect.width;
        return Math.max(0, Math.min(100, (x / rect.width) * 100));
    }

    private _startDrag(e: PointerEvent): void {
        const entityId = this._config.entity;
        const stateObj = this.hass?.states[entityId];
        if (!stateObj || !this._supportsRemote(stateObj)) return;

        const container = e.currentTarget as HTMLElement;
        container.setPointerCapture(e.pointerId);
        this._isDragging = true;
        this._dragPercentage = this._getDragPercent(e);
        this._haptic('light'); // Slight feedback on grab
    }

    private _handleDrag(e: PointerEvent): void {
        if (!this._isDragging) return;
        this._dragPercentage = this._getDragPercent(e);
    }

    private _cancelDrag(e: PointerEvent): void {
        if (!this._isDragging) return;
        const container = e.currentTarget as HTMLElement;
        if (container?.releasePointerCapture) {
            try {
                container.releasePointerCapture(e.pointerId);
            } catch {
                // Ignore if pointer capture already released
            }
        }
        this._isDragging = false;
        this.requestUpdate();
    }

    private _getDurationSeconds(stateObj: HassEntity): number {
        const attributes = stateObj.attributes as unknown as NowPlayingSensorData;
        if (attributes.duration_ticks && attributes.duration_ticks > 0) {
            return attributes.duration_ticks / 10000000;
        }
        const mediaDuration = (stateObj.attributes as any).media_duration;
        if (typeof mediaDuration === 'number' && mediaDuration > 0) {
            return mediaDuration;
        }
        if (attributes.runtime_minutes && attributes.runtime_minutes > 0) {
            return attributes.runtime_minutes * 60;
        }
        return 0;
    }

    private _getCurrentPositionSeconds(stateObj: HassEntity): number {
        const attributes = stateObj.attributes as unknown as NowPlayingSensorData;
        const durationSeconds = this._getDurationSeconds(stateObj);

        // 1. Determine base position
        let basePosition = 0;
        let updatedAt: string | undefined;

        const mediaPosition = (stateObj.attributes as any).media_position;
        if (typeof mediaPosition === 'number') {
            basePosition = mediaPosition;
            updatedAt = (stateObj.attributes as any).media_position_updated_at || stateObj.last_updated;
        } else if (typeof attributes.position_ticks === 'number') {
            basePosition = attributes.position_ticks / 10000000;
            updatedAt = stateObj.last_updated;
        } else if (typeof attributes.progress_percent === 'number' && durationSeconds > 0) {
            basePosition = (attributes.progress_percent / 100) * durationSeconds;
            updatedAt = stateObj.last_updated;
        }

        // 2. Extrapolate if playing
        const isMediaPlayer = stateObj.entity_id.startsWith('media_player.');
        const isPlaying = isMediaPlayer
            ? stateObj.state === 'playing'
            : (!attributes.is_paused && !!attributes.item_id);

        if (isPlaying && updatedAt) {
            const updatedAtMs = new Date(updatedAt).getTime();
            if (!isNaN(updatedAtMs)) {
                const elapsedSeconds = Math.max(0, (Date.now() - updatedAtMs) / 1000);
                const extrapolated = basePosition + elapsedSeconds;
                return durationSeconds > 0 ? Math.min(durationSeconds, Math.max(0, extrapolated)) : Math.max(0, extrapolated);
            }
        }

        return durationSeconds > 0 ? Math.min(durationSeconds, Math.max(0, basePosition)) : Math.max(0, basePosition);
    }

    private async _endDrag(e: PointerEvent): Promise<void> {
        if (!this._isDragging) return;
        const container = e.currentTarget as HTMLElement;
        if (container?.releasePointerCapture) {
            try {
                container.releasePointerCapture(e.pointerId);
            } catch {
                // Ignore if pointer capture already released
            }
        }
        this._isDragging = false;

        const finalPercent = this._getDragPercent(e);

        // Hold the seeked position optimistically until server catches up
        this._setOptimisticSeek(finalPercent);

        const entityId = this._config.entity;
        const stateObj = this.hass.states[entityId];
        if (!stateObj) return;

        const durationSeconds = this._getDurationSeconds(stateObj);
        if (durationSeconds <= 0) return;

        const attributes = stateObj.attributes as unknown as NowPlayingSensorData;
        const sessionId = attributes.session_id;

        if (entityId.startsWith('media_player.')) {
            const seekSeconds = Math.round(durationSeconds * (finalPercent / 100));
            await this.hass.callService('media_player', 'media_seek', {
                entity_id: entityId,
                seek_position: seekSeconds
            });
            return;
        }

        if (!sessionId) return;

        const seekTicks = Math.round(durationSeconds * 10000000 * (finalPercent / 100));

        await this.hass.callService('jellyha', 'session_seek', {
            entity_id: entityId,
            session_id: sessionId,
            position_ticks: seekTicks
        });
    }

    private _setOptimisticSeek(percent: number): void {
        if (this._optimisticSeekTimer) clearTimeout(this._optimisticSeekTimer);
        this._optimisticSeekPercent = percent;
        this.requestUpdate();
        this._optimisticSeekTimer = window.setTimeout(() => {
            this._optimisticSeekPercent = null;
            this.requestUpdate();
        }, 2500);
    }

    private async _handleSeekRelative(seconds: number): Promise<void> {
        this._haptic('light');
        const entityId = this._config.entity;
        const stateObj = this.hass.states[entityId];
        if (!stateObj || !this._supportsRemote(stateObj)) return;

        const durationSeconds = this._getDurationSeconds(stateObj);
        const currentPositionSeconds = this._getCurrentPositionSeconds(stateObj);
        const newPositionSeconds = Math.max(
            0,
            durationSeconds > 0
                ? Math.min(durationSeconds, currentPositionSeconds + seconds)
                : currentPositionSeconds + seconds
        );

        if (durationSeconds > 0) {
            this._setOptimisticSeek((newPositionSeconds / durationSeconds) * 100);
        }

        if (entityId.startsWith('media_player.')) {
            await this.hass.callService('media_player', 'media_seek', {
                entity_id: entityId,
                seek_position: Math.round(newPositionSeconds)
            });
            return;
        }

        const attributes = stateObj.attributes as unknown as NowPlayingSensorData;
        const sessionId = attributes.session_id;
        if (!sessionId) return;

        await this.hass.callService('jellyha', 'session_seek', {
            entity_id: entityId,
            session_id: sessionId,
            position_ticks: Math.round(newPositionSeconds * 10000000)
        });
    }

    private async _handlePosterRewind(): Promise<void> {
        const entityId = this._config.entity;
        const stateObj = this.hass.states[entityId];
        if (!stateObj || !this._supportsRemote(stateObj)) return;

        // Visual feedback
        this._rewindActive = true;
        setTimeout(() => {
            this._rewindActive = false;
        }, 1000);

        // Haptic feedback
        this._haptic('selection');

        // Rewind 20 seconds
        await this._handleSeekRelative(-20);
    }

    private _startLongPress(): void {
        const start = Date.now();
        const duration = 800; // ms to hold before stopping

        // Haptic feedback on initial press
        this._haptic('selection');

        const animate = () => {
            const elapsed = Date.now() - start;
            this._longPressProgress = Math.min(elapsed / duration, 1);

            if (this._longPressProgress >= 1) {
                this._longPressConsumed = true;
                this._handleControl('Stop');
                // Haptic feedback for action trigger
                this._haptic('success');
                // Mobile haptic vibration fallback
                if (navigator.vibrate) navigator.vibrate(50);
                // Trigger stop pulse animation
                this._stopPulse = true;
                setTimeout(() => { this._stopPulse = false; }, 600);
                this._endLongPress();
                return;
            }
            this._longPressRaf = requestAnimationFrame(animate);
        };

        this._longPressRaf = requestAnimationFrame(animate);
    }

    private _endLongPress(): void {
        if (this._longPressRaf) {
            cancelAnimationFrame(this._longPressRaf);
            this._longPressRaf = null;
        }
        this._longPressProgress = 0;
    }

    private _extractDominantColor(imgUrl: string): void {
        const img = new Image();
        img.crossOrigin = 'anonymous';
        img.onload = () => {
            try {
                const canvas = document.createElement('canvas');
                canvas.width = 50;
                canvas.height = 50;
                const ctx = canvas.getContext('2d');
                if (!ctx) return;
                ctx.drawImage(img, 0, 0, 50, 50);
                const data = ctx.getImageData(0, 0, 50, 50).data;

                let bestR = 0, bestG = 0, bestB = 0;
                let bestSaturation = 0;

                for (let i = 0; i < data.length; i += 16) {
                    const r = data[i], g = data[i + 1], b = data[i + 2];
                    const max = Math.max(r, g, b), min = Math.min(r, g, b);
                    const saturation = max === 0 ? 0 : (max - min) / max;
                    const brightness = max / 255;

                    if (saturation > bestSaturation && brightness > 0.15 && brightness < 0.95) {
                        bestSaturation = saturation;
                        bestR = r; bestG = g; bestB = b;
                    }
                }

                if (bestSaturation > 0.1) {
                    // Convert to HSL and boost lightness for visibility on dark backgrounds
                    const rn = bestR / 255, gn = bestG / 255, bn = bestB / 255;
                    const max = Math.max(rn, gn, bn), min = Math.min(rn, gn, bn);
                    let h = 0;
                    const l = (max + min) / 2;
                    const d = max - min;
                    const s = d === 0 ? 0 : d / (1 - Math.abs(2 * l - 1));

                    if (d !== 0) {
                        if (max === rn) h = ((gn - bn) / d + (gn < bn ? 6 : 0)) * 60;
                        else if (max === gn) h = ((bn - rn) / d + 2) * 60;
                        else h = ((rn - gn) / d + 4) * 60;
                    }

                    // Clamp lightness to at least 70% and saturation to at least 60%
                    const boostedL = Math.max(l * 100, 70);
                    const boostedS = Math.max(s * 100, 60);
                    this._dominantColor = `hsl(${Math.round(h)}, ${Math.round(boostedS)}%, ${Math.round(boostedL)}%)`;
                } else {
                    this._dominantColor = 'var(--primary-color)';
                }
            } catch {
                this._dominantColor = 'var(--primary-color)';
            }
        };
        img.onerror = () => {
            this._dominantColor = 'var(--primary-color)';
        };
        img.src = imgUrl;
    }

    public connectedCallback(): void {
        super.connectedCallback();
        this._resizeObserver = new ResizeObserver(() => {
            this._checkLayout();
        });
        this._resizeObserver.observe(this);
        this._startProgressTimer();

        this._visibilityHandler = () => {
            if (document.hidden) {
                this._stopIdleTimer();
            } else {
                if (this._config?.idle_backdrop_cycle && this._idleItems.length > 1) {
                    this._startIdleTimer();
                }
            }
        };
        document.addEventListener('visibilitychange', this._visibilityHandler);

        if (this._config?.idle_backdrop_cycle) {
            if (this._idleItems.length > 1 && !this._idleTimer) {
                this._startIdleTimer();
            } else if (this._idleItems.length === 0 && !this._fetchingIdleItems && this.hass) {
                this._fetchIdleLibraryItems();
            }
        }
    }

    public disconnectedCallback(): void {
        super.disconnectedCallback();
        if (this._resizeObserver) {
            this._resizeObserver.disconnect();
        }
        if (this._layoutCheckRaf) {
            cancelAnimationFrame(this._layoutCheckRaf);
            this._layoutCheckRaf = null;
        }
        this._stopProgressTimer();
        this._endLongPress();
        this._stopIdleTimer();
        if (this._visibilityHandler) {
            document.removeEventListener('visibilitychange', this._visibilityHandler);
            this._visibilityHandler = undefined;
        }
    }

    private _startProgressTimer(): void {
        this._stopProgressTimer();
        this._progressTimer = window.setInterval(() => {
            if (!this.isConnected || !this.hass || !this._config?.entity) return;
            const stateObj = this.hass.states[this._config.entity];
            if (!stateObj) return;
            const isMediaPlayer = this._config.entity.startsWith('media_player.');
            const isPlaying = isMediaPlayer
                ? stateObj.state === 'playing'
                : (!stateObj.attributes?.is_paused && !!stateObj.attributes?.item_id);
            if (isPlaying && !this._isDragging) {
                this.requestUpdate();
            }
        }, 1000);
    }

    private _stopProgressTimer(): void {
        if (this._progressTimer) {
            clearInterval(this._progressTimer);
            this._progressTimer = undefined;
        }
    }

    protected updated(changedProps: PropertyValues): void {
        super.updated(changedProps);
        if (changedProps.has('hass')) {
            this._checkLayout();
            if (this._config?.idle_backdrop_cycle) {
                if (this._idleItems.length === 0 && !this._fetchingIdleItems) {
                    this._fetchIdleLibraryItems();
                } else if (this._config.idle_content_source === 'latest_movie' || this._config.idle_content_source === 'latest_episode' || this._config.idle_content_source === 'latest_both') {
                    // Check if latest sensor changed
                    const movieSensor = (this._config.idle_content_source === 'latest_movie' || this._config.idle_content_source === 'latest_both') ? this._getItemFromLatestSensor('movie') : null;
                    const epSensor = (this._config.idle_content_source === 'latest_episode' || this._config.idle_content_source === 'latest_both') ? this._getItemFromLatestSensor('episode') : null;
                    const currentIds = this._idleItems.map(i => i.id).join(',');
                    const newIds = [movieSensor?.id, epSensor?.id].filter(Boolean).join(',');
                    if (newIds && newIds !== currentIds && !this._fetchingIdleItems) {
                        this._fetchIdleLibraryItems();
                    }
                }
            }
        }
        if (changedProps.has('_config')) {
            const oldConfig = changedProps.get('_config') as JellyHANowPlayingCardConfig | undefined;
            if (!this._config?.idle_backdrop_cycle) {
                this._stopIdleTimer();
            } else {
                const modeChanged = !oldConfig || oldConfig.idle_display_mode !== this._config.idle_display_mode;
                const filterChanged = !oldConfig || oldConfig.idle_media_type !== this._config.idle_media_type;
                const sourceChanged = !oldConfig || oldConfig.idle_content_source !== this._config.idle_content_source;
                const limitChanged = !oldConfig || oldConfig.idle_recent_limit !== this._config.idle_recent_limit;
                if (modeChanged || filterChanged || sourceChanged || limitChanged || this._idleItems.length === 0) {
                    this._idleItems = [];
                    this._stopIdleTimer();
                    this._fetchIdleLibraryItems();
                } else if (oldConfig?.idle_cycle_interval !== this._config.idle_cycle_interval || !this._idleTimer) {
                    this._startIdleTimer();
                }
            }
        }
    }

    private _checkLayout(): void {
        if (this._layoutCheckRaf) {
            cancelAnimationFrame(this._layoutCheckRaf);
        }
        this._layoutCheckRaf = requestAnimationFrame(() => {
            this._layoutCheckRaf = null;
            this._doLayoutCheck();
        });
    }

    private _doLayoutCheck(): void {
        const cardRect = this.getBoundingClientRect();
        const haCard = this.shadowRoot?.querySelector('ha-card');
        if (!haCard || cardRect.height === 0) return;

        // If card is in empty or error state, clear layout classes and exit immediately
        if (haCard.classList.contains('empty-state') || haCard.classList.contains('error-state')) {
            haCard.classList.remove('compact-height', 'micro-height', 'tall-narrow', 'very-tall-narrow');
            return;
        }

        const h = cardRect.height;
        const w = cardRect.width;

        // Hysteresis to prevent threshold oscillation
        const isCompact = haCard.classList.contains('compact-height') ? h <= 200 : h <= 190;
        haCard.classList.toggle('compact-height', isCompact);

        const isMicro = haCard.classList.contains('micro-height') ? h <= 185 : h <= 175;
        haCard.classList.toggle('micro-height', isMicro);

        const isTallNarrow = haCard.classList.contains('tall-narrow')
            ? (h >= 235 && w <= 405)
            : (h >= 245 && w <= 395);
        haCard.classList.toggle('tall-narrow', isTallNarrow);

        const isVeryTallNarrow = haCard.classList.contains('very-tall-narrow')
            ? (h >= 295 && w <= 455)
            : (h >= 305 && w <= 445);
        haCard.classList.toggle('very-tall-narrow', isVeryTallNarrow);

        const titleEl = this.shadowRoot?.querySelector('.title') as HTMLElement;
        const bottomEl = this.shadowRoot?.querySelector('.info-bottom') as HTMLElement;

        if (!titleEl || !bottomEl) return;

        const titleRect = titleEl.getBoundingClientRect();
        const bottomRect = bottomEl.getBoundingClientRect();

        const bottomSectionTop = bottomRect.top - cardRect.top;
        const SAFE_THRESHOLD = bottomSectionTop - 6;

        const titleBottomRel = titleRect.bottom - cardRect.top;

        // Check if this item has an active subtitle
        const stateObj = this._config?.entity ? this.hass?.states[this._config.entity] : null;
        const attrs = stateObj?.attributes as any;
        const itemId = stateObj ? this._extractItemId(stateObj) : null;
        const cachedItem = itemId ? this._resolvedMetadata[itemId] : null;
        const showSubtitle = this._config?.show_subtitle !== false;
        const seriesTitle = attrs?.series_title || attrs?.media_series_title || cachedItem?.series_name || '';
        const subtitle = showSubtitle ? (attrs?.artist_name || attrs?.media_artist || seriesTitle || cachedItem?.artist_name || '') : '';
        const hasSubtitle = !!subtitle;

        let curBottom = titleBottomRel;
        if (hasSubtitle) {
            curBottom += 20; // approximate subtitle height + margin
        }

        const projectedMetaBottom = curBottom + 18;
        const projectedClientBottom = projectedMetaBottom + 16;

        let newState = 0;
        if (projectedClientBottom > SAFE_THRESHOLD) {
            newState = 1; // Hide client-line
        }
        if (projectedMetaBottom > SAFE_THRESHOLD) {
            newState = 2; // Hide meta-line
        }
        if (hasSubtitle && curBottom > SAFE_THRESHOLD) {
            newState = 3; // Hide subtitle
        }

        if (this._overflowState !== newState) {
            this._overflowState = newState;
        }
    }

    private _formatSeconds(sec: number): string {
        const negative = sec < 0;
        const totalSeconds = Math.floor(Math.abs(sec));
        const hours = Math.floor(totalSeconds / 3600);
        const minutes = Math.floor((totalSeconds % 3600) / 60);
        const seconds = totalSeconds % 60;
        const sign = negative ? '-' : '';
        if (hours > 0) {
            return `${sign}${hours}:${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
        }
        return `${sign}${minutes}:${String(seconds).padStart(2, '0')}`;
    }

    private _formatTicks(ticks: number): string {
        return this._formatSeconds(ticks / 10000000);
    }

    static styles = css`
        :host {
            display: block;
            height: 100%;
            width: 100%;
            background: none !important;
            position: relative;
            z-index: 2;
        }
        ha-card {
            height: 100%;
            min-height: 0;
            overflow: hidden;
            position: relative;
            background: var(--ha-card-background, var(--card-background-color, #fff));
            border-radius: var(--ha-card-border-radius, 12px);
            box-shadow: var(--ha-card-box-shadow, none);
            border: var(--ha-card-border, 1px solid var(--ha-card-border-color, var(--divider-color, #e0e0e0)));
            transition: background 0.3s ease-out, border-color 0.3s ease-out, box-shadow 0.3s ease-out;
            container-type: inline-size;
            container-name: now-playing;
            display: flex;
            flex-direction: column;
            box-sizing: border-box;
            padding: 0;
            width: 100%;
            margin: 0;
        }

        .jellyha-now-playing.has-background {
            background: transparent;
            color: white;
        }
        .jellyha-now-playing.has-background .meta-line,
        .jellyha-now-playing.has-background .client-line,
        .jellyha-now-playing.has-background .time-elapsed,
        .jellyha-now-playing.has-background .time-remaining,
        .jellyha-now-playing.has-background .card-header,
        .jellyha-now-playing.has-background ha-icon-button:not(.music-subtle-btn) {
            color: #fff !important;
            text-shadow: 0 1px 4px rgba(0,0,0,0.5);
        }
        .jellyha-now-playing.has-background .poster-badge {
            box-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }
        .jellyha-now-playing.has-background .playback-controls ha-icon-button {
            background: rgba(255, 255, 255, 0.15);
        }
        .jellyha-now-playing.has-background .playback-controls ha-icon-button:hover {
            background: rgba(255, 255, 255, 0.25);
        }
        .jellyha-now-playing.has-background .card-content {
            padding: 18px 20px 14px !important;
        }
        .card-background {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-size: cover;
            background-position: center;
            filter: blur(5px) brightness(0.6);
            transform: scale(1.02);
            z-index: 0;
            transition: background-image 0.5s ease-in-out;
        }
        .card-overlay {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: linear-gradient(to bottom, rgba(0,0,0,0.2) 0%, rgba(0,0,0,0.6) 100%);
            z-index: 1;
        }
        .card-content {
            position: relative;
            z-index: 2;
            padding: 20px !important;
            display: flex;
            flex-direction: column;
            gap: 16px;
            height: 100%;
            box-sizing: border-box;
            overflow: visible;
        }
        .card-header {
            font-size: 1.25rem;
            font-weight: 500;
            color: var(--primary-text-color);
            line-height: 1.2;
            flex: 0 0 auto;
        }
        .main-container {
            display: flex;
            gap: 20px;
            align-items: stretch;
            flex: 1;
            min-height: 0;
            overflow: visible;
        }

        /* --- Poster with overlay badges --- */
        .poster-container {
            flex: 0 0 auto;
            height: 100%;
            aspect-ratio: 2 / 3;
            max-height: 100%;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 8px 16px rgba(0,0,0,0.4);
            transition: transform 0.2s ease-in-out;
            position: relative;
            cursor: pointer;
        }
        .poster-container:hover {
            transform: scale(1.02);
        }
        .poster-container.no-rewind {
            cursor: default;
        }
        .poster-container.no-rewind:hover {
            transform: none;
        }
        .poster-container img {
            width: 100%;
            height: 100%;
            object-fit: cover;
        }

        /* Poster overlay badges — matches Library Card style */
        .poster-badge {
            position: absolute;
            border-radius: 4px;
            color: #fff;
            z-index: 5;
            pointer-events: none;
            white-space: nowrap;
            text-shadow: 0 1px 4px rgba(0, 0, 0, 0.5);
        }
        .media-type-badge {
            top: 6px;
            left: 6px;
            padding: 2px 8px 1px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.3px;
            background: var(--primary-color);
            box-shadow: 0 2px 4px rgba(0,0,0,0.3);
            text-shadow: 0 1px 4px rgba(0, 0, 0, 0.5);
        }
        .media-type-badge.movie,
        .media-type-badge.latest-badge.movie {
            background-color: #AA5CC3;
            color: #ffffff;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
        }
        .media-type-badge.series,
        .media-type-badge.episode,
        .media-type-badge.tvshow,
        .media-type-badge.latest-badge.series,
        .media-type-badge.latest-badge.episode,
        .media-type-badge.latest-badge.tvshow {
            background-color: #F2A218;
            color: #ffffff;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
        }
        .media-type-badge.audio,
        .media-type-badge.latest-badge.audio {
            background-color: #10B981;
            color: #ffffff;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
        }
        .media-type-badge.idle-backdrop-top-badge {
            position: absolute !important;
            top: 14px;
            right: 16px;
            left: auto !important;
            bottom: auto !important;
            z-index: 5;
            margin: 0 !important;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 800;
            letter-spacing: 0.3px;
            text-transform: uppercase;
            padding: 2px 8px 1px 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
            text-shadow: 0 1px 4px rgba(0, 0, 0, 0.5) !important;
            pointer-events: none;
        }
        .media-type-badge.inline-badge {
            position: static !important;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            height: 22px;
            box-sizing: border-box;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 800;
            letter-spacing: 0.3px;
            text-transform: uppercase;
            padding: 0 8px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.4);
            text-shadow: 0 1px 4px rgba(0, 0, 0, 0.5) !important;
            pointer-events: none;
            flex-shrink: 0;
        }

        .rating-badge {
            bottom: 6px;
            right: 6px;
            display: inline-flex;
            align-items: center;
            gap: 2px;
            background: rgba(0, 0, 0, 0.6);
            color: #F59E0B;
            padding: var(--short-badge-padding, 3px 6px);
            font-weight: 600;
            font-size: 0.8rem;
            text-shadow: 0 1px 4px rgba(0, 0, 0, 0.5);
        }
        .rating-badge ha-icon {
            --mdc-icon-size: 13px;
            color: #F59E0B;
            margin-top: -1px;
        }
        .runtime-badge {
            bottom: 6px;
            left: 6px;
            display: inline-flex;
            align-items: center;
            gap: 2px;
            background: rgba(0, 0, 0, 0.6);
            color: rgba(255, 255, 255, 0.85);
            padding: var(--short-badge-padding, 3px 6px);
            font-weight: 600;
            font-size: 0.8rem;
            text-shadow: 0 1px 4px rgba(0, 0, 0, 0.5);
        }
        .runtime-badge ha-icon {
            --mdc-icon-size: 12px;
            color: rgba(255, 255, 255, 0.85);
            margin-top: -1px;
        }

        /* Rewind overlay */
        .rewind-overlay {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.4);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 10;
            animation: fadeIn 0.2s ease-out;
        }
        .rewind-overlay span {
            color: rgba(255, 255, 255, 0.95);
            font-weight: 700;
            font-size: 0.8rem;
            line-height: 1;
            letter-spacing: 0.5px;
            background: rgba(255, 255, 255, 0.15);
            backdrop-filter: blur(4px);
            -webkit-backdrop-filter: blur(4px);
            padding: 7px 10px 5px;
            border-radius: 20px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
            white-space: nowrap;
        }
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        @keyframes spin {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }
        .playback-controls .spinning ha-icon {
            animation: spin 1s linear infinite;
        }

        /* --- Info container --- */
        .info-container {
            flex: 1;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            align-self: stretch;
            min-height: 0;
            min-width: 0;
            overflow: visible;
        }
        .info-top {
            flex: 1 1 auto;
            min-height: 0;
            overflow: visible;
            display: flex;
            flex-direction: column;
            margin-bottom: 0;
            padding-bottom: 4px;
        }
        .header {
            margin-bottom: 0px;
            flex-shrink: 0;
        }

        .title-row {
            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            gap: 8px;
            width: 100%;
        }

        .title-row .title {
            flex: 1 1 auto;
            min-width: 0;
        }

        .media-type-badge.header-badge {
            position: static !important;
            flex-shrink: 0;
            margin-top: 6px;
            border-radius: 4px;
            font-size: 0.8rem;
            letter-spacing: 0.3px;
            padding: 2px 8px 1px 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.3);
            text-shadow: 0 1px 4px rgba(0, 0, 0, 0.5) !important;
            pointer-events: none;
            align-self: flex-start;
        }

        /* 4-line text structure */
        .title {
            font-size: 1.3rem;
            font-weight: 700;
            line-height: 1.2;
            color: var(--card-dominant-color, var(--primary-text-color));
            margin-top: 6px;
            margin-bottom: 2px;
            overflow: hidden;
        }
        .subtitle {
            font-size: 1.05rem;
            color: var(--card-dominant-color, var(--secondary-text-color));
            font-weight: 400;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            margin-bottom: 6px;
        }
        .meta-line {
            display: flex;
            align-items: center;
            flex-wrap: wrap;
            gap: 5px 8px;
            font-size: 0.85rem;
            color: var(--secondary-text-color);
            opacity: 0.85;
            margin-top: 4px;
            margin-bottom: 3px;
            line-height: 1.2;
        }
        .meta-year {
            font-size: 0.85rem;
            font-weight: 500;
        }
        .meta-dot {
            opacity: 0.45;
            font-size: 0.72rem;
            line-height: 1;
        }
        .genre-pill {
            display: inline-flex;
            align-items: center;
            background: rgba(var(--rgb-primary-text-color, 255, 255, 255), 0.08);
            border: 1px solid rgba(var(--rgb-primary-text-color, 255, 255, 255), 0.14);
            padding: 2px 7px;
            border-radius: 4px;
            font-size: 0.80rem;
            color: var(--secondary-text-color);
            line-height: 1.2;
            font-weight: 500;
            white-space: nowrap;
        }
        .has-background .genre-pill {
            background: rgba(255, 255, 255, 0.12);
            border: 1px solid rgba(255, 255, 255, 0.18);
            color: rgba(255, 255, 255, 0.92);
            text-shadow: 0 1px 2px rgba(0, 0, 0, 0.6);
        }
        .client-line {
            font-size: 0.80rem;
            color: var(--secondary-text-color);
            opacity: 0.70;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            margin-top: 7px;
        }

        /* --- Info Bottom: Controls + Progress --- */
        .info-bottom {
            flex: 0 0 auto;
            width: 100%;
            margin-top: auto;
            z-index: 5;
        }

        /* Playback controls (centered) */
        .playback-controls {
            display: flex;
            gap: 8px;
            align-items: center;
            justify-content: center;
            margin-bottom: 6px;
        }
        .playback-controls ha-icon-button:not(.music-subtle-btn) {
            --mdc-icon-button-size: 36px;
            --mdc-icon-size: 22px;
            color: var(--primary-text-color);
            background: rgba(var(--rgb-primary-text-color), 0.05);
            border-radius: 50%;
            transition: background 0.2s;
        }
        .playback-controls ha-icon-button:not(.music-subtle-btn):hover {
            background: rgba(var(--rgb-primary-text-color), 0.1);
        }
        .playback-controls ha-icon-button ha-icon {
            display: flex;
            align-items: center;
            justify-content: center;
        }

        /* Play/Pause button slightly larger */
        .play-pause-wrapper {
            position: relative;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .play-pause-btn {
            --mdc-icon-button-size: 44px !important;
            --mdc-icon-size: 30px !important;
        }

        /* Stop ring SVG */
        .stop-ring {
            position: absolute;
            top: 50%;
            left: 50%;
            width: 44px;
            height: 44px;
            transform: translate(-50%, -50%);
            pointer-events: none;
            z-index: 10;
        }

        /* Subtle music controls (shuffle/repeat) */
        .music-subtle-btn {
            --mdc-icon-button-size: 36px !important;
            --mdc-icon-size: 20px !important;
            opacity: 0.35;
            background: transparent !important;
            border-radius: 50%;
            transition: opacity 0.2s, color 0.2s;
        }
        .music-subtle-btn:hover {
            opacity: 0.7;
        }
        .music-subtle-btn.active {
            color: var(--card-dominant-color, var(--primary-color)) !important;
            opacity: 1 !important;
            background: transparent !important;
        }

        /* Stop confirmed pulse animation */
        .play-pause-wrapper.stop-pulse {
            animation: stopPulse 0.5s ease-out;
            border-radius: 50%;
        }
        @keyframes stopPulse {
            0% { transform: scale(1); box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.5); }
            50% { transform: scale(1.15); box-shadow: 0 0 0 12px rgba(239, 68, 68, 0); }
            100% { transform: scale(1); box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); }
        }

        /* --- Progress bar with seek handle --- */
        .progress-container {
            cursor: pointer;
            position: relative;
            width: 100%;
            padding: 4px 0;
            box-sizing: border-box;
            touch-action: none;
        }
        .progress-container.readonly {
            cursor: default;
        }
        .progress-container.readonly .seek-handle {
            display: none;
        }
        .progress-bar {
            height: 6px;
            background: rgba(var(--rgb-primary-text-color), 0.12);
            border-radius: 0;
            overflow: visible;
            position: relative;
            backdrop-filter: blur(8px);
            -webkit-backdrop-filter: blur(8px);
        }
        .has-background .progress-bar {
            background: rgba(255, 255, 255, 0.15);
        }
        .progress-fill {
            height: 100%;
            border-radius: 0;
            transition: background-color 0.5s ease;
            background: var(--card-dominant-color, var(--primary-color));
            opacity: 0.65;
        }
        .seek-handle {
            position: absolute;
            top: 50%;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            transform: translate(-50%, -50%);
            background: var(--card-dominant-color, var(--primary-color));
            box-shadow: 0 0 4px rgba(0,0,0,0.3);
            pointer-events: none;
            transition: background-color 0.5s ease, transform 0.2s ease;
        }

        /* --- Timestamps below progress bar --- */
        .timestamps {
            display: flex;
            justify-content: space-between;
            margin-top: 2px;
            padding: 0;
        }
        .time-elapsed,
        .time-remaining {
            font-size: 0.75rem;
            color: var(--secondary-text-color);
            opacity: 0.85;
            font-variant-numeric: tabular-nums;
            white-space: nowrap;
        }

        /* --- Empty & Error states --- */
        .empty-state, .error-state {
            text-align: center;
            padding: 20px;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            height: 100%;
            min-height: 140px;
            box-sizing: border-box;
        }
        .empty-state .card-content {
            padding: 0 !important;
            gap: 8px;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            overflow: visible;
            height: auto;
            min-height: 0;
        }
        .empty-state .logo-container.mini-icon {
            display: none;
        }
        .empty-state .logo-container.full-logo {
            display: flex;
            justify-content: center;
            opacity: 0.9;
            margin-bottom: 4px;
        }
        .empty-state img {
            max-width: 200px;
            height: auto;
        }
        .empty-state p {
            margin: 0;
            color: var(--secondary-text-color);
            font-size: 0.9rem;
            opacity: 0.7;
        }


        /* Compact empty state */
        @container now-playing (max-width: 250px) {
            .empty-state {
                padding: 14px 10px !important;
                min-height: 120px !important;
            }
            .empty-state .logo-container.full-logo {
                display: none;
            }
            .empty-state .logo-container.mini-icon {
                display: flex;
                opacity: 0.9;
                margin-bottom: 8px;
            }
            .empty-state img {
                max-width: 64px;
            }
            .empty-state p {
                font-size: 0.85rem;
                line-height: 1.25;
            }
        }

        /* Hide meta/client lines when narrow */
        @container now-playing (max-width: 320px) {
            .meta-line, .client-line {
                display: none !important;
            }
            .title {
                font-size: 1.25rem;
                margin-bottom: 2px;
            }
        }

        /* Adjust layout when very narrow */
        @container now-playing (max-width: 280px) {
            .main-container {
                gap: 12px;
            }
            .title {
                font-size: 1.1rem;
                display: -webkit-box;
                -webkit-line-clamp: 2;
                -webkit-box-orient: vertical;
                overflow: hidden;
                white-space: normal;
            }
            .header-badge {
                font-size: 0.7rem;
                padding: 1px 5px;
            }
        }

        ha-card:not(.empty-state):not(.error-state).compact-height .card-header {
            display: none !important;
        }
        ha-card:not(.empty-state):not(.error-state).compact-height .title {
            font-size: 1.2rem;
            line-height: 1.1;
            margin-bottom: 2px;
        }
        ha-card:not(.empty-state):not(.error-state).compact-height .header-badge {
            margin-top: 2px;
            font-size: 0.75rem;
            padding: 1px 6px;
        }
        ha-card:not(.empty-state):not(.error-state).compact-height .main-container {
            gap: 12px;
        }
        ha-card:not(.empty-state):not(.error-state).compact-height .card-content {
            gap: 8px;
            padding: 12px 16px !important;
        }
        ha-card:not(.empty-state):not(.error-state).compact-height .poster-container {
            min-height: 0;
            --short-badge-padding: 1px !important;
        }

        /* Ultra-Compact Micro Mode (Overlay controls on poster) */
        @container now-playing (max-width: 250px) {
            .card-header {
                display: none !important;
            }
            .poster-badge {
                display: none !important;
            }
            .info-top {
                display: flex !important;
                padding: 0 !important;
                margin: 0 !important;
            }
            .info-top .meta-line, .info-top .client-line {
                display: none !important;
            }
            .info-top .title {
                font-size: 1.10rem !important;
                line-height: 1.1;
                margin-bottom: 2px !important;
                color: var(--card-dominant-color, white) !important;
                text-shadow: 0 1px 3px rgba(0,0,0,0.8) !important;
                overflow: hidden;
                display: -webkit-box;
                -webkit-line-clamp: 2;
                -webkit-box-orient: vertical;
                white-space: normal !important;
            }
            .info-top .subtitle {
                font-size: 0.95rem !important;
                color: var(--card-dominant-color, rgba(255, 255, 255, 0.8)) !important;
                text-shadow: 0 1px 3px rgba(0,0,0,0.8) !important;
                margin-bottom: 0 !important;
                overflow: hidden;
                white-space: nowrap !important;
                text-overflow: ellipsis !important;
                opacity: 0.9;
            }
            .card-content {
                padding: 10px !important;
                justify-content: center;
                gap: 0;
            }
            .main-container {
                justify-content: center;
                gap: 0;
                position: relative;
                width: max-content;
                margin: 0 auto;
                border-radius: 8px;
                transition: transform 0.2s ease-in-out;
            }
            .main-container:hover {
                transform: scale(1.02);
            }
            .poster-container {
                flex: 0 0 auto !important;
                height: 100% !important;
                aspect-ratio: 2 / 3;
                box-shadow: 0 4px 12px rgba(0,0,0,0.5);
            }
            .poster-container:hover {
                transform: none;
            }
            .info-container {
                position: absolute;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                transform: none;
                background: linear-gradient(to bottom, rgba(0,0,0,0.7) 0%, rgba(0,0,0,0.2) 20%, transparent 50%, rgba(0,0,0,0.2) 80%, rgba(0,0,0,0.7) 100%);
                display: flex;
                flex-direction: column;
                justify-content: space-between;
                border-radius: 8px;
                padding: 12px 10px 4px 10px;
                box-sizing: border-box;
                pointer-events: none;
                z-index: 5;
                overflow: visible;
            }
            .info-bottom {
                pointer-events: auto;
                flex: 0 0 auto;
            }
            .playback-controls {
                margin-bottom: 4px;
            }
            .playback-controls ha-icon-button:not(.music-subtle-btn) {
                --mdc-icon-button-size: 36px;
                --mdc-icon-size: 24px;
                background: rgba(255, 255, 255, 0.25) !important;
                color: white !important;
            }
            .playback-controls ha-icon-button:not(.music-subtle-btn):hover {
                background: rgba(255, 255, 255, 0.4) !important;
            }
            .playback-controls .play-pause-btn {
                background: rgba(255, 255, 255, 0.25) !important;
            }
            .playback-controls .play-pause-btn:hover {
                background: rgba(255, 255, 255, 0.4) !important;
            }
            .progress-container {
                padding: 0;
            }
            .progress-bar {
                height: 5px; /* Thicker bar */
                border-radius: 2.5px;
            }
            .seek-handle {
                width: 10px;
                height: 10px;
            }
            .timestamps {
                margin-top: 2px;
                padding: 0;
                justify-content: space-between !important;
            }
            .time-elapsed,
            .time-remaining {
                color: rgba(255, 255, 255, 0.8);
                text-shadow: 0 1px 3px rgba(0,0,0,0.5);
                font-size: 0.7rem;
            }
            .rewind-overlay span {
                font-size: 0.75rem !important;
                line-height: 1 !important;
                padding: 5px 8px 4px !important;
                white-space: nowrap;
            }
        }

        /* Height-Based Compact Mode */
        ha-card:not(.empty-state):not(.error-state).micro-height {
            .card-header {
                display: none !important;
            }
            .info-top {
                display: flex !important;
                padding: 0 !important;
                margin: 0 !important;
            }
            .info-top .meta-line, .info-top .client-line {
                display: none !important;
            }
            .info-top .title {
                font-size: 1.25rem !important;
                line-height: 1.1;
                margin-bottom: 2px !important;
                color: var(--card-dominant-color, white) !important;
                text-shadow: 0 1px 3px rgba(0,0,0,0.8) !important;
                overflow: hidden;
                display: -webkit-box;
                -webkit-line-clamp: 2;
                -webkit-box-orient: vertical;
                white-space: normal !important;
            }
            .info-top .subtitle {
                font-size: 0.95rem !important;
                color: var(--card-dominant-color, rgba(255, 255, 255, 0.8)) !important;
                text-shadow: 0 1px 3px rgba(0,0,0,0.8) !important;
                margin-bottom: 0 !important;
                overflow: hidden;
                white-space: nowrap !important;
                text-overflow: ellipsis !important;
                opacity: 0.9;
            }
            .card-content {
                padding: 10px !important;
                justify-content: center;
                gap: 0;
            }
            .main-container {
                justify-content: center;
                gap: 0;
                position: relative;
                width: max-content;
                margin: 0 auto;
                border-radius: 8px;
                transition: transform 0.2s ease-in-out;
            }
            .main-container:hover {
                transform: scale(1.02);
            }
            .poster-container {
                flex: 0 0 auto !important;
                height: 100% !important;
                aspect-ratio: 2 / 3;
                box-shadow: 0 4px 12px rgba(0,0,0,0.5);
            }
            .poster-container:hover {
                transform: none;
            }
            .info-container {
                position: absolute;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                transform: none;
                background: linear-gradient(to bottom, rgba(0,0,0,0.7) 0%, rgba(0,0,0,0.2) 20%, transparent 50%, rgba(0,0,0,0.2) 80%, rgba(0,0,0,0.7) 100%);
                display: flex;
                flex-direction: column;
                justify-content: space-between;
                border-radius: 8px;
                padding: 12px 10px 4px 10px;
                box-sizing: border-box;
                pointer-events: none;
                z-index: 5;
                overflow: visible;
            }
            .info-bottom {
                pointer-events: auto;
                flex: 0 0 auto;
            }
            .playback-controls {
                margin-bottom: 4px;
            }
            .playback-controls ha-icon-button:not(.music-subtle-btn) {
                --mdc-icon-button-size: 36px;
                --mdc-icon-size: 24px;
                background: rgba(255, 255, 255, 0.25) !important;
                color: white !important;
            }
            .playback-controls ha-icon-button:not(.music-subtle-btn):hover {
                background: rgba(255, 255, 255, 0.4) !important;
            }
            .playback-controls .play-pause-btn {
                background: rgba(255, 255, 255, 0.25) !important;
            }
            .playback-controls .play-pause-btn:hover {
                background: rgba(255, 255, 255, 0.4) !important;
            }
            .progress-container {
                padding: 0 4px;
            }
            .progress-bar {
                height: 5px;
                border-radius: 2.5px;
            }
            .seek-handle {
                width: 10px;
                height: 10px;
            }
            .timestamps {
                margin-top: 2px;
                padding: 0 4px;
                justify-content: space-between !important;
            }
            .time-elapsed,
            .time-remaining {
                color: rgba(255, 255, 255, 0.8);
                text-shadow: 0 1px 3px rgba(0,0,0,0.5);
                font-size: 0.7rem;
            }
            .rewind-overlay span {
                font-size: 0.75rem !important;
                line-height: 1 !important;
                padding: 5px 8px 4px !important;
                white-space: nowrap;
            }
        }

        /* Tall but Narrow Mode */
        ha-card:not(.empty-state):not(.error-state).tall-narrow {
            .card-header {
                display: none !important;
            }
            .poster-badge {
                display: none !important;
            }
            .info-top {
                display: flex !important;
                padding: 0 !important;
                margin: 0 !important;
            }
            .info-top .meta-line, .info-top .client-line {
                display: none !important;
            }
            .info-top .title {
                font-size: 1.25rem !important;
                line-height: 1.1;
                margin-bottom: 2px !important;
                color: var(--card-dominant-color, white) !important;
                text-shadow: 0 1px 3px rgba(0,0,0,0.8) !important;
                overflow: hidden;
                display: -webkit-box;
                -webkit-line-clamp: 2;
                -webkit-box-orient: vertical;
                white-space: normal !important;
            }
            .info-top .subtitle {
                font-size: 0.95rem !important;
                color: var(--card-dominant-color, rgba(255, 255, 255, 0.8)) !important;
                text-shadow: 0 1px 3px rgba(0,0,0,0.8) !important;
                margin-bottom: 0 !important;
                overflow: hidden;
                white-space: nowrap !important;
                text-overflow: ellipsis !important;
                opacity: 0.9;
            }
            .card-content {
                padding: 10px !important;
                justify-content: center;
                gap: 0;
            }
            .main-container {
                justify-content: center;
                gap: 0;
                position: relative;
                width: max-content;
                margin: 0 auto;
                border-radius: 8px;
                transition: transform 0.2s ease-in-out;
            }
            .main-container:hover {
                transform: scale(1.02);
            }
            .poster-container {
                flex: 0 0 auto !important;
                height: 100% !important;
                aspect-ratio: 2 / 3;
                box-shadow: 0 4px 12px rgba(0,0,0,0.5);
            }
            .poster-container:hover {
                transform: none;
            }
            .info-container {
                position: absolute;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                transform: none;
                background: linear-gradient(to bottom, rgba(0,0,0,0.7) 0%, rgba(0,0,0,0.2) 20%, transparent 50%, rgba(0,0,0,0.2) 80%, rgba(0,0,0,0.7) 100%);
                display: flex;
                flex-direction: column;
                justify-content: space-between;
                border-radius: 8px;
                padding: 12px 10px 4px 10px;
                box-sizing: border-box;
                pointer-events: none;
                z-index: 5;
                overflow: visible;
            }
            .info-bottom {
                pointer-events: auto;
                flex: 0 0 auto;
            }
            .playback-controls {
                margin-bottom: 4px;
            }
            .playback-controls ha-icon-button:not(.music-subtle-btn) {
                --mdc-icon-button-size: 36px;
                --mdc-icon-size: 24px;
                background: rgba(255, 255, 255, 0.25) !important;
                color: white !important;
            }
            .playback-controls ha-icon-button:not(.music-subtle-btn):hover {
                background: rgba(255, 255, 255, 0.4) !important;
            }
            .playback-controls .play-pause-btn {
                background: rgba(255, 255, 255, 0.25) !important;
            }
            .playback-controls .play-pause-btn:hover {
                background: rgba(255, 255, 255, 0.4) !important;
            }
            .progress-container {
                padding: 0 4px;
            }
            .progress-bar {
                height: 5px;
                border-radius: 2.5px;
            }
            .seek-handle {
                width: 10px;
                height: 10px;
            }
            .timestamps {
                margin-top: 2px;
                padding: 0 4px;
                justify-content: space-between !important;
            }
            .time-elapsed,
            .time-remaining {
                color: rgba(255, 255, 255, 0.8);
                text-shadow: 0 1px 3px rgba(0,0,0,0.5);
                font-size: 0.7rem;
            }
            .rewind-overlay span {
                font-size: 0.75rem !important;
                line-height: 1 !important;
                padding: 5px 8px 4px !important;
                white-space: nowrap;
            }
        }

        /* Very Tall but Narrow Mode */
        ha-card:not(.empty-state):not(.error-state).very-tall-narrow {
            .card-header {
                display: none !important;
            }
            .poster-badge {
                display: none !important;
            }
            .info-top {
                display: flex !important;
                padding: 0 !important;
                margin: 0 !important;
            }
            .info-top .meta-line, .info-top .client-line {
                display: none !important;
            }
            .info-top .title {
                font-size: 1.25rem !important;
                line-height: 1.1;
                margin-bottom: 2px !important;
                color: var(--card-dominant-color, white) !important;
                text-shadow: 0 1px 3px rgba(0,0,0,0.8) !important;
                overflow: hidden;
                display: -webkit-box;
                -webkit-line-clamp: 2;
                -webkit-box-orient: vertical;
                white-space: normal !important;
            }
            .info-top .subtitle {
                font-size: 0.95rem !important;
                color: var(--card-dominant-color, rgba(255, 255, 255, 0.8)) !important;
                text-shadow: 0 1px 3px rgba(0,0,0,0.8) !important;
                margin-bottom: 0 !important;
                overflow: hidden;
                white-space: nowrap !important;
                text-overflow: ellipsis !important;
                opacity: 0.9;
            }
            .card-content {
                padding: 10px !important;
                justify-content: center;
                gap: 0;
            }
            .main-container {
                justify-content: center;
                gap: 0;
                position: relative;
                width: max-content;
                margin: 0 auto;
                border-radius: 8px;
                transition: transform 0.2s ease-in-out;
            }
            .main-container:hover {
                transform: scale(1.02);
            }
            .poster-container {
                flex: 0 0 auto !important;
                height: 100% !important;
                aspect-ratio: 2 / 3;
                box-shadow: 0 4px 12px rgba(0,0,0,0.5);
            }
            .poster-container:hover {
                transform: none;
            }
            .info-container {
                position: absolute;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                transform: none;
                background: linear-gradient(to bottom, rgba(0,0,0,0.85) 0%, rgba(0,0,0,0.3) 25%, transparent 45%, transparent 55%, rgba(0,0,0,0.4) 75%, rgba(0,0,0,0.7) 100%);
                display: flex;
                flex-direction: column;
                justify-content: space-between;
                border-radius: 8px;
                padding: 10px;
                box-sizing: border-box;
                pointer-events: none;
                z-index: 5;
                overflow: visible;
            }
            .info-bottom {
                pointer-events: auto;
                flex: 0 0 auto;
            }
            .playback-controls {
                margin-bottom: 8px;
            }
            .playback-controls ha-icon-button:not(.music-subtle-btn) {
                --mdc-icon-button-size: 36px;
                --mdc-icon-size: 24px;
                background: rgba(255, 255, 255, 0.25) !important;
                color: white !important;
            }
            .playback-controls ha-icon-button:not(.music-subtle-btn):hover {
                background: rgba(255, 255, 255, 0.4) !important;
            }
            .playback-controls .play-pause-btn {
                background: rgba(255, 255, 255, 0.25) !important;
            }
            .playback-controls .play-pause-btn:hover {
                background: rgba(255, 255, 255, 0.4) !important;
            }
            .progress-container {
                padding: 0 4px;
            }
            .progress-bar {
                height: 5px;
                border-radius: 2.5px;
            }
            .seek-handle {
                width: 10px;
                height: 10px;
            }
            .timestamps {
                margin-top: 5px;
                padding: 0 4px;
                justify-content: space-between !important;
            }
            .time-elapsed,
            .time-remaining {
                color: rgba(255, 255, 255, 0.8);
                text-shadow: 0 1px 3px rgba(0,0,0,0.5);
                font-size: 0.7rem;
            }
            .rewind-overlay span {
                font-size: 0.75rem !important;
                line-height: 1 !important;
                padding: 5px 8px 4px !important;
                white-space: nowrap;
            }
        }

        /* =========================================================================
           Ambient Idle Showcase Styles
           ========================================================================= */
        .idle-showcase-card {
            position: relative;
            min-height: 180px;
            overflow: hidden;
            display: flex;
            flex-direction: column;
            justify-content: flex-end !important;
            box-sizing: border-box;
            cursor: default;
            user-select: none;
            border-radius: var(--ha-card-border-radius, 12px);
            background: #111;
        }

        .idle-backdrop-container {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            overflow: hidden;
            pointer-events: none;
        }

        .idle-backdrop-img {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            object-fit: cover;
            object-position: center;
            opacity: 1;
            transition: opacity 0.8s ease-in-out;
            will-change: opacity;
        }

        .idle-backdrop-img.prev-backdrop {
            z-index: 2;
        }

        .idle-backdrop-img.prev-backdrop.fade-out {
            opacity: 0;
        }

        .idle-backdrop-scrim {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: linear-gradient(
                180deg,
                rgba(0, 0, 0, 0.4) 0%,
                rgba(0, 0, 0, 0) 25%,
                rgba(0, 0, 0, 0.05) 45%,
                rgba(0, 0, 0, 0.6) 70%,
                rgba(0, 0, 0, 0.94) 100%
            );
            pointer-events: none;
            z-index: 3;
        }

        .idle-bottom-content {
            position: relative;
            z-index: 4;
            padding: 16px 20px 20px 20px;
            display: flex;
            flex-direction: column;
            gap: 0 !important;
            margin-top: auto;
        }

        ha-card .idle-title,
        .idle-title {
            margin: 0 !important;
            padding: 0 !important;
            font-size: 1.35rem;
            font-weight: 700;
            line-height: 1.2;
            color: #ffffff;
            text-shadow: 0 2px 6px rgba(0, 0, 0, 0.85);
            display: -webkit-box;
            -webkit-line-clamp: 2;
            -webkit-box-orient: vertical;
            overflow: hidden;
        }

        .idle-meta-row {
            display: flex;
            align-items: center;
            flex-wrap: wrap;
            gap: 6px 8px;
            font-size: 0.85rem;
            color: rgba(255, 255, 255, 0.85);
            text-shadow: 0 1px 3px rgba(0, 0, 0, 0.85);
            margin: 4px 0 7px 0 !important;
            line-height: 1;
        }

        .idle-meta-text {
            display: inline-flex;
            align-items: center;
            height: 22px;
            line-height: 1;
            font-size: 0.85rem;
            font-weight: 500;
            transform: translateY(1px);
        }

        .idle-dot {
            opacity: 0.5;
            font-size: 0.72rem;
            display: inline-flex;
            align-items: center;
            height: 22px;
            line-height: 1;
            transform: translateY(0.5px);
        }

        .idle-rating-pill {
            display: inline-flex;
            align-items: center;
            gap: 3px;
            background: rgba(245, 158, 11, 0.25);
            border: 1px solid rgba(245, 158, 11, 0.45);
            color: #fbbf24;
            height: 22px;
            padding: 0 6px;
            border-radius: 4px;
            font-size: 0.78rem;
            font-weight: 700;
            line-height: 1;
            box-sizing: border-box;
            flex-shrink: 0;
        }

        .idle-rating-pill ha-icon {
            --mdc-icon-size: 12px;
            width: 12px;
            height: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-top: -1px;
            flex-shrink: 0;
        }

        .idle-rating-pill span {
            display: inline-flex;
            align-items: center;
            line-height: 1;
            transform: translateY(0.5px);
        }

        .idle-genre-pill {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            background: rgba(255, 255, 255, 0.12);
            border: 1px solid rgba(255, 255, 255, 0.16);
            height: 22px;
            padding: 0 7px;
            border-radius: 4px;
            font-size: 0.78rem;
            color: rgba(255, 255, 255, 0.9);
            line-height: 1;
            box-sizing: border-box;
            flex-shrink: 0;
        }

        .idle-overview {
            margin: 2px 0 0 0 !important;
            font-size: 0.8rem;
            line-height: 1.35;
            color: rgba(255, 255, 255, 0.72);
            text-shadow: 0 1px 3px rgba(0, 0, 0, 0.85);
            display: -webkit-box;
            -webkit-line-clamp: 2;
            -webkit-box-orient: vertical;
            overflow: hidden;
        }

        .idle-card-mode {
            cursor: default;
        }

        .idle-card-mode .info-container {
            justify-content: flex-start;
        }

        .idle-card-mode .poster-container {
            position: relative;
            overflow: hidden;
        }

        .idle-card-mode .poster-container .idle-poster-img {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            object-fit: cover;
            border-radius: 8px;
        }

        .idle-card-mode .poster-container .idle-poster-img.prev-poster {
            z-index: 2;
            opacity: 1;
            transition: opacity 0.8s ease-in-out;
            will-change: opacity;
        }

        .idle-card-mode .poster-container .idle-poster-img.prev-poster.fade-out {
            opacity: 0;
        }

        .idle-card-mode .idle-card-bg-container {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            overflow: hidden;
            pointer-events: none;
            z-index: 0;
            border-radius: var(--ha-card-border-radius, 12px);
            background: #111;
        }

        .idle-card-mode .idle-card-bg-img {
            position: absolute;
            top: -5%;
            left: -5%;
            width: 110%;
            height: 110%;
            object-fit: cover;
            object-position: center;
            filter: blur(5px) brightness(0.6);
            opacity: 1;
        }

        .idle-card-mode .idle-card-bg-img.prev-bg {
            z-index: 1;
            opacity: 1;
            transition: opacity 0.8s ease-in-out;
            will-change: opacity;
        }

        .idle-card-mode .idle-card-bg-img.prev-bg.fade-out {
            opacity: 0;
        }

        .idle-card-mode .title {
            margin-top: 4px;
            margin-bottom: 0;
            line-height: 1.25;
        }

        .idle-showcase-card .subtitle-row,
        .idle-card-mode .subtitle-row {
            margin-top: 5px;
            margin-bottom: 0;
        }

        .idle-showcase-card .subtitle,
        .idle-card-mode .subtitle {
            font-size: 0.95rem;
            font-weight: 500;
            color: rgba(255, 255, 255, 0.78);
            letter-spacing: 0.2px;
            text-shadow: 0 1px 3px rgba(0, 0, 0, 0.85);
            margin: 0;
            line-height: 1.25;
            display: inline-block;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            max-width: 100%;
        }

        /* Movie / no subtitle: Title followed directly by meta row */
        .idle-card-mode .title-row + .idle-meta-row,
        .idle-showcase-card .title-row + .idle-meta-row {
            margin-top: 8px !important;
            margin-bottom: 6px !important;
        }

        /* Episode / with subtitle: Subtitle row followed by meta row */
        .idle-card-mode .subtitle-row + .idle-meta-row,
        .idle-showcase-card .subtitle-row + .idle-meta-row {
            margin-top: 5px !important;
            margin-bottom: 6px !important;
        }

        .idle-card-desc {
            font-size: 0.82rem;
            color: rgba(255, 255, 255, 0.72);
            line-height: 1.35;
            margin-top: 2px;
            display: -webkit-box;
            -webkit-line-clamp: 3;
            -webkit-box-orient: vertical;
            overflow: hidden;
            text-shadow: 0 1px 2px rgba(0, 0, 0, 0.8);
        }

        @container now-playing (max-width: 320px) {
            .idle-overview {
                display: none !important;
            }
            .idle-title {
                font-size: 1.15rem !important;
            }
        }

        @container now-playing (max-width: 250px) {
            .idle-meta-row .idle-genre-pill {
                display: none !important;
            }
            .idle-bottom-content {
                padding: 10px !important;
            }
            .idle-title {
                font-size: 1rem !important;
            }
        }

    `;

}
