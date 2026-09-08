import { LitElement, html, TemplateResult, css, PropertyValues, nothing } from 'lit';
import { customElement, property, state } from 'lit/decorators.js';
import {
    HomeAssistant,
    JellyHANowPlayingCardConfig,
    NowPlayingSensorData
} from '../shared/types';
import { localize } from '../shared/localize';
import { formatRuntime, addImageParams } from '../shared/utils';

// Import editor for side effects
import '../editors/jellyha-now-playing-editor';

// Register card in the custom cards array
window.customCards = window.customCards || [];
window.customCards.push({
    type: 'jellyha-now-playing-card',
    name: 'JellyHA Now Playing',
    description: 'Display currently playing media from Jellyfin',
    preview: true,
});

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
    private _optimisticSeekTimer?: number;
    private _longPressRaf: number | null = null;
    private _longPressConsumed: boolean = false;
    private _resizeObserver?: ResizeObserver;

    private _cachedBackdropUrl: string | undefined;
    private _cachedItemId: string | undefined;
    private _cachedColorItemId: string | undefined;
    private _optimisticFavorites: Record<string, boolean> = {};

    public setConfig(config: JellyHANowPlayingCardConfig): void {
        this._config = {
            show_title: true,
            show_media_type_badge: true,
            show_year: true,
            show_client: true,
            show_user: true,
            show_time: false,
            show_background: true,
            show_genres: true,
            show_ratings: true,
            show_runtime: true,
            use_series_image: false,
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
            show_media_type_badge: true,
            show_year: true,
            show_client: true,
            show_user: true,
            show_time: false,
            show_background: true,
            show_genres: true,
            show_ratings: true,
            show_runtime: true,
            use_series_image: false,
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
            min_rows: 3,
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
            return this._renderEmpty();
        }

        const progressPercent = this._optimisticSeekPercent !== null ? this._optimisticSeekPercent : (attributes.progress_percent || 0);

        // Use series image if configured and available, otherwise use episode/movie image
        const rawImageUrl = this._config.use_series_image && attributes.series_image_url
            ? attributes.series_image_url
            : (attributes.image_url || (stateObj.attributes as any).entity_picture);
        const imageUrl = rawImageUrl;

        // Cache backdrop URL to prevent flicker - only update when item changes
        const currentItemId = attributes.item_id || (stateObj.attributes as any).media_content_id;
        if (currentItemId !== this._cachedItemId) {
            this._cachedItemId = currentItemId;
            const rawBackdropUrl = attributes.backdrop_url || rawImageUrl;
            this._cachedBackdropUrl = rawBackdropUrl ? addImageParams(rawBackdropUrl, 640) : undefined;
        }

        // Extract dominant color when item changes
        if (currentItemId !== this._cachedColorItemId && imageUrl) {
            this._cachedColorItemId = currentItemId;
            this._extractDominantColor(addImageParams(imageUrl, 80));
        }

        const backdropUrl = this._cachedBackdropUrl;
        const showBackground = this._config.show_background && backdropUrl;
        const isPaused = isMediaPlayer ? stateObj.state === 'paused' : attributes.is_paused;
        const mediaType = (attributes.media_type || (stateObj.attributes as any).media_content_type || '').toLowerCase();
        const isMusic = mediaType === 'audio' || mediaType === 'music';

        const displayTitle = attributes.title || (stateObj.attributes as any).media_title || '';
        const showSubtitle = this._config.show_subtitle !== false;
        const subtitle = showSubtitle ? (attributes.artist_name || (stateObj.attributes as any).media_artist || attributes.series_title || (stateObj.attributes as any).media_series_title || '') : '';
        const yearStr = (this._config.show_year !== false && attributes.year) ? String(attributes.year) : '';
        const genreStr = (this._config.show_genres && attributes.genres?.length) ? attributes.genres.slice(0, 2).join(', ') : '';
        const metaLine = [yearStr, genreStr].filter(Boolean).join(' • ');
        const userName = (this._config.show_user !== false) ? (attributes.user_name || '') : '';
        const clientInfo = (this._config.show_client !== false) ? (attributes.client || '') : '';

        // Media type badge text
        const season = attributes.season !== undefined ? attributes.season : (stateObj.attributes as any).media_season;
        const episode = attributes.episode !== undefined ? attributes.episode : (stateObj.attributes as any).media_episode;
        const badgeText = ((mediaType === 'episode' || mediaType === 'tvshow') && season !== undefined && episode !== undefined)
            ? `S${String(season).padStart(2, '0')}E${String(episode).padStart(2, '0')}`
            : attributes.media_type || '';

        // Determine effective favorite status using optimistic override if available
        const isFavorite = currentItemId && this._optimisticFavorites[currentItemId] !== undefined
            ? this._optimisticFavorites[currentItemId]
            : (attributes.is_favorite || false);

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
                                
                                ${this._config.show_media_type_badge !== false && badgeText ? html`
                                    <span class="poster-badge media-type-badge ${mediaType}">${badgeText}</span>
                                ` : nothing}
                                ${this._config.show_ratings && attributes.community_rating ? html`
                                    <span class="poster-badge rating-badge">
                                        <ha-icon icon="mdi:star"></ha-icon>
                                        ${attributes.community_rating.toFixed(1)}
                                    </span>
                                ` : nothing}
                                ${this._config.show_runtime && attributes.runtime_minutes ? html`
                                    <span class="poster-badge runtime-badge">
                                        <ha-icon icon="mdi:clock-outline"></ha-icon>
                                        ${mediaType === 'audio' && attributes.duration_ticks
                        ? `${Math.floor(attributes.duration_ticks / 10000000 / 60)}m ${Math.floor((attributes.duration_ticks / 10000000) % 60)}s`
                        : formatRuntime(attributes.runtime_minutes)}
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
                                    ${this._config.show_title !== false ? html`<div class="title">${displayTitle}</div>` : nothing}
                                    ${subtitle ? html`<div class="subtitle">${subtitle}</div>` : nothing}
                                    ${this._overflowState < 1 && metaLine ? html`<div class="meta-line">${metaLine}</div>` : nothing}
                                    ${this._overflowState < 1 && (userName || clientInfo) ? html`<div class="client-line">${userName ? html`<strong>${userName}</strong>` : nothing}${userName && clientInfo ? ' ' : ''}${clientInfo || nothing}</div>` : nothing}
                                </div>
                            </div>

                            <div class="info-bottom">
                                ${supportsRemote ? html`
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

                                ${this._config.show_time && attributes.duration_ticks ? html`
                                    <div class="timestamps">
                                        <span class="time-elapsed">${this._formatTicks(attributes.position_ticks || 0)}</span>
                                        <span class="time-remaining">${this._formatTicks(-((attributes.duration_ticks || 0) - (attributes.position_ticks || 0)))}</span>
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

    private _renderError(error: string): TemplateResult {
        return html`
            <ha-card class="error-state">
                <div class="card-content">
                    <p>${error}</p>
                </div>
            </ha-card>
        `;
    }

    private _supportsRemote(stateObj?: HassEntity | null): boolean {
        if (!stateObj) return false;
        if (this._config.show_controls === false) return false;
        if (this._config.show_controls === true) return true;
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
        container.releasePointerCapture(e.pointerId);
        this._isDragging = false;
    }

    private async _endDrag(e: PointerEvent): Promise<void> {
        if (!this._isDragging) return;
        const container = e.currentTarget as HTMLElement;
        container.releasePointerCapture(e.pointerId);
        this._isDragging = false;

        const finalPercent = this._getDragPercent(e);

        // Hold the seeked position optimistically until server catches up
        this._setOptimisticSeek(finalPercent);

        const entityId = this._config.entity;
        const stateObj = this.hass.states[entityId];
        if (!stateObj) return;

        const attributes = stateObj.attributes as unknown as NowPlayingSensorData;
        const sessionId = attributes.session_id;
        const durationTicks = attributes.duration_ticks;

        if (!durationTicks) return;

        if (entityId.startsWith('media_player.')) {
            const seekSeconds = Math.round((durationTicks / 10000000) * (finalPercent / 100));
            await this.hass.callService('media_player', 'media_seek', {
                entity_id: entityId,
                seek_position: seekSeconds
            });
            return;
        }

        if (!sessionId) return;

        const seekTicks = Math.round(durationTicks * (finalPercent / 100));

        await this.hass.callService('jellyha', 'session_seek', {
            entity_id: entityId,
            session_id: sessionId,
            position_ticks: seekTicks
        });
    }

    private _setOptimisticSeek(percent: number): void {
        if (this._optimisticSeekTimer) clearTimeout(this._optimisticSeekTimer);
        this._optimisticSeekPercent = percent;
        this._optimisticSeekTimer = window.setTimeout(() => {
            this._optimisticSeekPercent = null;
        }, 3000);
    }

    private async _handleSeekRelative(seconds: number): Promise<void> {
        this._haptic('light');
        const entityId = this._config.entity;
        const stateObj = this.hass.states[entityId];
        if (!stateObj || !this._supportsRemote(stateObj)) return;

        const attributes = stateObj.attributes as unknown as NowPlayingSensorData;
        const sessionId = attributes.session_id;
        const positionTicks = attributes.position_ticks || 0;

        const seekTicks = seconds * 10000000; // Convert seconds to ticks
        const newPositionTicks = Math.max(0, positionTicks + seekTicks);

        // Hold the seeked position optimistically to prevent jump back
        const durationTicks = attributes.duration_ticks;
        if (durationTicks) {
            this._setOptimisticSeek((newPositionTicks / durationTicks) * 100);
        }

        if (entityId.startsWith('media_player.')) {
            const newPositionSeconds = Math.round(newPositionTicks / 10000000);
            await this.hass.callService('media_player', 'media_seek', {
                entity_id: entityId,
                seek_position: newPositionSeconds
            });
            return;
        }

        if (!sessionId) return;

        await this.hass.callService('jellyha', 'session_seek', {
            entity_id: entityId,
            session_id: sessionId,
            position_ticks: newPositionTicks
        });
    }

    private async _handlePosterRewind(): Promise<void> {
        const entityId = this._config.entity;
        const stateObj = this.hass.states[entityId];
        if (!stateObj || !this._supportsRemote(stateObj)) return;

        const attributes = stateObj.attributes as unknown as NowPlayingSensorData;
        const sessionId = attributes.session_id;
        const positionTicks = attributes.position_ticks || 0;

        // Visual feedback
        this._rewindActive = true;
        setTimeout(() => {
            this._rewindActive = false;
        }, 1000);

        // Haptic feedback
        this._haptic('selection');

        // Calculate rewind position (20 seconds = 200,000,000 ticks)
        const rewindTicks = 20 * 10000000; // 20 seconds in ticks
        const newPositionTicks = Math.max(0, positionTicks - rewindTicks);

        // Hold the seeked position optimistically to prevent jump back
        const durationTicks = attributes.duration_ticks;
        if (durationTicks) {
            this._setOptimisticSeek((newPositionTicks / durationTicks) * 100);
        }

        if (entityId.startsWith('media_player.')) {
            const newPositionSeconds = Math.round(newPositionTicks / 10000000);
            await this.hass.callService('media_player', 'media_seek', {
                entity_id: entityId,
                seek_position: newPositionSeconds
            });
            return;
        }

        if (!sessionId) return;

        await this.hass.callService('jellyha', 'session_seek', {
            entity_id: entityId,
            session_id: sessionId,
            position_ticks: newPositionTicks
        });
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
    }

    public disconnectedCallback(): void {
        super.disconnectedCallback();
        if (this._resizeObserver) {
            this._resizeObserver.disconnect();
        }
        this._endLongPress();
    }

    protected updated(changedProps: PropertyValues): void {
        super.updated(changedProps);
        if (changedProps.has('hass')) {
            this._checkLayout();
        }
    }

    private _checkLayout(): void {
        requestAnimationFrame(() => {
            this._doLayoutCheck();
        });
    }

    private _doLayoutCheck(): void {
        const titleEl = this.shadowRoot?.querySelector('.title') as HTMLElement;
        const bottomEl = this.shadowRoot?.querySelector('.info-bottom') as HTMLElement;

        if (!titleEl || !bottomEl) return;

        const cardRect = this.getBoundingClientRect();
        const titleRect = titleEl.getBoundingClientRect();
        const bottomRect = bottomEl.getBoundingClientRect();

        const bottomSectionTop = bottomRect.top - cardRect.top;
        const SAFE_THRESHOLD = bottomSectionTop - 8;

        // Estimated heights for meta-line and client-line
        const PROJECTED_META_HEIGHT = 20;
        const PROJECTED_CLIENT_HEIGHT = 18;

        const titleBottomRel = titleRect.bottom - cardRect.top;

        // Check if subtitle + meta-line + client-line would overflow
        const projectedSubtitleBottom = titleBottomRel + 22; // subtitle height
        const projectedMetaBottom = projectedSubtitleBottom + PROJECTED_META_HEIGHT;
        const projectedClientBottom = projectedMetaBottom + PROJECTED_CLIENT_HEIGHT;

        let newState = 0;

        if (projectedClientBottom > SAFE_THRESHOLD) {
            newState = 1; // Hide meta-line and client-line
        }

        if (projectedSubtitleBottom > SAFE_THRESHOLD) {
            newState = 2; // Hide subtitle too
        }

        if (this._overflowState !== newState) {
            this._overflowState = newState;
        }
    }

    private _formatTicks(ticks: number): string {
        const negative = ticks < 0;
        const totalSeconds = Math.floor(Math.abs(ticks) / 10000000);
        const hours = Math.floor(totalSeconds / 3600);
        const minutes = Math.floor((totalSeconds % 3600) / 60);
        const seconds = totalSeconds % 60;
        const sign = negative ? '-' : '';
        if (hours > 0) {
            return `${sign}${hours}:${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
        }
        return `${sign}${minutes}:${String(seconds).padStart(2, '0')}`;
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
            overflow: hidden;
            position: relative;
            background: var(--ha-card-background, var(--card-background-color, #fff));
            border-radius: var(--ha-card-border-radius, 12px);
            box-shadow: var(--ha-card-box-shadow, none);
            border: var(--ha-card-border, 1px solid var(--ha-card-border-color, var(--divider-color, #e0e0e0)));
            transition: all 0.3s ease-out;
            container-type: size;
            container-name: now-playing;
            display: flex;
            flex-direction: column;
            box-sizing: border-box;
            min-height: 0;
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
            align-items: flex-start;
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
        }
        .media-type-badge {
            top: 6px;
            left: 6px;
            padding: 2px 8px 1px 8px;
            font-size: 0.8rem;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.3px;
            background: var(--primary-color);
            box-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }
        .media-type-badge.movie { background-color: #AA5CC3; }
        .media-type-badge.series { background-color: #F2A218; }
        .media-type-badge.episode { background-color: #F59E0B; }
        .media-type-badge.audio { background-color: #10B981; }

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
            height: 100%;
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
            font-size: 0.85rem;
            color: var(--secondary-text-color);
            opacity: 0.8;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            margin-bottom: 1px;
            margin-top: 5px;
        }
        .client-line {
            font-size: 0.75rem;
            color: var(--secondary-text-color);
            opacity: 0.4;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
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
            .empty-state .logo-container.full-logo {
                display: none;
            }
            .empty-state .logo-container.mini-icon {
                display: flex;
                opacity: 0.9;
                margin-bottom: 12px;
            }
            .empty-state img {
                max-width: 80px;
            }
            .empty-state p {
                font-size: 0.9rem;
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
        }

        /* Very short cards: hide extra text */
        @container now-playing (max-height: 195px) {
            .meta-line, .client-line {
                display: none !important;
            }
            .card-header {
                display: none !important;
            }
            .title {
                font-size: 1.2rem;
                line-height: 1.1;
                margin-bottom: 2px;
            }
            .main-container {
                gap: 12px;
            }
            .card-content {
                gap: 8px;
            }
            .poster-container {
                --short-badge-padding: 1px !important;
            }
        }

        /* Ultra-Compact Micro Mode (Overlay controls on poster) */
        @container now-playing (max-width: 350px) {
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
        @container now-playing (max-height: 180px) {
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

        /* Tall but Narrow Mode */
        @container now-playing (min-height: 240px) and (max-width: 400px) {
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
        @container now-playing (min-height: 300px) and (max-width: 450px) {
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

    `;

}
